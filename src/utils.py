import string
from Crypto.Cipher import AES
import pytz
from datetime import datetime


from rich.console import Console

console = Console()


server_key = b"16_r4ndom_bytes!"



# Definiamo una funzione che poi sfrutteremo per effettuare controlli sulle password scelte dagli utenti del sito web.
# La funzione accetta come parametri:
# - inp, ossia il parametro di input che accetta, e può essere una stringa o una sequenza di byte;
# - lb, lower bound, indica la lunhgezza minima valida per l'input (in questo caso 5 caratteri è la lunghezza minima);
# - ub, upper bound, indica la lunghezza massima valida per l'input (in questo caso 64 caratteri, che coincide con il valore di default).
def validate_string(inp, lb = 5, ub = 64):
    valid_charset = string.ascii_letters + string.digits  # Caratteri validi: lettere e numeri
    # isistance è una funzione che serve a verificare il tipo di un oggetto: nel nostro caso in particolare
    # viene effettuato un confronto tra l'input e il tipo stringa, poichè si verifica se l'input inp è una stringa
    if isinstance(inp, str):
        return lb <= len(inp) <= ub and all(c in valid_charset for c in inp)
    # Viene effettuato un confronto tra l'input e il tipo byte
    elif isinstance(inp, bytes):
        return lb <= len(inp) <= ub and all(c in valid_charset.encode() for c in inp) # la differenza rispetto al blocco precedente è che qui occorre convertire in byte la sequenza di caratteri valid_charset
    # Se l'input non è nè una stringa nè una sequenza di byte, la funzione ritorna False.
    return False


    
def validate_token(token):
    try:
        # Decifratura del token: conversione del token da esadecimale a bytes
        ct = bytes.fromhex(token)
        # Creazione di un cifrario, sfruttando i primi 16 byte come IV
        cipher = AES.new(server_key, AES.MODE_CBC, iv = ct[:16])
        # Decifrazione dei restanti 16 byte per ottenere il poll_id
        # Si decripta, poi si fa la strip per togliere gli spazi, e infine
        # si decodifica per ottenere una stringa leggibile a partire dai byte
        poll_id = cipher.decrypt(ct[16:]).strip().decode()
        return poll_id
    except Exception as e:
        # Aggiungiamo la server_key all'eccezione come parte del messaggio
        new_message = f"Errore nel decifrare il token: {str(e)} (server_key={server_key})"
        # Stampa il traceback, includendo la server_key nel messaggio
        console.print_exception(show_locals=True)
        # Rilancia l'errore con il nuovo messaggio
        raise Exception(new_message) from e



def set_expiration_date(expiration_date_str):
    try:
        if expiration_date_str is None:
            return None
        # Se la data di scadenza è stata fornita, la parsifichiamo
        expiration_date = datetime.fromisoformat(expiration_date_str)
        # Rendiamo la data di scadenza aware (con fuso orario)
        rome_tz = pytz.timezone('Europe/Rome')
        # tzinfo dà informazioni sul fuso orario, in particolare qui si vuole controllare 
        # se l'utente non ha fornito un fuso orario (is None): in caso affermativo si modifica 
        # la data rendendola aware e nello specifico rispetto al fuso orario di Roma, in caso 
        # negativo (la data è già aware) la si rende specifica al fuso orario di Roma con un'altra funzione
        if expiration_date.tzinfo is None:
            expiration_date = rome_tz.localize(expiration_date)
        else:
            expiration_date = expiration_date.astimezone(rome_tz)
            
        return expiration_date
    except ValueError:
        return None



def get_expiration_date(expiration_date_raw):
    # Configurazione del fuso orario di Roma: pytz.timezone('Europe/Rome') crea un oggetto timezone che rappresenta
    # il fuso orario dell'Europa/Roma
    rome_tz = pytz.timezone('Europe/Rome')
    # Inizializzazione della data di scadenza: fissiamo un valore di dafault nel caso in cui il parsing 
    # fallisca oppure se il valore è mancante
    expiration_date = None  

    # Gestione del parsing della data di scadenza
    try:
        # Caso 1: la data è un datetime
        if isinstance(expiration_date_raw, datetime):
            # Verifica se la data di scadenza è naive (ignora il fuso orario): la funzione tzinfo dà
            # informazioni sul fuso orario della data. Se la data di scadenza è naive, viene convertita
            # al fuso orario di Roma
            if expiration_date_raw.tzinfo is None: 
                expiration_date = pytz.UTC.localize(expiration_date_raw).astimezone(rome_tz)
            else:
                # Altrimenti, la data, che è già aware, viene semplicemente sincronizzata col fuso orario di Roma
                expiration_date = expiration_date_raw.astimezone(rome_tz) 
        
        # Caso 2: la data è una stringa (ISO)
        elif isinstance(expiration_date_raw, str): 
            # Se la data è ancora una stringa ISO, allora va convertita in datetime
            expiration_date = datetime.fromisoformat(expiration_date_raw)
            # Dopo la conversione si procede con lo stesso identico ragionamento fatto sopra
            if expiration_date.tzinfo is None:
                expiration_date = pytz.UTC.localize(expiration_date).astimezone(rome_tz)
            else:
                expiration_date = expiration_date.astimezone(rome_tz)
    except Exception as e:
        # Gestione dell'errore se il parsing fallisce
        expiration_date = None

    return expiration_date



def check_expiration_poll(expiration_date):
    # Otteniamo l'ora corrente in fuso orario di Roma
    rome_tz = pytz.timezone('Europe/Rome')
    current_time = datetime.now(rome_tz)
    current_time = current_time.replace(microsecond=0)

    # Verifichiamo se la data di scadenza è valida e se è scaduta
    if expiration_date and expiration_date < current_time:
        return True
    return False