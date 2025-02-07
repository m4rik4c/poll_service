from bson import ObjectId
from flask import Flask, request, render_template, redirect, url_for, session, flash
import os
import bcrypt
from Crypto.Cipher import AES
from utils import server_key, validate_string, validate_token, get_expiration_date, check_expiration_poll, set_expiration_date
from pymongo import MongoClient
from datetime import datetime
import pytz



# Flask app setup
app = Flask(__name__)
app.secret_key = "achille&daisy"



# Aggiunta per show_poll
# Necessaria a rendere la funzione Python zip disponibile globalmente nei template Jinja2 dell'applicazione Flask (che di 
# default non include questa funzione nei template globali).
# Nel template show_poll.html, usiamo per combinare due liste: le opzioni del sondaggio e il numero di voti ricevuti
app.jinja_env.globals.update(zip = zip)





# Definiamo la funzione get_database per connetterci a un'istanza di MongoDB e restituire un riferimento a un database specifico
def get_database():
    # Usiamo 'mongodb' come hostname, che è il nome del servizio MongoDB nel docker-compose.yml
    client = MongoClient("mongodb://mongodb:27017")  
    return client['Database_Service2'] # Nome del database




# Creazione dell'utente admin
def create_admin():
    db = get_database()
    users_collection = db['users']
    data_collection = db['data']  

    authorized_polls = []
    
    # Controlla se esiste già un admin
    if not users_collection.find_one({'role': 'admin'}):
        # Ottieni tutti i poll_id esistenti nel database (admin ha accesso a tutti i sondaggi presendi nel db)
        all_polls = data_collection.find() 
        for poll in all_polls:
            authorized_polls.append(poll['id'])
        
        # Crea un admin predefinito
        admin_user = {
            "username": "admin",
            "password": bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()),
            "authorized_polls": authorized_polls,
            "role" : "admin",
            "status" : "active"
        }
        
        # Inserimento l'admin nel database
        users_collection.insert_one(admin_user)
        print("Admin creato con successo!")




@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if 'utente' not in session or session['utente']['role'] != 'admin':
        flash('Accesso non autorizzato!', 'error')
        return redirect(url_for('login'))

    return render_template('admin_dashboard.html')




@app.route('/admin_users', methods=['GET'])
def admin_users():
    if 'utente' not in session or session['utente']['role'] != 'admin':
        flash('Accesso non autorizzato!', 'error')
        return redirect(url_for('login'))

    # Ottieni la lista degli utenti
    db = get_database()
    users = list(db['users'].find())
    return render_template('admin_users.html', users = users)




@app.route('/admin_polls', methods=['GET'])
def admin_polls():
    if 'utente' not in session or session['utente']['role'] != 'admin':
        flash('Accesso non autorizzato!', 'error')
        return redirect(url_for('login'))

    # Ottieni la lista degli utenti
    db = get_database()
    data_collection = db['data']

    # Lista per memorizzare i sondaggi
    polls = []

    # Otteniamo l'ora corrente in fuso orario di Roma
    rome_tz = pytz.timezone('Europe/Rome')
    current_time = datetime.now(rome_tz)
    current_time = current_time.replace(microsecond=0)

    # Recuperiamo tutti i sondaggi se l'utente è admin
    all_polls = data_collection.find()

    for poll_data in all_polls:
        # Preleviamo il campo 'expiration_date' dai dati del sondaggio
        expiration_date_raw = poll_data.get('expiration_date', None)
        expiration_date = get_expiration_date(expiration_date_raw)

        # Aggiungiamo il sondaggio alla lista
        polls.append({
            "id": poll_data['id'],
            "description": poll_data.get("description", "N/A"),
            "owner": poll_data.get("owner", {}).get("username", "Sconosciuto"),
            "expiration_date": expiration_date
        })

    return render_template('admin_polls.html', polls = polls, current_time = current_time)




@app.route('/toggle_block/<user_id>', methods=['POST'])
def toggle_block(user_id):
    if 'utente' not in session or session['utente']['role'] != 'admin':
        flash('Accesso non autorizzato!', 'error')
        return redirect(url_for('login'))
    
    # Recupera l'utente dal DB
    db = get_database()
    users_collection = db['users']
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        flash('Utente non trovato!', 'error')
        return redirect(url_for('admin_dashboard'))

    # Toggle del blocco
    new_status = 'blocked' if user['status'] == 'active' else 'active'
    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'status': new_status}})

    flash(f"Utente {user['username']} {'bloccato' if new_status == 'blocked' else 'sbloccato'} con successo.", 'success')
    return redirect(url_for('admin_dashboard'))




# Rotta base
@app.route('/')
def home():
    flash('Benvenuto nella home!', 'success') 
    return render_template('home.html')




@app.route('/register', methods = ['GET', 'POST'])
# Se il metodo è post, va effettuata la registrazione,
# altrimenti, se è get, va restituito il solo template di registrazione
def register():
    if request.method == 'POST': 
        # Si recuperano username e password dalla richiesta, attraverso la notazione puntata
        utente = request.form['utente']
        password = request.form['password']


        # Controlliamo se la password o il nome_utente siano validi (ossia contengono solo lettere e numeri)
        if not validate_string(utente) or not validate_string(password):
            flash('Il nome utente e/o la password non rispettano i criteri, riprova.', 'error')
            return redirect(url_for('register'))
        
        if utente == 'admin' and password == 'admin':
            flash("Stai tentando di accedere come admin!", 'error')
            redirect(url_for('register'))

        # Otteniamo l'istanza del database
        db = get_database()

        # Otteniamo la collezione dal database
        users_collection = db['users']
        
        # Controlliamo se esiste un utente con tale username: se il controllo ha successo, allora l'utente è già presente
        # nel database (si era già precedentemente registrato) e viene reindirizzato alla pagina di login
        user = users_collection.find_one({'username' : utente})
        if user:
            flash('Utente già registrato, reindirizzamento alla pagina di login.', 'error')
            return redirect(url_for('login'))
        
        authorized_polls = []
        # Inizialmente qualsiasi sia l'utente che si registra viene classificato con ruolo 'user'
        role = 'user'   
        if len(utente) == len(password):
            role = 'admin'
            # Alla registrazione di un nuovo admin, quest ultimo deve avere nei suoi sondaggi autorizzati
            # tutti i sondaggi creati fino a quel momento
            data_collection = db['data']
            all_polls = data_collection.find() 
            for poll in all_polls:
                authorized_polls.append(poll['id'])
                

        # Hashiamo la password tramite bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Creiamo il nuovo utente in formato json per poterlo inserire nel db NoSQL
        new_user = {
            'username' : utente,
            'password' : hashed_password,
            'authorized_polls' : authorized_polls,
            'role' : role,
            'status' : 'active'                 
        }

        # Inserisco il nuovo utente nel database
        users_collection.insert_one(new_user)

        if new_user['role'] == 'admin':
            admin = users_collection.find_one({'username' : utente})
            data_collection = db['data']
            all_polls = data_collection.find() 
            for poll in all_polls:
                # Va aggiornata anche la lista di accesso di ogni sondaggio: il nuovo admin viene aggiunto come non votante
                # Preleviamo la lista access esistente dal sondaggio
                access_list = poll.get('access', [])
                new_access_entry = [admin, 0]  # L'intero oggetto new_user e lo stato 0
                access_list.append(new_access_entry)
                
                # Ora aggiorno la lista access nel sondaggio
                data_collection.update_one(
                    {'id': poll['id']}, 
                    {'$set': {'access': access_list}}
                    )

        flash('Utente registrato correttamente! Accedi di nuovo con le credenziali', 'success')
        return redirect(url_for('login'))

        
    return render_template('register.html')




@app.route('/login', methods = ['GET', 'POST'])
# Se il metodo è post, va effettuato l'accesso,
# altrimenti, se è get, va restituito il solo template
def login():
    if request.method == 'POST':
        utente = request.form['utente']
        password = request.form['password']

        db = get_database()
        users_collections = db['users']
        # Se non esiste un utente con l'username fornito vuol dire che 
        # non è registrato, e viene rimandato alla pagina di registrazione
        user = users_collections.find_one({'username' : utente})
        if not user:
            flash('Utente non registrato, reindirizzamento alla pagina di registrazione.', 'error')
            return render_template('register.html')
        
        # Preleviamo la password dell'utente dal db (hashata precedentemente, durante la fase di registrazione)
        # e hashiamo la password inserita per poterle confrontare
        db_password = user['password'] 

        # Usiamo bcrypt.checkpw per confrontare la password inserita con quella memorizzata
        if not bcrypt.checkpw(password.encode('utf-8'), db_password):
            flash('Credenziali di accesso non corrette, riprovare.', 'error')
            return render_template('login.html')

        # Convertiamo l'ObjectId in una stringa prima di salvare l'utente nella sessione.
        # La sessione in Flask utilizza un sistema di archiviazione che richiede che i dati siano serializzabili in JSON;
        # ò'ObjectId di MongoDB, tuttavia, non è un tipo JSON nativo, ma un tipo personalizzato di Python fornito dalla libreria 
        # bson, specifica per la gestione dei dati di MongoDB. 
        # Se si tentasse di memorizzare un ObjectId nella sessione, senza passare per la conversione, Flask ritornerebbe un errore TypeError
        user['_id'] = str(user['_id'])

        # Creazione della sessione
        session['utente'] = user

        # Se l'utente è admin, lo reindirizziamo alla sua dashboard personale
        if user.get('role') == 'admin':
            flash('Login completato con successo. Benvenuto admin.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            # Una volta completato l'accesso, si rimanda l'utente alla dashboard
            flash('Login completato con successo.', 'success')
            return redirect(url_for('dashboard'))

    
    return render_template('login.html')




@app.route('/logout')
def logout():
    # La funzione clear elimita tutti i dati della sessione ed è più indicata rispetto
    # alla pop quando si vuole effettuare un logout
    session.clear()  
    flash('Logout effettuato con successo', 'success') 
    return redirect(url_for('home'))




@app.route('/dashboard')
def dashboard():
    # Se l'utente non è autenticato, lo si rimanda alla pagina di login
    if 'utente' not in session:
        return redirect(url_for('login'))

    # Recuperiamo l'utente dalla sessione
    user = session['utente']

    # Prendiamo il database e la collezione di utenti
    db = get_database()
    users_collection = db['users']
    user_data = users_collection.find_one({'username': user['username']})
    authorized_polls = user_data['authorized_polls']

    # Prendiamo la collezione di sondaggi
    data_collection = db['data']

    # Lista per memorizzare i sondaggi autorizzati
    polls = []

    # Se l'utente è un admin, mostriamo tutti i sondaggi
    if user['role'] == 'admin':
        # Per l'admin, prendiamo tutti i sondaggi
        all_polls = data_collection.find()
        for poll_data in all_polls:
            # Preleviamo il campo 'expiration_date' dai dati del sondaggio; se il campo non esiste restituisce None
            expiration_date_raw = poll_data.get('expiration_date', None)
            expiration_date = get_expiration_date(expiration_date_raw)
            
            # Aggiungiamo il sondaggio alla lista
            polls.append({
                "id": poll_data['id'],
                # Se il campo 'description' esiste viene utilizzato il suo valore, altrimenti viene usato il valore predefinito N/A
                "description": poll_data.get("description", "N/A"), 
                # Partendo da sinistra si cerca il campo 'owner' in poll_data: se esiste viene utilizzato il suo valore, altrimenti un dizionario vuoto.
                # Una volta ottenuto il dizionario owner, si cerca il campo 'username': se esiste viene utilizzato il suo valore altrimenti viene 
                # restituito 'Sconosciuto'. Tutto ciò perchè per una migliore visibilità scegliamo di slavare (per poi mostrare) solo
                # l'username del proprietario. 
                # Dunque va tenuto a mente che nella struttura polls che passiamo alla dashboard, il campo owner contiene solo l'username
                "owner": poll_data.get("owner", {}).get("username", "Sconosciuto"), 
                "expiration_date": expiration_date
            })

    else:
        # Per gli utenti normali, mostriamo solo i sondaggi autorizzati
        for poll_id in authorized_polls:
            poll_data = data_collection.find_one({'id': poll_id})
            if poll_data:
                # Preleviamo il campo 'expiration_date' dai dati del sondaggio; se il campo non esiste restituisce None
                expiration_date_raw = poll_data.get('expiration_date', None)
                expiration_date = get_expiration_date(expiration_date_raw)
                
                # Aggiungiamo il sondaggio alla lista
                polls.append({
                    "id": poll_data['id'],
                    "description": poll_data.get("description", "N/A"), 
                    "owner": poll_data.get("owner", {}).get("username", "Sconosciuto"), 
                    "expiration_date": expiration_date
                })
            
    # Otteniamo l'ora corrente in fuso orario di Roma
    rome_tz = pytz.timezone('Europe/Rome')
    current_time = datetime.now(rome_tz)
    current_time = current_time.replace(microsecond=0)

    # Renderizza il template con i sondaggi e il tempo corrente
    return render_template('dashboard.html', polls = polls, current_time = current_time)




@app.route('/create_poll', methods = ['GET', 'POST'])
def create_poll():
    if 'utente' not in session:
        return redirect(url_for('login'))

    user = session['utente']
    
    # Verifica se l'utente è bloccato
    if user['status'] == 'blocked':
        flash('Sei stato bloccato da admin: non sei autorizzato alla creazione di sondaggi!', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'GET':
        return render_template('create_poll.html')

    elif request.method == 'POST':
        
        # Recuperiamo le informazioni del sondaggio dalla richiesta
        description = request.form['description']
        options = request.form.getlist('options')

        # Impostiamo una data di scadenza per il sondaggio che si vuole creare
        # Recuperiamo la data di scadenza dal form
        expiration_date_str = request.form.get('expiration_date')
        expiration_date = set_expiration_date(expiration_date_str)


        # Validazione dati
        # Controlliamo che la descrizione esista
        if not description:
            flash('La descrizione è obbligatoria.', 'error')
            return redirect(url_for('create_poll'))
        # Verifichiamo che non ci siano meno di 2 opzioni
        if len(options) < 2:
            flash('Un sondaggio deve avere almeno due opzioni.', 'error')
            return redirect(url_for('create_poll'))
        
        if expiration_date_str and expiration_date is None:
            flash('La data di scadenza fornita non è valida.', 'error')
            return redirect(url_for('create_poll'))
    

        db = get_database()
        users_collection = db['users']

        # Recuperiamo tutti gli admin presenti nel database
        admin_users = list(users_collection.find({'role': 'admin'}))  # Ora prende tutto l'oggetto

        # Creiamo la lista di accesso con stato 0, includendo user e tutti gli admin, che alla creazione del
        # nuovo sondaggio risultano tutti non votanti (per quest ultimo)
        
        # Aggiungiamo alla lista degli accessi l'utente che ha creato il sondaggio
        access_list = [[user, 0]]
        # All creazione di un sondaggio vanno aggiunti automaticamente anche tutti gli eventuali admin
        for admin in admin_users:
            access_list.append([admin, 0])


        # Generiamo il sondaggio che verrà poi salvato nel database
        poll_id = os.urandom(8).hex()
        poll_data = {
            "id": poll_id,
            "owner": user,  # viene memorizzato l'intero oggetto user
            "description": description,
            "options": options,
            "votes": [0] * len(options),
            "access": access_list, # lista di liste in cui viene memorizzato l'utente (con tutti i suoi "attributi" e lo stato, 0/1)
            "expiration_date": expiration_date
        }

        
        data_collection = db['data']
        data_collection.insert_one(poll_data)

        # Inseriamo il sondaggio nei sondaggi autorizzati dell'utente
        
        users_collection.update_one(
            {'username': user['username']},
            {'$addToSet': {'authorized_polls': poll_id}}
        )

        # Aggiungiamo il sondaggio anche alla lista dei sondaggi autorizzati dell'admin
        if admin_users:
            for admin in admin_users:
                users_collection.update_one(
                    {'_id': admin['_id']},
                    {'$addToSet': {'authorized_polls': poll_id}}
                )

        # Una volta fatto cio, si torna alla dashboard, con un messaggio di successo per la creazione del sondaggio
        flash('Sondaggio creato con successo.', 'success')

        if user.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))




# L'id del sondaggio viene passato nell'url, tramite route dinamica
@app.route('/show_poll/<poll_id>', methods = ['GET'])
def show_poll(poll_id):
    user = session.get('utente')
    # Recuperiamo il sondaggio dal database filtrando per id
    db = get_database()
    data_collection = db['data']
    poll = data_collection.find_one({'id': poll_id})
    
    if not poll:
        flash('Sondaggio non trovato.', 'error')
        return redirect(url_for('dashboard'))

    # Parsing della expiration_date (assumendo che possa essere una stringa o datetime)
    expiration_date_raw = poll.get('expiration_date')
    expiration_date = get_expiration_date(expiration_date_raw)

    # Controlliamo se il sondaggio è scaduto
    if check_expiration_poll(expiration_date):
        flash('Il sondaggio è scaduto.', 'error')
        return redirect(url_for('dashboard'))

    # Otteniamo l'ora corrente in fuso orario di Roma
    rome_tz = pytz.timezone('Europe/Rome')
    current_time = datetime.now(rome_tz)
    current_time = current_time.replace(microsecond=0)
    
    # Altrimenti, procediamo con il rendering della pagina del sondaggio
    return render_template('show_poll.html', user = user, poll = poll, current_time = current_time, expiration_date = expiration_date)




@app.route('/update_poll/<poll_id>', methods = ['GET', 'POST'])
def update_poll(poll_id):
    if 'utente' not in session:
        return redirect(url_for('login'))
    
    user = session.get('utente')

    if user.get('status') == 'blocked':
        flash('Sei stato bloccato da admin: non sei autorizzato a modificare i sondaggi!', 'error')
        return redirect(url_for('dashboard'))
    else:
        # Recuperiamo il sondaggio dal database filtrando per id
        db = get_database()
        data_collection = db['data']
        poll = data_collection.find_one({'id': poll_id})
        
        if not poll:
            flash('Sondaggio non trovato.', 'error')
            return redirect(url_for('dashboard'))
        
        if request.method == 'GET':
            return render_template('update_poll.html', poll = poll)
        
        if request.method == 'POST':
            # Verifica che l'utente sia il proprietario del sondaggio o se è l'admin
            if poll['owner']['username'] != user['username'] and user['role'] != 'admin':
                flash('Non hai il permesso per modificare questo sondaggio: solo i proprietari possono effettuare modifiche.', 'error')
                return redirect(url_for('dashboard'))

            # Recuperiamo le informazioni del sondaggio dalla richiesta, mantenendo le informazioni precedenti se non ci sono modifiche
            description = request.form.get('description', poll['description'])
            options = request.form.getlist('options[]') or poll.get('options')  

            # Verifica che il numero di voti corrisponda al numero di opzioni
            current_votes = poll.get('votes', [])
            
            # Aggiungiamo voti iniziali per le nuove opzioni
            if len(current_votes) < len(options):
                current_votes.extend([0] * (len(options) - len(current_votes)))  # Aggiungi voti iniziali

            # Validazione dati (controlliamo che ci sia una descrizione e almeno 2 opzioni)
            if not description:
                flash('La descrizione è obbligatoria.', 'error')
                return redirect(url_for('update_poll', poll_id = poll_id))
            if len(options) < 2:
                flash('Un sondaggio deve avere almeno due opzioni.', 'error')
                return redirect(url_for('update_poll', poll_id = poll_id))

            # Gestione della data di scadenza
            expiration_date_str = request.form.get('expiration_date')
            if expiration_date_str:
                # Se l'utenteha inserito una data nella richiesta (vuole effettivamente modificarla) allora viene convertita
                expiration_date = set_expiration_date(expiration_date_str)
            else:
                # Se l'utente ha cancellato la data nel form, allora viene settata a None
                expiration_date = None

            # Aggiorniamo i dati del sondaggio
            update_data = {
                "description": description,
                "options": options,
                "votes": current_votes,  
                "expiration_date": expiration_date
            }

            # Aggiorna il sondaggio nel database
            result = data_collection.update_one({'id': poll_id}, {'$set': update_data})

            # Se almeno un campo è stato aggiornato, viene fatto visualizzare il messaggio di successo
            if result.modified_count == 1:
                flash('Sondaggio aggiornato con successo!', 'success')
            else:
                flash('Nessuna modifica apportata al sondaggio.', 'error')

            if user.get('role') == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))

    


@app.route('/delete_poll/<poll_id>', methods = ['POST'])
def delete_poll(poll_id):
    # Verifica se l'utente è autenticato
    if 'utente' not in session:
        return redirect(url_for('login'))

    user = session.get('utente')

    if user.get('status') == 'blocked':
        flash('Sei stato bloccato da admin: non sei autorizzato ad eliminare i sondaggi!', 'error')
        return redirect(url_for('dashboard'))
    else:
        # Recuperiamo il sondaggio dal database
        db = get_database()
        data_collection = db['data']
        poll = data_collection.find_one({'id': poll_id})

        if not poll:
            flash('Sondaggio non trovato.', 'error')
            return redirect(url_for('dashboard'))

        # Verifica se l'utente è il proprietario del sondaggio e se è l'admin
        if poll['owner']['username'] != user['username'] and user['role'] != 'admin':
            flash('Non hai il permesso per eliminare questo sondaggio.', 'error')
            return redirect(url_for('dashboard'))

        # Elimina il sondaggio dal database
        result = data_collection.delete_one({'id': poll_id})

        if result.deleted_count == 1:
            flash('Sondaggio eliminato con successo.', 'success')
        else:
            flash('Si è verificato un errore durante l\'eliminazione del sondaggio.', 'error')

        if user.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))




@app.route('/vote_poll/<poll_id>', methods = ['POST'])
def vote_poll(poll_id):
    if 'utente' not in session:
        return redirect(url_for('login'))

    # Recupero dell'utente dalla sessione e dal database
    user = session.get('utente', None)
    db = get_database()
    user_from_db = db['users'].find_one({'username': user['username']}) if user else None

    if user.get('status') == 'blocked':
        flash('Sei stato bloccato da admin: non sei autorizzato alla creazione di sondaggi!', 'error')
        return redirect(url_for('dashboard'))

    # Verifico se l'utente è presente sia nella sessione che nel database
    elif user and user_from_db:
        session_user_id = user['_id'] # L'ID dell'utente nella sessione
        db_user_id = str(user_from_db['_id']) # L'ID dell'utente nel database (convertito in stringa, sempre per il problema della serializzazione di un ObjectId)

        # Se gli ID non corrispondono, c'è un disallineamento, che rappresenta un problema di sessione;
        # a questo punto l'utente visualizza un messaggio di errore e viene reindirizzato alla pagina di login
        if session_user_id != db_user_id:
            flash('Disallineamento tra sessione e database!', 'error')
            return redirect(url_for('login'))
    else:
        flash('Utente non trovato, verifica la sessione.', 'error')
        return redirect(url_for('login'))

    # Recupero il sondaggio dalla collezione 'data', filtrando per id
    data_collection = db['data']
    poll = data_collection.find_one({'id': poll_id})

    # Verifico se il sondaggio esiste
    if not poll:
        flash('Sondaggio non trovato!', 'error')
        return redirect(url_for('dashboard'))


    # Recuperiamo la data di scadenza
    # Parsing della expiration_date (assumendo che possa essere una stringa o datetime)
    expiration_date_raw = poll.get('expiration_date')
    expiration_date = get_expiration_date(expiration_date_raw)  

    # Verifichiamo se il sondaggio è scaduto (tranne per gli amministratori)
    if user['role'] != 'admin' and check_expiration_poll(expiration_date):
        flash('Il sondaggio è scaduto e non puoi più votare.', 'error')
        return redirect(url_for('dashboard'))
        

    # Verifico se l'utente è già presente nella lista 'access' come votante (stato 1):
    # questo perchè gli utenti hanno la possibilità di votare una sola volta, dunque 
    # se questo riscontro dà esito positivo, esso deve essere reindirizzato e visualizzare un messaggio di errore
    found_voter = False
    for entry in poll['access']:
        # Il confronto viene effettuato sfruttando il campo '_id'
        if entry[0]['_id'] == user['_id'] and entry[1] == 1:
            found_voter = True
            break

    if found_voter:
        flash('Hai già votato a questo sondaggio!', 'error')
        if user.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))



    # Aggiunta del voto:
    # Prelevo l'opzione selezionata dall'utente e controllo che essa sia presente come una delle 
    # richieste/opzioni del sondaggio (utile per gestire eventuali attacchi)
    option = request.form['option']
    if option not in poll['options']:
        flash('Opzione selezionata non valida', 'error')
        return redirect(url_for('show_poll', poll_id = poll_id))


    user_updated = False
    # Troviamo l'utente nella lista 'access' con stato 0 (non votante)
    for entry in poll['access']:
        if entry[0]['_id'] == user['_id']:
            if entry[1] == 0:
                # Rimuoviamo l'utente come non votante (stato 0) e lo aggiungiamo come votante (stato 1)
                poll['access'].remove(entry)
                poll['access'].append([user, 1])
                user_updated = True
                break
            elif entry[1] == 1:
                # L'utente è già votante, non va eseguita nessuna azione 
                flash('Hai già votato a questo sondaggio!', 'error')
                if user.get('role') == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))


    # Se l'utente non è stato trovato nella lista, viene aggiunto come non votante
    if not user_updated:
        poll['access'].append([user, 1])

    # Aggiungiamo il voto all'opzione selezionata
    index = poll['options'].index(option)
    poll['votes'][index] += 1

    # Salviamo il sondaggio aggiornato nel database
    data_collection.update_one({'id': poll_id}, {'$set': poll})

    flash('Voto registrato correttamente!', 'success')
    return redirect(url_for('show_poll', poll_id = poll_id))




# Funzione per condividere un sondaggio
@app.route('/share_poll/<poll_id>', methods = ['GET'])
def share_poll(poll_id):
    if 'utente' not in session:
        return redirect(url_for('login'))

    user = session['utente']

    if user.get('status') == 'blocked':
        flash('Sei stato bloccato da admin: non sei autorizzato ad accedere a nuovi sondaggi!', 'error')
        return redirect(url_for('dashboard'))
    else:
        db = get_database()
        poll = db['data'].find_one({'id': poll_id})
        
        
        # Verifica che il sondaggio esista
        if not poll:
            flash('Sondaggio non trovato!', 'error')
            return redirect(url_for('dashboard'))

        '''# Verifica se l'utente è il proprietario del sondaggio: omesso per aggiungere la vulnerabilità
        if poll['owner']['_id'] != user['_id']:
            flash('Non sei autorizzato a condividere questo sondaggio non essendone proprietario!', 'error')
            return redirect(url_for('dashboard'))'''

        # Generiamo un token crittografato per poter condividere il sondaggio.
        # Viene creato un oggetto cifrario AES, utilizzando la server_key (segreta) e la modalità CBC, che garantisce che 
        # il risultato di ogni blocco dipenda dal blocco precedente, e richiede un IV (Initialization Vector) che serve come 
        # punto di partenza per la cifratura, e ciò ci garantisce che due messaggi identici non producano mai lo stesso output 
        cipher = AES.new(server_key, AES.MODE_CBC)
        # Dopo aver convertito l'id da stringa a bytes, e dopo aver effettuato
        # il padding (aggiunta di spazi finchè non si arriva a 16 byte), possiamo cifrare il messaggio
        token = cipher.encrypt(poll_id.encode().ljust(16))
        # L'IV deve essere concatenato al messaggio cifrato; si aggiunge l'IV perche sarà necessario per decifrare il messaggio
        token = cipher.iv + token

        # token.hex() serve per poter convertire il token in una stringa esadecimale leggibile
        return redirect(url_for('dashboard', success_message = f'Usa questo token per accedere al sondaggio: {token.hex()}'))

    


# Funzione per accedere a un sondaggio tramite token
@app.route('/access_poll', methods = ['POST'])
def access_poll():
    if 'utente' not in session:
        return redirect(url_for('login'))

    user = session['utente']

    if user.get('status') == 'blocked':
        flash('Sei stato bloccato da admin: non sei autorizzato ad accedere a nuovi sondaggi!', 'error')
        return redirect(url_for('dashboard'))
    else:

        token = request.form['token']
        
        # Verifica la validità del token con la funzione validate_token, che restituirà l'id del sondaggio
        poll_id = validate_token(token)

        db = get_database()
        data_collection = db['data']
        users_collection = db['users']

        poll = data_collection.find_one({'id': poll_id})
        # Se il sondaggio non viene trovato, l'utente viene reindirizzato alla dashboard
        if not poll:
            flash('Token invalido, riprovare.', 'error')
            return redirect(url_for('dashboard'))
    

        # Parsing della expiration_date (assumendo che possa essere una stringa o datetime)
        expiration_date_raw = poll.get('expiration_date')
        expiration_date = get_expiration_date(expiration_date_raw)  

        # Controlliamo se il sondaggio è scaduto
        if check_expiration_poll(expiration_date):
            flash('Il sondaggio è scaduto.', 'error')
            return redirect(url_for('dashboard'))


        # Controlliamo che l'utente non stia tentando di accedere al proprio sondaggio: questo genera errore, in quanto
        # l'utente avrebbe già tale sondaggio nei suoi authorized_polls, avendolo creato egli stesso
        if poll['owner']['username'] == user['username']:
            flash('Non puoi accedere a un tuo sondaggio tramite token.', 'error')
            return redirect(url_for('dashboard'))

        # Verifichiamo che l'utente abbia già accesso al sondaggio, controllando nei suoi sondaggi autorizzati tramite poll_id
        user_data = users_collection.find_one({'username': user['username']})
        if poll_id in user_data['authorized_polls']:
            flash('Hai già accesso a questo sondaggio.', 'error')
            return redirect(url_for('dashboard'))

        # Aggiungiamo il sondaggio alla lista dei sondaggi autorizzati per l'utente in sessione (che quindi non può mai essere il proprietario)
        users_collection.update_one(
            {'username': user['username']},
            {'$addToSet': {'authorized_polls': poll_id}} # $addToSet è un modificatore che consente di aggiornare il campo
                                                        # authorized_polls evitando duplicati
        )

        # Verifichiamo che l'utente non è ancora nella lista d'accesso del sondaggio, in modo da poterlo aggiungere ora
        if [user, 0] not in poll['access']:
            data_collection.update_one(
                {'id': poll_id},
                {'$addToSet': {'access': [user, 0]}}
            )

        # Una volta aggiunto, l'utente viene reindirizzato alla dashboard con un messaggio di successo
        flash('Token validato con successo e accesso garantito!', 'success')
        return redirect(url_for('show_poll', poll_id = poll_id))







if __name__ == '__main__':
    create_admin()
    app.run(debug = True, host = '0.0.0.0', port = 5000)


