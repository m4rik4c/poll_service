# Usa un'immagine di base Python
FROM python:3.10

# Imposta la cartella di lavoro all'interno del contenitore
#WORKDIR /app

# Installa le dipendenze dal requirements.txt
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Copia i file locali dalla cartella src alla cartella di lavoro nel contenitore
COPY src .

# Comando per eseguire l'app Flask
CMD ["python", "/app/app.py"]
