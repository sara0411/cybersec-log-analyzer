FROM python:3.9-slim

WORKDIR /app

# Installation des dépendances minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Installation des bibliothèques Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p data/raw_logs data/processed data/uploads data/reports models

# Exposer le port
EXPOSE 8000

# Définir les variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py

# Volume pour les données persistantes
VOLUME ["/app/data", "/app/models"]

# Commande pour démarrer l'application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]