import os
import sys
import nltk
from app import app

# Télécharger les ressources NLTK nécessaires
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')

if __name__ == "__main__":
    # Créer les répertoires nécessaires s'ils n'existent pas
    os.makedirs('data/uploads', exist_ok=True)
    os.makedirs('data/reports', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    # Paramètres de démarrage
    debug = "--debug" in sys.argv
    port = 8000
    
    # Lancer l'application
    app.run(host='0.0.0.0', port=port, debug=debug)