import nltk
import re
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import TfidfVectorizer
nltk.data.path.append('C:/Users/PC/AppData/Local/Packages/PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0/LocalCache/Roaming/nltk_data')
# Télécharger les ressources NLTK nécessaires
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

def tokenize_logs(logs):
    """Tokenise chaque entrée de log après nettoyage simple."""
    tokenized_logs = []
    for log in logs:
        if isinstance(log, str):
            # Normaliser le texte
            log = log.lower()
            # Tokeniser
            tokens = word_tokenize(log)
            # Garder uniquement les tokens alphanumériques
            tokens = [token for token in tokens if token.isalnum()]
            tokenized_logs.append(tokens)
        else:
            tokenized_logs.append([])
    return tokenized_logs

def extract_features(logs):
    """Extrait les vecteurs TF-IDF des logs bruts."""
    vectorizer = TfidfVectorizer(
        tokenizer=word_tokenize,
        token_pattern=None  # Important pour utiliser notre tokenizer NLTK
    )
    features = vectorizer.fit_transform(logs)
    return features, vectorizer
