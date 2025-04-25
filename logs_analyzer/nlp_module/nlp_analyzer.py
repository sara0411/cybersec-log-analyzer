import nltk
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import TfidfVectorizer

# Télécharger les ressources NLTK nécessaires
nltk.download('punkt')

def tokenize_logs(logs):
    """Tokenize log entries."""
    return [word_tokenize(log) for log in logs]

def extract_features(logs):
    """Extract features using TF-IDF."""
    vectorizer = TfidfVectorizer()
    features = vectorizer.fit_transform(logs)
    return features, vectorizer