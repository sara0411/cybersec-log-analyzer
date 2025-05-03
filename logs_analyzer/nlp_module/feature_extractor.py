import numpy as np
import pandas as pd
import nltk
import re
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
df=pd.read_csv('C:/Users/PC/Documents/LogAnalyser/cybersec-log-analyzer/advanced_cybersecurity_data.csv')
class LogFeatureExtractor:
    def __init__(self):
        # Téléchargement des ressources NLTK nécessaires
        try:
            nltk.data.find('tokenizers/punkt')
            nltk.data.find('corpora/stopwords')
        except LookupError:
            nltk.download('punkt')
            nltk.download('stopwords')
        
        self.stop_words = set(stopwords.words('english'))
        
        # Liste de mots spécifiques à la sécurité
        self.security_keywords = [
            'sql', 'injection', 'script', 'xss', 'cross', 'site', 'admin', 
            'password', 'login', 'shell', 'exec', 'drop', 'table', 'select',
            'attack', 'malicious', 'vulnerability', 'exploit', 'payload',
            'bypass', 'auth', 'authorization', 'authentication', 'hack'
        ]
        
    def tokenize_text(self, text):
        """Tokenise et filtre le texte."""
        if not isinstance(text, str):
            return []
            
        # Normalisation du texte
        text = text.lower()
        
        # Tokenisation
        tokens = word_tokenize(text)
        
        # Filtrage des tokens
        tokens = [token for token in tokens if token.isalnum() and token not in self.stop_words]
            
        return tokens
        
    def preprocess_logs_for_nlp(self, df):
        """Prépare les logs Apache pour l'analyse NLP."""
        # Créer une colonne combinée de texte
        if 'url' in df.columns and 'method' in df.columns:
            df['text_for_analysis'] = df['method'].astype(str) + ' ' + df['url'].astype(str)
        else:
            df['text_for_analysis'] = df['raw']
        
        # Tokenisation
        df['tokens'] = df['text_for_analysis'].apply(self.tokenize_text)
        
        return df
        
    def extract_tfidf_features(self, texts, max_features=1000):
        """Extrait les caractéristiques TF-IDF des textes."""
        vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),  # Unigrammes et bigrammes
            stop_words='english'
        )
        
        features = vectorizer.fit_transform(texts)
        feature_names = vectorizer.get_feature_names_out()
        
        return features, vectorizer, feature_names
        
    def extract_security_features(self, df):
        """Extrait des caractéristiques spécifiques à la sécurité sur les Apache logs."""
        # Fonction pour compter les mots clés de sécurité
        def count_security_keywords(text):
            if not isinstance(text, str):
                return 0
            text = text.lower()
            return sum(1 for keyword in self.security_keywords if keyword in text)
        
        # Compter les caractères spéciaux
        def count_special_chars(text):
            if not isinstance(text, str):
                return 0
            special_chars = re.findall(r'[;\'\"<>(){}[\]\\|=&]', text)
            return len(special_chars)
        
        # Application sur la colonne 'text_for_analysis'
        df['security_keyword_count'] = df['text_for_analysis'].apply(count_security_keywords)
        df['special_char_count'] = df['text_for_analysis'].apply(count_special_chars)
        
        # Détecter les modèles d'injection SQL
        df['has_sql_pattern'] = df['text_for_analysis'].apply(
            lambda x: 1 if isinstance(x, str) and re.search(r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b.*\b(FROM|INTO|WHERE|TABLE)\b)', x, re.IGNORECASE) else 0
        )
        
        # Détecter les modèles XSS
        df['has_xss_pattern'] = df['text_for_analysis'].apply(
            lambda x: 1 if isinstance(x, str) and re.search(r'<[^>]*script|javascript:|on\w+\s*=', x, re.IGNORECASE) else 0
        )
        
        return df
    
    def process_data(self, df):
        """Pipeline complet pour extraire les features NLP des logs Apache."""
        # Prétraitement des logs
        df = self.preprocess_apache_logs_for_nlp(df)
        
        # Extraction des caractéristiques de sécurité
        df = self.extract_security_features(df)
        
        # Extraction des caractéristiques TF-IDF
        if len(df) > 0:
            tfidf_features, vectorizer, feature_names = self.extract_tfidf_features(
                df['text_for_analysis'].fillna('')
            )
            tfidf_df = pd.DataFrame(
                tfidf_features.toarray(),
                columns=feature_names
            )
            
            # Joindre les caractéristiques de sécurité et TF-IDF
            features_df = pd.concat([
                df[['security_keyword_count', 'special_char_count', 'has_sql_pattern', 'has_xss_pattern']].reset_index(drop=True),
                tfidf_df.reset_index(drop=True)
            ], axis=1)
            
            return df, features_df, vectorizer
        else:
            return df, pd.DataFrame(), None

