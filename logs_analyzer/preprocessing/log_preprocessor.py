import re
import pandas as pd
import json
from datetime import datetime
from logs_analyzer.nlp_module.feature_extractor import LogFeatureExtractor

class LogPreprocessor:
    def __init__(self):
        # Expression régulière pour logs Apache/Nginx
        self.apache_pattern = re.compile(r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)')

        # Patterns d'attaques
        self.sql_patterns = [
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b.*\b(FROM|INTO|WHERE|TABLE)\b",
            r"(';--|\b(OR|AND)\b\s+\d+=\d+)",
            r"((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))"
        ]
        self.xss_patterns = [
            r"<[^>]*script",
            r"((%3C)|<)((%2F)|/)*[a-z0-9%]+((%3E)|>)",
            r"((%3C)|<)[^\n]+((%3E)|>)"
        ]
        self.extractor=LogFeatureExtractor()
        
    def process_log_file(self, filepath):
        """Lit un fichier de logs ligne par ligne, parse et retourne un DataFrame prêt à l'analyse."""
        parsed_logs = []

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = self.parse_apache_log(line.strip())
                parsed_logs.append(parsed)

        df = pd.DataFrame(parsed_logs)

        # Vérifie que 'raw' est bien présent
        if 'raw' not in df.columns:
            df['raw'] = ""  # ou tu peux lever une exception personnalisée

        return df

    
    def process_data(self, df):
        """Pipeline complet pour extraire les features NLP des logs Apache."""
        # Prétraitement des logs
        df = self.extractor.preprocess_logs_for_nlp(df)

        # Extraction des caractéristiques de sécurité
        df = self.extractor.extract_security_features(df)

        # Extraction des caractéristiques TF-IDF
        if len(df) > 0:
            tfidf_features, vectorizer, feature_names = self.extractor.extract_tfidf_features(
                df['text_for_analysis'].fillna('')
            )
            tfidf_df = pd.DataFrame(
                tfidf_features.toarray(),
                columns=feature_names
            )

            # Joindre les caractéristiques de sécurité et TF-IDF
            features_df = pd.concat([df[['security_keyword_count', 'special_char_count', 'has_sql_pattern', 'has_xss_pattern']].reset_index(drop=True),
                                     tfidf_df.reset_index(drop=True)], axis=1)

            return df, features_df, vectorizer
        else:
            return df, pd.DataFrame(), None

    def parse_apache_log(self, log_line):
        """Parse une seule ligne de log Apache."""
        match = self.apache_pattern.match(log_line)
        if match:
            ip, timestamp, request, status, size = match.groups()
            try:
                req_parts = request.split()
                method = req_parts[0] if len(req_parts) > 0 else ""
                url = req_parts[1] if len(req_parts) > 1 else ""
            except Exception:
                method, url = "", ""

            return {
                "timestamp": timestamp,
                "ip": ip,
                "method": method,
                "url": url,
                "status": int(status),
                "size": int(size),
                "raw": log_line,
                "parsed": True
            }

        return {
            "raw": log_line,
            "parsed": False
        }

    def extract_payloads(self, parsed_log):
        """Détecte les charges utiles suspectes dans un log Apache."""
        payloads = []
        url = parsed_log.get("url", "")

        for pattern in self.sql_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                payloads
