import re
import pandas as pd
import json
from datetime import datetime

class LogPreprocessor:
    def __init__(self):
        # Expressions régulières pour différents formats de logs
        self.apache_pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)'
        self.syslog_pattern = r'(\w{3}\s+\d+\s+\d+:\d+:\d+) (\S+) (\S+): (.*)'
        self.mysql_error_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}) (\d+) \[(.*?)\] (.*)'

    def detect_log_type(self, log_line):
        """Détecte automatiquement le type de log."""
        if re.match(self.apache_pattern, log_line):
            return "apache"
        elif re.match(self.syslog_pattern, log_line):
            return "syslog"
        elif re.match(self.mysql_error_pattern, log_line):
            return "mysql_error"
        else:
            return "unknown"

    def parse_apache_log(self, log_line):
        """Parse les logs Apache/Nginx."""
        match = re.match(self.apache_pattern, log_line)
        if match:
            ip, timestamp, request, status, size = match.groups()
            # Extraction de la méthode HTTP et de l'URL
            req_parts = request.split()
            method = req_parts[0] if len(req_parts) > 0 else ""
            url = req_parts[1] if len(req_parts) > 1 else ""
            
            return {
                "timestamp": timestamp,
                "ip": ip,
                "method": method,
                "url": url,
                "status": int(status),
                "size": int(size),
                "raw": log_line
            }
        return {"raw": log_line, "parsed": False}

    def parse_syslog(self, log_line):
        """Parse les logs système."""
        match = re.match(self.syslog_pattern, log_line)
        if match:
            timestamp, host, process, message = match.groups()
            return {
                "timestamp": timestamp,
                "host": host,
                "process": process,
                "message": message,
                "raw": log_line
            }
        return {"raw": log_line, "parsed": False}

    def extract_payloads(self, parsed_log):
        """Extrait les potentielles charges utiles d'attaque (ex: injection SQL, XSS)."""
        payloads = []
        
        # Si c'est un log Apache/Nginx
        if "url" in parsed_log:
            # Recherche de paramètres GET suspects
            url = parsed_log.get("url", "")
            
            # Signes d'injection SQL
            sql_patterns = [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b.*\b(FROM|INTO|WHERE|TABLE)\b)",
                r"(';--|\b(OR|AND)\b\s+\d+=\d+)",
                r"((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))"
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    payloads.append(("SQL_INJECTION", url))
                    break
            
            # Signes de XSS
            xss_patterns = [
                r"<[^>]*script",
                r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
                r"((\%3C)|<)[^\n]+((\%3E)|>)"
            ]
            
            for pattern in xss_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    payloads.append(("XSS", url))
                    break
                    
        # Extrait également les payloads des messages syslog
        if "message" in parsed_log:
            message = parsed_log.get("message", "")
            # Signes d'accès non autorisé
            if re.search(r"(failed|invalid|unauthorized)\s+(login|password|access|authentication)", 
                        message, re.IGNORECASE):
                payloads.append(("AUTH_FAILURE", message))
                
        return payloads

    def process_log_file(self, file_path):
        """Traite un fichier log complet et retourne les données structurées."""
        processed_entries = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                log_type = self.detect_log_type(line)
                parsed_entry = {}
                
                if log_type == "apache":
                    parsed_entry = self.parse_apache_log(line)
                elif log_type == "syslog":
                    parsed_entry = self.parse_syslog(line)
                else:
                    parsed_entry = {"raw": line, "type": "unknown"}
                
                parsed_entry["log_type"] = log_type
                
                # Extraction des charges utiles potentielles
                if log_type != "unknown":
                    payloads = self.extract_payloads(parsed_entry)
                    if payloads:
                        parsed_entry["potential_threats"] = payloads
                
                processed_entries.append(parsed_entry)
        
        # Conversion en DataFrame pour faciliter l'analyse
        df = pd.DataFrame(processed_entries)
        return df

    def save_processed_logs(self, df, output_path):
        """Sauvegarde les logs traités au format CSV et JSON."""
        # Sauvegarde au format CSV
        df.to_csv(output_path + ".csv", index=False)
        
        # Sauvegarde au format JSON
        records = df.to_dict(orient='records')
        with open(output_path + ".json", 'w') as f:
            json.dump(records, f, indent=2)
            
        return output_path