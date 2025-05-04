import re
import pandas as pd
import json
from datetime import datetime

class LogPreprocessor:
    def __init__(self):
        # Expression régulière pour logs Apache/Nginx
        self.apache_pattern = re.compile(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)')

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

    def parse_apache_log(self, log_line):
        """Parse une seule ligne de log Apache."""
        match = self.apache_pattern.match(log_line)
        if match:
            ip, timestamp, request, status, size = match.groups()
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

    def extract_payloads(self, parsed_log):
        """Détecte les charges utiles suspectes dans un log Apache."""
        payloads = []

        url = parsed_log.get("url", "")
        for pattern in self.sql_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                payloads.append(("SQL_INJECTION", url))
                break

        for pattern in self.xss_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                payloads.append(("XSS", url))
                break

        return payloads

    def process_log_file(self, file_path):
        """Traite un fichier complet de logs Apache."""
        processed_entries = []

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parsed_entry = self.parse_apache_log(line)
                parsed_entry["log_type"] = "apache"

                # Extraction des menaces potentielles
                if parsed_entry.get("parsed", True):
                    payloads = self.extract_payloads(parsed_entry)
                    if payloads:
                        parsed_entry["potential_threats"] = payloads

                processed_entries.append(parsed_entry)

        df = pd.DataFrame(processed_entries)

        # Conversion de timestamp en format datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', format='%d/%b/%Y:%H:%M:%S %z')

        return df

    def save_processed_logs(self, df, output_path):
        """Sauvegarde les résultats traités en CSV et JSON."""
        df.to_csv(output_path + ".csv", index=False)

        records = df.to_dict(orient='records')
        with open(output_path + ".json", 'w', encoding='utf-8') as f:
            json.dump(records, f, indent=2)

        return output_path
