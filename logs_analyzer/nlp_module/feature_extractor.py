# logs_analyzer/nlp_module/feature_extractor.py
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
from tld import get_tld
from collections import Counter
from sklearn.preprocessing import StandardScaler

class LogFeatureExtractor:
    """
    Extracts features from log data.  Handles both text and CSV formats.
    """
    def __init__(self):
        """
        Initializes the LogFeatureExtractor.
        """
        self.scaler = None # Initialize scaler

    def process_csv_logs(self, df):
        """
        Processes CSV logs to extract relevant features for anomaly detection.

        Args:
            df (pandas.DataFrame):  DataFrame containing the CSV log data.

        Returns:
            pandas.DataFrame:  DataFrame with extracted features.
        """
        # Basic features (status code, method, etc.)
        df['status_code_cat'] = df['status'].astype('category').cat.codes  # Changed from 'status_code'
        df['method_cat'] = df['method'].astype('category').cat.codes
        df['user_agent_cat'] = df['user_agent'].astype('category').cat.codes
        df['country_cat'] = df['ip_address'].astype('category').cat.codes # Placeholder
        df['request_size_norm'] = np.log1p(df['size'])  # Changed from 'response_size'
        df['unknown_value_norm'] =  0 # Placeholder

        # Normalize the 'request_size_norm' feature
        self.scaler = StandardScaler()
        df['request_size_norm'] = self.scaler.fit_transform(df[['request_size_norm']])

        return df

    def preprocess_logs_for_nlp(self, df):
        """
        Preprocesses log messages for NLP-based analysis.

        Args:
            df (pandas.DataFrame): DataFrame containing raw log messages.

        Returns:
            pandas.DataFrame:  DataFrame with preprocessed text.
        """
        # Combine relevant columns into a single text column
        df['text_for_analysis'] = df['message'].fillna('') + ' ' +  df['level'].fillna('') + ' ' + df['timestamp'].astype(str).fillna('') # Changed from df['severity']

        # Basic text cleaning - preserving more characters
        df['text_for_analysis'] = df['text_for_analysis'].apply(self._clean_text)
        return df

    def extract_security_features(self, df):
        """
        Extracts security-related features from log messages.

        Args:
            df (pandas.DataFrame): DataFrame containing log messages.

        Returns:
            pandas.DataFrame: DataFrame with added security features.
        """
        df['security_keyword_count'] = df['text_for_analysis'].apply(self._count_security_keywords)
        df['special_char_count'] = df['text_for_analysis'].apply(self._count_special_chars)
        df['has_sql_pattern'] = df['text_for_analysis'].apply(self._check_sql_pattern)
        df['has_xss_pattern'] = df['text_for_analysis'].apply(self._check_xss_pattern)
        return df

    def _clean_text(self, text):
        """
        Cleans text by converting to lowercase and preserving more special characters
        relevant to web requests and potential attacks.

        Args:
            text (str): The text to clean.

        Returns:
            str: The cleaned text.
        """
        # Keep alphanumeric characters, whitespace, and common web/attack related symbols
        allowed_chars = r"[^a-zA-Z0-9\s<>/=?&%;:'\",.\(\)\+\-\*!@#\$]"
        text = re.sub(allowed_chars, '', text)
        text = text.lower()
        return text

    def _count_security_keywords(self, text):
        """
        Counts the number of security-related keywords in the text.

        Args:
            text (str): The text to analyze.

        Returns:
            int: The number of security keywords found.
        """
        security_keywords = ['error', 'warning', 'failure', 'invalid', 'attack', 'malicious',
                               'exploit', 'vulnerability', 'breach', 'injection', 'xss', 'sql',
                               'csrf', 'rce', 'authentication', 'authorization', 'access denied',
                               'illegal', 'forbidden', 'denied', 'dropped', 'blocked']
        count = 0
        for keyword in security_keywords:
            count += len(re.findall(r'\b' + keyword + r'\b', text))
        return count

    def _count_special_chars(self, text):
        """
        Counts the number of special characters in the text (all non-alphanumeric and non-whitespace).

        Args:
            text (str): The text to analyze.

        Returns:
            int: The number of special characters found.
        """
        special_chars = r"[^a-zA-Z0-9\s]"
        return len(re.findall(special_chars, text))

    def _check_sql_pattern(self, text):
        """
        Checks if the text contains a potential SQL injection pattern.

        Args:
            text (str): The text to analyze.

        Returns:
            int: 1 if a pattern is found, 0 otherwise.
        """
        sql_patterns = [
            r"(select\s*\w*\s*from\s*\w*)",
            r"(insert\s*into\s*\w*)",
            r"(update\s*\w*\s*set)",
            r"(delete\s*from\s*\w*)",
            r"(;\s*--)",
            r"(;\s*/\*)",
            r"(union\s*all\s*select)",
            r"(union\s*select)",
            r"(alter\s*table)",
            r"(drop\s*table)",
            r"(truncate\s*table)",
            r"('[\w\s]+'='[\w\s]+')",
            r"(\bOR\b\s+\d+\s*=\s*\d+)",
            r"(\bAND\b\s+\d+\s*=\s*\d+)",
            r"(\bEXEC\b\s+\w+)",
            r"(\bDECLARE\b\s+@\w+)"
        ]
        for pattern in sql_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 1
        return 0

    def _check_xss_pattern(self, text):
        """
        Checks if the text contains a potential XSS attack pattern.

        Args:
            text (str): The text to analyze.

        Returns:
            int: 1 if a pattern is found, 0 otherwise.
        """
        xss_patterns = [
            r"(<script.*?>.*?</script>)",
            r"(<img.*?src=[\'\"]?javascript:.*?[\'\"]?>)",
            r"(<.*?on\w+\s*=)",
            r"(eval\s*\()",
            r"(expression\s*\()",
            r"(javascript:)",
            r"(vbscript:)",
            r"(data:text/html)",
            r"(<iframe.*?>.*?</iframe>)",
            r"(<object.*?>.*?</object>)",
            r"(<embed.*?>.*?</embed>)",
            r"(<applet.*?>.*?</applet>)",
            r"(<body onload=)",
            r"(<html.*xmlns=)",
            r"(svg onload=)",
            r"(marquee onstart=)"
        ]
        for pattern in xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 1
        return 0