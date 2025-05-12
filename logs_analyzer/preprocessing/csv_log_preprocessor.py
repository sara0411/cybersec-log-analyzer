import pandas as pd
import numpy as np

class CSVLogPreprocessor:
    """
    Preprocessor for CSV log files.  Handles parsing and initial cleaning.
    """
    def __init__(self):
        """
        Initializes the CSVLogPreprocessor.
        """
        pass  # No specific initialization needed

    def process(self, log_file_path):
        """
        Processes the CSV log file.

        Args:
            log_file_path (str): Path to the CSV log file.

        Returns:
            pandas.DataFrame: A cleaned and processed DataFrame.
        """
        try:
            # Read the CSV file into a pandas DataFrame
            df = pd.read_csv(log_file_path)

            # Basic data cleaning (handle missing values, remove duplicates, etc.)
            df = self._clean_data(df)

            # Rename columns for consistency
            df = self._rename_columns(df)

            # Convert timestamp
            df = self._convert_timestamp(df)
            
            return df
        
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found at {log_file_path}")
        except pd.errors.EmptyDataError:
            raise pd.errors.EmptyDataError(f"Log file at {log_file_path} is empty")
        except Exception as e:
            raise Exception(f"Error processing CSV log file: {e}")

    def _clean_data(self, df):
        """
        Handles missing values and removes duplicates.

        Args:
            df (pandas.DataFrame): Input DataFrame.

        Returns:
            pandas.DataFrame: Cleaned DataFrame.
        """
        # Drop rows where all values are missing
        df.dropna(how='all', inplace=True)
        # Drop duplicate rows
        df.drop_duplicates(inplace=True)
        # Fill any remaining missing values with a placeholder (important for subsequent processing)
        df.fillna('unknown', inplace=True)
        return df
    
    def _rename_columns(self, df):
        """
        Rename columns for consistency.

        Args:
            df (pandas.DataFrame): Input DataFrame

        Returns:
            pandas.DataFrame: DataFrame with renamed columns
        """
        # Rename columns
        df.rename(columns={
            'time_local': 'timestamp',
            'status': 'status_code',
            'method': 'method',
            'uri': 'url',
            'bytes_sent': 'response_size',
            'remote_addr': 'ip_address',
            'http_user_agent': 'user_agent',
            'referer': 'referrer'
        }, inplace=True, errors='ignore')  # errors='ignore' prevents errors if a column doesn't exist
        return df

    def _convert_timestamp(self, df):
        """
        Convert timestamp to datetime

        Args:
            df (pandas.DataFrame): Input DataFrame

        Returns:
            pandas.DataFrame: DataFrame with converted timestamp
        """
        # Convert 'timestamp' to datetime, handling potential errors
        if 'timestamp' in df.columns:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                try:
                    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                except Exception as e:
                    print(f"Error converting timestamp: {e}")
                    df['timestamp'] = pd.NaT  # Set to Not a Time on conversion failure
        return df
