# logs_analyzer/train_anomaly_model.py
import sys
print(sys.path)
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import load_model
#from preprocessing.csv_log_preprocessor import CSVLogPreprocessor
from .nlp_module.feature_extractor import LogFeatureExtractor
from .lstm_module.lstm_anomaly_detector import create_lstm_autoencoder
from logs_analyzer.preprocessing.csv_log_preprocessor import CSVLogPreprocessor
# Configuration
LOG_FILE_PATH = 'your_normal_csv_logs.txt' # Path to your normal log data
SEQUENCE_LENGTH = 30
BATCH_SIZE = 64
EPOCHS = 50
NUM_FEATURES = 6 # Adjust based on the features you extract
MODEL_SAVE_PATH = 'models/lstm_autoencoder_anomaly.h5' # Updated path

# Load and preprocess data
preprocessor = CSVLogPreprocessor()
try:
    df = preprocessor.process(LOG_FILE_PATH)
    extractor = LogFeatureExtractor()
    df_featured = extractor.process_csv_logs(df.copy())

    # Select features for the model
    model_features = ['status_code_cat', 'method_cat', 'user_agent_cat', 'country_cat', 'request_size_norm', 'unknown_value_norm']
    data = df_featured[model_features].values

    # Scale the data
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data)

    # Prepare sequences
    def create_sequences(data, sequence_length):
        sequences = []
        for i in range(len(data) - sequence_length):
            sequences.append(data[i:i + sequence_length])
        return np.array(sequences)

    X = create_sequences(data_scaled, SEQUENCE_LENGTH)

    # Split data (optional, but good practice)
    X_train, X_val = train_test_split(X, test_size=0.2, random_state=42)

    # Create and train the LSTM autoencoder
    model = create_lstm_autoencoder(SEQUENCE_LENGTH, NUM_FEATURES)
    history = model.fit(X_train, X_train, epochs=EPOCHS, batch_size=BATCH_SIZE, validation_data=(X_val, X_val))

    # Save the trained model and scaler
    model.save(MODEL_SAVE_PATH)
    import joblib
    joblib.dump(scaler, 'models/scaler_anomaly.joblib') # Updated path

    print(f"Trained anomaly detection model saved to {MODEL_SAVE_PATH}")

except FileNotFoundError:
    print(f"Error: The file '{LOG_FILE_PATH}' was not found. Please update the path.")
except Exception as e:
    print(f"An error occurred during training: {e}")