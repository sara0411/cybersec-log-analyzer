import joblib
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler  # Or your CSV scaler

class AnomalyDetector:
    def __init__(self):
        self.text_model = None
        self.text_tokenizer = None
        self.text_vectorizer = None
        self.csv_model = None
        self.csv_scaler = None

    def load_text_model(self, model_path, tokenizer_path, vectorizer_path):
        try:
            self.text_model = load_model(model_path)
            # Load your tokenizer and vectorizer here (e.g., using joblib.load())
            import joblib
            self.text_tokenizer = joblib.load(tokenizer_path)
            self.text_vectorizer = joblib.load(vectorizer_path)
            return self.text_model
        except Exception as e:
            print(f"Error loading text model: {e}")
            return None

    def predict_text(self, texts):
        if self.text_model and self.text_tokenizer and self.text_vectorizer:
            # Preprocess your text data using the loaded tokenizer and vectorizer
            # Then make predictions using self.text_model
            # This part will depend on your specific text model architecture
            pass
        else:
            print("Text model not loaded.")
            return None, None

    def load_csv_model(self, model_path, scaler_path):
        try:
            self.csv_model = joblib.load(model_path)
            self.csv_scaler = joblib.load(scaler_path)
            return self.csv_model
        except Exception as e:
            print(f"Error loading CSV model: {e}")
            return None

    def predict_csv(self, data):
        if self.csv_model and self.csv_scaler:
            scaled_data = self.csv_scaler.transform(data)
            predictions = self.csv_model.predict(scaled_data)
            return predictions
        else:
            print("CSV model not loaded.")
            return None