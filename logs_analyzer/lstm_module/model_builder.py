import numpy as np
import pandas as pd
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Embedding, Dropout, Bidirectional
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split
import os
import pickle

class LogClassifier:
    def __init__(self, max_words=10000, max_sequence_length=100):
        self.max_words = max_words
        self.max_sequence_length = max_sequence_length
        self.tokenizer = Tokenizer(num_words=max_words)
        self.model = None
        self.label_mapping = {}
        self.inverse_label_mapping = {}
        
    def prepare_text_data(self, texts):
        """Prépare les textes pour le modèle LSTM."""
        # Ajuster le tokenizer sur les textes
        self.tokenizer.fit_on_texts(texts)
        
        # Convertir les textes en séquences
        sequences = self.tokenizer.texts_to_sequences(texts)
        
        # Padding des séquences
        padded_sequences = pad_sequences(sequences, maxlen=self.max_sequence_length)
        
        return padded_sequences
        
    def prepare_labels(self, labels):
        """Prépare les étiquettes pour l'entraînement."""
        # Créer un mapping des étiquettes vers des indices
        unique_labels = sorted(set(labels))
        self.label_mapping = {label: i for i, label in enumerate(unique_labels)}
        self.inverse_label_mapping = {i: label for label, i in self.label_mapping.items()}
        
        # Convertir les étiquettes en indices
        label_indices = [self.label_mapping[label] for label in labels]
        
        # Convertir en one-hot encoding
        one_hot_labels = to_categorical(label_indices, num_classes=len(unique_labels))
        
        return one_hot_labels
        
    def build_model(self, num_classes):
        """Construit le modèle LSTM."""
        model = Sequential()
        
        # Couche d'embedding
        model.add(Embedding(self.max_words, 128, input_length=self.max_sequence_length))
        
        # Couches LSTM bidirectionnelles
        model.add(Bidirectional(LSTM(128, return_sequences=True)))
        model.add(Dropout(0.3))
        model.add(Bidirectional(LSTM(64)))
        model.add(Dropout(0.3))
        
        # Couches denses
        model.add(Dense(64, activation='relu'))
        model.add(Dropout(0.3))
        model.add(Dense(num_classes, activation='softmax'))
        
        # Compilation du modèle
        model.compile(
            loss='categorical_crossentropy',
            optimizer='adam',
            metrics=['accuracy']
        )
        
        self.model = model
        return model
        
    def train(self, X_train, y_train, validation_split=0.2, epochs=10, batch_size=32):
        """Entraîne le modèle LSTM."""
        if self.model is None:
            raise ValueError("Le modèle n'a pas été construit. Appelez build_model d'abord.")
            
        # Entraîner le modèle
        history = self.model.fit(
            X_train, y_train,
            validation_split=validation_split,
            epochs=epochs,
            batch_size=batch_size
        )
        
        return history
        
    def predict(self, texts):
        """Prédire les classes pour de nouveaux textes."""
        if self.model is None:
            raise ValueError("Le modèle n'a pas été entraîné.")
            
        # Préparer les données
        sequences = self.tokenizer.texts_to_sequences(texts)
        padded_sequences = pad_sequences(sequences, maxlen=self.max_sequence_length)
        
        # Prédire les classes
        predictions = self.model.predict(padded_sequences)
        
        # Convertir les prédictions en étiquettes
        predicted_indices = np.argmax(predictions, axis=1)
        predicted_labels = [self.inverse_label_mapping[idx] for idx in predicted_indices]
        
        # Retourner à la fois les étiquettes et les probabilités
        return predicted_labels, predictions
        
    def save_model(self, model_dir):
        """Sauvegarde le modèle et ses paramètres."""
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        # Sauvegarder le modèle Keras
        self.model.save(os.path.join(model_dir, 'lstm_model.h5'))
        
        # Sauvegarder le tokenizer
        with open(os.path.join(model_dir, 'tokenizer.pickle'), 'wb') as handle:
            pickle.dump(self.tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)
            
        # Sauvegarder les mappings d'étiquettes
        with open(os.path.join(model_dir, 'label_mapping.pickle'), 'wb') as handle:
            pickle.dump({
                'label_mapping': self.label_mapping,
                'inverse_label_mapping': self.inverse_label_mapping
            }, handle, protocol=pickle.HIGHEST_PROTOCOL)
            
    @classmethod
    def load_model(cls, model_dir):
        """Charge un modèle sauvegardé."""
        instance = cls()
        
        # Charger le modèle Keras
        instance.model = load_model(os.path.join(model_dir, 'lstm_model.h5'))
        
        # Charger le tokenizer
        with open(os.path.join(model_dir, 'tokenizer.pickle'), 'rb') as handle:
            instance.tokenizer = pickle.load(handle)
            
        # Charger les mappings d'étiquettes
        with open(os.path.join(model_dir, 'label_mapping.pickle'), 'rb') as handle:
            mappings = pickle.load(handle)
            instance.label_mapping = mappings['label_mapping']
            instance.inverse_label_mapping = mappings['inverse_label_mapping']
            
        return instance