import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Embedding, Dropout

def create_model(input_dim, output_dim):
    """Create LSTM model for log classification."""
    model = Sequential()
    model.add(Embedding(input_dim=input_dim, output_dim=64))
    model.add(LSTM(100, return_sequences=True))
    model.add(LSTM(50))
    model.add(Dense(30, activation='relu'))
    model.add(Dropout(0.2))
    model.add(Dense(output_dim, activation='softmax'))
    model.compile(loss='categorical_crossentropy', 
                  optimizer='adam', 
                  metrics=['accuracy'])
    return model

def train_model(model, X_train, y_train, epochs=10, batch_size=64):
    """Train the LSTM model."""
    history = model.fit(X_train, y_train, 
                       epochs=epochs, 
                       batch_size=batch_size,
                       validation_split=0.2)
    return history