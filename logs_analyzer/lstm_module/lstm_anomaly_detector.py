# logs_analyzer/lstm_module/lstm_anomaly_detector.py

from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, LSTM, Dense, RepeatVector, TimeDistributed
from tensorflow.keras.optimizers import Adam

def create_lstm_autoencoder(sequence_length, num_features, embedding_dim=64, lstm_units=128):
    """
    Creates an LSTM-based autoencoder for anomaly detection in log sequences.

    Args:
        sequence_length (int): The length of the input sequences.
        num_features (int): The number of features per time step.
        embedding_dim (int): The dimensionality of the embedding layer (if used).
        lstm_units (int): The number of units in the LSTM layers.

    Returns:
        tensorflow.keras.Model: The LSTM autoencoder model.
    """
    input_sequence = Input(shape=(sequence_length, num_features))

    # Encoder
    lstm_encoder = LSTM(lstm_units, activation='relu', return_sequences=True)(input_sequence)
    lstm_encoder = LSTM(lstm_units // 2, activation='relu')(lstm_encoder)
    repeat_vector = RepeatVector(sequence_length)(lstm_encoder)

    # Decoder
    lstm_decoder = LSTM(lstm_units // 2, activation='relu', return_sequences=True)(repeat_vector)
    lstm_decoder = LSTM(lstm_units, activation='relu', return_sequences=True)(lstm_decoder)

    # Output layer (reconstruct the input)
    output_sequence = TimeDistributed(Dense(num_features, activation='linear'))(lstm_decoder)

    autoencoder = Model(inputs=input_sequence, outputs=output_sequence)
    autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
    return autoencoder

if __name__ == '__main__':
    # Example usage:
    seq_len = 10  # Example sequence length
    n_features = 6 # Example number of features per log entry
    model = create_lstm_autoencoder(seq_len, n_features)
    model.summary()