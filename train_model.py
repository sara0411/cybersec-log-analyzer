import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from logs_analyzer.preprocessing.log_preprocessor import LogPreprocessor
from logs_analyzer.nlp_module.feature_extractor import LogFeatureExtractor
from logs_analyzer.lstm_module.model_builder import LogClassifier

def main():
    # Chemin vers les données
    processed_logs_dir = "data/processed"
    models_dir = "models"

    # Créer le répertoire des modèles s'il n'existe pas
    os.makedirs(models_dir, exist_ok=True)

    # Chargement des données prétraitées
    logs_data = None

    for filename in os.listdir(processed_logs_dir):
        if filename.endswith(".csv"):
            file_path = os.path.join(processed_logs_dir, filename)
            print(f"Chargement des données: {file_path}")

            if logs_data is None:
                logs_data = pd.read_csv(file_path)
                print("Columns in loaded data:", logs_data.columns)
            else:
                logs_data = pd.concat([logs_data, pd.read_csv(file_path)], ignore_index=True)

    if logs_data is None or len(logs_data) == 0:
        print("Aucune donnée trouvée. Veuillez d'abord exécuter le préprocesseur de logs.")
        return

    print(f"Nombre total d'entrées de logs: {len(logs_data)}")

    # Pour l'entraînement, nous avons besoin d'étiquettes. Dans un environnement réel,
    # vous auriez besoin de logs étiquetés. Ici, nous allons simuler quelques étiquettes.

    # Créer une colonne d'étiquettes basée sur des règles simples (à des fins d'exemple)
    def assign_label(row):
        if 'potential_threats' in row and pd.notna(row['potential_threats']):
            if 'SQL_INJECTION' in str(row['potential_threats']):
                return 'sql_injection'
            elif 'XSS' in str(row['potential_threats']):
                return 'xss_attack'
            else:
                return 'other_attack'
        elif 'status' in row and pd.notna(row['status']) and int(row['status']) >= 500:
            return 'server_error'
        elif 'status' in row and pd.notna(row['status']) and int(row['status']) == 403:
            return 'unauthorized_access'
        else:
            return 'normal'

    logs_data['label'] = logs_data.apply(assign_label, axis=1)

    print("Distribution des étiquettes:")
    print(logs_data['label'].value_counts())

    # Extraction des caractéristiques NLP
    feature_extractor = LogFeatureExtractor()

    print("Prétraitement des logs pour le NLP...")
    logs_data = feature_extractor.preprocess_logs_for_nlp(logs_data)

    print("Extraction des caractéristiques de sécurité...")
    logs_data = feature_extractor.extract_security_features(logs_data)

    # Entraînement du modèle LSTM
    print("Préparation des données pour le modèle LSTM...")
    classifier = LogClassifier(max_words=5000, max_sequence_length=100)

    # Préparer les données d'entrée et les étiquettes
    X = classifier.prepare_text_data(logs_data['text_for_analysis'].fillna(''))
    y = classifier.prepare_labels(logs_data['label'])

    # Diviser en ensembles d'entraînement et de test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Construction du modèle LSTM...")
    classifier.build_model(num_classes=len(set(logs_data['label'])))

    print("Entraînement du modèle LSTM...")
    history = classifier.train(X_train, y_train, epochs=5, batch_size=32)

    # Évaluation du modèle
    print("\nÉvaluation du modèle...")
    loss, accuracy = classifier.model.evaluate(X_test, y_test)
    print(f"Précision sur l'ensemble de test: {accuracy:.4f}")

    # Sauvegarder le modèle
    print("Sauvegarde du modèle...")
    model_path = os.path.join(models_dir, 'lstm_classifier')
    classifier.save_model(model_path)
    print(f"Modèle sauvegardé à:{model_path}")

if __name__ == "__main__":
    main()