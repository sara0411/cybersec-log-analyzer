import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib

def main():
    # Chemin vers les données traitées
    processed_logs_dir = "data/processed"
    models_dir = "models"

    # Créer le répertoire des modèles s'il n'existe pas
    os.makedirs(models_dir, exist_ok=True)

    # Chargement des données traitées CSV
    logs_data = None
    for filename in os.listdir(processed_logs_dir):
        if filename.endswith(".csv"):
            file_path = os.path.join(processed_logs_dir, filename)
            print(f"Chargement des données CSV: {file_path}")
            if logs_data is None:
                logs_data = pd.read_csv(file_path)
            else:
                logs_data = pd.concat([logs_data, pd.read_csv(file_path)], ignore_index=True)

    if logs_data is None or len(logs_data) == 0:
        print("Aucune donnée CSV trouvée. Veuillez d'abord exécuter le préprocesseur de logs.")
        return

    print(f"Nombre total d'entrées de logs CSV: {len(logs_data)}")

    # Sélection des caractéristiques et de la cible
    features = ['ip', 'method', 'status', 'size'] # Use the actual column names
    target = 'Anomaly_Flag'

    if target not in logs_data.columns or not all(f in logs_data.columns for f in features):
        print("Colonnes nécessaires ('Anomaly_Flag' et les caractéristiques) non trouvées dans les données CSV.")
        print(f"Target column present: {target in logs_data.columns}")
        print(f"Missing feature columns: {[f for f in features if f not in logs_data.columns]}")
        print(f"Available columns: {logs_data.columns.tolist()}")
        return

    X = logs_data[features].copy()
    y = logs_data[target].copy()

    # Encodage des caractéristiques catégorielles
    encoders = {}
    X_encoded = pd.DataFrame()
    for column in X.columns:
        encoder = LabelEncoder()
        X_encoded[column] = encoder.fit_transform(X[column])
        encoders[column] = encoder

    # Division des données en ensembles d'entraînement et de test
    X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.2, random_state=42)

    # Entraînement d'un modèle (Random Forest comme exemple)
    print("Entraînement du modèle de classification CSV...")
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)

    # Évaluation du modèle
    y_pred = model.predict(X_test)
    print("\nÉvaluation du modèle CSV:")
    print("Précision:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Sauvegarde du modèle et des encodeurs
    csv_model_path = os.path.join(models_dir, 'csv_anomaly_model.joblib')
    joblib.dump(model, csv_model_path)
    encoders_path = os.path.join(models_dir, 'csv_feature_encoders.joblib')
    joblib.dump(encoders, encoders_path)

    print(f"Modèle de classification CSV sauvegardé à: {csv_model_path}")
    print(f"Encodeurs de caractéristiques CSV sauvegardés à: {encoders_path}")

if __name__ == "__main__":
    main()