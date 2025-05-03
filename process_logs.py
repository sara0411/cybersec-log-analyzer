import os
from logs_analyzer.preprocessing.log_preprocessor import LogPreprocessor

def main():
    preprocessor = LogPreprocessor()
    
    # Chemin vers les logs bruts
    raw_logs_dir = "data/raw_logs"
    processed_logs_dir = "data/processed"
    
    # Créer le répertoire de sortie s'il n'existe pas
    os.makedirs(processed_logs_dir, exist_ok=True)
    
    # Traiter tous les fichiers de logs dans le répertoire
    for filename in os.listdir(raw_logs_dir):
        if filename.endswith(".log"):
            input_path = os.path.join(raw_logs_dir, filename)
            output_base = os.path.join(processed_logs_dir, os.path.splitext(filename)[0])
            
            print(f"Traitement du fichier: {input_path}")
            try:
                processed_df = preprocessor.process_log_file(input_path)
                output_path = preprocessor.save_processed_logs(processed_df, output_base)
                print(f"Traitement terminé. Résultats sauvegardés dans: {output_path}")
                
                # Afficher quelques statistiques
                print(f"Nombre d'entrées: {len(processed_df)}")
                if "potential_threats" in processed_df.columns:
                    threats = processed_df[processed_df["potential_threats"].notna()]
                    print(f"Menaces potentielles détectées: {len(threats)}")
                
            except Exception as e:
                print(f"Erreur lors du traitement du fichier {input_path}: {str(e)}")

if __name__ == "__main__":
    main()