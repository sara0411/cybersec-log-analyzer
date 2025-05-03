import os
import uuid
import json
import pandas as pd
import tempfile
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for

from logs_analyzer.preprocessing.log_preprocessor import LogPreprocessor
from logs_analyzer.nlp_module.feature_extractor import LogFeatureExtractor
from logs_analyzer.lstm_module.model_builder import LogClassifier

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'data/uploads'
MODELS_DIR = 'models'
REPORTS_DIR = 'data/reports'

# Créer les répertoires s'ils n'existent pas
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Initialiser les objets d'analyse
preprocessor = LogPreprocessor()
feature_extractor = LogFeatureExtractor()

# Charger le modèle s'il existe
model_path = os.path.join(MODELS_DIR, 'lstm_classifier')
if os.path.exists(os.path.join(model_path, 'lstm_model.h5')):
    classifier = LogClassifier.load_model(model_path)
    model_loaded = True
else:
    classifier = None
    model_loaded = False

# Stocker les analyses temporairement en mémoire
analysis_results = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'logfile' not in request.files:
        return redirect(url_for('home'))
        
    file = request.files['logfile']
    if file.filename == '':
        return redirect(url_for('home'))
        
    # Sauvegarder le fichier
    file_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{file.filename}")
    file.save(file_path)
    
    # Analyser les logs
    return process_logs(file_path)

@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    if 'logtext' not in request.form:
        return redirect(url_for('home'))
        
    log_text = request.form['logtext']
    if not log_text.strip():
        return redirect(url_for('home'))
        
    # Sauvegarder le texte dans un fichier temporaire
    temp_file = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4()}.log")
    with open(temp_file, 'w') as f:
        f.write(log_text)
    
    # Analyser les logs
    return process_logs(temp_file)
    
def process_logs(file_path):
    # Identifier chaque analyse avec un UUID
    analysis_id = str(uuid.uuid4())
    
    try:
        # Prétraitement des logs
        processed_df = preprocessor.process_log_file(file_path)
        
        # Extraction des caractéristiques NLP
        processed_df = feature_extractor.preprocess_logs_for_nlp(processed_df)
        processed_df = feature_extractor.extract_security_features(processed_df)
        
        # Classification des menaces
        threats = []
        
        if model_loaded and 'text_for_analysis' in processed_df.columns:
            texts = processed_df['text_for_analysis'].fillna('').tolist()
            predicted_labels, probabilities = classifier.predict(texts)
            
            # Ajouter les prédictions au DataFrame
            processed_df['predicted_label'] = predicted_labels
            
            # Identifier les entrées avec des menaces potentielles
            for i, (label, probs) in enumerate(zip(predicted_labels, probabilities)):
                if label != 'normal':
                    max_prob = probs.max() * 100
                    threat = {
                        'id': f"threat_{i}",
                        'type': label.replace('_', ' ').title(),
                        'probability': f"{max_prob:.1f}",
                        'log_entry': processed_df.iloc[i]['raw'] if 'raw' in processed_df.columns else "Log entry not available",
                        'severity': 'high' if max_prob > 80 else 'medium' if max_prob > 50 else 'low',
                        'details': {
                            'full_log': processed_df.iloc[i].to_dict(),
                            'features': {
                                'security_keywords': processed_df.iloc[i].get('security_keyword_count', 0),
                                'special_chars': processed_df.iloc[i].get('special_char_count', 0),
                                'sql_pattern': "Oui" if processed_df.iloc[i].get('has_sql_pattern', 0) == 1 else "Non",
                                'xss_pattern': "Oui" if processed_df.iloc[i].get('has_xss_pattern', 0) == 1 else "Non"
                            }
                        }
                    }
                    threats.append(threat)
        else:
            # Détection basée sur des règles si le modèle n'est pas disponible
            for i, row in processed_df.iterrows():
                if 'potential_threats' in row and pd.notna(row['potential_threats']):
                    threat_type = str(row['potential_threats']).replace('[', '').replace(']', '').replace("'", "")
                    threat = {
                        'id': f"threat_{i}",
                        'type': threat_type.replace('_', ' ').title(),
                        'probability': "N/A",
                        'log_entry': row['raw'] if 'raw' in row else "Log entry not available",
                        'severity': 'high',
                        'details': {
                            'full_log': row.to_dict()
                        }
                    }
                    threats.append(threat)
                    
        # Calcul des statistiques
        stats = {
            'total_entries': len(processed_df),
            'total_threats': len(threats),
            'risk_score': calculate_risk_score(threats, len(processed_df)),
            'risk_class': calculate_risk_class(len(threats), len(processed_df))
        }
        
        # Distribution des types de logs
        if 'log_type' in processed_df.columns:
            log_types_counts = processed_df['log_type'].value_counts().to_dict()
            log_types = {
                'labels': list(log_types_counts.keys()),
                'values': list(log_types_counts.values())
            }
        else:
            log_types = {
                'labels': ['Inconnu'],
                'values': [len(processed_df)]
            }
            
        # Générer des recommandations d'actions
        actions = generate_actions(threats, stats)
        
        # Stocker les résultats pour les requêtes ultérieures
        analysis_results[analysis_id] = {
            'threats': threats,
            'processed_df': processed_df,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Rendre la page de résultats
        return render_template('results.html', 
                              stats=stats, 
                              threats=threats, 
                              log_types=log_types, 
                              actions=actions,
                              analysis_id=analysis_id)
                              
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/threat-details/<threat_id>')
def threat_details(threat_id):
    # Trouver la menace dans les résultats stockés
    for analysis_id, data in analysis_results.items():
        for threat in data['threats']:
            if threat['id'] == threat_id:
                # Formater les détails en HTML
                details_html = f"""
                <div class="threat-details">
                    <h3>Détails de la menace : {threat['type']}</h3>
                    <p><strong>Sévérité :</strong> <span class="{threat['severity']}">{threat['severity'].capitalize()}</span></p>
                    <p><strong>Log complet :</strong></p>
                    <pre>{threat['log_entry']}</pre>
                    
                    <h4>Caractéristiques détectées</h4>
                    <ul>
                """
                
                if 'features' in threat['details']:
                    features = threat['details']['features']
                    for feature, value in features.items():
                        details_html += f"<li><strong>{feature}:</strong> {value}</li>"
                
                details_html += """
                    </ul>
                    
                    <h4>Recommandations</h4>
                    <ul>
                """
                
                # Recommandations basées sur le type de menace
                if 'sql' in threat['type'].lower():
                    details_html += """
                        <li>Utilisez des requêtes préparées ou des ORM</li>
                        <li>Sanitisez toutes les entrées utilisateur</li>
                        <li>Limitez les privilèges de la base de données</li>
                    """
                elif 'xss' in threat['type'].lower():
                    details_html += """
                        <li>Utilisez l'échappement HTML pour toutes les sorties</li>
                        <li>Implémentez des entêtes Content-Security-Policy</li>
                        <li>Utilisez des frameworks sécurisés qui échappent automatiquement</li>
                    """
                elif 'auth' in threat['type'].lower():
                    details_html += """
                        <li>Implémentez des limites de tentatives de connexion</li>
                        <li>Utilisez l'authentification à deux facteurs</li>
                        <li>Renforcez la complexité des mots de passe</li>
                    """
                else:
                    details_html += """
                        <li>Vérifiez et mettez à jour vos systèmes régulièrement</li>
                        <li>Implémentez un pare-feu d'application Web (WAF)</li>
                        <li>Effectuez des audits de sécurité réguliers</li>
                    """
                
                details_html += """
                    </ul>
                </div>
                """
                
                return jsonify({"details": details_html})
    
    return jsonify({"details": "Détails non disponibles"})

@app.route('/download-report')
def download_report():
    # TODO: Générer un rapport PDF ou CSV
    # Pour le moment, nous allons simplement retourner un JSON
    report_file = os.path.join(REPORTS_DIR, f"report_{uuid.uuid4()}.json")
    
    with open(report_file, 'w') as f:
        json.dump(list(analysis_results.values())[-1], f, default=str)
        
    return send_file(report_file, as_attachment=True)

def calculate_risk_score(threats, total_entries):
    if total_entries == 0:
        return "0%"
        
    # Pondérer la gravité
    high_threats = sum(1 for t in threats if t['severity'] == 'high')
    medium_threats = sum(1 for t in threats if t['severity'] == 'medium')
    low_threats = sum(1 for t in threats if t['severity'] == 'low')
    
    # Calcul du score (plus élevé = plus de risque)
    score = (high_threats * 5 + medium_threats * 3 + low_threats) / total_entries * 100
    score = min(score, 100)  # Plafonner à 100%
    
    return f"{score:.1f}%"
    
def calculate_risk_class(num_threats, total_entries):
    if total_entries == 0:
        return "low"
        
    threat_ratio = num_threats / total_entries
    
    if threat_ratio > 0.1:
        return "high"
    elif threat_ratio > 0.05:
        return "medium"
    else:
        return "low"
        
def generate_actions(threats, stats):
    actions = []
    
    # Obtenir les types de menaces uniques
    threat_types = set(t['type'].lower() for t in threats)
    
    # Recommandations générales basées sur le score de risque
    risk_score = float(stats['risk_score'].replace('%', ''))
    
    if risk_score > 50:
        actions.append({
            'description': "Effectuez un audit de sécurité complet du système immédiatement",
            'priority': 'high'
        })
    
    # Recommandations spécifiques basées sur les types de menaces
    if any('sql' in t for t in threat_types):
        actions.append({
            'description': "Revoir et sécuriser toutes les requêtes SQL, implémenter des requêtes préparées",
            'priority': 'high'
        })
        
    if any('xss' in t for t in threat_types):
        actions.append({
            'description': "Mettre en place un échappement HTML et des en-têtes CSP pour prévenir les attaques XSS",
            'priority': 'high'
        })
        
    if any('auth' in t for t in threat_types) or any('unauthorized' in t for t in threat_types):
        actions.append({
            'description': "Renforcer l'authentification et implémenter une authentification à deux facteurs",
            'priority': 'medium'
        })
        
    # Recommandations générales
    if len(threats) > 0:
        actions.append({
            'description': "Mettre à jour tous les logiciels et frameworks à la dernière version stable",
            'priority': 'medium'
        })
        
        actions.append({
            'description': "Configurer un système de surveillance et d'alerte en temps réel",
            'priority': 'medium' if risk_score > 30 else 'low'
        })
    
    # Si aucune menace n'est détectée
    if len(threats) == 0:
        actions.append({
            'description': "Continuer la surveillance régulière des logs et maintenir les bonnes pratiques de sécurité",
            'priority': 'low'
        })
        
    return actions

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Page non trouvée"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error="Erreur serveur interne"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)