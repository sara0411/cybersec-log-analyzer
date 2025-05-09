import os
import uuid
import json
import pandas as pd
import tempfile
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for
from tensorflow.keras.models import load_model
import joblib
import traceback
import numpy as np

from logs_analyzer.preprocessing.log_preprocessor import LogPreprocessor
from logs_analyzer.preprocessing.csv_log_preprocessor import CSVLogPreprocessor
from logs_analyzer.nlp_module.feature_extractor import LogFeatureExtractor
from logs_analyzer.lstm_module.model_builder import LogClassifier

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'data/uploads'
MODELS_DIR = 'models'
REPORTS_DIR = 'data/reports'

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

# Initialize analysis objects
preprocessor = LogPreprocessor()
csv_preprocessor = CSVLogPreprocessor()
feature_extractor = LogFeatureExtractor()

# Load text log model
model_path = os.path.join(MODELS_DIR, 'lstm_classifier')
classifier = None
model_loaded = False
try:
    if os.path.exists(os.path.join(model_path, 'lstm_model.h5')):
        classifier = LogClassifier.load_model(model_path)
        model_loaded = True
        print("Text log model loaded successfully.")
    else:
        print("Text log model not found.")
except Exception as e:
    print(f"Error loading text log model: {e}")
    traceback.print_exc()

# Load CSV anomaly detection model and encoders
CSV_MODEL_PATH = os.path.join(MODELS_DIR, 'csv_anomaly_model.joblib')
CSV_ENCODERS_PATH = os.path.join(MODELS_DIR, 'csv_feature_encoders.joblib')
csv_model = None
csv_encoders = None
csv_model_loaded = False
try:
    if os.path.exists(CSV_MODEL_PATH) and os.path.exists(CSV_ENCODERS_PATH):
        csv_model = joblib.load(CSV_MODEL_PATH)
        csv_encoders = joblib.load(CSV_ENCODERS_PATH)
        csv_model_loaded = True
        print("CSV anomaly detection model loaded successfully.")
    else:
        print("CSV anomaly detection model or encoders not found.")
except Exception as e:
    print(f"Error loading CSV anomaly detection model: {e}")
    traceback.print_exc()

# Define sequence length and anomaly threshold for CSV autoencoder (if you still intend to use it)
SEQUENCE_LENGTH = 30
ANOMALY_THRESHOLD = 0.05

# Store analysis results in memory
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

    file_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{file.filename}")
    try:
        file.save(file_path)
    except Exception as e:
        error_message = f"Error saving file: {e}"
        print(error_message)
        traceback.print_exc()
        return render_template('error.html', error=error_message), 500

    return process_logs(file_path)

@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    if 'logtext' not in request.form:
        return redirect(url_for('home'))

    log_text = request.form['logtext']
    if not log_text.strip():
        return redirect(url_for('home'))

    temp_file = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4()}.log")
    try:
        with open(temp_file, 'w') as f:
            f.write(log_text)
    except Exception as e:
        error_message = f"Error writing to temp file: {e}"
        print(error_message)
        traceback.print_exc()
        return render_template('error.html', error=error_message), 500

    processed_df = preprocessor.process_log_file(temp_file)
    processed_df = feature_extractor.preprocess_logs_for_nlp(processed_df)
    processed_df = feature_extractor.extract_security_features(processed_df)

    # Debugging 1: Print Processed DataFrame
    print("\n--- Processed DataFrame for Text Analysis ---")
    print(processed_df.to_string())
    print("-----------------------------------------------\n")

    threats = analyze_text_logs(processed_df)
    print("Detected Threats in analyze_text:", threats) # Debugging line
    stats = calculate_text_stats(processed_df, threats)
    log_types = calculate_text_log_types(processed_df)
    actions = generate_text_actions(threats, stats)

    analysis_id = str(uuid.uuid4())
    analysis_results[analysis_id] = {
        'threats': threats,
        'processed_df': processed_df,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'log_format': 'text',
    }

    return render_template('results.html',
                           stats=stats,
                           threats=threats,
                           log_types=log_types,
                           actions=actions,
                           analysis_id=analysis_id)

def detect_log_format(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()
            if ',' in first_line and len(first_line.split(',')) >= 7:
                return 'csv'
            else:
                return 'text'
    except Exception as e:
        print(f"Error detecting log format: {e}")
        traceback.print_exc()
        return 'text'

def analyze_csv_logs(processed_df):
    threats = []
    if csv_model_loaded and csv_encoders is not None and not processed_df.empty:
        try:
            features = list(csv_encoders.keys())
            if all(col in processed_df.columns for col in features):
                X = processed_df[features].copy()
                X_encoded = pd.DataFrame()
                for column in X.columns:
                    if column in csv_encoders:
                        X_encoded[column] = csv_encoders[column].transform(X[column])
                    else:
                        print(f"Warning: Encoder not found for column {column}")
                        return [{"error": f"Encoder missing for column: {column}"}]

                predictions = csv_model.predict(X_encoded)
                probabilities = csv_model.predict_proba(X_encoded)[:, 1]

                for i in range(len(predictions)):
                    if predictions[i] == 1:
                        threat = {
                            'id': f"csv_anomaly_{i}",
                            'type': 'Anomaly Detected',
                            'probability': f"{probabilities[i] * 100:.2f}",
                            'log_entry': processed_df.iloc[i].to_dict(),
                            'severity': 'high' if probabilities[i] > 0.7 else 'medium' if probabilities[i] > 0.4 else 'low',
                            'details': {'full_log': processed_df.iloc[i].to_dict()}
                        }
                        threats.append(threat)
            else:
                print("Warning: Missing required columns for CSV anomaly detection.")
        except Exception as e:
            error_message = f"Error analyzing CSV logs: {e}"
            print(error_message)
            traceback.print_exc()
            threats = [{"error": error_message}]
    else:
        print("CSV anomaly detection model or encoders not loaded or no data to analyze.")
    return threats

def calculate_csv_stats(processed_df, threats):
    stats = {
        'total_entries': len(processed_df),
        'total_anomalies': len(threats),
        'anomaly_rate': f"{(len(threats) / len(processed_df) * 100):.2f}%" if len(processed_df) > 0 else "0.00%"
    }
    return stats

def calculate_csv_log_types(processed_df):
    log_types = {'labels': processed_df['Request_Type'].unique().tolist(), 'values': processed_df['Request_Type'].value_counts().tolist()} if 'Request_Type' in processed_df.columns else {'labels': ['CSV Entry'], 'values': [len(processed_df)]}
    return log_types

def generate_csv_actions(threats, stats):
    actions = []
    if stats.get('total_anomalies', 0) > 0:
        actions.append({'description': 'Investigate the detected anomalies in the CSV logs.', 'priority': 'high'})
        actions.append({'description': f"Review the {stats.get('total_anomalies', 0)} anomalous log entries.", 'priority': 'medium'})
        actions.append({'description': f"The anomaly rate is {stats.get('anomaly_rate', 'N/A')}.", 'priority': 'low'})
    else:
        actions.append({'description': 'No anomalies detected in the CSV logs.', 'priority': 'low'})
    return actions

def analyze_text_logs(processed_df):
    """Analyzes text logs for threats."""
    threats = []
    if model_loaded and 'text_for_analysis' in processed_df.columns:
        try:
            texts = processed_df['text_for_analysis'].fillna('').tolist()

            # Debugging 2: Print the 'text_for_analysis' column
            print("\n--- Text for Analysis (Input to LSTM) ---")
            for text in texts:
                print(text)
            print("-------------------------------------------\n")

            predicted_labels, probabilities = classifier.predict(texts)

            # Debugging 3: Print Raw LSTM Predictions
            print("\n--- Raw LSTM Predictions ---")
            for i, (label, probs) in enumerate(zip(predicted_labels, probabilities)):
                print(f"Entry {i}: Predicted Label - {label}, Probabilities - {probs}")
            print("----------------------------\n")

            processed_df['predicted_label'] = predicted_labels

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
        except Exception as e:
            error_message = f"Error analyzing text logs: {e}"
            print(error_message)
            traceback.print_exc()
            threats = [{"error": error_message}]
    else:
        for i, row in processed_df.iterrows():
            if 'potential_threats' in row and pd.notna(row['potential_threats']):
                print("Potential Threat Found (Legacy):", row['raw'], row['potential_threats'])
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
    return threats

def calculate_text_stats(processed_df, threats):
    if len(processed_df) == 0:
        return {'total_entries': 0, 'total_threats': 0, 'risk_score': "0%", 'risk_class': "low"}

    stats = {
        'total_entries': len(processed_df),
        'total_threats': len(threats),
        'risk_score': calculate_risk_score(threats, len(processed_df)),
        'risk_class': calculate_risk_class(len(threats), len(processed_df))
    }
    return stats

def calculate_text_log_types(processed_df):
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
    return log_types

def generate_text_actions(threats, stats):
    actions = []
    threat_types = set(t['type'].lower() for t in threats)
    risk_score = float(stats['risk_score'].replace('%', ''))

    if risk_score > 50:
        actions.append({
            'description': "Perform a full security audit of the system immediately.",
            'priority': 'high'
        })

    if any('sql' in t for t in threat_types):
        actions.append({
            'description': "Review and secure all SQL queries; implement prepared statements.",
            'priority': 'high'
        })

    if any('xss' in t for t in threat_types):
        actions.append({
            'description': "Implement HTML escaping and Content Security Policy (CSP) headers.",
            'priority': 'high'
        })

    if any('auth' in t for t in threat_types) or any('unauthorized' in t for t in threat_types):
        actions.append({
            'description': "Strengthen authentication; implement two-factor authentication.",
            'priority': 'medium'
        })

    if len(threats) > 0:
        actions.append({
            'description': "Update all software and frameworks to the latest stable version.",
            'priority': 'medium'
        })
        actions.append({
            'description': "Configure a real-time monitoring and alerting system.",
            'priority': 'medium' if risk_score > 30 else 'low'
        })

    if len(threats) == 0:
        actions.append({
            'description': "Continue regular log monitoring and maintain security best practices.",
            'priority': 'low'
        })
    return actions

def process_logs(file_path):
    analysis_id = str(uuid.uuid4())
    log_format = detect_log_format(file_path)

    try:
        if log_format == 'csv':
            processed_df = csv_preprocessor.process(file_path)
            threats = analyze_csv_logs(processed_df)
            stats = calculate_csv_stats(processed_df, threats)
            log_types = calculate_csv_log_types(processed_df)
            actions = generate_csv_actions(threats, stats)
        else:
            processed_df = preprocessor.process_log_file
            processed_df = preprocessor.process_log_file(file_path)
            processed_df = feature_extractor.preprocess_logs_for_nlp(processed_df)
            processed_df = feature_extractor.extract_security_features(processed_df)
            threats = analyze_text_logs(processed_df)
            stats = calculate_text_stats(processed_df, threats)
            log_types = calculate_text_log_types(processed_df)
            actions = generate_text_actions(threats, stats)

        analysis_results[analysis_id] = {
            'threats': threats,
            'processed_df': processed_df,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'log_format': log_format,
        }

        return render_template('results.html',
                               stats=stats,
                               threats=threats,
                               log_types=log_types,
                               actions=actions,
                               analysis_id=analysis_id)

    except Exception as e:
        error_message = f"Error processing logs: {e}"
        print(error_message)
        traceback.print_exc()
        return render_template('error.html', error=error_message), 500

@app.route('/threat-details/<threat_id>')
def threat_details(threat_id):
    for analysis_id, data in analysis_results.items():
        if data.get('log_format') == 'csv':
            for threat in data['threats']:
                if threat['id'] == threat_id:
                    details_html = f"""
                    <div class="threat-details">
                        <h3>Anomaly Details</h3>
                        <p><strong>Type:</strong> {threat['type']}</p>
                        <p><strong>Probability:</strong> {threat['probability']}</p>
                        <p><strong>Severity:</strong> {threat['severity'].capitalize()}</p>
                        <h4>Log Entry:</h4>
                        <pre>{json.dumps(threat['log_entry'], indent=4, default=str)}</pre>
                    </div>
                    """
                    return jsonify({"details": details_html})
        else:
            for threat in data['threats']:
                if threat['id'] == threat_id:
                    details_html = f"""
                    <div class="threat-details">
                        <h3>Threat Details: {threat['type']}</h3>
                        <p><strong>Severity:</strong> <span class="{threat['severity']}">{threat['severity'].capitalize()}</span></p>
                        <p><strong>Full Log Entry:</strong></p>
                        <pre>{threat['log_entry']}</pre>

                        <h4>Detected Features</h4>
                        <ul>
                    """
                    if 'features' in threat['details']:
                        features = threat['details']['features']
                        for feature, value in features.items():
                            details_html += f"<li><strong>{feature}:</strong> {value}</li>"
                    details_html += """
                        </ul>

                        <h4>Recommendations</h4>
                        <ul>
                    """
                    if 'sql' in threat['type'].lower():
                        details_html += """
                            <li>Use prepared statements or ORMs.</li>
                            <li>Sanitize all user input.</li>
                            <li>Limit database privileges.</li>
                        """
                    elif 'xss' in threat['type'].lower():
                        details_html += """
                            <li>Use HTML escaping for all output.</li>
                            <li>Implement Content Security Policy (CSP) headers.</li>
                            <li>Use secure frameworks that auto-escape.</li>
                        """
                    elif 'auth' in threat['type'].lower():
                        details_html += """
                            <li>Implement login attempt limits.</li>
                            <li>Use two-factor authentication.</li>
                            <li>Enforce strong password complexity.</li>
                        """
                    else:
                        details_html += """
                            <li>Regularly patch and update systems.</li>
                            <li>Implement a Web Application Firewall (WAF).</li>
                            <li>Conduct regular security audits.</li>
                        """
                    details_html += """
                        </ul>
                    </div>
                    """
                    return jsonify({"details": details_html})

    return jsonify({"details": "Details not available"})

@app.route('/download-report')
def download_report():
    report_file = os.path.join(REPORTS_DIR, f"report_{uuid.uuid4()}.json")
    if analysis_results:
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(list(analysis_results.values())[-1], f, default=str)
            return send_file(report_file, as_attachment=True)
        except Exception as e:
            error_message = f"Error generating report: {e}"
            print(error_message)
            traceback.print_exc()
            return jsonify({"error": error_message}), 500
    else:
        return jsonify({"error": "No analysis to export"}), 400

def calculate_risk_score(threats, total_entries):
    if total_entries == 0:
        return "0%"
    high_threats = sum(1 for t in threats if t['severity'] == 'high')
    medium_threats = sum(1 for t in threats if t['severity'] == 'medium')
    low_threats = sum(1 for t in threats if t['severity'] == 'low')
    score = (high_threats * 5 + medium_threats * 3 + low_threats) / total_entries * 100
    score = min(score, 100)
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

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    error_message = f"Internal server error: {e}"
    print(error_message)
    traceback.print_exc()
    return render_template('error.html', error=error_message), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=True)