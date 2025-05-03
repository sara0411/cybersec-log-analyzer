# API de l'Analyseur de Logs de Sécurité

Ce document décrit les points de terminaison de l'API disponibles pour l'Analyseur de Logs de Sécurité.

## Points de terminaison

### 1. Analyser un fichier de logs

**Endpoint**: `/analyze`

**Méthode**: POST

**Format**: multipart/form-data

**Paramètres**:
- `logfile`: Fichier de logs à analyser

**Réponse**: HTML rendu avec les résultats de l'analyse

### 2. Analyser du texte de logs

**Endpoint**: `/analyze-text`

**Méthode**: POST

**Format**: application/x-www-form-urlencoded

**Paramètres**:
- `logtext`: Texte des logs à analyser

**Réponse**: HTML rendu avec les résultats de l'analyse

### 3. Obtenir les détails d'une menace

**Endpoint**: `/threat-details/<threat_id>`

**Méthode**: GET

**Paramètres**:
- `threat_id`: ID de la menace

**Réponse**: JSON avec les détails de la menace
```json
{
  "details": "<HTML formaté avec les détails de la menace>"
}