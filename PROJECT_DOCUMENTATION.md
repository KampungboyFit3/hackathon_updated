# Phishing Detection System - Project Documentation

**Last Updated:** 2026-04-09
**Project Status:** Phase 8 Complete

---

## Table of Contents

1. [Project Objective](#1-project-objective)
2. [System Architecture](#2-system-architecture)
3. [Phase 1: ML Training](#3-phase-1-ml-training)
4. [Phase 2: Backend API](#4-phase-2-backend-api)
5. [Phase 2.5: Logging System](#5-phase-25-logging-system)
6. [Phase 3: VirusTotal Integration](#6-phase-3-virustotal-integration)
7. [Project Structure](#7-project-structure)
8. [Configuration](#8-configuration)
9. [How to Run](#9-how-to-run)
10. [API Reference](#10-api-reference)
11. [Troubleshooting](#11-troubleshooting)
12. [Next Steps](#12-next-steps)
13. [Phase 7: Email Phishing Detection](#13-phase-7-email-phishing-detection)
14. [Phase 8: Command-Line Analysis](#14-phase-8-command-line-analysis)

---

## 1. Project Objective

### Purpose
Build a production-ready phishing detection system for analyzing multiple input types using:
- **Machine Learning** (Random Forest, Logistic Regression) for pattern detection
- **VirusTotal API** for threat intelligence
- **Hybrid Approach** (ML + Rules + Header Analysis) for comprehensive detection
- **Feedback Loop** for continuous learning

### Supported Input Types
| Type | Description | Detection Method |
|------|-------------|------------------|
| `url` | URL phishing detection | RF + VT + Rules |
| `sms` | SMS phishing detection | TF-IDF + Rules + VT |
| `email` | Email phishing detection | TF-IDF + Rules + Header + VT |
| `command` | Malicious shell command detection | TF-IDF + Rules |

### Target Users
- Security Engineers
- SOC Teams
- Internal security tools
- Developer workstations (command analysis)

### Success Criteria
- ≥90% recall on phishing detection
- Functional API deployed on VPS
- Feedback loop implemented
- Model retraining pipeline working
- Multi-type support (URL, SMS, Email, Command)

---

## 2. System Architecture

### Multi-Type Detection Flow
```
┌─────────────────────────────────────────────────────────────┐
│                      Client Request                          │
│         (curl / API / Browser / Terminal / Email)           │
└─────────────────────────────┬───────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Backend                            │
│                     Port: 8000                              │
└─────────────────────────────┬───────────────────────────────┘
                               ↓
                 ┌─────────────┴─────────────┐
                 ↓                           ↓
           [URL/SMS]                 [Email/Command]
                 ↓                           ↓
    ┌────────────┴────────┐      ┌──────────┴──────────┐
    ↓                    ↓      ↓                     ↓
┌─────────┐         ┌─────────┐ ┌─────────┐     ┌─────────┐
│   URL   │         │   SMS   │ │  Email  │     │ Command │
│  Model  │         │  Model  │ │  Model  │     │  Model  │
└────┬────┘         └────┬────┘ └────┬────┘     └────┬────┘
     ↓                   ↓          ↓                ↓
┌────┴──────────────────┴──────────┴────────────────┴────┐
│                    Decision Engine                        │
│            (ML + Rules + VT + Header Analysis)           │
└─────────────────────────────┬───────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────┐
│                   Async Logger                              │
│              (Queue + Threading + Daily Rotation)           │
└─────────────────────────────┬───────────────────────────────┘
                               ↓
              ┌────────────────┴────────────────┐
              ↓                                 ↓
    predictions_*.csv (Daily)          model_retraining_pipeline
```

### Detection Priority (per type)

#### URL Detection
```
URL → VirusTotal Check → [If Malicious: Return VT]
                        → [If Clean: ML Model]
                        → Log result
```

#### SMS/Email Detection
```
Text → URL Extraction → VirusTotal + URL ML
                      → Rule Engine (keywords, urgency)
                      → ML Model (TF-IDF)
                      → Decision Engine
                      → Log result
```

#### Command Detection
```
Command → Rule Engine (obfuscation, reverse shell, etc.)
        → ML Model (TF-IDF char n-grams)
        → Decision Engine
        → Log result
```

---

## 3. Phase 1: ML Training

### Overview
Trained a Random Forest classifier on 11,429 phishing/legitimate URLs using **54 URL-only features** (no external API required).

### Model Performance (v2)

| Metric | Score |
|--------|-------|
| Accuracy | 89.98% |
| Precision | 89.60% |
| **Recall** | **90.46%** ✓ |
| F1 Score | 90.03% |
| AUC | 0.99 |

### Key Features (Top 10)
1. `nb_www` (11.08%) - Has www prefix
2. `phish_hints` (7.96%) - Suspicious keywords count
3. `longest_word_path` (6.13%) - Longest path segment
4. `ratio_digits_url` (6.07%) - Digit ratio in URL
5. `longest_words_raw` (4.69%) - Longest word
6. `length_hostname` (4.55%) - Hostname length
7. `length_url` (4.49%) - Total URL length
8. `char_repeat` (4.33%) - Repeated characters
9. `length_words_raw` (4.05%) - Word count
10. `shortest_word_host` (3.99%) - Shortest hostname word

### Why URL-Only Features?
The original dataset had 87 features, but 33 required external data (Google Index, PageRank, WHOIS, etc.). Training on these would cause all real predictions to be "phishing" because external features defaulted to 0.

**Solution:** Retrained on 54 URL-only features that can be extracted from URL structure alone.

### Training Files
- `training/models/phishing_model_rf_v2.pkl` - Trained model
- `training/models/feature_names_v2.pkl` - Feature list
- `training/models/model_info_v2.json` - Model metadata
- `training/data/processed/dataset_v1.csv` - Cleaned dataset

---

## 4. Phase 2: Backend API

### Technology Stack
- **FastAPI** - Web framework
- **Uvicorn** - ASGI server
- **Pydantic** - Request/response validation

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API info |
| `GET` | `/health` | Health check |
| `POST` | `/predict` | URL phishing prediction |
| `POST` | `/virustotal/check` | Direct VT check |
| `GET` | `/logs` | List log files |
| `POST` | `/retrain` | Trigger model retraining |

### Request/Response Format

```bash
# Request
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"input": "http://example.com/login.php"}'

# Response
{
  "prediction": "phishing",
  "confidence": 0.78,
  "source": "ml_model",
  "model_version": "v2",
  "vt_detected_by": null,
  "vt_confidence": null
}
```

---

## 5. Phase 2.5: Logging System

### Features
- **Async Logging** - Background thread with queue
- **Daily Rotation** - `predictions_YYYY-MM-DD.csv`
- **Non-blocking** - No delay to API response

### Log Schema
```csv
url,prediction,confidence,source,model_version,vt_malicious,vt_confidence,vt_detected_by,timestamp
https://google.com,legitimate,0.78,ml_model,v2,False,,,2026-04-08T10:30:00Z
http://malicious.com,phishing,0.7,virustotal,v2,True,70,MockEngine1|MockEngine2,2026-04-08T10:31:00Z
```

### Log Location
```
backend/logs/predictions_2026-04-08.csv
```

---

## 6. Phase 3: VirusTotal Integration

### Detection Flow
```
URL → VirusTotal Check
         ↓
   [If Malicious: Return VT verdict immediately]
         ↓
   [If Suspicious: Combine VT + ML confidence]
         ↓
   [If Clean/Unknown: Use ML prediction]
         ↓
   Log result
```

### Modes
1. **Mock Mode (Default)** - Simulates VT behavior without API key
2. **Real Mode** - Uses actual VirusTotal API

### Mock Detection Rules
```python
# Triggers malicious:
- Contains brand names (paypal, apple, microsoft) + suspicious keywords
- Multiple hyphens (more than 3)
- Suspicious TLDs (.tk, .ml, .ga, .cf, .gq)
- Punycode (xn--)
- URL shorteners (bit.ly, tinyurl)
```

### Rate Limiting
- **Delay:** 1.5 seconds between VT API calls
- **Cache:** 24 hours per URL
- **Cache Location:** `backend/cache/vt_*.json`

### Source Types
| Source | Meaning |
|--------|---------|
| `virustotal` | VT detected as malicious |
| `ml_model` | ML model prediction (VT clean) |
| `consensus` | VT suspicious + ML phishing |

---

## 7. Project Structure

```
phishing-detection-system/
│
├── index.html                     # Frontend UI (URL + SMS + Email + Command)
│
├── training/                     # ML Training Pipeline
│   ├── data/
│   │   ├── raw/                   # Original dataset
│   │   │   ├── dataset_phishing.csv
│   │   │   ├── sms_spam.csv       # SMS dataset
│   │   │   ├── CEAS_08.csv        # Email dataset
│   │   │   └── command_synthetic.csv  # Command dataset
│   │   └── processed/
│   │       ├── dataset_v1.csv
│   │       ├── sms_cleaned.csv
│   │       ├── email_cleaned.csv
│   │       └── command_cleaned.csv
│   ├── models/                    # Trained models
│   │   ├── phishing_model_rf_v2.pkl   # URL model v2
│   │   ├── phishing_model_rf_v3.pkl   # URL model v3 (retrained)
│   │   ├── feature_names_v2.pkl
│   │   ├── feature_names_v3.pkl
│   │   ├── model_info_v2.json
│   │   ├── model_info_v3.json
│   │   ├── sms/                    # SMS model
│   │   │   ├── sms_model.pkl
│   │   │   ├── sms_vectorizer.pkl
│   │   │   └── sms_model_info.json
│   │   ├── email/                 # Email model
│   │   │   ├── email_model.pkl
│   │   │   ├── email_vectorizer.pkl
│   │   │   └── email_model_info.json
│   │   └── command/               # Command model
│   │       ├── command_model.pkl
│   │       ├── command_vectorizer.pkl
│   │       └── command_model_info.json
│   └── src/
│       ├── preprocess.py          # URL preprocessing
│       ├── train.py               # URL training
│       ├── sms_preprocess.py      # SMS preprocessing
│       ├── sms_train.py           # SMS training
│       ├── email_preprocess.py    # Email preprocessing
│       ├── email_train.py         # Email training
│       ├── command_preprocess.py  # Command preprocessing
│       ├── command_train.py       # Command training
│       └── generate_command_data.py  # Synthetic command data
│
├── backend/                       # FastAPI Backend
│   ├── app.py                    # Main application (v1.2.0)
│   ├── config.py                 # Configuration
│   ├── .env                      # Environment variables
│   ├── .env.example
│   ├── requirements.txt
│   ├── services/
│   │   ├── detection.py         # URL detection
│   │   ├── sms_detection.py      # SMS detection
│   │   ├── sms_rules.py           # SMS rule engine
│   │   ├── eml_parser.py          # Email parser (.eml)
│   │   ├── email_detection.py    # Email detection
│   │   ├── email_rules.py         # Email rule engine
│   │   ├── command_detection.py  # Command detection
│   │   └── command_rules.py       # Command rule engine
│   ├── utils/
│   │   ├── virustotal_check.py   # VT integration
│   │   └── logger.py             # Async logging
│   ├── logs/                     # Prediction logs (with type column)
│   └── cache/                    # VT response cache
│
├── shared/                        # Shared Modules
│   └── features.py              # URL feature extraction
│
├── scripts/
│   ├── retrain.py               # URL retraining
│   ├── retrain_url_only.py
│   └── (future) sms_retrain.py
│
├── PROJECT_DOCUMENTATION.md       # Main documentation
├── RETRAIN_GUIDE.md             # Retraining guide
├── QUICK_START.md               # Quick start guide
├── requirements.txt
├── venv/                        # Virtual environment
└── cache/                       # Root cache folder
```

---

## 8. Configuration

### Backend Config (`backend/config.py`)

```python
# Model
MODEL_VERSION = "v2"

# API
API_HOST = "0.0.0.0"
API_PORT = 8000

# Logging
LOG_DIR = "./backend/logs"

# VirusTotal
VT_API_KEY = ""           # Leave empty for mock mode
VT_USE_MOCK = True        # Set False for real API
VT_RATE_LIMIT = 1.5       # Seconds between calls
VT_CACHE_HOURS = 24       # Cache duration
```

### Environment Variables (`backend/.env`)

```bash
# VirusTotal (optional - leave empty for mock mode)
VT_API_KEY=your_virustotal_api_key_here
VT_USE_MOCK=true

# Set to false to use real VirusTotal API
```

---

## 9. How to Run

### Prerequisites
```bash
# Install dependencies
cd phishing-detection-system
pip install scikit-learn pandas numpy joblib fastapi uvicorn pydantic
```

### Local Development

```bash
# 1. Start the server
cd backend
python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000

# 2. Test health endpoint
curl http://localhost:8000/health

# 3. Test prediction
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"input": "https://www.google.com/"}'
```

### Docker Deployment

```bash
# Build and run
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Test URLs

```bash
# Legitimate URLs (should return legitimate)
curl -X POST http://localhost:8000/predict \
  -d '{"input": "https://www.google.com/"}'
curl -X POST http://localhost:8000/predict \
  -d '{"input": "https://www.microsoft.com/"}'
curl -X POST http://localhost:8000/predict \
  -d '{"input": "https://github.com/"}'

# Suspicious URLs (should return phishing)
curl -X POST http://localhost:8000/predict \
  -d '{"input": "http://secure-paypal-login.suspicious.com/"}'
curl -X POST http://localhost:8000/predict \
  -d '{"input": "http://malicious-site.com/verify.php"}'
```

---

## 10. API Reference

### POST /predict

**Request:**
```json
{
  "input": "http://example.com/login.php",
  "type": "url",
  "use_virustotal": true
}
```

**Response:**
```json
{
  "prediction": "legitimate",
  "confidence": 0.78,
  "source": "ml_model",
  "model_version": "v2",
  "vt_detected_by": null,
  "vt_confidence": null
}
```

### Supported `type` Values

| Type | Description | Required Fields |
|------|-------------|------------------|
| `url` | URL phishing detection | `input` (URL string) |
| `sms` | SMS phishing detection | `input` (SMS text) |
| `email` | Email phishing detection | `input` (email text or EML format) |
| `command` | Malicious command detection | `input` (shell command) |

### Example: Email Detection

**Request:**
```json
{
  "input": "Subject: Verify Account\nFrom: security@bank.com\n\nURGENT: Your account suspended. Click here: http://bit.ly/fake",
  "type": "email",
  "use_virustotal": true
}
```

**Response:**
```json
{
  "prediction": "phishing",
  "confidence": 0.95,
  "source": "rule_engine",
  "ml_prediction": "phishing",
  "ml_confidence": 0.9482,
  "rule_score": 14,
  "rule_signals": [
    ["url_count", 1],
    ["url_shortener", 2],
    ["urgency_words", 2]
  ],
  "header_flags": ["suspicious_tld"]
}
```

### Example: Command Detection

**Request:**
```json
{
  "input": "powershell -enc SGVsbG8=",
  "type": "command"
}
```

**Response:**
```json
{
  "prediction": "malicious",
  "confidence": 0.60,
  "source": "rule_engine",
  "ml_prediction": "malicious",
  "ml_confidence": 0.7382,
  "rule_score": 8,
  "rule_signals": [
    ["obfuscation", 5],
    ["base64_encoding", 3]
  ]
}
```

### POST /virustotal/check

**Request:**
```json
{
  "url": "http://suspicious-site.com/"
}
```

**Response:**
```json
{
  "url": "http://suspicious-site.com/",
  "malicious": true,
  "suspicious": false,
  "confidence": 70,
  "detected_by": ["MockEngine1", "MockEngine2", "MockEngine3"],
  "total_engines": 70,
  "source": "virustotal_mock"
}
```

### GET /health

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "virustotal": "mock"
}
```

### GET /logs

**Response:**
```json
{
  "logs": ["predictions_2026-04-08.csv"],
  "count": 1,
  "log_dir": "C:\\path\\to\\logs"
}
```

---

## 11. Troubleshooting

### Issue: All URLs Predicted as Phishing

**Cause:** Using v1 model with external features defaulted to 0.

**Solution:** Use v2 model (URL-only features):
```python
# Already configured in backend - just ensure using v2
MODEL_VERSION = "v2"  # in detection.py
```

### Issue: VirusTotal Not Working

**Cause:** Rate limiting or invalid API key.

**Solution:**
1. Check `VT_USE_MOCK=true` in config
2. Verify API key format (32 characters)
3. Check rate limits on free tier (4 requests/minute)

### Issue: Logs Not Appearing

**Cause:** Async logger needs time to flush.

**Solution:**
```bash
# Wait 2-3 seconds after prediction
# Or check log file directly
cat backend/logs/predictions_*.csv
```

### Issue: Model Not Loading

**Cause:** Model files missing or path incorrect.

**Solution:**
```bash
# Verify model exists
ls training/models/phishing_model_rf_v2.pkl
ls training/models/feature_names_v2.pkl
```

---

## 12. Next Steps

### Phase 4: Retraining Pipeline
- [x] Create `scripts/retrain.py` - Main retraining script
- [x] Load predictions from `logs/`
- [x] Merge with existing dataset
- [x] Retrain model with new data
- [x] Version new model (v3)
- [x] API endpoint `/retrain`

### Phase 5: Simple Web UI
- [x] Create index.html frontend
- [x] URL input + scan button
- [x] Connect to /predict API
- [x] Show result (phishing/legitimate)
- [x] History from /logs API
- [x] Add CORS middleware

### Phase 6: SMS Phishing Detection
- [x] Clean and preprocess SMS dataset
- [x] Train SMS ML model (TF-IDF + LogReg)
- [x] Create rule engine for SMS keywords
- [x] Create URL extractor from SMS
- [x] Add SMS endpoint (/predict with type="sms")
- [x] Add type column to logging (url/sms)
- [x] Real VirusTotal integration

### Phase 7: Chrome Extension
- [ ] Create browser extension
- [ ] Context menu integration
- [ ] Popup UI

### Phase 8: Command-Line Analysis
- [x] Create synthetic command dataset (MITRE ATT&CK patterns)
- [x] Train ML model (TF-IDF + LogReg, 83.82% accuracy)
- [x] Create rule engine (obfuscation, reverse shell, etc.)
- [x] Add command endpoint (/predict with type="command")
- [x] Add type column to logging

### Future Enhancements
- [ ] Multiple threat intelligence sources
- [ ] Real-time WebSocket updates
- [ ] Dashboard for analytics
- [ ] User feedback system
- [ ] Behavioral anomaly detection (Phase 9)
- [ ] Static file analysis (Phase 10)

---

## Phase 4: Retraining Pipeline (Detailed)

### Configuration
```python
# scripts/retrain.py
RETRAIN_CONFIDENCE_THRESHOLD = 0.85  # Only use high-confidence predictions
MIN_NEW_SAMPLES = 1                  # Minimum before retraining
MODEL_VERSION = "v3"
```

### Pipeline Flow
```
Prediction Logs → Filter (conf ≥ 0.85) → Extract Features → Merge → Train → Save v3
     ↓
  backend/logs/ + logs/ (both directories)
     ↓
  Deduplicate with existing dataset
     ↓
  Train Random Forest (same hyperparams as v2)
     ↓
  Save: model_v3.pkl + feature_names_v3.pkl + model_info_v3.json
     ↓
  Compare with v2: keep best model
```

### Retrain API Endpoint

```bash
# Trigger retraining
curl -X POST http://localhost:8000/retrain

# Response
{
  "status": "success",
  "version": "v3",
  "new_samples": 5,
  "total_samples": 11435,
  "metrics": {"recall": 0.91},
  "v2_comparison": {
    "v2_recall": 0.90,
    "v3_recall": 0.91,
    "improvement": 0.01
  }
}
```

### Manual Retraining
```bash
# Run retraining script directly
python scripts/retrain.py
```

### v3 Model Metadata
```json
{
  "version": "v3",
  "parent_version": "v2",
  "retrain_config": {
    "confidence_threshold": 0.85,
    "min_new_samples": 1
  },
  "training_data": {
    "original_samples": 11430,
    "new_samples": 5,
    "total_samples": 11435
  },
  "comparison": {
    "v2_recall": 0.9046,
    "v3_recall": 0.91,
    "improvement": 0.0054
  }
}
```

---

## Phase 5: Simple Web UI (Detailed)

### Overview
Simple single-page HTML frontend that calls the backend API.

### Files
- `index.html` - Main frontend (in project root)

### Features
- URL input box + Scan button
- Real-time result (phishing/legitimate)
- Confidence bar
- Recent scan history
- Server status indicator

### Architecture
```
index.html (Browser)  →  localhost:8000 (Backend API)
```

### Usage
1. Start backend: `python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000`
2. Open `index.html` in browser (double-click file)
3. Enter URL → Click Scan

### API Endpoints Used
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/predict` | POST | Scan URL |
| `/logs` | GET | History |
| `/health` | GET | Server status |

### PowerShell Commands (for Windows)
```powershell
# Start backend
cd C:\Users\Administrator\Documents\HACKATHON\phishing-detection-system\backend
python -m uvicorn app:app --host 0.0.0.0 --port 8000

# Test health (in new terminal)
Invoke-RestMethod -Uri http://localhost:8000/health

# Predict URL
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="https://google.com/"} | ConvertTo-Json) -ContentType "application/json"

# Retrain model
Invoke-RestMethod -Uri http://localhost:8000/retrain -Method POST
```

### CORS Configuration
The backend includes CORS middleware to allow browser requests:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Phase 6: SMS Phishing Detection (Detailed)

### Overview
SMS phishing detection using hybrid approach: ML + Rule Engine + VirusTotal

### Dataset
- Source: SMS Spam Collection (Kaggle)
- Location: `training/data/raw/sms_spam.csv`
- Messages: 5,127 (after cleaning)

### System Architecture
```
SMS Input
   ↓
[1] URL Extraction (if exists)
        ↓
        → VirusTotal + URL ML Model

[2] Rule Engine
        ↓
        keyword detection, urgency signals, money words

[3] SMS ML Model (TF-IDF + Logistic Regression)
        ↓

[4] Decision Engine (Combine results)
        ↓
Final Prediction (phishing/suspicious/legitimate)
```

### Files
| File | Purpose |
|------|---------|
| `training/src/sms_preprocess.py` | Clean SMS dataset |
| `training/src/sms_train.py` | Train SMS model |
| `training/models/sms/sms_model.pkl` | Trained model |
| `training/models/sms/sms_vectorizer.pkl` | TF-IDF vectorizer |
| `backend/services/sms_detection.py` | SMS detection service |
| `backend/services/sms_rules.py` | Rule engine |

### Model Performance
| Metric | Score |
|--------|-------|
| Accuracy | 97.08% |
| Precision | 88.10% |
| Recall | 88.10% |
| F1 | 88.10% |

### Usage
```powershell
# Scan SMS
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="URGENT! Your bank account suspended. Click here: http://bit.ly/fake";type="sms"} | ConvertTo-Json) -ContentType "application/json"

# Response
{
  "prediction": "phishing",
  "confidence": 0.95,
  "source": "rule_engine",
  "rule_score": 7,
  "rule_signals": [...]
}
```

### Log Schema (with type column)
```
url,type,prediction,confidence,source,model_version,vt_malicious,vt_confidence,vt_detected_by,timestamp
https://google.com,url,legitimate,0.82,ml_model,v3,False,,,2026-04-08T...
URGENT! Your bank...,sms,phishing,0.95,rule_engine,v2,False,,,2026-04-08T...
```

### Supported Types
| Type | Description |
|------|-------------|
| `url` | URL phishing detection |
| `sms` | SMS phishing detection |
| `email` | Email phishing detection |
| `command` | Malicious shell command detection |

---

## Quick Reference Commands

```bash
# Start server
cd backend && python -m uvicorn app:app --reload --port 8000

# Test health
curl http://localhost:8000/health

# Predict URL
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"input": "https://example.com/"}'

# View logs
cat backend/logs/predictions_*.csv

# Run training
python scripts/retrain_url_only.py

# Retrain from prediction logs
python scripts/retrain.py

# Trigger retrain via API
curl -X POST http://localhost:8000/retrain

# Test SMS detection (PowerShell)
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="URGENT! Your bank account suspended";type="sms"} | ConvertTo-Json) -ContentType "application/json"

# Test URL detection (PowerShell)
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="https://google.com/"} | ConvertTo-Json) -ContentType "application/json"

# Test Email detection (PowerShell)
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="Subject: Verify Account`nFrom: security@bank.com`n`nURGENT: Your account suspended. Click here: http://bit.ly/fake";type="email"} | ConvertTo-Json) -ContentType "application/json"

# Test Command detection (PowerShell)
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="cmd /c whoami";type="command"} | ConvertTo-Json) -ContentType "application/json"

# Docker
docker-compose up --build

# Open frontend (with backend running)
# Double-click index.html in File Explorer
# OR access via browser
http://127.0.0.1:8000/index.html

# Frontend Features
- URL scanning with type="url"
- SMS scanning with type="sms"
- Email scanning with type="email"
- Command scanning with type="command"
- Real-time results with confidence
- History with type badges
- Dark theme professional UI
```

---

## Phase 7: Email Phishing Detection (Detailed)

### Overview
Email phishing detection using hybrid approach: ML + Rule Engine + Header Analysis + VirusTotal

### Dataset
- Source: CEAS_08 (Kaggle)
- Location: `training/data/raw/CEAS_08.csv`
- Emails: 39,154 (after cleaning: 34,142)
- Label: 1 = phishing, 0 = legitimate

### System Architecture
```
Email Input
   ↓
[1] EML Parser
   ↓
   extract: subject, sender, body, URLs
   ↓
[2] Header Analysis
   ↓
   sender mismatch, suspicious domain, free email brands
   ↓
[3] URL Extraction
   ↓
   → VirusTotal + URL ML Model
   ↓
[4] Rule Engine
   ↓
   keywords: urgency, money, account, phishing
   URL patterns: shorteners, suspicious TLDs
   ↓
[5] Email ML Model (TF-IDF + Logistic Regression)
   ↓
[6] Decision Engine (Combine results)
   ↓
Final Prediction (phishing/suspicious/legitimate)
```

### Files
| File | Purpose |
|------|---------|
| `training/src/email_preprocess.py` | Clean CEAS_08 dataset |
| `training/src/email_train.py` | Train Email model |
| `training/models/email/email_model.pkl` | Trained model |
| `training/models/email/email_vectorizer.pkl` | TF-IDF vectorizer |
| `backend/services/eml_parser.py` | Parse .eml files |
| `backend/services/email_detection.py` | Email detection service |
| `backend/services/email_rules.py` | Rule engine |

### Model Performance
| Metric | Score |
|--------|-------|
| Accuracy | 99.56% |
| Precision | 99.64% |
| Recall | 99.47% |
| F1 | 99.56% |

### Usage
```powershell
# Scan Email
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="Subject: Verify Account`nFrom: security@bank.com`n`nURGENT: Your account suspended. Click here: http://bit.ly/fake";type="email"} | ConvertTo-Json) -ContentType "application/json"

# Response
{
  "prediction": "phishing",
  "confidence": 0.95,
  "source": "rule_engine",
  "ml_prediction": "phishing",
  "ml_confidence": 0.9482,
  "rule_score": 14,
  "rule_signals": [
    ["url_count", 1],
    ["url_shortener", 2],
    ["urgency_words", 2],
    ["money_words", 2],
    ["account_words", 2],
    ["brand_urgency", 3]
  ],
  "header_flags": ["suspicious_tld"]
}
```

### Supported Input Formats
1. **EML Format**: `"Subject: ...\nFrom: ...\n\nBody..."`
2. **Plain Text**: `"Your email body text..."`

---

## Phase 8: Command-Line Analysis (Detailed)

### Overview
Malicious shell command detection using hybrid approach: ML + Rule Engine
Based on MITRE ATT&CK patterns and common attack techniques.

### Dataset
- Source: Synthetic (generated from attack patterns)
- Location: `training/data/raw/command_synthetic.csv`
- Commands: 337 (160 malicious, 177 legitimate)
- Categories: Obfuscation, Remote Download, Reverse Shell, Privilege Escalation, etc.

### System Architecture
```
Command Input
   ↓
[1] Command Cleaner
   ↓
   lowercase, remove special chars, normalize
   ↓
[2] Rule Engine
   ↓
   pattern matching: obfuscation, reverse shell, download, persistence
   scoring: +1 to +5 per pattern
   ↓
[3] ML Model (TF-IDF + Logistic Regression)
   ↓
   char_wb analyzer, ngram (1,3), max_features=1000
   ↓
[4] Decision Engine
   ↓
   if rule_score >= 8: malicious
   elif rule_score >= 4 + ML confident: malicious
   elif ML confident > 0.8: malicious
   else: legitimate
   ↓
Final Prediction (malicious/suspicious/legitimate)
```

### Files
| File | Purpose |
|------|---------|
| `training/src/generate_command_data.py` | Generate synthetic dataset |
| `training/src/command_preprocess.py` | Clean command dataset |
| `training/src/command_train.py` | Train Command model |
| `training/models/command/command_model.pkl` | Trained model |
| `training/models/command/command_vectorizer.pkl` | TF-IDF vectorizer |
| `backend/services/command_detection.py` | Command detection service |
| `backend/services/command_rules.py` | Rule engine |

### Model Performance
| Metric | Score |
|--------|-------|
| Accuracy | 83.82% |
| Precision | 86.21% |
| Recall | 78.12% |
| F1 | 81.97% |
| CV F1 Mean | 86.33% |

### Rule Categories
| Category | Score | Examples |
|----------|-------|----------|
| Obfuscation | +5 | `cmd /c`, `powershell -enc`, `bash -c` |
| Reverse Shell | +5 | `/dev/tcp/`, `nc -e`, `bash -i` |
| Remote Download | +4 | `curl http://...`, `wget`, `Invoke-WebRequest` |
| Credential Access | +5 | `mimikatz`, `LaZagne`, `pwdump` |
| Privilege Escalation | +4 | `sudo su`, `chmod 777`, `whoami /priv` |
| Persistence | +4 | `reg add`, `cron`, `launchctl` |
| Lateral Movement | +4 | `psexec`, `wmic`, `winrm` |
| Disable Security | +4 | `netsh firewall off`, `sc stop` |

### Usage
```powershell
# Test malicious command
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="powershell -enc SGVsbG8=";type="command"} | ConvertTo-Json) -ContentType "application/json"

# Test legitimate command
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="git status";type="command"} | ConvertTo-Json) -ContentType "application/json"

# Response (malicious)
{
  "prediction": "malicious",
  "confidence": 0.60,
  "source": "rule_engine",
  "ml_prediction": "malicious",
  "ml_confidence": 0.7382,
  "rule_score": 8,
  "rule_signals": [
    ["obfuscation", 5],
    ["base64_encoding", 3]
  ]
}

# Response (legitimate)
{
  "prediction": "legitimate",
  "confidence": 0.70,
  "source": "ml_model",
  "ml_prediction": "legitimate",
  "ml_confidence": 0.70,
  "rule_score": 0,
  "rule_signals": []
}
```

### Note on Dataset Size
The synthetic dataset is relatively small (337 samples). For better performance:
1. Add more real attack commands from malware analysis
2. Collect samples from security logs over time
3. Use the retraining pipeline to improve model

---

## Contact & Support

For issues or questions, refer to:
- VirusTotal API Docs: https://developers.virustotal.com/
- FastAPI Docs: https://fastapi.tiangolo.com/
- Scikit-learn Docs: https://scikit-learn.org/

---

**End of Documentation**
