# Retraining Guide

This guide explains how to retrain the phishing detection models.

---

## Table of Contents

1. [Overview](#1-overview)
2. [URL Model Retraining](#2-url-model-retraining)
3. [SMS Model Retraining](#3-sms-model-retraining)
4. [How It Works](#4-how-it-works)
5. [Troubleshooting](#5-troubleshooting)

---

## 1. Overview

### What is Retraining?

Retraining is the process of updating the ML model with new predictions from the API. This helps the model learn from real-world data and improve over time.

### Why Retrain?

- Model learns from new phishing patterns
- Improves detection accuracy
- Adapts to new threats

### Confidence Threshold

We only use high-confidence predictions for retraining:
- **URL**: Confidence ≥ 0.85
- **SMS**: Confidence ≥ 0.85

This ensures quality training data.

---

## 2. URL Model Retraining

### Prerequisites

1. Backend is running
2. New predictions in logs (`backend/logs/predictions_*.csv`)
3. At least 10 new high-confidence predictions

### Step-by-Step

**Option A: Using API**

```powershell
# Trigger retraining via API
Invoke-RestMethod -Uri http://localhost:8000/retrain -Method POST
```

**Option B: Using Script**

```powershell
# Run retraining script directly
cd C:\Users\Administrator\Documents\HACKATHON\phishing-detection-system
python scripts/retrain.py
```

### Expected Output

```
============================================================
PHISHING DETECTION - RETRAINING PIPELINE
============================================================
[LOADING PREDICTION LOGS]
  Loaded: backend/logs/predictions_2026-04-08.csv (12 rows)
[FILTERING BY CONFIDENCE >= 0.85]
  Kept: 10 / 12 (83.3%)
[RETRAINING COMPLETE]
  New samples added: 10
  Total samples: 11439
  Recall: 0.9187
  Version: v3
```

### Output Files

| File | Location |
|------|---------|
| New Model | `training/models/phishing_model_rf_v3.pkl` |
| Feature Names | `training/models/feature_names_v3.pkl` |
| Metadata | `training/models/model_info_v3.json` |

---

## 3. SMS Model Retraining

### Prerequisites

1. Backend is running
2. New SMS predictions logged with `type=sms`
3. At least 10 new high-confidence predictions

### Step-by-Step

**Option A: Using API (Future)**

```powershell
Invoke-RestMethod -Uri http://localhost:8000/sms-retrain -Method POST
```

**Option B: Using Script (Future)**

```powershell
python scripts/sms_retrain.py
```

### Expected Output (Future)

```
============================================================
SMS SPAM DETECTION - RETRAINING PIPELINE
============================================================
[LOADING SMS PREDICTION LOGS]
  Loaded: backend/logs/predictions_2026-04-08.csv
  Filtered by type=sms: 15 messages
[FILTERING BY CONFIDENCE >= 0.85]
  Kept: 12 / 15 (80%)
[RETRAINING COMPLETE]
  New samples added: 12
  Total samples: 5139
  Precision: 0.89
  Version: v2
```

### Output Files (Future)

| File | Location |
|------|---------|
| New Model | `training/models/sms/sms_model_v2.pkl` |
| Vectorizer | `training/models/sms/sms_vectorizer_v2.pkl` |
| Metadata | `training/models/sms/sms_model_info_v2.json` |

---

## 4. How It Works

### URL Retraining Pipeline

```
Prediction Logs (daily CSV)
    ↓
Filter: confidence ≥ 0.85
    ↓
Extract 54 features from URLs
    ↓
Deduplicate with existing dataset
    ↓
Merge with existing data
    ↓
Train Random Forest (same hyperparams as v2)
    ↓
Evaluate: accuracy, precision, recall, F1
    ↓
Compare with previous version
    ↓
Save if better: v3 model
```

### SMS Retraining Pipeline (Future)

```
Prediction Logs (daily CSV)
    ↓
Filter: type="sms" AND confidence ≥ 0.85
    ↓
Extract TF-IDF features
    ↓
Deduplicate with existing data
    ↓
Merge with existing SMS data
    ↓
Train Logistic Regression
    ↓
Evaluate
    ↓
Save if better: v2 model
```

---

## 5. Troubleshooting

### Problem: "No new samples to retrain"

**Cause**: Not enough high-confidence predictions

**Solution**:
1. Make more predictions via API
2. Check confidence threshold (default: 0.85)
3. Lower threshold if needed (edit `RETRAIN_CONFIDENCE_THRESHOLD` in script)

---

### Problem: "Model worse than previous"

**Cause**: New data may have noise

**Solution**:
1. Check log file quality
2. Consider manual review of new data
3. Keep previous model as fallback

---

### Problem: "Log file not found"

**Cause**: Logs directory path wrong

**Solution**:
1. Check `backend/config.py` for LOG_DIR
2. Verify `backend/logs/` has CSV files

---

## Quick Reference

| Task | Command |
|------|--------|
| Retrain URL model | `python scripts/retrain.py` |
| Retrain via API | `Invoke-RestMethod -Uri http://localhost:8000/retrain -Method POST` |
| View logs | `Get-Content backend/logs/predictions_2026-04-08.csv` |
| Check model | `Get-Content training/models/model_info_v3.json` |

---

## Configuration

### Retrain Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `RETRAIN_CONFIDENCE_THRESHOLD` | 0.85 | Min confidence for training data |
| `MIN_NEW_SAMPLES` | 10 | Min new samples before retraining |
| `MODEL_VERSION` | v3 | Output model version |

---

## Notes

- Always backup previous model before retraining
- Test new model before deploying
- Monitor metrics after retraining
- Keep track of model versions

---

**End of Retraining Guide**