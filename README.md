# Phishing Detection System - ML Training Pipeline

## Overview

Machine Learning training pipeline for URL-based phishing detection.

## Features

- Data validation and cleaning
- Versioned data processing
- Random Forest and Logistic Regression models
- Comprehensive evaluation metrics
- Feature importance tracking

## Data Lineage

| Version | Samples | Legitimate | Phishing | Date |
|---------|---------|------------|----------|------|
| v1      | 11430   | ~5700      | ~5700    | 2026-04-07 |

## Usage

### Full Pipeline

```bash
cd training/src
python -c "
from preprocess import main as preprocess_main
from train import main as train_main
from evaluate import main as evaluate_main
import joblib
import config

X_train, X_test, y_train, y_test, feature_names, metadata = preprocess_main()
models = train_main(X_train, y_train, feature_names, metadata)
evaluate_main(X_test, y_test, models)
"
```

### Individual Steps

```bash
# Step 1: Preprocess data
python src/preprocess.py

# Step 2: Train models
python src/train.py

# Step 3: Evaluate models
python src/evaluate.py
```

## Output Files

### Models
- `models/phishing_model_rf_v1.pkl` - Random Forest
- `models/phishing_model_lr_v1.pkl` - Logistic Regression
- `models/feature_names.pkl` - Feature names list
- `models/model_info.json` - Model metadata

### Processed Data
- `data/processed/dataset_v1.csv` - Cleaned dataset
- `data/processed/metadata_v1.json` - Lineage tracking

### Evaluation
- `models/confusion_matrix_rf.png`
- `models/confusion_matrix_lr.png`
- `models/roc_curve_rf.png`
- `models/evaluation_info.json`

## Requirements

```
pip install -r requirements.txt
```

## Metrics Target

| Metric | Target | Priority |
|--------|--------|----------|
| Recall | ≥90% | Critical |
| Precision | >80% | High |
| F1 | >85% | High |

## Future Extensions

- XGBoost / LightGBM models
- Feature selection based on importance
- Cross-validation
- Hyperparameter optimization
