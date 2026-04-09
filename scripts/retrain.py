"""
Retraining Pipeline for Phishing Detection Model
Loads high-confidence predictions from logs, merges with dataset, retrains model.
"""

import os
import sys
import glob
import pandas as pd
import numpy as np
from datetime import datetime
import json
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, classification_report
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.features import extract_url_features, URL_ONLY_FEATURES

RETRAIN_CONFIDENCE_THRESHOLD = 0.85
MIN_NEW_SAMPLES = 1
MODEL_VERSION = "v3"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIRS = [
    os.path.join(BASE_DIR, "backend", "logs"),
    os.path.join(BASE_DIR, "logs"),
]
DATASET_PATH = os.path.join(BASE_DIR, "training", "data", "processed", "dataset_v1.csv")
MODEL_DIR = os.path.join(BASE_DIR, "training", "models")


def load_prediction_logs(log_dirs: list) -> pd.DataFrame:
    """Load all prediction logs from specified directories."""
    print("[LOADING PREDICTION LOGS]")
    
    all_dfs = []
    for log_dir in log_dirs:
        if not os.path.exists(log_dir):
            print(f"  Directory not found: {log_dir}")
            continue
            
        pattern = os.path.join(log_dir, "predictions_*.csv")
        files = glob.glob(pattern)
        
        for filepath in files:
            try:
                df = pd.read_csv(filepath)
                df["source_file"] = os.path.basename(filepath)
                all_dfs.append(df)
                print(f"  Loaded: {filepath} ({len(df)} rows)")
            except Exception as e:
                print(f"  Error loading {filepath}: {e}")
    
    if not all_dfs:
        print("  No prediction logs found!")
        return pd.DataFrame()
    
    combined = pd.concat(all_dfs, ignore_index=True)
    print(f"  Total rows loaded: {len(combined)}")
    
    return combined


def filter_by_confidence(df: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """Filter predictions by confidence threshold."""
    print(f"\n[FILTERING BY CONFIDENCE >= {threshold}]")
    
    original_count = len(df)
    df_filtered = df[df["confidence"] >= threshold].copy()
    
    print(f"  Kept: {len(df_filtered)} / {original_count} ({len(df_filtered)/max(1,original_count)*100:.1f}%)")
    print(f"  Filtered out: {original_count - len(df_filtered)}")
    
    return df_filtered


def extract_features_from_urls(urls: pd.Series) -> pd.DataFrame:
    """Extract 54 features from URLs."""
    print("\n[EXTRACTING FEATURES FROM URLS]")
    
    feature_rows = []
    for i, url in enumerate(urls):
        if i % 100 == 0:
            print(f"  Processing: {i}/{len(urls)}...")
        
        try:
            features = extract_url_features(str(url))
            feature_rows.append(features)
        except Exception as e:
            print(f"  Error processing URL {i}: {e}")
            feature_rows.append({name: 0.0 for name in URL_ONLY_FEATURES})
    
    df_features = pd.DataFrame(feature_rows)
    print(f"  Extracted features: {df_features.shape}")
    
    return df_features


def convert_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Convert prediction labels to training format."""
    print("\n[CONVERTING LABELS]")
    
    df = df.copy()
    df["status"] = df["prediction"].map({
        "phishing": 1,
        "legitimate": 0
    })
    
    valid_labels = df["status"].notna()
    df = df[valid_labels].copy()
    
    print(f"  Valid labels: {len(df)}")
    print(f"  Label distribution:")
    print(f"    phishing (1): {(df['status'] == 1).sum()}")
    print(f"    legitimate (0): {(df['status'] == 0).sum()}")
    
    return df


def deduplicate_with_existing(new_df: pd.DataFrame, existing_df: pd.DataFrame) -> pd.DataFrame:
    """Remove URLs that already exist in the dataset."""
    print("\n[DEDUPLICATING WITH EXISTING DATASET]")
    
    existing_urls = set(existing_df["url"].dropna().unique())
    new_count = len(new_df)
    
    new_df = new_df[~new_df["url"].isin(existing_urls)].copy()
    
    print(f"  Original new samples: {new_count}")
    print(f"  Removed (already in dataset): {new_count - len(new_df)}")
    print(f"  Unique new samples: {len(new_df)}")
    
    return new_df


def merge_datasets(existing_df: pd.DataFrame, new_df: pd.DataFrame) -> pd.DataFrame:
    """Merge existing dataset with new labeled data."""
    print("\n[MERGING DATASETS]")
    
    original_count = len(existing_df)
    new_count = len(new_df) if len(new_df) > 0 else 0
    
    if new_count == 0:
        print("  No new data to merge")
        return existing_df
    
    try:
        merged = pd.concat([existing_df, new_df], ignore_index=True)
        print(f"  Original: {original_count}")
        print(f"  Added: {new_count}")
        print(f"  Total: {len(merged)}")
        return merged
    except Exception as e:
        print(f"  Merge error: {e}")
        return existing_df


def load_existing_dataset(path: str) -> pd.DataFrame:
    """Load original training dataset."""
    print("\n[LOADING EXISTING DATASET]")
    
    if not os.path.exists(path):
        print(f"  Dataset not found: {path}")
        return pd.DataFrame()
    
    df = pd.read_csv(path)
    print(f"  Loaded: {len(df)} samples")
    print(f"  Columns: {len(df.columns)}")
    
    return df


def prepare_training_data(df: pd.DataFrame) -> tuple:
    """Prepare features and labels for training."""
    print("\n[PREPARING TRAINING DATA]")
    
    available_features = [f for f in URL_ONLY_FEATURES if f in df.columns]
    missing_features = set(URL_ONLY_FEATURES) - set(available_features)
    
    if missing_features:
        print(f"  WARNING: Missing features: {missing_features}")
        for f in missing_features:
            df[f] = 0.0
    
    X = df[URL_ONLY_FEATURES].copy()
    y = df["label"].map({1: 1, 0: 0, "1": 1, "0": 0})
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  Features: {X.shape[1]}")
    print(f"  Train: {len(X_train)}, Test: {len(X_test)}")
    print(f"  Class distribution:")
    print(f"    Phishing: {int((y == 1).sum())}")
    print(f"    Legitimate: {int((y == 0).sum())}")
    
    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train) -> RandomForestClassifier:
    """Train Random Forest model."""
    print("\n[TRAINING MODEL]")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42
    )
    
    model.fit(X_train, y_train)
    print("  Training complete")
    
    return model


def evaluate_model(model, X_test, y_test) -> dict:
    """Evaluate model and return metrics."""
    print("\n[EVALUATING MODEL]")
    
    y_pred = model.predict(X_test)
    
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred)
    }
    
    print("\n  Metrics:")
    for name, value in metrics.items():
        status = "[PASS]" if (name != "recall" or value >= 0.90) else "[FAIL]"
        print(f"    {name.capitalize():12s}: {value:.4f} {status}")
    
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    
    return metrics


def load_v2_metrics() -> dict:
    """Load v2 model metrics for comparison."""
    v2_info_path = os.path.join(MODEL_DIR, "model_info_v2.json")
    
    if os.path.exists(v2_info_path):
        with open(v2_info_path, "r") as f:
            v2_info = json.load(f)
            return v2_info.get("metrics", {})
    
    return {"recall": 0.90}


def save_artifacts(model, metrics: dict, new_samples_count: int, original_count: int):
    """Save model and metadata."""
    print("\n[SAVING ARTIFACTS]")
    
    v2_metrics = load_v2_metrics()
    
    model_path = os.path.join(MODEL_DIR, f"phishing_model_rf_{MODEL_VERSION}.pkl")
    joblib.dump(model, model_path)
    print(f"  Model: {model_path}")
    
    feature_path = os.path.join(MODEL_DIR, f"feature_names_{MODEL_VERSION}.pkl")
    joblib.dump(URL_ONLY_FEATURES, feature_path)
    print(f"  Features: {feature_path}")
    
    metadata = {
        "version": MODEL_VERSION,
        "parent_version": "v2",
        "created_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feature_count": len(URL_ONLY_FEATURES),
        "feature_type": "url_only",
        "features": URL_ONLY_FEATURES,
        "retrain_config": {
            "confidence_threshold": RETRAIN_CONFIDENCE_THRESHOLD,
            "min_new_samples": MIN_NEW_SAMPLES
        },
        "training_data": {
            "original_samples": original_count,
            "new_samples": new_samples_count,
            "total_samples": original_count + new_samples_count
        },
        "metrics": {k: float(v) for k, v in metrics.items()},
        "comparison": {
            "v2_recall": v2_metrics.get("recall", 0),
            "v3_recall": metrics.get("recall", 0),
            "improvement": metrics.get("recall", 0) - v2_metrics.get("recall", 0)
        },
        "note": "Retrained from prediction logs with high confidence threshold"
    }
    
    metadata_path = os.path.join(MODEL_DIR, f"model_info_{MODEL_VERSION}.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata: {metadata_path}")
    
    return metadata


def run_retraining():
    """Main retraining pipeline."""
    print("=" * 60)
    print("PHISHING DETECTION - RETRAINING PIPELINE")
    print(f"Version: {MODEL_VERSION}")
    print(f"Confidence Threshold: {RETRAIN_CONFIDENCE_THRESHOLD}")
    print("=" * 60)
    
    logs_df = load_prediction_logs(LOGS_DIRS)
    
    if len(logs_df) == 0:
        print("\nNo prediction logs found. Exiting.")
        return None
    
    filtered_df = filter_by_confidence(logs_df, RETRAIN_CONFIDENCE_THRESHOLD)
    
    if len(filtered_df) < MIN_NEW_SAMPLES:
        print(f"\nNot enough samples: {len(filtered_df)} < {MIN_NEW_SAMPLES}")
        print("Skipping retraining.")
        return None
    
    filtered_df = convert_labels(filtered_df)
    
    existing_df = load_existing_dataset(DATASET_PATH)
    
    if len(existing_df) == 0:
        print("No existing dataset found. Exiting.")
        return None
    
    filtered_df = deduplicate_with_existing(filtered_df, existing_df)
    
    if len(filtered_df) == 0:
        print("No new unique samples after deduplication.")
        return None
    
    new_features = extract_features_from_urls(filtered_df["url"])
    new_features["label"] = filtered_df["status"].values
    
    original_count = len(existing_df)
    
    merged_df = merge_datasets(existing_df, new_features)
    
    X_train, X_test, y_train, y_test = prepare_training_data(merged_df)
    
    model = train_model(X_train, y_train)
    
    metrics = evaluate_model(model, X_test, y_test)
    
    v2_metrics = load_v2_metrics()
    print("\n[COMPARISON WITH V2]")
    print(f"  V2 Recall: {v2_metrics.get('recall', 0):.4f}")
    print(f"  V3 Recall: {metrics.get('recall', 0):.4f}")
    print(f"  Improvement: {metrics.get('recall', 0) - v2_metrics.get('recall', 0):.4f}")
    
    new_count = len(filtered_df)
    metadata = save_artifacts(model, metrics, new_count, original_count)
    
    print("\n" + "=" * 60)
    print("RETRAINING COMPLETE")
    print("=" * 60)
    print(f"  New samples added: {new_count}")
    print(f"  Total samples: {original_count + new_count}")
    print(f"  Recall: {metrics.get('recall', 0):.4f}")
    print(f"  Version: {MODEL_VERSION}")
    
    return {
        "version": MODEL_VERSION,
        "new_samples": new_count,
        "total_samples": original_count + new_count,
        "metrics": metrics,
        "v2_comparison": {
            "v2_recall": v2_metrics.get("recall", 0),
            "v3_recall": metrics.get("recall", 0),
            "improvement": metrics.get("recall", 0) - v2_metrics.get("recall", 0)
        }
    }


if __name__ == "__main__":
    result = run_retraining()
    sys.exit(0 if result else 1)