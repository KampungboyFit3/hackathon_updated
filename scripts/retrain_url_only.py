"""
URL-Only Feature Extraction Pipeline
Extracts only features that can be computed from URL structure.
Excludes features requiring external data (Google, WHOIS, Alexa, etc.)
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime
import json
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

# Features that CAN be extracted from URL structure only
URL_ONLY_FEATURES = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_or",
    "nb_eq",
    "nb_underscore",
    "nb_tilde",
    "nb_percent",
    "nb_slash",
    "nb_star",
    "nb_colon",
    "nb_comma",
    "nb_semicolumn",
    "nb_dollar",
    "nb_space",
    "nb_www",
    "nb_com",
    "nb_dslash",
    "http_in_path",
    "https_token",
    "ratio_digits_url",
    "ratio_digits_host",
    "punycode",
    "port",
    "tld_in_path",
    "tld_in_subdomain",
    "abnormal_subdomain",
    "nb_subdomains",
    "prefix_suffix",
    "random_domain",
    "shortening_service",
    "path_extension",
    "nb_redirection",
    "length_words_raw",
    "char_repeat",
    "shortest_words_raw",
    "shortest_word_host",
    "shortest_word_path",
    "longest_words_raw",
    "longest_word_host",
    "longest_word_path",
    "avg_words_raw",
    "avg_word_host",
    "avg_word_path",
    "phish_hints",
    "suspecious_tld",
    "login_form",
    "submit_email",
    "onmouseover"
]

# Features requiring external data - EXCLUDED from training
EXTERNAL_FEATURES = [
    "google_index",
    "page_rank",
    "web_traffic",
    "domain_age",
    "domain_registration_length",
    "whois_registered_domain",
    "dns_record",
    "domain_in_brand",
    "brand_in_subdomain",
    "brand_in_path",
    "statistical_report",
    "nb_hyperlinks",
    "ratio_intHyperlinks",
    "ratio_extHyperlinks",
    "ratio_nullHyperlinks",
    "nb_extCSS",
    "ratio_intRedirection",
    "ratio_extRedirection",
    "ratio_intErrors",
    "ratio_extErrors",
    "external_favicon",
    "links_in_tags",
    "ratio_intMedia",
    "ratio_extMedia",
    "sfh",
    "iframe",
    "popup_window",
    "safe_anchor",
    "right_clic",
    "empty_title",
    "domain_in_title",
    "domain_with_copyright",
    "nb_external_redirection"
]

# Validation
assert len(URL_ONLY_FEATURES) + len(EXTERNAL_FEATURES) == 87, "Feature count mismatch"
assert len(set(URL_ONLY_FEATURES) & set(EXTERNAL_FEATURES)) == 0, "Overlap detected"


def load_and_filter_data(raw_path: str) -> pd.DataFrame:
    """Load raw data and filter to URL-only features."""
    print("[LOADING DATA]")
    df = pd.read_csv(raw_path)
    print(f"  Total samples: {len(df)}")
    print(f"  Original features: {len(df.columns) - 2}")
    
    # Select URL-only features + url + status
    cols_to_keep = ["url", "status"] + URL_ONLY_FEATURES
    df_filtered = df[cols_to_keep].copy()
    
    # Remove duplicates
    original_count = len(df_filtered)
    df_filtered = df_filtered.drop_duplicates(subset=["url"])
    if original_count > len(df_filtered):
        print(f"  Removed {original_count - len(df_filtered)} duplicate URLs")
    
    print(f"  Filtered features: {len(URL_ONLY_FEATURES)}")
    print(f"  Final samples: {len(df_filtered)}")
    
    return df_filtered


def prepare_training_data(df: pd.DataFrame) -> tuple:
    """Prepare features and labels for training."""
    print("\n[PREPARING TRAINING DATA]")
    
    # Features
    X = df[URL_ONLY_FEATURES].copy()
    
    # Labels: legitimate=0, phishing=1
    y = df["status"].map({"legitimate": 0, "phishing": 1})
    
    print(f"  Features shape: {X.shape}")
    print(f"  Label distribution: {dict(y.value_counts())}")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  Train samples: {len(X_train)}")
    print(f"  Test samples: {len(X_test)}")
    
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


def evaluate_model(model, X_test, y_test, feature_names) -> dict:
    """Evaluate model and return metrics."""
    print("\n[EVALUATING MODEL]")
    
    y_pred = model.predict(X_test)
    
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred)
    }
    
    print(f"\n  Metrics:")
    for name, value in metrics.items():
        status = "[PASS]" if (name != "recall" or value >= 0.90) else "[FAIL]"
        print(f"    {name.capitalize():12s}: {value:.4f} {status}")
    
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    
    # Feature importance
    importance = model.feature_importances_
    sorted_idx = np.argsort(importance)[::-1]
    
    print(f"\n  Top 10 Important Features:")
    for i in range(min(10, len(sorted_idx))):
        idx = sorted_idx[i]
        print(f"    {i+1:2d}. {feature_names[idx]}: {importance[idx]:.4f}")
    
    return metrics


def save_artifacts(model, feature_names, metrics, version: str = "v2"):
    """Save model and metadata."""
    print("\n[SAVING ARTIFACTS]")
    
    base_dir = r"C:\Users\Administrator\Documents\HACKATHON\phishing-detection-system\training\models"
    
    # Save model
    model_path = os.path.join(base_dir, f"phishing_model_rf_{version}.pkl")
    joblib.dump(model, model_path)
    print(f"  Model: {model_path}")
    
    # Save feature names
    feature_path = os.path.join(base_dir, f"feature_names_{version}.pkl")
    joblib.dump(feature_names, feature_path)
    print(f"  Features: {feature_path}")
    
    # Save metadata
    metadata = {
        "version": version,
        "created_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feature_count": len(feature_names),
        "feature_type": "url_only",
        "features": feature_names,
        "excluded_features": EXTERNAL_FEATURES,
        "metrics": {k: float(v) for k, v in metrics.items()},
        "note": "Model trained on URL-only features. No external data required."
    }
    
    metadata_path = os.path.join(base_dir, f"model_info_{version}.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata: {metadata_path}")
    
    return model_path, feature_path


def main():
    print("=" * 60)
    print("PHISHING DETECTION - URL-ONLY FEATURES TRAINING")
    print("=" * 60)
    
    raw_path = r"B:\Game\AIML\archive (1)\dataset_phishing.csv"
    
    # Step 1: Load and filter
    df = load_and_filter_data(raw_path)
    
    # Step 2: Prepare data
    X_train, X_test, y_train, y_test = prepare_training_data(df)
    
    # Step 3: Train
    model = train_model(X_train, y_train)
    
    # Step 4: Evaluate
    metrics = evaluate_model(model, X_test, y_test, URL_ONLY_FEATURES)
    
    # Step 5: Save
    model_path, feature_path = save_artifacts(model, URL_ONLY_FEATURES, metrics, "v2")
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"\n  Model: {model_path}")
    print(f"  Features: {len(URL_ONLY_FEATURES)} (URL-only)")
    print(f"  Recall: {metrics['recall']:.2%}")
    print(f"  Precision: {metrics['precision']:.2%}")
    print(f"  F1 Score: {metrics['f1']:.2%}")
    
    return model, URL_ONLY_FEATURES


if __name__ == "__main__":
    main()
