"""
Backend Configuration
Includes VirusTotal settings
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = os.path.join(BASE_DIR, "..", "training", "models", "phishing_model_rf_v2.pkl")
FEATURE_NAMES_PATH = os.path.join(BASE_DIR, "..", "training", "models", "feature_names_v2.pkl")
LOG_DIR = os.path.join(BASE_DIR, "backend", "logs")

API_HOST = "0.0.0.0"
API_PORT = 8000
API_RELOAD = False

LABEL_MAPPING = {
    0: "legitimate",
    1: "phishing"
}

SUPPORTED_TYPES = ["url", "sms", "email", "command"]

# VirusTotal Configuration
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_USE_MOCK = os.environ.get("VT_USE_MOCK", "true").lower() in ["true", "1", "yes"]
VT_RATE_LIMIT = 1.5
VT_CACHE_HOURS = 24
