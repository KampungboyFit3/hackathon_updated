"""
Phishing Detection Service with VirusTotal Integration
Flow: VirusTotal Check (First) → ML Model Fallback
"""

import os
import sys
import joblib
from typing import Dict, List, Optional
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from shared.features import extract_features_array, URL_ONLY_FEATURES

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.virustotal_check import get_vt_checker, check_url_virustotal


MODEL_VERSION = "v3"
MODEL_FILENAME = f"phishing_model_rf_{MODEL_VERSION}.pkl"
FEATURE_FILENAME = f"feature_names_{MODEL_VERSION}.pkl"


class PhishingDetector:
    def __init__(
        self,
        model_path: Optional[str] = None,
        feature_names_path: Optional[str] = None,
        use_virustotal: bool = True,
        vt_api_key: Optional[str] = None
    ):
        self.model = None
        self.feature_names = None
        self.model_path = model_path
        self.feature_names_path = feature_names_path
        self.loaded = False
        self.use_virustotal = use_virustotal
        self.vt_api_key = vt_api_key
        self.vt_checker = None
    
    def load(self):
        if self.loaded:
            return
        
        if self.model_path is None:
            self.model_path = os.path.join(
                os.path.dirname(__file__), "..", "..", "training", "models", MODEL_FILENAME
            )
        
        if self.feature_names_path is None:
            self.feature_names_path = os.path.join(
                os.path.dirname(__file__), "..", "..", "training", "models", FEATURE_FILENAME
            )
        
        print(f"[Detector] Loading model from: {self.model_path}")
        self.model = joblib.load(self.model_path)
        
        print(f"[Detector] Loading feature names from: {self.feature_names_path}")
        self.feature_names = joblib.load(self.feature_names_path)
        
        if self.use_virustotal:
            self.vt_checker = get_vt_checker(api_key=self.vt_api_key)
        
        self.loaded = True
        print(f"[Detector] Model loaded. Features: {len(self.feature_names)}")
        print(f"[Detector] VirusTotal: {'Enabled' if self.use_virustotal else 'Disabled'}")
    
    def _get_ml_prediction(self, url: str) -> Dict:
        features = extract_features_array(url, self.feature_names)
        features_array = np.array(features).reshape(1, -1)
        
        prediction = self.model.predict(features_array)[0]
        probabilities = self.model.predict_proba(features_array)[0]
        
        ml_confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
        label = "phishing" if prediction == 1 else "legitimate"
        
        return {
            "prediction": label,
            "confidence": round(ml_confidence, 4)
        }
    
    def predict(self, url: str) -> Dict:
        if not self.loaded:
            self.load()
        
        if self.use_virustotal and self.vt_checker:
            vt_result = self.vt_checker.get_result(url)
            
            if vt_result["malicious"]:
                return {
                    "prediction": "phishing",
                    "confidence": vt_result["confidence"] / 100,
                    "source": "virustotal",
                    "model_version": MODEL_VERSION,
                    "vt_detected_by": vt_result["detected_by"],
                    "vt_confidence": vt_result["confidence"]
                }
            
            elif vt_result.get("suspicious", False):
                ml_result = self._get_ml_prediction(url)
                ml_confidence = ml_result["confidence"]
                
                if ml_result["prediction"] == "phishing":
                    combined_confidence = (vt_result["confidence"] + ml_confidence) / 200
                    return {
                        "prediction": "phishing",
                        "confidence": round(combined_confidence, 4),
                        "source": "consensus",
                        "model_version": MODEL_VERSION,
                        "vt_detected_by": vt_result["detected_by"],
                        "ml_prediction": "phishing",
                        "vt_confidence": vt_result["confidence"] / 100
                    }
                else:
                    return {
                        "prediction": "legitimate",
                        "confidence": round(1 - (vt_result["confidence"] / 200), 4),
                        "source": "virustotal",
                        "model_version": MODEL_VERSION,
                        "vt_suspicious": True,
                        "vt_detected_by": vt_result["detected_by"]
                    }
        
        ml_result = self._get_ml_prediction(url)
        
        return {
            "prediction": ml_result["prediction"],
            "confidence": ml_result["confidence"],
            "source": "ml_model",
            "model_version": MODEL_VERSION
        }
    
    def predict_batch(self, urls: List[str]) -> List[Dict]:
        if not self.loaded:
            self.load()
        
        results = []
        for url in urls:
            results.append(self.predict(url))
        
        return results
    
    def get_virustotal_result(self, url: str) -> Dict:
        if not self.loaded:
            self.load()
        
        if self.use_virustotal and self.vt_checker:
            return self.vt_checker.get_result(url)
        
        return {
            "error": "VirusTotal is disabled"
        }


_detector = None


def get_detector(
    use_virustotal: bool = True,
    vt_api_key: Optional[str] = None
) -> PhishingDetector:
    global _detector
    
    if _detector is None:
        _detector = PhishingDetector(
            use_virustotal=use_virustotal,
            vt_api_key=vt_api_key
        )
        _detector.load()
    
    return _detector


def predict_phishing(
    url: str,
    use_virustotal: bool = True,
    vt_api_key: Optional[str] = None
) -> Dict:
    detector = get_detector(
        use_virustotal=use_virustotal,
        vt_api_key=vt_api_key
    )
    return detector.predict(url)


def get_virustotal_check(
    url: str,
    vt_api_key: Optional[str] = None
) -> Dict:
    checker = get_vt_checker(api_key=vt_api_key)
    return checker.get_result(url)


if __name__ == "__main__":
    detector = PhishingDetector(use_virustotal=True)
    detector.load()
    
    test_urls = [
        "https://www.google.com/",
        "https://www.microsoft.com/",
        "http://malicious-site.com/verify.php",
        "http://secure-paypal-login.suspicious.com/",
        "https://github.com/security",
        "http://bit.ly/test123",
    ]
    
    print("\n" + "=" * 70)
    print("PHISHING PREDICTION WITH VIRUSTOTAL INTEGRATION")
    print("=" * 70)
    
    for url in test_urls:
        result = detector.predict(url)
        
        source_icon = "[VT]" if result["source"] == "virustotal" else "[ML]" if result["source"] == "ml_model" else "[VT+ML]"
        status = "[PHISHING]" if result["prediction"] == "phishing" else "[LEGITIMATE]"
        
        print(f"\n{source_icon} {status} {result['prediction']}")
        print(f"    URL: {url}")
        print(f"    Confidence: {result['confidence']:.2%}")
        print(f"    Source: {result['source']}")
        
        if "vt_detected_by" in result:
            print(f"    VT Detected by: {result['vt_detected_by']}")
        
        print()
