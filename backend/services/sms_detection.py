"""
SMS Phishing Detection Service
Combines ML model, Rule Engine, and URL extraction (VirusTotal)
"""

import os
import sys
import joblib
import re
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.services.sms_rules import check_message as rule_check, extract_urls as extract_urls_from_sms
from backend.utils.virustotal_check import check_url_virustotal

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "training", "models", "sms")


class SMSDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.loaded = False
    
    def load(self):
        if self.loaded:
            return
        
        model_path = os.path.join(MODEL_DIR, "sms_model.pkl")
        vectorizer_path = os.path.join(MODEL_DIR, "sms_vectorizer.pkl")
        
        if not os.path.exists(model_path):
            print(f"[SMSDetector] Model not found: {model_path}")
            return
        
        print(f"[SMSDetector] Loading model from: {model_path}")
        self.model = joblib.load(model_path)
        
        print(f"[SMSDetector] Loading vectorizer from: {vectorizer_path}")
        self.vectorizer = joblib.load(vectorizer_path)
        
        self.loaded = True
        print(f"[SMSDetector] Loaded successfully")
    
    def predict(self, message: str, use_virustotal: bool = True) -> Dict:
        """Predict if SMS is phishing."""
        if not self.loaded:
            self.load()
        
        message = message.strip()
        if not message:
            return {"error": "Empty message"}
        
        urls = extract_urls_from_sms(message)
        
        rule_result = rule_check(message)
        
        ml_result = self._ml_predict(message)
        
        vt_result = None
        if use_virustotal and urls:
            vt_result = self._check_urls_virustotal(urls)
        
        final = self._combine_results(ml_result, rule_result, vt_result)
        
        return final
    
    def _ml_predict(self, message: str) -> Dict:
        """Get ML model prediction."""
        if not self.model or not self.vectorizer:
            return {"prediction": "safe", "confidence": 0.5, "source": "ml_model"}
        
        message_clean = message.lower()
        message_tfidf = self.vectorizer.transform([message_clean])
        
        prediction = self.model.predict(message_tfidf)[0]
        probabilities = self.model.predict_proba(message_tfidf)[0]
        
        confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
        label = "spam" if prediction == 1 else "ham"
        
        return {
            "prediction": label,
            "confidence": round(confidence, 4),
            "source": "ml_model"
        }
    
    def _check_urls_virustotal(self, urls: List[str]) -> Optional[Dict]:
        """Check URLs via VirusTotal."""
        if not urls:
            return None
        
        results = []
        for url in urls[:3]:
            try:
                vt = check_url_virustotal(url)
                if vt and vt.get("malicious"):
                    results.append(vt)
            except Exception as e:
                continue
        
        if not results:
            return None
        
        avg_confidence = sum(r.get("confidence", 0) for r in results) / len(results)
        malicious_count = sum(1 for r in results if r.get("malicious"))
        
        return {
            "malicious": malicious_count > 0,
            "confidence": round(avg_confidence, 2),
            "urls_checked": len(urls),
            "detected_by": [r.get("detected_by", []) for r in results]
        }
    
    def _combine_results(self, ml_result: Dict, rule_result: Dict, vt_result: Optional[Dict]) -> Dict:
        """Combine ML, Rule, and VT results."""
        
        if vt_result and vt_result.get("malicious"):
            final_prediction = "phishing"
            confidence = vt_result["confidence"] / 100
            source = "virustotal"
        
        elif rule_result["prediction"] == "phishing":
            final_prediction = "phishing"
            confidence = rule_result["confidence"]
            source = "rule_engine"
        
        elif rule_result["prediction"] == "suspicious":
            if ml_result["prediction"] == "spam":
                final_prediction = "phishing"
                confidence = (rule_result["confidence"] + ml_result["confidence"]) / 2
                source = "consensus"
            else:
                final_prediction = "suspicious"
                confidence = rule_result["confidence"]
                source = "rule_engine"
        
        elif ml_result["prediction"] == "spam":
            final_prediction = "phishing"
            confidence = ml_result["confidence"]
            source = "ml_model"
        
        else:
            final_prediction = "legitimate"
            confidence = ml_result["confidence"]
            source = "ml_model"
        
        return {
            "prediction": final_prediction,
            "confidence": round(confidence, 4),
            "source": source,
            "ml_prediction": ml_result.get("prediction"),
            "ml_confidence": ml_result.get("confidence"),
            "rule_score": rule_result.get("rule_score", 0),
            "rule_signals": rule_result.get("signals", []),
            "vt_result": vt_result
        }


_detector = None


def get_sms_detector() -> SMSDetector:
    """Get singleton SMS detector."""
    global _detector
    if _detector is None:
        _detector = SMSDetector()
    return _detector


def detect_sms(message: str, use_virustotal: bool = True) -> Dict:
    """Main function to detect SMS phishing."""
    detector = get_sms_detector()
    return detector.predict(message, use_virustotal=use_virustotal)