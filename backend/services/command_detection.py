"""
Command Detection Service
Combines ML model and Rule Engine for malicious command detection
"""

import os
import sys
import joblib
import re
from typing import Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.services.command_rules import check_command as rule_check

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "training", "models", "command")


class CommandDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.loaded = False
    
    def load(self):
        if self.loaded:
            return
        
        model_path = os.path.join(MODEL_DIR, "command_model.pkl")
        vectorizer_path = os.path.join(MODEL_DIR, "command_vectorizer.pkl")
        
        if not os.path.exists(model_path):
            print(f"[CommandDetector] Model not found: {model_path}")
            return
        
        print(f"[CommandDetector] Loading model from: {model_path}")
        self.model = joblib.load(model_path)
        
        print(f"[CommandDetector] Loading vectorizer from: {vectorizer_path}")
        self.vectorizer = joblib.load(vectorizer_path)
        
        self.loaded = True
        print(f"[CommandDetector] Loaded successfully")
    
    def predict(self, command: str) -> Dict:
        """Predict if command is malicious."""
        if not self.loaded:
            self.load()
        
        if not command or not command.strip():
            return {"error": "Empty command"}
        
        command = command.strip()
        
        rule_result = rule_check(command)
        
        ml_result = self._ml_predict(command)
        
        final = self._combine_results(ml_result, rule_result)
        
        final["command_preview"] = command[:100] + "..." if len(command) > 100 else command
        
        return final
    
    def _ml_predict(self, command: str) -> Dict:
        """Get ML model prediction."""
        if not self.model or not self.vectorizer:
            return {"prediction": "legitimate", "confidence": 0.5, "source": "ml_model"}
        
        command_clean = command.lower()
        command_tfidf = self.vectorizer.transform([command_clean])
        
        prediction = self.model.predict(command_tfidf)[0]
        probabilities = self.model.predict_proba(command_tfidf)[0]
        
        confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
        label = "malicious" if prediction == 1 else "legitimate"
        
        return {
            "prediction": label,
            "confidence": round(confidence, 4),
            "source": "ml_model"
        }
    
    def _combine_results(self, ml_result: Dict, rule_result: Dict) -> Dict:
        """Combine ML and Rule results."""
        
        if rule_result["rule_score"] >= 8:
            final_prediction = "malicious"
            confidence = rule_result["confidence"]
            source = "rule_engine"
        
        elif rule_result["rule_score"] >= 4:
            if ml_result["prediction"] == "malicious" and ml_result["confidence"] > 0.75:
                final_prediction = "malicious"
                confidence = (rule_result["confidence"] + ml_result["confidence"]) / 2
                source = "consensus"
            else:
                final_prediction = "suspicious"
                confidence = rule_result["confidence"]
                source = "rule_engine"
        
        elif ml_result["prediction"] == "malicious" and ml_result["confidence"] > 0.8:
            final_prediction = "malicious"
            confidence = ml_result["confidence"]
            source = "ml_model"
        
        else:
            final_prediction = "legitimate"
            confidence = 0.7 if ml_result["prediction"] == "legitimate" else 0.5
            source = "ml_model"
        
        return {
            "prediction": final_prediction,
            "confidence": round(confidence, 4),
            "source": source,
            "ml_prediction": ml_result.get("prediction"),
            "ml_confidence": ml_result.get("confidence"),
            "rule_score": rule_result.get("rule_score", 0),
            "rule_signals": rule_result.get("signals", [])
        }


_detector = None


def get_command_detector() -> CommandDetector:
    """Get singleton command detector."""
    global _detector
    if _detector is None:
        _detector = CommandDetector()
    return _detector


def detect_command(command: str) -> Dict:
    """Main function to detect malicious command."""
    detector = get_command_detector()
    return detector.predict(command)