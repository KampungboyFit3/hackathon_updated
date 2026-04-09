"""
Email Phishing Detection Service
Combines ML model, Rule Engine, URL extraction, and VirusTotal
"""

import os
import sys
import re
import joblib
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.services.email_rules import check_email as rule_check
from backend.services.eml_parser import parse_eml_content
from backend.utils.virustotal_check import check_url_virustotal

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "training", "models", "email")


class EmailDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.loaded = False
    
    def load(self):
        if self.loaded:
            return
        
        model_path = os.path.join(MODEL_DIR, "email_model.pkl")
        vectorizer_path = os.path.join(MODEL_DIR, "email_vectorizer.pkl")
        
        if not os.path.exists(model_path):
            print(f"[EmailDetector] Model not found: {model_path}")
            return
        
        print(f"[EmailDetector] Loading model from: {model_path}")
        self.model = joblib.load(model_path)
        
        print(f"[EmailDetector] Loading vectorizer from: {vectorizer_path}")
        self.vectorizer = joblib.load(vectorizer_path)
        
        self.loaded = True
        print(f"[EmailDetector] Loaded successfully")
    
    def predict(self, email_input: str, use_virustotal: bool = True) -> Dict:
        """
        Predict if email is phishing.
        
        Args:
            email_input: Either raw email text or parsed dict with subject, body, sender, urls
            use_virustotal: Whether to check URLs via VirusTotal
        """
        if not self.loaded:
            self.load()
        
        if isinstance(email_input, dict):
            parsed = email_input
        else:
            parsed = parse_eml_content(email_input)
            
            if not parsed.get("text_combined", "").strip():
                parsed["subject"] = "Subject: "
                parsed["body"] = email_input
                parsed["subject_clean"] = ""
                parsed["body_clean"] = email_input.lower()
                parsed["text_combined"] = email_input.lower()
                
                import re
                urls = re.findall(r'https?://\S+', email_input, re.IGNORECASE)
                parsed["urls"] = urls[:20]
        
        email_text = parsed.get("text_combined", "") or (parsed.get("subject_clean", "") + " " + parsed.get("body_clean", ""))
        
        if not email_text.strip():
            return {"error": "Empty email content"}
        
        sender = parsed.get("sender", "")
        urls = parsed.get("urls", [])
        
        rule_result = rule_check(
            parsed.get("body", "") + " " + parsed.get("subject", ""),
            sender,
            urls
        )
        
        ml_result = self._ml_predict(email_text)
        
        vt_result = None
        if use_virustotal and urls:
            vt_result = self._check_urls_virustotal(urls)
        
        header_result = self._check_header(sender, urls)
        
        final = self._combine_results(ml_result, rule_result, vt_result, header_result)
        
        final["parsed"] = {
            "subject": parsed.get("subject", ""),
            "sender": sender,
            "url_count": len(urls),
            "urls": urls[:3]
        }
        
        return final
    
    def _ml_predict(self, text: str) -> Dict:
        """Get ML model prediction."""
        if not self.model or not self.vectorizer:
            return {"prediction": "safe", "confidence": 0.5, "source": "ml_model"}
        
        text_tfidf = self.vectorizer.transform([text])
        
        prediction = self.model.predict(text_tfidf)[0]
        probabilities = self.model.predict_proba(text_tfidf)[0]
        
        confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
        label = "phishing" if prediction == 1 else "legitimate"
        
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
    
    def _check_header(self, sender: str, urls: List[str]) -> Dict:
        """Check email header for suspicious indicators."""
        header_flags = []
        
        if not sender:
            header_flags.append("missing_sender")
        
        sender_lower = sender.lower()
        
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'secure[-\s]?login',
            r'verify[-\s]?account',
            r'update[-\s]?payment'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, sender_lower):
                header_flags.append(f"sender_pattern:{pattern}")
        
        free_email_patterns = [
            r'gmail\.com', r'yahoo\.com', r'hotmail\.com', r'outlook\.com'
        ]
        
        brand_keywords = ['bank', 'paypal', 'amazon', 'apple', 'microsoft', 'irs', 'security']
        
        has_free_email = any(re.search(p, sender_lower) for p in free_email_patterns)
        has_brand = any(brand in sender_lower for brand in brand_keywords)
        
        if has_free_email and has_brand:
            header_flags.append("free_email_brand")
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(tld in sender_lower for tld in suspicious_tlds):
            header_flags.append("suspicious_tld")
        
        return {
            "header_flags": header_flags,
            "is_suspicious": len(header_flags) > 0
        }
    
    def _combine_results(self, ml_result: Dict, rule_result: Dict, vt_result: Optional[Dict], header_result: Dict) -> Dict:
        """Combine ML, Rule, VT, and Header results."""
        
        if vt_result and vt_result.get("malicious"):
            final_prediction = "phishing"
            confidence = vt_result["confidence"] / 100
            source = "virustotal"
        
        elif rule_result["rule_score"] >= 7:
            final_prediction = "phishing"
            confidence = rule_result["confidence"]
            source = "rule_engine"
        
        elif rule_result["rule_score"] >= 4:
            if ml_result["prediction"] == "phishing" and ml_result["confidence"] > 0.8:
                final_prediction = "phishing"
                confidence = (rule_result["confidence"] + ml_result["confidence"]) / 2
                source = "consensus"
            else:
                final_prediction = "suspicious"
                confidence = rule_result["confidence"]
                source = "rule_engine"
        
        elif ml_result["prediction"] == "phishing" and ml_result["confidence"] > 0.85:
            final_prediction = "phishing"
            confidence = ml_result["confidence"]
            source = "ml_model"
        
        else:
            final_prediction = "legitimate"
            confidence = 0.7 + (1 - ml_result["confidence"]) * 0.2 if ml_result["prediction"] == "legitimate" else 0.6
            source = "ml_model"
        
        return {
            "prediction": final_prediction,
            "confidence": round(confidence, 4),
            "source": source,
            "ml_prediction": ml_result.get("prediction"),
            "ml_confidence": ml_result.get("confidence"),
            "rule_score": rule_result.get("rule_score", 0),
            "rule_signals": rule_result.get("signals", []),
            "header_flags": header_result.get("header_flags", []),
            "vt_result": vt_result
        }


_detector = None


def get_email_detector() -> EmailDetector:
    """Get singleton email detector."""
    global _detector
    if _detector is None:
        _detector = EmailDetector()
    return _detector


def detect_email(email_input: str, use_virustotal: bool = True) -> Dict:
    """Main function to detect email phishing."""
    detector = get_email_detector()
    return detector.predict(email_input, use_virustotal=use_virustotal)