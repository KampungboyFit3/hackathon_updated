"""
Email Rule Engine
Keyword-based detection for email phishing
"""

import re
from typing import Dict, List


URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "limited time", "expire",
    "expires", "hurry", "last chance", "today only", "24 hours",
    "suspended", "unauthorized", "breach", "compromised"
]

MONEY_KEYWORDS = [
    "prize", "winner", "won", "free money", "cash", "dollar", "rm",
    "bank", "account", "payment", "reward", "gift", "voucher",
    "coupon", "credit", "debited", "credited", "refund", "tax",
    "invoice", "bill", "irs", "irs tax", "lottery"
]

ACCOUNT_KEYWORDS = [
    "verify your account", "account suspended", "account blocked", "account locked",
    "password", "otp", "pin", "login", "signin", "update your", "confirm your",
    "identity", "kyc", "security alert", "unusual activity", "breach",
    "suspended", "blocked", "locked"
]

PHISHING_KEYWORDS = [
    "click here", "tap here", "open link", "visit website",
    "call now", "text reply", "share", "forward", "log in",
    "sign in", "update payment", "validate", "re-activate"
]

SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
    "work", "live", "click", "link", "info", "pw"
]

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com"
]

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "netflix", "facebook",
    "instagram", "twitter", "whatsapp", "bank", "chase", "wells fargo",
    "citi", "bank of america", "irs", "social security"
]


def extract_score(email_text: str, sender: str = "", urls: List[str] = None) -> Dict:
    """Calculate rule-based score for email."""
    email_lower = email_text.lower()
    
    score = 0
    signals = []
    
    if urls:
        score += min(len(urls) * 2, 6)
        signals.append(("url_count", len(urls)))
        
        for url in urls:
            url_lower = url.lower()
            
            has_suspicious_tld = any(tld in url_lower for tld in SUSPICIOUS_TLDS)
            if has_suspicious_tld:
                score += 3
                signals.append(("suspicious_tld", 3))
            
            has_shortener = any(s in url_lower for s in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"])
            if has_shortener:
                score += 2
                signals.append(("url_shortener", 2))
            
            has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
            if has_ip:
                score += 3
                signals.append(("ip_url", 3))
    
    urgency_count = sum(1 for word in URGENCY_KEYWORDS if word in email_lower)
    if urgency_count > 0:
        score += min(urgency_count * 1, 4)
        signals.append(("urgency_words", min(urgency_count * 1, 4)))
    
    money_count = sum(1 for word in MONEY_KEYWORDS if word in email_lower)
    if money_count > 0:
        score += min(money_count * 1, 4)
        signals.append(("money_words", min(money_count * 1, 4)))
    
    account_count = sum(1 for word in ACCOUNT_KEYWORDS if word in email_lower)
    if account_count > 0:
        score += min(account_count * 1, 4)
        signals.append(("account_words", min(account_count * 1, 4)))
    
    phishing_count = sum(1 for word in PHISHING_KEYWORDS if word in email_lower)
    if phishing_count > 0:
        score += min(phishing_count * 1, 3)
        signals.append(("phishing_action", min(phishing_count * 1, 3)))
    
    brand_count = sum(1 for word in BRAND_KEYWORDS if word in email_lower)
    if brand_count > 0 and any(word in email_lower for word in ["verify", "account", "login", "suspended"]):
        score += 3
        signals.append(("brand_urgency", 3))
    
    if sender:
        sender_lower = sender.lower()
        
        has_free_email = any(free in sender_lower for free in FREE_EMAIL_DOMAINS)
        if has_free_email and any(brand in sender_lower for brand in BRAND_KEYWORDS):
            score += 3
            signals.append(("free_email_brand", 3))
        
        has_suspicious_sender = any(tld in sender_lower for tld in SUSPICIOUS_TLDS)
        if has_suspicious_sender:
            score += 2
            signals.append(("suspicious_sender_tld", 2))
    
    return {
        "rule_score": score,
        "signals": signals,
        "is_suspicious": score >= 4
    }


def check_email(email_text: str, sender: str = "", urls: List[str] = None) -> Dict:
    """Full rule engine check for email."""
    result = extract_score(email_text, sender, urls)
    
    if result["rule_score"] >= 7:
        prediction = "phishing"
        confidence = min(0.6 + (result["rule_score"] - 7) * 0.08, 0.95)
    elif result["rule_score"] >= 4:
        prediction = "suspicious"
        confidence = min(0.3 + result["rule_score"] * 0.1, 0.7)
    else:
        prediction = "safe"
        confidence = 0.6
    
    return {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "rule_score": result["rule_score"],
        "signals": result["signals"]
    }


def get_threat_level(score: int) -> str:
    """Get threat level description."""
    if score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


if __name__ == "__main__":
    test_emails = [
        {
            "text": "URGENT: Your account has been suspended. Click here to verify your identity immediately.",
            "sender": "security@paypal-alert.com",
            "urls": ["http://bit.ly/fake", "http://suspicious.tk/login"]
        },
        {
            "text": "Meeting scheduled for tomorrow at 3pm. Please confirm your attendance.",
            "sender": "john@gmail.com",
            "urls": []
        }
    ]
    
    print("Email Rule Engine Test")
    print("=" * 50)
    
    for i, email in enumerate(test_emails):
        result = check_email(email["text"], email["sender"], email["urls"])
        print(f"\nTest {i+1}:")
        print(f"  Prediction: {result['prediction']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Rule Score: {result['rule_score']}")
        print(f"  Signals: {result['signals']}")