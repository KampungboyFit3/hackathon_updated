"""
SMS Rule Engine
Keyword-based detection for SMS phishing
"""

import re
from typing import Dict, List


URGENCY_KEYWORDS = [
    "urgent", "now", "immediately", "act fast", "limited time",
    "expire", "expires", "hurry", "last chance", "today only"
]

MONEY_KEYWORDS = [
    "prize", "winner", "won", "free money", "cash", "rm", "dollar",
    "bank", "account", "payment", "reward", "gift", "voucher",
    "coupon", "credit", "debited", "credited"
]

ACCOUNT_KEYWORDS = [
    "verify", "suspended", "blocked", "locked", "account",
    "password", "otp", "pin", "login", "signin", "update",
    "confirm", "identity", "kyc"
]

PHISHING_KEYWORDS = [
    "click here", "tap here", "open link", "visit website",
    "call now", "text reply", "share", "forward"
]

SHORTENERS = [
    "bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
]


def extract_score(message: str) -> Dict:
    """
    Calculate rule-based score for SMS message.
    
    Returns:
        dict with score breakdown and final rule_score
    """
    message_lower = message.lower()
    
    score = 0
    signals = []
    
    has_url = extract_urls(message)
    if has_url:
        score += 3
        signals.append(("contains_link", 3))
    
    has_shortener = any(s in message_lower for s in SHORTENERS)
    if has_shortener:
        score += 2
        signals.append(("shortened_url", 2))
    
    urgency_count = sum(1 for word in URGENCY_KEYWORDS if word in message_lower)
    if urgency_count > 0:
        score += min(urgency_count * 1, 3)
        signals.append(("urgency_words", min(urgency_count * 1, 3)))
    
    money_count = sum(1 for word in MONEY_KEYWORDS if word in message_lower)
    if money_count > 0:
        score += min(money_count * 1, 3)
        signals.append(("money_words", min(money_count * 1, 3)))
    
    account_count = sum(1 for word in ACCOUNT_KEYWORDS if word in message_lower)
    if account_count > 0:
        score += min(account_count * 1, 3)
        signals.append(("account_words", min(account_count * 1, 3)))
    
    phishing_count = sum(1 for word in PHISHING_KEYWORDS if word in message_lower)
    if phishing_count > 0:
        score += min(phishing_count * 1, 2)
        signals.append(("phishing_action", min(phishing_count * 1, 2)))
    
    has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', message))
    if has_ip:
        score += 3
        signals.append(("ip_address", 3))
    
    has_phone = bool(re.search(r'\d{10,}', message.replace(' ', '')))
    if has_phone:
        score += 1
        signals.append(("phone_number", 1))
    
    return {
        "rule_score": score,
        "signals": signals,
        "is_suspicious": score >= 3
    }


def extract_urls(message: str) -> List[str]:
    """Extract URLs from SMS message."""
    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(url_pattern, message, re.IGNORECASE)
    return urls


def check_message(message: str) -> Dict:
    """
    Full rule engine check for a message.
    
    Returns:
        dict with prediction and confidence
    """
    result = extract_score(message)
    
    if result["rule_score"] >= 5:
        prediction = "phishing"
        confidence = min(0.5 + (result["rule_score"] - 5) * 0.1, 0.95)
    elif result["rule_score"] >= 3:
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
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"


if __name__ == "__main__":
    test_messages = [
        "URGENT! Your bank account has been suspended. Click here to verify: http://bit.ly/fake",
        "Hey, are we still meeting for dinner?",
        "Congratulations! You've won RM5000! Text CLAIM to 12345 to receive your prize!",
    ]
    
    print("SMS Rule Engine Test")
    print("=" * 50)
    
    for msg in test_messages:
        result = check_message(msg)
        print(f"\nMessage: {msg[:50]}...")
        print(f"  Prediction: {result['prediction']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Rule Score: {result['rule_score']}")
        print(f"  Signals: {result['signals']}")