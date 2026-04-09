"""
URL Feature Extractor - URL-Only Features
Extracts 54 features that can be computed from URL structure alone.
Matches the features used in phishing_model_rf_v2.pkl
"""

import re
from urllib.parse import urlparse
from typing import Dict, List


# Features used in the v2 model (URL-only, no external data required)
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

SUSPICIOUS_TLDS = ["xyz", "top", "club", "online", "site", "buzz", "tk", "ml", "ga", "cf", "gq"]
SUSPICIOUS_WORDS = ["login", "verify", "bank", "secure", "update", "confirm", "account", "password", "signin", "alert"]
SHORTENING_SERVICES = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]


def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extract 54 URL-only features from a URL string.
    No external API calls required.
    """
    parsed = urlparse(url)
    features = {}
    
    # URL length features
    features["length_url"] = len(url)
    features["length_hostname"] = len(parsed.netloc)
    
    # IP address detection
    features["ip"] = 1 if _is_ip_address(parsed.netloc) else 0
    
    # Character counts
    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_or"] = url.count("|")
    features["nb_eq"] = url.count("=")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_percent"] = url.count("%")
    features["nb_slash"] = url.count("/")
    features["nb_star"] = url.count("*")
    features["nb_colon"] = url.count(":")
    features["nb_comma"] = url.count(",")
    features["nb_semicolumn"] = url.count(";")
    features["nb_dollar"] = url.count("$")
    features["nb_space"] = url.count(" ")
    
    # Pattern features
    features["nb_www"] = 1 if parsed.netloc.startswith("www.") else 0
    features["nb_com"] = 1 if ".com" in url.lower() else 0
    features["nb_dslash"] = 1 if "//" in url[8:] else 0
    features["http_in_path"] = 1 if "/http" in url.lower() else 0
    features["https_token"] = 1 if url.lower().startswith("https") else 0
    
    # Ratio features
    digits_url = sum(c.isdigit() for c in url)
    features["ratio_digits_url"] = digits_url / len(url) if len(url) > 0 else 0
    
    hostname_digits = sum(c.isdigit() for c in parsed.netloc)
    features["ratio_digits_host"] = hostname_digits / len(parsed.netloc) if len(parsed.netloc) > 0 else 0
    
    # Encoding features
    features["punycode"] = 1 if "xn--" in url.lower() else 0
    
    # Port detection
    features["port"] = 1 if ":" in parsed.netloc and _has_port(parsed.netloc) else 0
    
    # TLD features
    features["tld_in_path"] = 1 if _tld_in_path(url) else 0
    features["tld_in_subdomain"] = 1 if _tld_in_subdomain(parsed.netloc) else 0
    
    # Subdomain features
    features["abnormal_subdomain"] = 1 if _has_abnormal_subdomain(parsed.netloc) else 0
    features["nb_subdomains"] = _count_subdomains(parsed.netloc)
    
    # Suspicious patterns
    features["prefix_suffix"] = 1 if _has_prefix_suffix(url) else 0
    features["random_domain"] = 1 if _is_random_domain(parsed.netloc) else 0
    features["shortening_service"] = 1 if _is_shortening_service(url) else 0
    features["path_extension"] = 1 if _has_path_extension(url) else 0
    features["nb_redirection"] = _count_redirections(url)
    
    # Word features
    words = re.split(r"[/&?=_.-]", url.lower())
    words = [w for w in words if w]
    
    features["length_words_raw"] = len(words)
    features["char_repeat"] = _count_char_repeats(url)
    
    if words:
        features["shortest_words_raw"] = min(len(w) for w in words)
        features["longest_words_raw"] = max(len(w) for w in words)
        features["avg_words_raw"] = sum(len(w) for w in words) / len(words)
    else:
        features["shortest_words_raw"] = 0
        features["longest_words_raw"] = 0
        features["avg_words_raw"] = 0
    
    # Hostname word features
    hostname_words = re.split(r"[/&?=_.-]", parsed.netloc.lower())
    hostname_words = [w for w in hostname_words if w]
    
    if hostname_words:
        features["shortest_word_host"] = min(len(w) for w in hostname_words)
        features["longest_word_host"] = max(len(w) for w in hostname_words)
        features["avg_word_host"] = sum(len(w) for w in hostname_words) / len(hostname_words)
    else:
        features["shortest_word_host"] = 0
        features["longest_word_host"] = 0
        features["avg_word_host"] = 0
    
    # Path word features
    path = parsed.path
    path_words = re.split(r"[/&?=_.-]", path.lower())
    path_words = [w for w in path_words if w]
    
    if path_words:
        features["shortest_word_path"] = min(len(w) for w in path_words)
        features["longest_word_path"] = max(len(w) for w in path_words)
        features["avg_word_path"] = sum(len(w) for w in path_words) / len(path_words)
    else:
        features["shortest_word_path"] = 0
        features["longest_word_path"] = 0
        features["avg_word_path"] = 0
    
    # Phishing indicators
    features["phish_hints"] = _count_phish_hints(url)
    
    # TLD analysis
    tld = _get_tld(url)
    features["suspecious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # Form indicators
    features["login_form"] = 1 if _has_login_form(url) else 0
    features["submit_email"] = 1 if "submit" in url.lower() or "email" in url.lower() else 0
    
    # JavaScript indicators
    features["onmouseover"] = 1 if "onmouseover" in url.lower() else 0
    
    return features


def extract_features_array(url: str, feature_names: List[str]) -> List[float]:
    """Extract features as ordered array matching feature_names."""
    features = extract_url_features(url)
    return [features.get(name, 0.0) for name in feature_names]


# Helper functions
def _is_ip_address(hostname: str) -> bool:
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    host_part = hostname.split(":")[0]
    return bool(re.match(ip_pattern, host_part))


def _has_port(netloc: str) -> bool:
    if ":" in netloc:
        parts = netloc.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return True
    return False


def _tld_in_path(url: str) -> bool:
    common_tlds = [".com", ".org", ".net", ".edu", ".gov", ".io", ".co"]
    url_lower = url.lower()
    for tld in common_tlds:
        if url_lower.count(tld) > 1:
            return True
    return False


def _tld_in_subdomain(netloc: str) -> bool:
    common_tlds = [".com", ".org", ".net"]
    subdomain = netloc.replace("www.", "")
    parts = subdomain.split(".")
    for part in parts[:-1]:
        if any(tld in part for tld in common_tlds):
            return True
    return False


def _has_abnormal_subdomain(netloc: str) -> bool:
    subdomain = netloc.replace("www.", "")
    parts = subdomain.split(".")
    return len(parts) > 3


def _count_subdomains(netloc: str) -> int:
    subdomain = netloc.replace("www.", "")
    parts = subdomain.split(".")
    return max(0, len(parts) - 2)


def _has_prefix_suffix(url: str) -> bool:
    if "-" in url:
        parts = url.split("//")
        if len(parts) > 1 and "-" in parts[1].split("/")[0]:
            return True
    return False


def _is_random_domain(netloc: str) -> bool:
    domain = netloc.replace("www.", "").split(".")[0]
    if len(domain) > 20:
        consonant_ratio = sum(1 for c in domain.lower() if c in "bcdfghjklmnpqrstvwxyz") / len(domain)
        if consonant_ratio > 0.8:
            return True
    return False


def _is_shortening_service(url: str) -> bool:
    url_lower = url.lower()
    for service in SHORTENING_SERVICES:
        if service in url_lower:
            return True
    return False


def _has_path_extension(url: str) -> bool:
    suspicious_extensions = [".exe", ".php", ".asp", ".jsp", ".cgi", ".pl", ".py"]
    url_lower = url.lower()
    for ext in suspicious_extensions:
        if ext in url_lower:
            return True
    return False


def _count_redirections(url: str) -> int:
    return url.lower().count("redirect") + url.lower().count("url=") + url.lower().count("goto")


def _count_phish_hints(url: str) -> int:
    url_lower = url.lower()
    count = 0
    for word in SUSPICIOUS_WORDS:
        count += url_lower.count(word)
    return count


def _get_tld(url: str) -> str:
    url_lower = url.lower()
    tlds = ["xyz", "top", "club", "online", "site", "buzz", "tk", "ml", "ga", "cf", "gq", 
            "com", "org", "net", "edu", "gov", "io", "co", "info", "biz"]
    for tld in tlds:
        if url_lower.endswith("." + tld) or "." + tld + "/" in url_lower:
            return tld
    parts = url_lower.split(".")
    if len(parts) > 1:
        return parts[-1].split("/")[0]
    return ""


def _has_login_form(url: str) -> bool:
    login_indicators = ["login", "signin", "sign-in", "auth", "verify", "account"]
    url_lower = url.lower()
    return any(indicator in url_lower for indicator in login_indicators)


def _count_char_repeats(text: str) -> int:
    count = 0
    prev_char = ""
    for char in text:
        if char == prev_char:
            count += 1
        prev_char = char
    return count


# Alias for backward compatibility
def extract_url_features_old(url: str) -> Dict[str, float]:
    """Legacy function - redirects to new implementation."""
    return extract_url_features(url)


if __name__ == "__main__":
    print("URL Feature Extractor - v2 (URL-Only)")
    print(f"Features count: {len(URL_ONLY_FEATURES)}")
    print()
    
    test_urls = [
        "https://www.google.com/",
        "https://www.facebook.com/login/",
        "http://malicious-site.com/verify.php",
        "http://secure-bank-login.com.evil.com/update",
    ]
    
    for url in test_urls:
        features = extract_url_features(url)
        phish_hints = features.get("phish_hints", 0)
        print(f"URL: {url}")
        print(f"  Length: {features['length_url']}, Phish hints: {phish_hints}")
        print()
