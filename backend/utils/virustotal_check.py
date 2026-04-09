"""
VirusTotal API Integration
Supports both mock mode (no API key) and real API mode.
Results are cached to avoid rate limits.
"""

import os
import hashlib
import time
import json
from typing import Dict, Optional
from datetime import datetime, timedelta
import requests

try:
    import joblib
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False


class VirusTotalChecker:
    def __init__(self, api_key: Optional[str] = None, use_mock: bool = True):
        self.api_key = api_key
        self.use_mock = use_mock or api_key is None
        self.base_url = "https://www.virustotal.com/api/v3"
        self.cache_dir = self._get_cache_dir()
        self.rate_limit_delay = 1.5
        self.last_request_time = 0
        
        if self.use_mock:
            print("[VirusTotal] Running in MOCK mode (no API key)")
        else:
            print(f"[VirusTotal] Running with API key: {api_key[:8]}...")
    
    def _get_cache_dir(self) -> str:
        cache_dir = os.path.join(os.path.dirname(__file__), "..", "..", "cache")
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir
    
    def _get_cache_path(self, url: str) -> str:
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"vt_{url_hash}.json")
    
    def _get_from_cache(self, url: str) -> Optional[Dict]:
        if not CACHE_AVAILABLE:
            return None
        
        cache_path = self._get_cache_path(url)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r") as f:
                    cached = json.load(f)
                
                cached_time = datetime.fromisoformat(cached["cached_at"])
                if datetime.now() - cached_time < timedelta(hours=24):
                    return cached["result"]
            except:
                pass
        return None
    
    def _save_to_cache(self, url: str, result: Dict):
        if not CACHE_AVAILABLE:
            return
        
        cache_path = self._get_cache_path(url)
        try:
            with open(cache_path, "w") as f:
                json.dump({
                    "url": url,
                    "result": result,
                    "cached_at": datetime.now().isoformat()
                }, f)
        except:
            pass
    
    def _rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def check_url(self, url: str) -> Dict:
        cached_result = self._get_from_cache(url)
        if cached_result:
            print(f"[VirusTotal] Cache hit for: {url[:50]}...")
            return cached_result
        
        if self.use_mock:
            result = self._mock_check(url)
        else:
            result = self._real_check(url)
        
        self._save_to_cache(url, result)
        return result
    
    def _mock_check(self, url: str) -> Dict:
        print(f"[VirusTotal] Mock check for: {url[:50]}...")
        
        url_lower = url.lower()
        
        phishing_keywords = [
            "secure", "login", "verify", "account", "update", "confirm",
            "bank", "paypal", "apple", "microsoft", "google", "amazon",
            "facebook", "netflix", "ebay", "banking"
        ]
        
        suspicious_patterns = [
            "secure-", "login-", "-secure", "-login", "--", ".tk", ".ml",
            ".ga", ".cf", ".gq", "bit.ly", "tinyurl", "goo.gl"
        ]
        
        threat_level = 0
        detected_by = []
        
        for keyword in phishing_keywords:
            if keyword in url_lower:
                threat_level += 1
        
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                threat_level += 2
        
        if url.count("-") > 3:
            threat_level += 2
        
        if "xn--" in url_lower:
            threat_level += 3
        
        malicious_indicators = []
        if threat_level >= 6:
            malicious_indicators = ["MockEngine1", "MockEngine2", "MockEngine3"]
        elif threat_level >= 3:
            malicious_indicators = ["MockEngine1"]
        
        is_malicious = len(malicious_indicators) > 0
        confidence = min(100, threat_level * 10)
        
        return {
            "malicious": is_malicious,
            "suspicious": threat_level >= 3,
            "harmless": not is_malicious and threat_level < 3,
            "undetected": not is_malicious,
            "confidence": confidence,
            "detected_by": malicious_indicators,
            "total_engines": 70,
            "source": "virustotal_mock"
        }
    
    def _real_check(self, url: str) -> Dict:
        self._rate_limit()
        
        url_id = hashlib.md5(url.encode()).hexdigest()
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis = attributes.get("last_analysis_results", {})
                
                malicious = sum(1 for r in last_analysis.values() if r.get("category") == "malicious")
                suspicious = sum(1 for r in last_analysis.values() if r.get("category") == "suspicious")
                total = len(last_analysis)
                
                detected_by = [
                    engine for engine, result in last_analysis.items()
                    if result.get("category") in ["malicious", "suspicious"]
                ]
                
                return {
                    "malicious": malicious > 0,
                    "suspicious": suspicious > 0,
                    "harmless": malicious == 0 and suspicious == 0,
                    "undetected": malicious == 0,
                    "confidence": min(100, (malicious + suspicious) / max(total, 1) * 100),
                    "detected_by": detected_by,
                    "total_engines": total,
                    "source": "virustotal"
                }
            
            elif response.status_code == 404:
                return {
                    "malicious": False,
                    "suspicious": False,
                    "harmless": True,
                    "undetected": True,
                    "confidence": 0,
                    "detected_by": [],
                    "total_engines": 0,
                    "source": "virustotal",
                    "note": "URL not found in VirusTotal database"
                }
            
            elif response.status_code == 429:
                return {
                    "malicious": False,
                    "suspicious": False,
                    "harmless": False,
                    "undetected": False,
                    "confidence": 0,
                    "detected_by": [],
                    "total_engines": 0,
                    "source": "virustotal",
                    "error": "Rate limited"
                }
            
            else:
                return {
                    "malicious": False,
                    "suspicious": False,
                    "harmless": False,
                    "undetected": False,
                    "confidence": 0,
                    "detected_by": [],
                    "total_engines": 0,
                    "source": "virustotal",
                    "error": f"API error: {response.status_code}"
                }
        
        except Exception as e:
            return {
                "malicious": False,
                "suspicious": False,
                "harmless": False,
                "undetected": False,
                "confidence": 0,
                "detected_by": [],
                "total_engines": 0,
                "source": "virustotal",
                "error": str(e)
            }
    
    def get_result(self, url: str) -> Dict:
        result = self.check_url(url)
        return result


_vt_checker = None


def get_vt_checker(api_key: Optional[str] = None, use_mock: Optional[bool] = None) -> VirusTotalChecker:
    global _vt_checker
    
    if _vt_checker is None:
        if use_mock is None:
            use_mock = api_key is None
        
        _vt_checker = VirusTotalChecker(api_key=api_key, use_mock=use_mock)
    
    return _vt_checker


def check_url_virustotal(url: str, api_key: Optional[str] = None) -> Dict:
    checker = get_vt_checker(api_key=api_key)
    return checker.get_result(url)


if __name__ == "__main__":
    print("Testing VirusTotal Checker")
    print("=" * 50)
    
    test_urls = [
        "https://www.google.com/",
        "http://malicious-site.com/verify.php",
        "http://secure-paypal-login.suspicious.com/",
        "https://github.com/security",
    ]
    
    checker = get_vt_checker()
    
    for url in test_urls:
        result = checker.get_result(url)
        status = "MALICIOUS" if result["malicious"] else "CLEAN"
        print(f"\n{status}: {url}")
        print(f"  Confidence: {result['confidence']}%")
        print(f"  Detected by: {result['detected_by']}")
        print(f"  Source: {result['source']}")
