"""
Enhanced Async Logger with VirusTotal Support
Logs predictions with source, confidence, and VT results
"""

import os
import sys
from datetime import datetime
from queue import Queue
import threading
import csv


def get_default_log_dir():
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(backend_dir, "logs")


class AsyncPredictionLogger:
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = get_default_log_dir()
        self.log_dir = os.path.abspath(log_dir)
        self.queue = Queue()
        self.running = True
        self._ensure_log_dir()
        
        self.writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.writer_thread.start()
    
    def _ensure_log_dir(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def _get_log_filename(self) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"predictions_{date_str}.csv")
    
    def _get_header(self) -> list:
        return [
            "url",
            "type",
            "prediction",
            "confidence",
            "source",
            "model_version",
            "vt_malicious",
            "vt_confidence",
            "vt_detected_by",
            "timestamp"
        ]
    
    def _write_header_if_needed(self, filename: str):
        if not os.path.exists(filename):
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(self._get_header())
    
    def log(self, url: str, prediction: str, confidence: float, source: str, input_type: str = "url", **kwargs):
        entry = {
            "url": url,
            "type": input_type,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "source": source,
            "model_version": kwargs.get("model_version", "v2"),
            "vt_malicious": str(kwargs.get("vt_malicious", "")),
            "vt_confidence": kwargs.get("vt_confidence", ""),
            "vt_detected_by": "|".join(kwargs.get("vt_detected_by", [])),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        self.queue.put(entry)
    
    def log_prediction_result(self, url: str, result: dict):
        self.log(
            url=url,
            prediction=result["prediction"],
            confidence=result["confidence"],
            source=result["source"],
            model_version=result.get("model_version", "v2"),
            vt_malicious=result.get("vt_detected_by") is not None,
            vt_confidence=result.get("vt_confidence", ""),
            vt_detected_by=result.get("vt_detected_by", [])
        )
    
    def _writer_loop(self):
        while self.running:
            try:
                entry = self.queue.get(timeout=1)
                self._write_entry(entry)
                self.queue.task_done()
            except:
                continue
    
    def _write_entry(self, entry: dict):
        filename = self._get_log_filename()
        self._write_header_if_needed(filename)
        
        with open(filename, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                entry["url"],
                entry["type"],
                entry["prediction"],
                entry["confidence"],
                entry["source"],
                entry["model_version"],
                entry["vt_malicious"],
                entry["vt_confidence"],
                entry["vt_detected_by"],
                entry["timestamp"]
            ])
    
    def shutdown(self):
        self.running = False
        self.writer_thread.join(timeout=5)
        while not self.queue.empty():
            entry = self.queue.get()
            self._write_entry(entry)


_global_logger = None


def get_logger(log_dir: str = None) -> AsyncPredictionLogger:
    global _global_logger
    if _global_logger is None:
        _global_logger = AsyncPredictionLogger(log_dir)
    return _global_logger


def log_prediction(url: str, prediction: str, confidence: float, source: str, **kwargs):
    logger = get_logger()
    logger.log(url, prediction, confidence, source, **kwargs)


def log_prediction_result(url: str, result: dict, input_type: str = "url"):
    logger = get_logger()
    logger.log(url, prediction=result["prediction"], confidence=result["confidence"], 
              source=result["source"], input_type=input_type,
              model_version=result.get("model_version", "v2"),
              vt_malicious=result.get("vt_detected_by") is not None,
              vt_confidence=result.get("vt_confidence", ""),
              vt_detected_by=result.get("vt_detected_by", []))


if __name__ == "__main__":
    logger = AsyncPredictionLogger("test_logs")
    
    logger.log("http://example.com", "legitimate", 0.95, "ml_model", model_version="v2")
    logger.log("http://malicious.com", "phishing", 0.87, "virustotal", 
               model_version="v2", vt_malicious=True, vt_detected_by=["Engine1", "Engine2"])
    
    import time
    time.sleep(2)
    
    logger.shutdown()
    
    print("Test logs written successfully")
