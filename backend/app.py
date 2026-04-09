"""
Phishing Detection API - FastAPI Application
Phase 3: VirusTotal + ML Model Integration
"""

from dotenv import load_dotenv
load_dotenv()  # Load .env file into environment variables

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import Optional
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from backend.services.detection import predict_phishing, get_virustotal_check
from backend.services.sms_detection import detect_sms
from backend.services.email_detection import detect_email
from backend.services.command_detection import detect_command
from backend.utils.logger import log_prediction_result
import backend.config as config

app = FastAPI(
    title="Phishing Detection API",
    description="ML-based phishing detection with VirusTotal integration",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = None


def get_logger():
    global logger
    if logger is None:
        from backend.utils.logger import AsyncPredictionLogger
        logger = AsyncPredictionLogger(config.LOG_DIR)
    return logger


class PredictRequest(BaseModel):
    input: str
    type: Optional[str] = "url"
    use_virustotal: Optional[bool] = True
    
    @validator("input")
    def validate_input(cls, v):
        if not v or len(v) < 5:
            raise ValueError("Input must be at least 5 characters")
        return v
    
    @validator("type")
    def validate_type(cls, v):
        if v not in config.SUPPORTED_TYPES:
            raise ValueError(f"Type must be one of: {config.SUPPORTED_TYPES}")
        return v


class PredictResponse(BaseModel):
    prediction: str
    confidence: float
    source: str
    model_version: Optional[str] = None
    vt_detected_by: Optional[list] = None
    vt_confidence: Optional[float] = None


class VTCheckRequest(BaseModel):
    url: str
    
    @validator("url")
    def validate_url(cls, v):
        if not v or len(v) < 5:
            raise ValueError("URL must be at least 5 characters")
        return v


class VTCheckResponse(BaseModel):
    url: str
    malicious: bool
    suspicious: bool
    confidence: float
    detected_by: list
    total_engines: int
    source: str


@app.get("/")
def root():
    return {
        "message": "Phishing Detection API",
        "version": "1.1.0",
        "features": ["ML Model (Random Forest)", "VirusTotal Integration"],
        "endpoints": {
            "predict": "POST /predict",
            "health": "GET /health",
            "logs": "GET /logs",
            "virustotal": "POST /virustotal/check"
        }
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": True,
        "virustotal": "mock" if config.VT_USE_MOCK else "real"
    }


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    try:
        if request.type == "sms":
            result = detect_sms(
                message=request.input,
                use_virustotal=request.use_virustotal
            )
        elif request.type == "email":
            result = detect_email(
                email_input=request.input,
                use_virustotal=request.use_virustotal
            )
        elif request.type == "command":
            result = detect_command(
                command=request.input
            )
        else:
            result = predict_phishing(
                url=request.input,
                use_virustotal=request.use_virustotal
            )
        
        log_prediction_result(url=request.input, result=result, input_type=request.type)
        
        return PredictResponse(**result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/virustotal/check", response_model=VTCheckResponse)
def virustotal_check(request: VTCheckRequest):
    try:
        result = get_virustotal_check(url=request.url)
        
        return VTCheckResponse(
            url=request.url,
            malicious=result.get("malicious", False),
            suspicious=result.get("suspicious", False),
            confidence=result.get("confidence", 0),
            detected_by=result.get("detected_by", []),
            total_engines=result.get("total_engines", 0),
            source=result.get("source", "unknown")
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs")
def list_logs():
    log_dir = config.LOG_DIR
    if not os.path.exists(log_dir):
        return {"logs": [], "count": 0}
    
    files = [f for f in os.listdir(log_dir) if f.endswith(".csv")]
    files.sort(reverse=True)
    
    return {
        "logs": files,
        "count": len(files),
        "log_dir": log_dir
    }


class RetrainResponse(BaseModel):
    status: str
    version: Optional[str] = None
    new_samples: Optional[int] = None
    total_samples: Optional[int] = None
    metrics: Optional[dict] = None
    v2_comparison: Optional[dict] = None
    message: Optional[str] = None


@app.post("/retrain", response_model=RetrainResponse)
def trigger_retrain():
    """
    Trigger the retraining pipeline.
    Loads high-confidence predictions from logs, merges with dataset, retrains model.
    """
    try:
        import subprocess
        import sys
        
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "scripts", "retrain.py"
        )
        
        if not os.path.exists(script_path):
            raise HTTPException(status_code=500, detail="Retrain script not found")
        
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__))
        )
        
        output = result.stdout
        stderr = result.stderr
        
        if result.returncode != 0:
            return RetrainResponse(
                status="error",
                message=f"Retraining failed: {stderr[:500]}"
            )
        
        if "No new unique samples" in output or "Skipping retraining" in output:
            return RetrainResponse(
                status="skipped",
                message="No new samples to retrain"
            )
        
        import re
        version_match = re.search(r"Version:\s*(\S+)", output)
        samples_match = re.search(r"New samples added:\s*(\d+)", output)
        total_match = re.search(r"Total samples:\s*(\d+)", output)
        recall_match = re.search(r"Recall:\s*([\d.]+)", output)
        v2_recall_match = re.search(r"V2 Recall:\s*([\d.]+)", output)
        
        metrics_dict = {}
        if recall_match:
            metrics_dict = {"recall": float(recall_match.group(1))}
        
        comparison = {}
        if v2_recall_match and recall_match:
            comparison = {
                "v2_recall": float(v2_recall_match.group(1)),
                "v3_recall": float(recall_match.group(1)),
                "improvement": float(recall_match.group(1)) - float(v2_recall_match.group(1))
            }
        
        return RetrainResponse(
            status="success",
            version=version_match.group(1) if version_match else "v3",
            new_samples=int(samples_match.group(1)) if samples_match else None,
            total_samples=int(total_match.group(1)) if total_match else None,
            metrics=metrics_dict,
            v2_comparison=comparison,
            message="Retraining completed successfully"
        )
    
    except Exception as e:
        return RetrainResponse(
            status="error",
            message=str(e)
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=config.API_HOST,
        port=config.API_PORT,
        reload=config.API_RELOAD
    )
