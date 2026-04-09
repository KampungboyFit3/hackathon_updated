# Quick Start Guide - Phishing Detection System

## One-Command Setup

```bash
cd phishing-detection-system

# Install dependencies
pip install scikit-learn pandas numpy joblib fastapi uvicorn pydantic requests

# Start server
cd backend && python -m uvicorn app:app --reload --port 8000
```

## Common Commands

### Start Server
```bash
cd backend
python -m uvicorn app:app --reload --port 8000
```

### Test APIs
```bash
# Health check
curl http://localhost:8000/health

# Predict URL
curl -X POST http://localhost:8000/predict -H "Content-Type: application/json" -d "{\"input\": \"https://google.com\"}"

# VirusTotal check
curl -X POST http://localhost:8000/virustotal/check -H "Content-Type: application/json" -d "{\"url\": \"http://malicious.com\"}"
```

### Check Logs
```bash
# View recent predictions
cat backend/logs/predictions_*.csv

# Or via API
curl http://localhost:8000/logs
```

## Test URLs

| URL | Expected Result |
|-----|-----------------|
| `https://google.com` | Legitimate |
| `https://microsoft.com` | Legitimate |
| `http://secure-paypal-login.suspicious.com` | Phishing |
| `http://malicious-site.com/verify.php` | Phishing |

## Docker Commands
```bash
# Start
docker-compose up --build -d

# Stop
docker-compose down

# View logs
docker-compose logs -f
```

## File Locations

| File | Path |
|------|------|
| ML Model | `training/models/phishing_model_rf_v2.pkl` |
| Features | `training/models/feature_names_v2.pkl` |
| Logs | `backend/logs/predictions_YYYY-MM-DD.csv` |
| VT Cache | `backend/cache/` |
| Docs | `PROJECT_DOCUMENTATION.md` |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port in use | Change port: `--port 8001` |
| Model not loading | Check `training/models/` exists |
| Logs missing | Wait 2-3 seconds (async) |

## Full Documentation

See `PROJECT_DOCUMENTATION.md` for complete details.
