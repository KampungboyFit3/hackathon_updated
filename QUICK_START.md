# Phishing Detection System - Quick Start Guide

> This guide is for beginners. Every step is explained in detail.

---

## Table of Contents

1. [What Do I Need First?](#1-what-do-i-need-first)
2. [Starting the API Server](#2-starting-the-api-server)
3. [Testing the API](#3-testing-the-api)
4. [Common Tasks](#4-common-tasks)
5. [Troubleshooting](#5-troubleshooting)

---

## 1. What Do I Need First?

Before doing anything, you need:

1. **A terminal/command prompt open** - This is where you type commands
2. **The project folder** - Located at `C:\Users\Administrator\Documents\HACKATHON\phishing-detection-system`
3. **Python installed** - The project already has a virtual environment set up

That's it! Let's go to the next step.

---

## 2. Starting the API Server

The API is what lets you use the phishing detection system. Here's how to start it:

### Step 2.1: Open a NEW Terminal

1. Click the **Start** button on your computer
2. Type `powershell` in the search box
3. Click **Windows PowerShell** to open it

You should see a window that looks like this:

```
PS C:\Users\Administrator>
```

### Step 2.2: Navigate to the Project Folder

Copy and paste this command into PowerShell, then press Enter:

```powershell
cd C:\Users\Administrator\Documents\HACKATHON\phishing-detection-system
```

You should now see:

```
PS C:\Users\Administrator\Documents\HACKATHON\phishing-detection-system>
```

### Step 2.3: Activate the Virtual Environment

Copy and paste this command, then press Enter:

```powershell
.\venv\Scripts\Activate.ps1
```

You should see `(venv)` appear at the beginning:

```
(venv) PS C:\Users\Administrator\Documents\HACKATHON\phishing-detection-system>
```

### Step 2.4: Start the Server

Copy and paste this command, then press Enter:

```powershell
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

You should see messages like these:

```
INFO:     Started server process [1234]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

**IMPORTANT: Keep this terminal window open!** The server is now running.

---

## 3. Testing the API

Now that the server is running, you can test it. You need to open a **SECOND** terminal window for these commands.

### Step 3.1: Open a SECOND Terminal

Follow the same steps from Step 2.1 above to open another PowerShell window.

### Step 3.2: Test Health Check

This tells you if the API is working. Copy and paste this:

```powershell
Invoke-RestMethod -Uri http://localhost:8000/health
```

You should see a response like this:

```
status                   model_loaded virustotal
-----                   -----------  ---------
healthy                     True       mock
```

Great! The API is working!

### Step 3.3: Predict a URL

This checks if a URL is phishing or legitimate. Copy and paste this:

```powershell
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="https://www.google.com/"} | ConvertTo-Json) -ContentType "application/json"
```

You should see a response like this:

```
prediction      : legitimate
confidence     : 0.7743
source          : ml_model
model_version  : v3
vt_detected_by   :
vt_confidence   :
```

Try with a suspicious URL:

```powershell
Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="http://secure-paypal-login.suspicious.com/"} | ConvertTo-Json) -ContentType "application/json"
```

### Step 3.4: List Logs

This shows all the prediction logs. Copy and paste this:

```powershell
Invoke-RestMethod -Uri http://localhost:8000/logs
```

### Step 3.5: Retrain the Model

This retrains the model with new data. Copy and paste this:

```powershell
Invoke-RestMethod -Uri http://localhost:8000/retrain -Method POST
```

You should see a response like this:

```
status       : success
version     : v3
new_samples : 10
total_samples: 11439
message     : Retraining completed successfully
```

---

## 4. Common Tasks

Here are the most common things you'll want to do:

### Task A: Check if a website is phishing

```
1. Start the server (Step 2)
2. Open a new terminal
3. Run this command (replace the URL):

Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="THE_URL_HERE"} | ConvertTo-Json) -ContentType "application/json"

4. Look at the "prediction" value:
   - "phishing" = bad, malicious website
   - "legitimate" = OK, safe website
```

### Task B: Retrain the model with new data

```
1. Make some predictions first (the system needs new data)
2. Start the server if not running
3. Run this command:

Invoke-RestMethod -Uri http://localhost:8000/retrain -Method POST
```

### Task C: View prediction logs

```
1. Start the server if not running
2. Run this command:

Invoke-RestMethod -Uri http://localhost:8000/logs
```

### Task D: Stop the server

```
1. Go to the terminal where the server is running
2. Press CTRL+C on your keyboard
```

---

## 5. Troubleshooting

### Problem 1: "Parameter '-X' not found" or "Parameter '-d' not found"

**This means you're using Linux/Mac commands in PowerShell.**

Use PowerShell commands instead:

| Wrong (Linux) | Correct (PowerShell) |
|--------------|---------------------|
| `curl -X POST url` | `Invoke-RestMethod -Uri url -Method POST` |

---

### Problem 2: "Could not import module 'app'"

**This means the module path is wrong.**

Make sure you're in the project folder (with the `backend` folder inside) and use:

```powershell
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Not just `python -m uvicorn app:app ...`

---

### Problem 3: "The remote server returned an error: (403) Forbidden"

**This might mean the server isn't running or there's a firewall issue.**

1. Make sure you have a terminal running the server (Step 2)
2. Try stopping and restarting the server

---

### Problem 4: "Invoke-WebRequest : The remote name could not be resolved"

**This means the server isn't running.**

1. Make sure you started the server in a separate terminal (Step 2)
2. Check that the server terminal shows "Uvicorn running on http://0.0.0.0:8000"

---

### Problem 5: The command is hanging/not responding

**Press CTRL+C to cancel, then try again.**

If it keeps happening, the server might have crashed. Check the server terminal window for error messages.

---

## Quick Command Reference

Copy and paste these commands:

| What you want to do | Command |
|---------------------|---------|
| Start the server | `python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000` |
| Health check | `Invoke-RestMethod -Uri http://localhost:8000/health` |
| Predict URL | `Invoke-RestMethod -Uri http://localhost:8000/predict -Method POST -Body (@{input="URL_HERE"} \| ConvertTo-Json) -ContentType "application/json"` |
| Retrain model | `Invoke-RestMethod -Uri http://localhost:8000/retrain -Method POST` |
| List logs | `Invoke-RestMethod -Uri http://localhost:8000/logs` |

---

## Need More Help?

- Check `PROJECT_DOCUMENTATION.md` for detailed documentation
- Check `README.md` for general information

---

**End of Quick Start Guide**