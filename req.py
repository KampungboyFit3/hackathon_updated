import requests
# Predict
response = requests.post(
    "http://localhost:8000/predict",
    json={"input": "https://www.signin.bankofamerica-login.com"}
)
print(response.json())