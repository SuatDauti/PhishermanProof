import joblib
import pandas as pd
from urllib.parse import urlparse
import re

# Load the trained model, scaler, and expected features
xgb_model = joblib.load('Data/xgboost_model.pkl')
scaler = joblib.load('Data/scaler.pkl')
expected_features = joblib.load('Data/features.pkl')

def extract_features(url):
    """Basic example feature extraction from a URL."""
    features = {
        "has_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", url) else 0,
        "has_https": 1 if url.startswith("https") else 0,
        "has_port": 1 if ":" in urlparse(url).netloc else 0,
        "has_at": 1 if "@" in url else 0,
        "url_length": len(url),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "has_admin": 1 if "admin" in url.lower() else 0,
        "has_login": 1 if "login" in url.lower() else 0,
        "has_secure": 1 if "secure" in url.lower() else 0,
        "has_account": 1 if "account" in url.lower() else 0,
        "has_update": 1 if "update" in url.lower() else 0,
        "has_verify": 1 if "verify" in url.lower() else 0,
        "has_bank": 1 if "bank" in url.lower() else 0,
        "has_free": 1 if "free" in url.lower() else 0,
        "has_pay": 1 if "pay" in url.lower() else 0,
        "has_click": 1 if "click" in url.lower() else 0
    }
    return features

print("\n🔍 Phishing URL Detector - Type 'exit' to quit")

while True:
    url = input("Enter a URL: ").strip()
    if url.lower() == "exit":
        break

    try:
        # Extract features
        features_dict = extract_features(url)
        df = pd.DataFrame([features_dict])

        # Reindex to match training features
        df = df.reindex(columns=expected_features, fill_value=0)

        # Scale
        df_scaled = scaler.transform(df)

        # Predict
        prediction = xgb_model.predict(df_scaled)[0]

        print("⚠️  Phishing Detected!" if prediction == 1 else "✅ Legitimate Website.")
    except Exception as e:
        print(f"Error: {e}")
