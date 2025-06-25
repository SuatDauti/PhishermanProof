from flask import Flask, render_template, request
import joblib
import pandas as pd
import sys
import os

# Add the 'ml' directory to Python's module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ml')))

# Import the feature extraction function from your module
from singleUrlFeatureExtraction import extract_features

# Initialize the Flask app
app = Flask(__name__)

# Define path to model directory
model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ml', 'model'))

# Load pre-trained model, scaler, and feature names
model = joblib.load(os.path.join(model_dir, 'xgboost_model.pkl'))
scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
features = joblib.load(os.path.join(model_dir, 'features.pkl'))

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        try:
            # Extract features from the input URL
            feature_dict = extract_features(url)
            df = pd.DataFrame([feature_dict])

            # Align columns with training features
            df = df.reindex(columns=features, fill_value=0)

            # Scale and predict
            df_scaled = scaler.transform(df)
            prediction = model.predict(df_scaled)[0]

            # Output result
            result = "⚠️ Phishing Detected!" if prediction == 1 else "✅ Legitimate Website"
        except Exception as e:
            result = f"❌ Error analyzing URL: {e}"
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
