from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import RandomForestClassifier

app = FastAPI(title="AI Phishing Detector API")

# Train model directly here
np.random.seed(42)
n = 1000
df = pd.DataFrame({
    'length':    np.concatenate([np.random.randint(5, 20, n//2), np.random.randint(20, 60, n//2)]),
    'has_https': np.concatenate([np.ones(n//2), np.zeros(n//2)]),
    'has_ip':    np.concatenate([np.zeros(n//2), np.random.randint(0, 2, n//2)]),
    'num_dots':  np.concatenate([np.random.randint(1, 3, n//2), np.random.randint(3, 8, n//2)]),
    'num_special': np.concatenate([np.random.randint(0, 2, n//2), np.random.randint(2, 8, n//2)]),
    'is_phishing': [0]*(n//2) + [1]*(n//2)
})

X = df[['length', 'has_https', 'has_ip', 'num_dots', 'num_special']]
y = df['is_phishing']
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

class URLRequest(BaseModel):
    url: str

def extract_features(url):
    return {
        'length':      len(url),
        'has_https':   1 if url.startswith('https') else 0,
        'has_ip':      1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        'num_dots':    url.count('.'),
        'num_special': len(re.findall(r'[@\-_=?&%]', url))
    }

@app.get("/")
def home():
    return {"message": "AI Phishing Detector is running! ✅"}

@app.post("/check")
def check_url(request: URLRequest):
    features = extract_features(request.url)
    df_input = pd.DataFrame([features])
    result = model.predict(df_input)[0]
    confidence = model.predict_proba(df_input)[0][result] * 100
    return {
        "url": request.url,
        "result": "PHISHING" if result == 1 else "SAFE",
        "confidence": f"{confidence:.1f}%",
        "is_phishing": bool(result)
    }