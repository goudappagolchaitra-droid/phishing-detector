from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import pandas as pd
import re

app = FastAPI(title="AI Phishing Detector API")

# Load saved model
from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import pandas as pd
import re

app = FastAPI(title="AI Phishing Detector API")

# Load saved model
with open('phishing_model.pkl', 'rb') as f:
    model = pickle.load(f)

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
    model = pickle.load(f)

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