from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import numpy as np
import joblib
import sys
import os
from datetime import datetime
import requests
import time
VIRUSTOTAL_API_KEY = "f9c2f725adab651cfe7b497f8e2f073c03eb45dcaae0b006c93e6c3e546b104d"


def check_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if response.status_code != 200:
            return None
        scan_id = response.json()["data"]["id"]
        time.sleep(3)
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers,
            timeout=10
        )
        if result.status_code != 200:
            return None
        stats = result.json()["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless
        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "is_malicious": malicious > 0 or suspicious > 2
        }
    except Exception:
        return None
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features, FEATURE_NAMES

app = FastAPI(
    title="AI Phishing Detector API",
    description="Real-time phishing detection using ML",
    version="2.0"
)

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load trained model
print("Loading model...")
model = joblib.load("phishing_model_v2.pkl")
print("Model loaded!")

# Store scan history in memory
scan_history = []

class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    subject: str
    body: str
    sender: str = ""

@app.get("/")
def home():
    return {
        "message": "AI Phishing Detector v2.0 is running!",
        "endpoints": ["/check", "/check-email", "/history", "/stats"]
    }

@app.post("/check")
def check_url(request: URLRequest):
    try:
        url = request.url.strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL is empty")
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.replace('www.', '')
        is_trusted = any(domain == td or domain.endswith('.' + td) 
                        for td in TRUSTED_DOMAINS)
        if is_trusted:
            return {
                "url": url,
                "result": "SAFE",
                "confidence": "99.0%",
                "risk_level": "LOW",
                "is_phishing": False,
                "reasons": ["Verified trusted domain"],
                "features_analyzed": 30,
                "virustotal": None,
                "scanned_at": datetime.now().isoformat()
            }

        # Extract 30+ features
        features = extract_features(url)
        df_input = pd.DataFrame([features])[FEATURE_NAMES]

        # Predict
        result = model.predict(df_input)[0]
        proba = model.predict_proba(df_input)[0]
        confidence = proba[result] * 100

        # VirusTotal check
        vt_result = check_virustotal(url)
        if vt_result and vt_result["is_malicious"]:
            result = 1

        # Risk level
        if confidence >= 90:
            risk = "HIGH" if result == 1 else "LOW"
        elif confidence >= 70:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # Reasons
        reasons = []
        if features['has_ip']:
            reasons.append("Contains IP address instead of domain")
        if features['has_suspicious_tld']:
            reasons.append("Suspicious domain extension")
        if features['num_suspicious_words'] > 0:
            reasons.append(f"Contains {features['num_suspicious_words']} suspicious keywords")
        if not features['has_https']:
            reasons.append("No HTTPS encryption")
        if features['is_shortened']:
            reasons.append("URL shortener detected")
        if features['num_subdomains'] > 2:
            reasons.append("Too many subdomains")
        if features['has_encoded_chars']:
            reasons.append("Encoded characters detected")
        if vt_result and vt_result["malicious"] > 0:
            reasons.append(f"Flagged by {vt_result['malicious']} security engines")

        response = {
            "url": url,
            "result": "PHISHING" if result == 1 else "SAFE",
            "confidence": f"{confidence:.1f}%",
            "risk_level": risk,
            "is_phishing": bool(result),
            "reasons": reasons if result == 1 else ["No threats detected"],
            "features_analyzed": len(FEATURE_NAMES),
            "virustotal": vt_result,
            "scanned_at": datetime.now().isoformat()
        }

        scan_history.append(response)
        if len(scan_history) > 100:
            scan_history.pop(0)

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/check-email")
def check_email(request: EmailRequest):
    try:
        # Suspicious email keywords
        phishing_keywords = [
            'urgent', 'verify', 'suspended', 'click here',
            'confirm your', 'update your', 'login to',
            'account locked', 'winner', 'prize', 'free',
            'limited time', 'act now', 'immediate action',
            'password expired', 'unusual activity', 'security alert'
        ]

        text = (request.subject + " " + request.body).lower()
        found_keywords = [k for k in phishing_keywords if k in text]

        # Check for URLs in email body
        import re
        urls_in_body = re.findall(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', 
            request.body
        )

        # Analyze each URL found
        url_results = []
        for url in urls_in_body[:5]:
            features = extract_features(url)
            df_input = pd.DataFrame([features])[FEATURE_NAMES]
            result = model.predict(df_input)[0]
            url_results.append({
                "url": url,
                "is_phishing": bool(result)
            })

        phishing_url_count = sum(1 for r in url_results if r['is_phishing'])

        # Calculate email risk score
        risk_score = 0
        risk_score += len(found_keywords) * 10
        risk_score += phishing_url_count * 30
        if request.sender and not request.sender.endswith(
            ('.com', '.org', '.net', '.edu', '.gov')
        ):
            risk_score += 20

        is_phishing = risk_score >= 30

        return {
            "result": "PHISHING" if is_phishing else "SAFE",
            "risk_score": min(risk_score, 100),
            "is_phishing": is_phishing,
            "suspicious_keywords": found_keywords,
            "urls_found": len(urls_in_body),
            "phishing_urls": phishing_url_count,
            "url_details": url_results,
            "scanned_at": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
def get_history():
    return {
        "total_scans": len(scan_history),
        "history": scan_history[-20:]
    }

@app.get("/stats")
def get_stats():
    if not scan_history:
        return {"message": "No scans yet"}

    total = len(scan_history)
    phishing = sum(1 for s in scan_history if s['is_phishing'])
    safe = total - phishing

    return {
        "total_scans": total,
        "phishing_detected": phishing,
        "safe_urls": safe,
        "phishing_percentage": f"{(phishing/total*100):.1f}%",
        "last_scan": scan_history[-1]['scanned_at'] if scan_history else None
    }