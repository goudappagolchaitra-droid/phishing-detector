import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features, FEATURE_NAMES

print("Step 1: Loading URLs...")

with open('phishing.txt', 'r') as f:
    phishing_urls = [line.strip() for line in f if line.strip()]

# Manually crafted phishing URLs (obvious ones)
manual_phishing = [
    'http://paypal-login-verify.xyz/account?update=true',
    'http://secure-banking-update.com/verify',
    'http://apple-id-locked.fake.net/unlock',
    'http://amazon-prize-winner.click/claim',
    'http://192.168.1.1/bank/login.php',
    'http://free-iphone-winner.click/prize',
    'http://login-paypal-secure.xyz/verify',
    'http://microsoft-account-verify.xyz',
    'http://signin-amazon-update.com/account',
    'http://ebay-account-suspended.xyz/restore',
    'http://secure-paypal-login.net/update',
    'http://account-verify-google.xyz/login',
    'http://facebook-login-secure.xyz/account',
    'http://netflix-billing-update.com/payment',
    'http://bank-secure-login.xyz/verify',
    'http://urgent-account-update.com/signin',
    'http://password-reset-secure.xyz/update',
    'http://confirm-identity-now.click/verify',
    'http://win-free-gift-card.tk/claim',
    'http://limited-offer-click.ml/free',
    'http://10.0.0.1/router/login',
    'http://172.16.0.1/admin/login.php',
    'http://phishing-site.ga/steal',
    'http://malware-download.cf/install',
    'http://fake-bank-secure.gq/login',
]

safe_urls = [
    'https://google.com', 'https://youtube.com',
    'https://github.com', 'https://stackoverflow.com',
    'https://wikipedia.org', 'https://microsoft.com',
    'https://apple.com', 'https://amazon.com',
    'https://linkedin.com', 'https://twitter.com',
    'https://reddit.com', 'https://netflix.com',
    'https://spotify.com', 'https://dropbox.com',
    'https://slack.com', 'https://zoom.us',
    'https://paypal.com', 'https://ebay.com',
    'https://adobe.com', 'https://salesforce.com',
    'https://npmjs.com', 'https://pypi.org',
    'https://kaggle.com', 'https://medium.com',
    'https://twitch.tv', 'https://discord.com',
    'https://notion.so', 'https://figma.com',
    'https://canva.com', 'https://trello.com',
    'https://gitlab.com', 'https://heroku.com',
    'https://vercel.com', 'https://netlify.com',
    'https://cloudflare.com', 'https://stripe.com',
    'https://shopify.com', 'https://wordpress.com',
    'https://mongodb.com', 'https://docker.com',
    'https://tensorflow.org', 'https://pytorch.org',
    'https://numpy.org', 'https://reactjs.org',
    'https://vuejs.org', 'https://angular.io',
    'https://nodejs.org', 'https://nextjs.org',
    'https://www.google.com', 'https://www.youtube.com',
    'https://www.github.com', 'https://www.amazon.com',
    'https://www.microsoft.com', 'https://www.apple.com',
    'https://www.linkedin.com', 'https://www.twitter.com',
    'https://www.reddit.com', 'https://www.netflix.com',
    'https://www.spotify.com', 'https://www.paypal.com',
    'https://www.ebay.com', 'https://www.adobe.com',
    'https://docs.google.com', 'https://mail.google.com',
    'https://drive.google.com', 'https://maps.google.com',
    'https://developer.apple.com', 'https://support.apple.com',
    'https://docs.microsoft.com', 'https://support.microsoft.com',
    'https://developer.mozilla.org', 'https://docs.python.org',
    'https://docs.github.com', 'https://aws.amazon.com',
    'https://cloud.google.com', 'https://azure.microsoft.com',
    'https://www.bbc.com', 'https://www.cnn.com',
    'https://www.nytimes.com', 'https://www.reuters.com',
    'https://www.bloomberg.com', 'https://www.forbes.com',
    'https://www.techcrunch.com', 'https://www.wired.com',
    'https://www.instagram.com', 'https://www.facebook.com',
    'https://www.whatsapp.com', 'https://www.telegram.org',
    'https://www.coursera.org', 'https://www.udemy.com',
    'https://www.edx.org', 'https://www.khanacademy.org',
    'https://www.freecodecamp.org', 'https://www.leetcode.com',
    'https://www.hackerrank.com', 'https://www.codecademy.com',
    'https://www.w3schools.com', 'https://www.geeksforgeeks.org',
]

print(f"Phishing from file: {len(phishing_urls)}")
print(f"Manual phishing: {len(manual_phishing)}")
print(f"Safe URLs: {len(safe_urls)}")

print("\nStep 2: Extracting features...")
all_data = []

# Real phishing from file (use 900)
for i, url in enumerate(phishing_urls[:900]):
    try:
        f = extract_features(url)
        f['is_phishing'] = 1
        all_data.append(f)
    except:
        pass
    if i % 100 == 0:
        print(f"  File phishing: {i}...")

# Manual phishing (repeated 4x to give more weight)
for url in manual_phishing * 4:
    try:
        f = extract_features(url)
        f['is_phishing'] = 1
        all_data.append(f)
    except:
        pass

# Safe URLs (repeated 5x for balance)
for url in safe_urls * 5:
    try:
        f = extract_features(url)
        f['is_phishing'] = 0
        all_data.append(f)
    except:
        pass

df = pd.DataFrame(all_data).fillna(0)
print(f"\nTotal dataset: {len(df)}")
print(f"Phishing: {int(df['is_phishing'].sum())}")
print(f"Safe: {int(len(df) - df['is_phishing'].sum())}")

print("\nStep 3: Training...")
X = df[FEATURE_NAMES]
y = df['is_phishing']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
model.fit(X_train, y_train)

acc = accuracy_score(y_test, model.predict(X_test))
print(f"Accuracy: {acc*100:.2f}%")
print(classification_report(
    y_test, model.predict(X_test),
    target_names=['Safe', 'Phishing']
))

joblib.dump(model, 'phishing_model_v2.pkl')
print("Model saved!")

print("\nQuick test:")
test_cases = [
    ('https://google.com', 'SAFE'),
    ('http://paypal-login-verify.xyz/account?update=true', 'PHISHING'),
    ('https://github.com', 'SAFE'),
    ('http://192.168.1.1/bank/login.php', 'PHISHING'),
    ('http://free-iphone-winner.click/prize', 'PHISHING'),
    ('https://amazon.com', 'SAFE'),
    ('http://secure-banking-update.com/verify', 'PHISHING'),
    ('https://microsoft.com', 'SAFE'),
    ('http://apple-id-locked.fake.net/unlock', 'PHISHING'),
    ('https://stackoverflow.com', 'SAFE'),
]

correct = 0
for url, expected in test_cases:
    f = extract_features(url)
    df_t = pd.DataFrame([f])[FEATURE_NAMES]
    pred = model.predict(df_t)[0]
    result = 'PHISHING' if pred == 1 else 'SAFE'
    status = '✓' if result == expected else '✗ WRONG'
    if result == expected:
        correct += 1
    print(f"  {status} | {result} | {url[:55]}")

print(f"\nTest score: {correct}/{len(test_cases)}")