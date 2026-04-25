import re
import urllib.parse
from datetime import datetime

def extract_features(url):
    features = {}
    
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
        path = parsed.path
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        
        # HTTPS check
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # IP address in URL
        features['has_ip'] = 1 if re.search(
            r'(\d{1,3}\.){3}\d{1,3}', domain) else 0
        
        # Count special characters
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersand'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_hash'] = url.count('#')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        
        # Suspicious keywords
        suspicious_words = [
            'login', 'signin', 'verify', 'secure', 'account',
            'update', 'confirm', 'banking', 'paypal', 'password',
            'credential', 'ebay', 'amazon', 'apple', 'microsoft',
            'free', 'winner', 'click', 'prize', 'urgent'
        ]
        features['num_suspicious_words'] = sum(
            1 for word in suspicious_words 
            if word in url.lower()
        )
        
        # URL entropy (randomness)
        import math
        prob = [float(url.count(c)) / len(url) for c in set(url)]
        features['url_entropy'] = -sum(
            p * math.log(p, 2) for p in prob if p > 0
        )
        
        # Domain features
        features['num_subdomains'] = len(domain.split('.')) - 2
        features['has_www'] = 1 if domain.startswith('www.') else 0
        
        # TLD features
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov']
        suspicious_tlds = ['.xyz', '.click', '.tk', '.ml', 
                          '.ga', '.cf', '.gq', '.top', '.zip']
        
        features['has_common_tld'] = 1 if any(
            domain.endswith(t) for t in common_tlds) else 0
        features['has_suspicious_tld'] = 1 if any(
            domain.endswith(t) for t in suspicious_tlds) else 0
        
        # Port in URL
        features['has_port'] = 1 if ':' in domain else 0
        
        # URL shortener
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 
                     'ow.ly', 'short.io']
        features['is_shortened'] = 1 if any(
            s in url for s in shorteners) else 0
        
        # Double slash in path
        features['has_double_slash'] = 1 if '//' in path else 0
        
        # Encoded characters
        features['has_encoded_chars'] = 1 if '%' in url else 0
        
        # Query string features
        query = parsed.query
        features['query_length'] = len(query)
        features['num_query_params'] = len(
            query.split('&')) if query else 0
        
        # Digit ratio
        features['digit_ratio'] = (
            features['num_digits'] / len(url) if len(url) > 0 else 0
        )
        
    except Exception:
        # Return zeros if URL parsing fails
        default_features = [
            'url_length','domain_length','path_length','has_https',
            'has_ip','num_dots','num_hyphens','num_underscores',
            'num_slashes','num_question_marks','num_equals','num_at',
            'num_ampersand','num_percent','num_hash','num_digits',
            'num_letters','num_suspicious_words','url_entropy',
            'num_subdomains','has_www','has_common_tld',
            'has_suspicious_tld','has_port','is_shortened',
            'has_double_slash','has_encoded_chars','query_length',
            'num_query_params','digit_ratio'
        ]
        features = {f: 0 for f in default_features}
    
    return features

# List of all feature names (for consistent ordering)
FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'has_https',
    'has_ip', 'num_dots', 'num_hyphens', 'num_underscores',
    'num_slashes', 'num_question_marks', 'num_equals', 'num_at',
    'num_ampersand', 'num_percent', 'num_hash', 'num_digits',
    'num_letters', 'num_suspicious_words', 'url_entropy',
    'num_subdomains', 'has_www', 'has_common_tld',
    'has_suspicious_tld', 'has_port', 'is_shortened',
    'has_double_slash', 'has_encoded_chars', 'query_length',
    'num_query_params', 'digit_ratio'
]