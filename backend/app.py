from flask import Flask, request, jsonify, send_file
import pickle
import re
from urllib.parse import urlparse
import tldextract
import ipaddress
import pandas as pd
import numpy as np
from datetime import datetime
import whois
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# --- Enhanced Blacklist and Whitelist ---
BLACKLISTED_KEYWORDS = [
    'login', 'verify', 'signin', 'account', 'update', 'confirm', 
    'password', 'secure', 'banking', 'authenticate', 'validation',
    'security', 'ebay', 'paypal', 'amazon', 'bank', 'credit',
    'card', 'social', 'security', 'irs', 'tax', 'urgent',
    'alert', 'important', 'action', 'required', 'suspended'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.info',
    '.loan', '.work', '.party', '.gq', '.download', '.stream'
]

WHITELISTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", 
    "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com", 
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "gemini.com", "openai.com"
]

# --- Load the trained model and scaler ---
print("Loading the trained model and scaler...")
model = None
scaler = None
feature_names = []

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    with open(os.path.join(BASE_DIR, 'phishing_model.pkl'), 'rb') as file:
        model = pickle.load(file)
    print("[OK] Model loaded successfully.")
    
    with open(os.path.join(BASE_DIR, 'scaler.pkl'), 'rb') as file:
        scaler = pickle.load(file)
    print("[OK] Scaler loaded successfully.")
    
    with open(os.path.join(BASE_DIR, 'feature_names.pkl'), 'rb') as file:
        feature_names = pickle.load(file)
    print("[OK] Feature names loaded successfully.")
        
except FileNotFoundError as e:
    print(f"[ERROR] Error loading files: {e}")
    print("Please run model_training.py first to generate the required files.")
except Exception as e:
    print(f"[ERROR] Error loading model: {e}")

# --- Enhanced Feature Extraction Functions ---
def having_ip_address(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        ipaddress.ip_address(netloc)
        return 1
    except:
        return 0

def url_length(url):
    return len(str(url))

def having_at_symbol(url):
    return 1 if "@" in str(url) else 0

def having_dash_symbol(url):
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

def subdomain_count(url):
    extracted = tldextract.extract(url)
    subdomains = extracted.subdomain.split('.')
    count = len([s for s in subdomains if s])
    return min(count, 5)

def is_shortened_url(url):
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 
        'buff.ly', 'adf.ly', 'shorte.st', 'clic.ws', 'bc.vc', 'po.st'
    ]
    domain = urlparse(url).netloc.lower()
    return 1 if any(shortener in domain for shortener in shorteners) else 0

def digit_ratio(url):
    domain = urlparse(url).netloc
    if len(domain) == 0:
        return 0
    return sum(c.isdigit() for c in domain) / len(domain)

def special_char_ratio(url):
    special_chars = r'[!@#$%^&*()+={\[}\]|\\:;"\'<,>?/]'
    if len(url) == 0:
        return 0
    return len(re.findall(special_chars, url)) / len(url)

def check_https(url):
    try:
        return 1 if urlparse(url).scheme == 'https' else 0
    except:
        return 0

def domain_age(url):
    try:
        domain = urlparse(url).netloc
        if not domain or len(domain) < 4:
            return 1
            
        domain_info = whois.whois(domain)
        
        if domain_info and domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if isinstance(creation_date, datetime):
                age = (datetime.now() - creation_date).days
                return 1 if age < 180 else 0
        return 1
    except Exception:
        return 1

def check_phishing_keywords(url):
    url_lower = url.lower()
    return 1 if any(keyword in url_lower for keyword in BLACKLISTED_KEYWORDS) else 0

def check_suspicious_tld(url):
    extracted = tldextract.extract(url)
    tld = '.' + extracted.suffix
    return 1 if tld in SUSPICIOUS_TLDS else 0

def path_length(url):
    return min(len(urlparse(url).path), 100)

def has_query_parameters(url):
    return 1 if len(urlparse(url).query) > 0 else 0

def query_length(url):
    return len(urlparse(url).query)

def get_url_entropy(url):
    url_str = str(url)
    if len(url_str) <= 1:
        return 0
    
    entropy = 0
    for char in set(url_str):
        p_x = float(url_str.count(char)) / len(url_str)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return min(entropy, 10)

def check_domain_hyphen(url):
    domain = urlparse(url).netloc
    return 1 if domain.count('-') >= 2 else 0

def check_http_in_path(url):
    path = urlparse(url).path.lower()
    return 1 if 'http' in path else 0

def check_fake_https(url):
    domain = urlparse(url).netloc.lower()
    return 1 if 'https' in domain or 'ssl' in domain else 0

def check_typosquatting(url):
    popular_domains = [
        'google', 'facebook', 'amazon', 'youtube', 'twitter', 'instagram',
        'linkedin', 'microsoft', 'apple', 'netflix', 'paypal', 'ebay'
    ]
    domain = urlparse(url).netloc.lower()
    for popular in popular_domains:
        if popular in domain and domain != popular + '.com':
            if any(typo in domain for typo in [popular + 's', popular + '-', popular + '_']):
                return 1
            if len(domain) - len(popular) <= 3:
                return 1
    return 0

def check_redirects(url):
    return 1 if url.count('//') > 1 else 0

def get_port_number(url):
    try:
        parsed = urlparse(url)
        if parsed.port and parsed.port not in [80, 443, 8080]:
            return 1
        return 0
    except:
        return 0

def extract_all_features(url):
    """Extract all features for a given URL"""
    features = [
        having_ip_address(url),
        url_length(url),
        having_at_symbol(url),
        having_dash_symbol(url),
        subdomain_count(url),
        is_shortened_url(url),
        digit_ratio(url),
        special_char_ratio(url),
        check_https(url),
        domain_age(url),
        check_phishing_keywords(url),
        check_suspicious_tld(url),
        path_length(url),
        has_query_parameters(url),
        query_length(url),
        get_url_entropy(url),
        check_domain_hyphen(url),
        check_http_in_path(url),
        check_fake_https(url),
        check_typosquatting(url),
        check_redirects(url),
        get_port_number(url)
    ]
    return features

def heuristic_check(url):
    """Additional heuristic checks for phishing URLs"""
    domain = urlparse(url).netloc.lower()
    
    # Immediate red flags
    if having_ip_address(url) == 1:
        return True, "Uses IP address instead of domain name"
    
    if having_at_symbol(url) == 1:
        return True, "Contains @ symbol (suspicious redirect)"
    
    if check_typosquatting(url) == 1:
        return True, "Possible typosquatting detected"
    
    if check_fake_https(url) == 1:
        return True, "Fake HTTPS in domain name"
    
    # Check for excessive subdomains
    if subdomain_count(url) >= 4:
        return True, "Too many subdomains"
    
    # Check for suspicious TLD
    if check_suspicious_tld(url) == 1:
        return True, "Suspicious domain extension"
    
    # Check for phishing keywords in domain
    domain_keywords = any(keyword in domain for keyword in BLACKLISTED_KEYWORDS)
    if domain_keywords and not any(safe in domain for safe in ['google', 'microsoft', 'apple']):
        return True, "Phishing keywords in domain"
    
    return False, ""

# --- The main prediction endpoint ---
@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
        
    if not model or not scaler:
        return jsonify({
            'error': 'Model not loaded properly.',
            'is_phishing': True,
            'confidence': 0.95
        }), 500

    data = request.get_json()
    if not data:
        return jsonify({
            'error': 'No JSON data provided.',
            'is_phishing': True,
            'confidence': 0.95
        }), 400

    url = data.get('url', '').strip()
    if not url:
        return jsonify({
            'error': 'No URL provided.',
            'is_phishing': True,
            'confidence': 0.95
        }), 400

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        domain = urlparse(url).netloc.lower()
        
        # Extract features first to return them in all cases
        features = extract_all_features(url)
        features_dict = {}
        if feature_names and len(feature_names) == len(features):
            features_dict = {name: (float(val) if isinstance(val, (int, float, np.integer, np.floating)) else val) for name, val in zip(feature_names, features)}
        
        # Check whitelist first
        for safe_domain in WHITELISTED_DOMAINS:
            if domain == safe_domain or domain.endswith('.' + safe_domain):
                return jsonify({
                    'is_phishing': False,
                    'url': url,
                    'confidence': 0.0,
                    'message': 'Domain is on the whitelist.',
                    'whitelisted': True,
                    'features': features_dict
                })

        # Heuristic check for immediate red flags
        heuristic_phishing, heuristic_reason = heuristic_check(url)
        if heuristic_phishing:
            return jsonify({
                'is_phishing': True,
                'url': url,
                'confidence': 0.95,
                'message': f'Heuristic detection: {heuristic_reason}',
                'heuristic_detection': True,
                'features': features_dict
            })
        
        features_df = pd.DataFrame([features], columns=feature_names)
        
        # Scale features
        features_scaled = scaler.transform(features_df)
        
        # Make prediction
        prediction_proba = model.predict_proba(features_scaled)
        phishing_score = prediction_proba[0][1]

        # Use lower threshold to catch more phishing sites
        threshold = 0.3

        is_phishing = phishing_score > threshold
        confidence = phishing_score if is_phishing else 1 - phishing_score

        # Additional safety: if any strong indicator is present, mark as phishing
        strong_indicators = [
            features[0],  # IP address
            features[2],  # @ symbol
            features[5],  # Shortened URL
            features[11], # Suspicious TLD
            features[18], # Fake HTTPS
            features[19]  # Typosquatting
        ]
        
        if any(strong_indicators) and phishing_score > 0.1:
            is_phishing = True
            confidence = max(confidence, 0.8)

        return jsonify({
            'is_phishing': bool(is_phishing),
            'url': url,
            'phishing_score': float(phishing_score),
            'confidence': float(confidence),
            'threshold_used': float(threshold),
            'heuristic_checked': True,
            'features': features_dict
        })

    except Exception as e:
        return jsonify({
            'error': f'Error processing URL: {str(e)}',
            'is_phishing': True,
            'confidence': 0.9,
            'message': 'Error occurred - marking as phishing for safety'
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    status = {
        'model_loaded': model is not None,
        'scaler_loaded': scaler is not None,
        'feature_names_loaded': len(feature_names) > 0,
        'status': 'ready' if (model and scaler) else 'not ready',
        'environment': 'production'
    }
    return jsonify(status)

@app.route('/test', methods=['GET'])
def test():
    return jsonify({
        'status': 'Server is running!', 
        'message': 'Phishing detection API is ready',
        'version': '2.0',
        'environment': 'production'
    })

@app.route('/', methods=['GET'])
def home():
    return send_file('index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
