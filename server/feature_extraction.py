import pandas as pd
import re
from urllib.parse import urlparse
import tldextract
import ipaddress
import whois
from datetime import datetime
from sklearn.preprocessing import LabelEncoder
import numpy as np
import requests
import ssl
import socket
from urllib.request import urlopen
import time

# --- 1. Data Loading and Cleaning ---
print("Loading data...")
try:
    df = pd.read_csv('phishing_site_urls.csv')
    print(f"Original dataset shape: {df.shape}")
    
    # Data validation
    if 'URL' not in df.columns or 'Label' not in df.columns:
        raise ValueError("Dataset must contain 'URL' and 'Label' columns")
    
    # Clean data
    df = df.dropna()
    df = df.drop_duplicates()
    print(f"After cleaning dataset shape: {df.shape}")
    
except FileNotFoundError:
    print("Error: 'phishing_site_urls.csv' not found.")
    exit()
except Exception as e:
    print(f"Error loading data: {e}")
    exit()

# --- 2. Advanced Feature Extraction Functions ---
print("Defining advanced feature extraction functions...")

def having_ip_address(url):
    """Check if URL uses IP address instead of domain name"""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        ipaddress.ip_address(netloc)
        return 1
    except:
        return 0

def url_length(url):
    """Calculate URL length - longer URLs are more suspicious"""
    return len(str(url))

def having_at_symbol(url):
    """Check for @ symbol in URL - often used in phishing"""
    return 1 if "@" in str(url) else 0

def having_dash_symbol(url):
    """Check for dash in domain name"""
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

def subdomain_count(url):
    """Count number of subdomains - more subdomains = more suspicious"""
    extracted = tldextract.extract(url)
    subdomains = extracted.subdomain.split('.')
    count = len([s for s in subdomains if s])
    return min(count, 5)  # Cap at 5 for normalization

def is_shortened_url(url):
    """Check if URL uses shortening service"""
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 
        'buff.ly', 'adf.ly', 'shorte.st', 'clic.ws', 'bc.vc', 'po.st',
        'viralurl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im'
    ]
    domain = urlparse(url).netloc.lower()
    return 1 if any(shortener in domain for shortener in shorteners) else 0

def digit_ratio(url):
    """Ratio of digits in domain - high ratio is suspicious"""
    domain = urlparse(url).netloc
    if len(domain) == 0:
        return 0
    return sum(c.isdigit() for c in domain) / len(domain)

def special_char_ratio(url):
    """Ratio of special characters in URL"""
    special_chars = r'[!@#$%^&*()+={\[}\]|\\:;"\'<,>?/]'
    if len(url) == 0:
        return 0
    return len(re.findall(special_chars, url)) / len(url)

def check_https(url):
    """Check if URL uses HTTPS"""
    try:
        return 1 if urlparse(url).scheme == 'https' else 0
    except:
        return 0

def domain_age(url):
    """Check if domain is young (potential phishing indicator)"""
    try:
        domain = urlparse(url).netloc
        if not domain or len(domain) < 4:
            return 1  # Treat invalid domains as suspicious
            
        domain_info = whois.whois(domain)
        
        if domain_info and domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if isinstance(creation_date, datetime):
                age = (datetime.now() - creation_date).days
                return 1 if age < 180 else 0  # Less than 6 months
        return 1  # If we can't get age, treat as suspicious
    except Exception:
        return 1  # If WHOIS fails, treat as suspicious

def check_phishing_keywords(url):
    """Check for common phishing keywords"""
    keywords = [
        'login', 'verify', 'signin', 'account', 'update', 'confirm', 
        'password', 'secure', 'banking', 'authenticate', 'validation',
        'security', 'ebay', 'paypal', 'amazon', 'bank', 'credit',
        'card', 'social', 'security', 'irs', 'tax', 'urgent',
        'alert', 'important', 'action', 'required', 'suspended',
        'limited', 'verifyyouraccount', 'credential', 'password'
    ]
    url_lower = url.lower()
    return 1 if any(keyword in url_lower for keyword in keywords) else 0

def check_suspicious_tld(url):
    """Check for suspicious top-level domains"""
    suspicious_tlds = [
        '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.info',
        '.loan', '.work', '.party', '.gq', '.download', '.stream',
        '.live', '.webcam', '.country', '.mom', '.win', '.review'
    ]
    extracted = tldextract.extract(url)
    tld = '.' + extracted.suffix
    return 1 if tld in suspicious_tlds else 0

def path_length(url):
    """Calculate path length - longer paths are suspicious"""
    return min(len(urlparse(url).path), 100)  # Cap at 100

def has_query_parameters(url):
    """Check if URL has query parameters"""
    return 1 if len(urlparse(url).query) > 0 else 0

def query_length(url):
    """Length of query string"""
    return len(urlparse(url).query)

def get_url_entropy(url):
    """Calculate Shannon entropy of URL - high entropy suggests random generation"""
    url_str = str(url)
    if len(url_str) <= 1:
        return 0
    
    entropy = 0
    for char in set(url_str):
        p_x = float(url_str.count(char)) / len(url_str)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return min(entropy, 10)  # Cap entropy

def check_domain_hyphen(url):
    """Check if domain has multiple hyphens"""
    domain = urlparse(url).netloc
    return 1 if domain.count('-') >= 2 else 0

def check_http_in_path(url):
    """Check if 'http' appears in path (suspicious)"""
    path = urlparse(url).path.lower()
    return 1 if 'http' in path else 0

def check_fake_https(url):
    """Check for fake HTTPS in domain"""
    domain = urlparse(url).netloc.lower()
    return 1 if 'https' in domain or 'ssl' in domain else 0

def check_typosquatting(url):
    """Basic typosquatting detection"""
    popular_domains = [
        'google', 'facebook', 'amazon', 'youtube', 'twitter', 'instagram',
        'linkedin', 'microsoft', 'apple', 'netflix', 'paypal', 'ebay'
    ]
    domain = urlparse(url).netloc.lower()
    for popular in popular_domains:
        if popular in domain and domain != popular + '.com':
            # Check for common typos
            if any(typo in domain for typo in [popular + 's', popular + '-', popular + '_']):
                return 1
            # Check for character omissions/additions
            if len(domain) - len(popular) <= 3:
                return 1
    return 0

def check_redirects(url):
    """Check for multiple redirects in URL"""
    return 1 if url.count('//') > 1 else 0

def get_port_number(url):
    """Check if non-standard port is used"""
    try:
        parsed = urlparse(url)
        if parsed.port and parsed.port not in [80, 443, 8080]:
            return 1
        return 0
    except:
        return 0

# --- 3. Apply Feature Extraction to the Dataset ---
print("Extracting features from URLs...")

features_config = [
    ('having_ip_address', having_ip_address),
    ('url_length', url_length),
    ('having_at_symbol', having_at_symbol),
    ('having_dash_symbol', having_dash_symbol),
    ('subdomain_count', subdomain_count),
    ('is_shortened_url', is_shortened_url),
    ('digit_ratio', digit_ratio),
    ('special_char_ratio', special_char_ratio),
    ('check_https', check_https),
    ('domain_age', domain_age),
    ('phishing_keywords', check_phishing_keywords),
    ('suspicious_tld', check_suspicious_tld),
    ('path_length', path_length),
    ('has_query_parameters', has_query_parameters),
    ('query_length', query_length),
    ('url_entropy', get_url_entropy),
    ('multiple_hyphens', check_domain_hyphen),
    ('http_in_path', check_http_in_path),
    ('fake_https', check_fake_https),
    ('typosquatting', check_typosquatting),
    ('multiple_redirects', check_redirects),
    ('non_standard_port', get_port_number)
]

for feature_name, feature_func in features_config:
    try:
        df[feature_name] = df['URL'].apply(feature_func)
        print(f"✓ Extracted feature: {feature_name}")
    except Exception as e:
        print(f"✗ Error extracting {feature_name}: {e}")
        df[feature_name] = 0

# --- 4. Label Encoding ---
print("Encoding labels...")
label_encoder = LabelEncoder()
df['Label'] = label_encoder.fit_transform(df['Label'])
print(f"Label distribution: {dict(zip(label_encoder.classes_, np.bincount(df['Label'])))}")

# --- 5. Save the New Dataset ---
print("Saving the new dataset with features...")
df_features = df.drop('URL', axis=1)
df_features.to_csv('phishing_features.csv', index=False)
print(f"✓ Feature extraction complete. Saved with {df_features.shape[1]} features.")