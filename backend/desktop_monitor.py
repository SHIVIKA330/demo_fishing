import pyperclip
import requests
import time
from urllib.parse import urlparse

# URL of your running Flask server
API_URL = "http://127.0.0.1:5000/predict"
# Storage for the last copied text to prevent continuous re-sending
last_copied = ""

def is_valid_url(text):
    """Simple check to see if the clipboard content looks like a URL."""
    # Add http:// if scheme is missing to allow parsing
    if not text.startswith(('http://', 'https://')):
        text = 'http://' + text
    
    try:
        result = urlparse(text)
        # Check if netloc (domain) is present and the scheme is valid
        return all([result.netloc, result.scheme in ['http', 'https']]) and '.' in result.netloc
    except:
        return False

def analyze_url(url):
    """Sends the URL to your Flask API for prediction and prints the result."""
    print(f"\n[SCANNING CLIPBOARD] -> {url}")
    try:
        response = requests.post(
            API_URL, 
            json={"url": url}, 
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            score = data.get('phishing_score', 0)
            
            if data.get('is_phishing'):
                print(f"🚨🚨 WARNING: PHISHING DETECTED! Confidence: {score:.2f}")
            else:
                print(f"✅ URL is safe. Confidence: {1-score:.2f}")
        else:
            print(f"API Error: Server responded with status {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"NETWORK ERROR: Is Flask server running? {e}")

if __name__ == "__main__":
    print("\n--- Cross-App Phishing Monitor Started (Clipboard Mode) ---")
    print("Action: Copy any link from WhatsApp, Instagram, or SMS to scan.")
    print("Press Ctrl+C to stop.")
    
    while True:
        try:
            current_clipboard = pyperclip.paste()
            
            # Check if clipboard changed and contains a valid-looking URL
            if current_clipboard != last_copied and is_valid_url(current_clipboard):
                # Update last_copied to prevent immediate re-scan
                last_copied = current_clipboard 
                analyze_url(current_clipboard)
            
            time.sleep(1) # Check clipboard every second

        except KeyboardInterrupt:
            print("\n--- Monitor Stopped ---")
            break
        except Exception:
            # Continue monitoring even if there's a temporary error
            time.sleep(1)