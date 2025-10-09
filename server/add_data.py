import pandas as pd
import requests
import os
import io

def fetch_phishtank_data():
    """Fetches a list of verified phishing URLs from PhishTank."""
    url = "http://data.phishtank.com/data/online-valid.csv.bz2"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return pd.read_csv(io.BytesIO(response.content), compression='bz2', encoding='utf-8')
    except Exception as e:
        print(f"Error fetching data from PhishTank: {e}")
    return pd.DataFrame()

# --- 1. Load the existing dataset ---
file_path = 'phishing_site_urls.csv'
if os.path.exists(file_path):
    df_existing = pd.read_csv(file_path)
    print(f"Loaded existing dataset with {len(df_existing)} entries.")
else:
    df_existing = pd.DataFrame(columns=['URL', 'Label'])
    print("Existing dataset not found. A new one will be created.")

# --- 2. Define new data to add ---
df_phishtank = fetch_phishtank_data()
if not df_phishtank.empty:
    df_phishtank = df_phishtank[['url']]
    df_phishtank.rename(columns={'url': 'URL'}, inplace=True)
    df_phishtank['Label'] = 'bad'
    print(f"Fetched {len(df_phishtank)} new phishing URLs.")

new_urls_data = [
    # Phishing websites (additional)
    {'URL': 'https://www.fakepaypal-secure.com/verify-account', 'Label': 'bad'},
    {'URL': 'http://amazon-prime-shipping-update.net/login', 'Label': 'bad'},
    
    # Legitimate websites
    {'URL': 'https://www.python.org/', 'Label': 'good'},
    {'URL': 'https://github.com/', 'Label': 'good'},
    {'URL': 'https://www.gla.ac.in/', 'Label': 'good'},
    {'URL': 'https://www.microsoft.com/en-us/', 'Label': 'good'},
]

df_new = pd.DataFrame(new_urls_data)

# --- 3. Combine and save the data ---
if not df_phishtank.empty:
    df_combined = pd.concat([df_existing, df_phishtank, df_new], ignore_index=True)
else:
    df_combined = pd.concat([df_existing, df_new], ignore_index=True)

# Remove any duplicate URLs that might have been added
df_combined.drop_duplicates(subset=['URL'], inplace=True)

df_combined.to_csv(file_path, index=False)
print(f"Dataset updated. New total number of entries: {len(df_combined)}.")