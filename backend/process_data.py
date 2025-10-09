import pandas as pd
import os

def process_all_csvs(directory):
    """Loads all CSV files in a directory and combines them into a single DataFrame."""
    all_dfs = []
    # Loop through all files in the directory
    for filename in os.listdir(directory):
        if filename.endswith(".csv"):
            file_path = os.path.join(directory, filename)
            try:
                # Read the CSV file into a DataFrame
                df = pd.read_csv(file_path)
                all_dfs.append(df)
            except Exception as e:
                print(f"Error loading {filename}: {e}")

    if not all_dfs:
        print("No CSV files found.")
        return pd.DataFrame(columns=['URL', 'Label'])

    # Concatenate all DataFrames into one
    df_combined = pd.concat(all_dfs, ignore_index=True)
    df_combined.drop_duplicates(inplace=True)
    
    # Standardize column names if they are different
    if 'url' in df_combined.columns and 'label' in df_combined.columns:
        df_combined.rename(columns={'url': 'URL', 'label': 'Label'}, inplace=True)
        
    return df_combined

# Run the script
if __name__ == "__main__":
    current_directory = os.path.dirname(os.path.abspath(__file__))
    
    # Process all CSVs and save the cleaned data
    df_final = process_all_csvs(current_directory)
    if not df_final.empty:
        df_final.to_csv('phishing_site_urls_combined.csv', index=False)
        print(f"All datasets combined into 'phishing_site_urls_combined.csv'. Total entries: {len(df_final)}")