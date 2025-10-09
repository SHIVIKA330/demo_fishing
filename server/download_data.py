import os
from kaggle.api.kaggle_api_extended import KaggleApi

# This initializes the API client
api = KaggleApi()

# This authenticates the API using the kaggle.json file
api.authenticate()

# This is the command to download the dataset.
# The 'path' parameter specifies where to save the files.
# The 'unzip=True' automatically unzips the downloaded file.
api.dataset_download_files('taruntiwarihp/phishing-site-urls', path='.', unzip=True)

print("Dataset downloaded successfully and unzipped to the 'server' directory!")