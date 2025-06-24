# SOURCES dict

# Lists each feed with its URL and where to save it.

# The openphish feed is plain text, so we wrap it into a DataFrame.

# download_and_save()

# Uses requests to fetch the content.

# Parses into a pandas DataFrame (read_csv or manual list-to-DataFrame).

# Creates parent folders with os.makedirs(..., exist_ok=True).

# Saves with df.to_csv(...).

# Prints how many rows were saved and the first 5 lines for a quick sanity check.
# scripts/download_data.py




#!data is fetched, parsed, and saved.
# scripts/download_data.py

import os
import requests
from io import StringIO
import pandas as pd
from pathlib import Path

# Ensure you have the `tranco` package installed:

from tranco import Tranco

# ──────────────────────────────────────────────────────────────
# 1. CONFIGURATION
# Define each source with:
#   • url     – where to download
#   • path    – where to save
#   • is_txt  – True if it’s a plain-text list, not CSV
# ──────────────────────────────────────────────────────────────
SOURCES = {
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "path": "data/raw/phishing_sources/phishtank.csv",
        "is_txt": False
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "path": "data/raw/phishing_sources/openphish.csv",
        "is_txt": True
    }
}

# ──────────────────────────────────────────────────────────────
# 2. DOWNLOAD & SAVE FUNCTION
# Handles both CSV and plain-text feeds, ensures directories exist,
# saves CSV, and prints row count + head for sanity checking.
# ──────────────────────────────────────────────────────────────
def download_and_save(name, url, path, is_txt=False):
    print(f"-> Downloading {name} from {url}")
    resp = requests.get(url)
    resp.raise_for_status()
    text = resp.text

    if is_txt:
        # One URL per line → build a DataFrame
        urls = [line.strip() for line in text.splitlines() if line.strip()]
        df = pd.DataFrame({"url": urls})
    else:
        # CSV feed → let pandas parse it
        df = pd.read_csv(StringIO(text))

    # Ensure folder exists
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Save without pandas index
    df.to_csv(path, index=False)

    print(f"  ✔ Saved {len(df)} rows to {path}")
    print(df.head(), "\n")


# ──────────────────────────────────────────────────────────────
# 3. DOWNLOAD TRONCO TOP 100K USING THE `tranco` PACKAGE
# This handles fetching the dynamic list ID, caching, and subsetting.
# ──────────────────────────────────────────────────────────────
def download_tranco_top100k(path):
    print("-> Fetching latest Tranco Top 100k")
    t = Tranco(cache=True, cache_dir=".tranco_cache")
    latest_list = t.list()           # retrieves latest daily list
    top100k = latest_list.top(100_000)  # get top 100k domains

    df = pd.DataFrame(top100k, columns=["url"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)

    print(f"  ✔ Saved {len(df)} rows to {path}")
    print(df.head(), "\n")


# ──────────────────────────────────────────────────────────────
# 4. MAIN ENTRY POINT
# Loops through SOURCES and then handles Tranco separately.
# ──────────────────────────────────────────────────────────────
def main():
    # 4.a Download PhishTank & OpenPhish
    for name, info in SOURCES.items():
        download_and_save(name, info["url"], info["path"], info.get("is_txt", False))

    # 4.b Download Tranco Top 100k
    tranco_path = "data/raw/legitimate_sources/tranco_top100k.csv"
    download_tranco_top100k(tranco_path)


if __name__ == "__main__":
    main()
