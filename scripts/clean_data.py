# scripts/clean_data.py

import os
import glob
import pandas as pd
from urllib.parse import urlparse

# ──────────────────────────────────────────────────────────────
# CONFIGURATION
# Point these at the folders where you stored your raw downloads
# ──────────────────────────────────────────────────────────────
PHISH_DIR = "data/raw/phishing_sources"
LEGIT_DIR = "data/raw/legitimate_sources"

# Output files
OUTPUT_PHISH = "data/raw/phish.csv"
OUTPUT_LEGIT = "data/raw/legit.csv"

# URL columns in each source (if CSV headers differ)
PHISH_URL_COLS = ["url"]  # phishtank and openphish already have 'url'
LEGIT_URL_COLS = [
    "url",
    "domain",
]  # Tranco uses no header by default; we'll treat it as 'url'


# ──────────────────────────────────────────────────────────────
# STEP 1: LOAD & LABEL
#  • Read every CSV in PHISH_DIR, tag label='phish'
#  • Read every CSV in LEGIT_DIR, tag label='legit'
# ──────────────────────────────────────────────────────────────
def load_and_label(path_pattern, label, url_cols):
    """
    Reads all files matching path_pattern,
    extracts the first matching column as 'url',
    adds a 'label' column.
    """
    dfs = []
    for filepath in glob.glob(path_pattern):
        df = pd.read_csv(filepath, usecols=lambda c: c in url_cols, dtype=str)
        # Some feeds might name the column 'domain'
        if "domain" in df.columns and "url" not in df.columns:
            df = df.rename(columns={"domain": "url"})
        # Keep only the 'url' column
        df = df[["url"]].copy()
        df["label"] = label
        dfs.append(df)
        print(f"  Loaded {len(df)} rows from {filepath}")
    combined = pd.concat(dfs, ignore_index=True)
    print(f"⮞ Total {label} rows before cleaning: {len(combined)}\n")
    return combined


# ──────────────────────────────────────────────────────────────
# STEP 2: CLEANING FUNCTIONS
#  • normalize_url: strip whitespace, lowercase
#  • is_valid_url: ensure scheme and netloc exist
# ──────────────────────────────────────────────────────────────


def normalize_url(u: str) -> str:
    """Strip, lowercase, and ensure a scheme is present."""
    u = u.strip().lower()
    # If there's no scheme, assume HTTP
    if "://" not in u:
        u = "http://" + u
    return u


def is_valid_url(u: str) -> bool:
    """Check that URL has a valid http/https scheme and a netloc."""
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────
# STEP 3: MAIN CLEANING PIPELINE
#  1) Load & label both classes
#  2) Normalize URLs
#  3) Deduplicate within each class
#  4) Drop invalid URLs
#  5) Save to OUTPUT_*.csv
# ──────────────────────────────────────────────────────────────
def main():
    # 3.1 Load
    phish_df = load_and_label(
        f"{PHISH_DIR}/*.csv", label="phish", url_cols=PHISH_URL_COLS
    )
    legit_df = load_and_label(
        f"{LEGIT_DIR}/*.csv", label="legit", url_cols=LEGIT_URL_COLS
    )

    # 3.2 Normalize
    for df in (phish_df, legit_df):
        df["url"] = df["url"].astype(str).apply(normalize_url)

    # 3.3 Deduplicate
    before_phish = len(phish_df)
    phish_df = phish_df.drop_duplicates(subset="url")
    print(f"– Dropped {before_phish - len(phish_df)} duplicate phish URLs")

    before_legit = len(legit_df)
    legit_df = legit_df.drop_duplicates(subset="url")
    print(f"– Dropped {before_legit - len(legit_df)} duplicate legit URLs\n")

    # 3.4 Validate
    phish_valid = phish_df["url"].apply(is_valid_url)
    legit_valid = legit_df["url"].apply(is_valid_url)
    print(f"– Removing {len(phish_df) - phish_valid.sum()} invalid phish URLs")
    print(f"– Removing {len(legit_df) - legit_valid.sum()} invalid legit URLs\n")
    phish_df = phish_df[phish_valid]
    legit_df = legit_df[legit_valid]

    # 3.5 Save
    os.makedirs(os.path.dirname(OUTPUT_PHISH), exist_ok=True)
    phish_df.to_csv(OUTPUT_PHISH, index=False)
    legit_df.to_csv(OUTPUT_LEGIT, index=False)

    # 3.6 Final counts
    print(f"✔ Final phish URLs: {len(phish_df)} saved to {OUTPUT_PHISH}")
    print(f"✔ Final legit URLs: {len(legit_df)} saved to {OUTPUT_LEGIT}")


if __name__ == "__main__":
    main()
