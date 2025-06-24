# scripts/extract_url_features.py

import os
import pandas as pd
import math
from urllib.parse import urlparse

# ──────────────────────────────────────────────────────────────
# 1. CONFIG & PATHS
# ──────────────────────────────────────────────────────────────
INPUT_CSV = "data/processed/train.csv"
OUTPUT_CSV = "data/processed/features.csv"

# ──────────────────────────────────────────────────────────────
# 2. HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────


def url_length(u: str) -> int:
    """Total number of characters in the URL."""
    return len(u)


def count_chars(u: str, chars: str) -> int:
    """Count how many times any character in 'chars' appears in u."""
    return sum(u.count(c) for c in chars)


def has_https(u: str) -> int:
    """1 if URL uses https, else 0."""
    return 1 if u.startswith("https://") else 0


def token_count(u: str) -> int:
    """Number of path tokens when splitting on '/','?','&','='."""
    parsed = urlparse(u)
    # split path by '/', then query string by '&' or '='
    path_tokens = [t for t in parsed.path.split("/") if t]
    query_tokens = []
    if parsed.query:
        for part in parsed.query.split("&"):
            query_tokens.extend(part.split("="))
    return len(path_tokens) + len(query_tokens)


def hostname_entropy(u: str) -> float:
    """
    Shannon entropy of the hostname characters.
    High entropy can indicate randomness (like in generated phishing domains).
    """
    h = urlparse(u).hostname or ""
    if not h:
        return 0.0
    # frequency of each character
    freqs = {}
    for c in h:
        freqs[c] = freqs.get(c, 0) + 1
    # compute entropy
    ent = 0.0
    for count in freqs.values():
        p = count / len(h)
        ent -= p * math.log2(p)
    return ent


def count_digits(u: str) -> int:
    """Count numeric characters in the URL."""
    return sum(c.isdigit() for c in u)


# ──────────────────────────────────────────────────────────────
# 3. MAIN EXTRACTION PIPELINE
# ──────────────────────────────────────────────────────────────
def main():
    # 3.1 Load your train.csv (must contain 'url' and 'label' columns)
    df = pd.read_csv(INPUT_CSV)
    print(f"Loaded {len(df)} rows from {INPUT_CSV}")

    # 3.2 Initialize a new DataFrame for features
    features = pd.DataFrame()
    features["url"] = df["url"]
    features["label"] = df["label"]

    # 3.3 Compute features one by one
    print("Extracting features…")
    features["url_length"] = df["url"].apply(url_length)
    features["count_slash"] = df["url"].apply(lambda u: count_chars(u, "/"))
    features["count_dot"] = df["url"].apply(lambda u: count_chars(u, "."))
    features["count_dash"] = df["url"].apply(lambda u: count_chars(u, "-"))
    features["count_at"] = df["url"].apply(lambda u: count_chars(u, "@"))
    features["count_question"] = df["url"].apply(lambda u: count_chars(u, "?"))
    features["count_equal"] = df["url"].apply(lambda u: count_chars(u, "="))
    features["count_digits"] = df["url"].apply(count_digits)
    features["https_flag"] = df["url"].apply(has_https)
    features["token_count"] = df["url"].apply(token_count)
    features["host_entropy"] = df["url"].apply(hostname_entropy)

    # 3.4 Save the feature matrix
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    features.to_csv(OUTPUT_CSV, index=False)
    print(
        f"✔ Saved {len(features)} rows with {len(features.columns)-2} features to {OUTPUT_CSV}"
    )
    print(features.head(), "\n")
    print(features.describe().T)
    print(features.info())
    print(features.shape)


if __name__ == "__main__":
    main()
