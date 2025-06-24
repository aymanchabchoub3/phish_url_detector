import os
import json                        # for caching WHOIS results
import ssl
import socket                     # for network socket connections
import requests                   # to call the WhoisXMLAPI HTTP endpoint
import pandas as pd               # to load and save CSV data
from datetime import datetime, timezone  # for timezone-aware date calculations
from urllib.parse import urlparse # to extract domains from URLs
from cryptography import x509      # to parse DER-encoded SSL certificates
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv    # to load environment variables from .env

# Load environment variables from a .env file in project root
load_dotenv()
API_KEY = os.getenv("WHOISXML_API_KEY")  # your personal API key for WhoisXMLAPI

# Paths and settings
INPUT_CSV        = "data/processed/features.csv"  # base features file with URL, label, etc.
OUTPUT_CSV       = "data/processed/features_with_network.csv"  # final enriched output
CERT_TIMEOUT_SEC = 5.0                # seconds to wait for an SSL connection
CACHE_FILE       = ".whois_cache.json"  # path for local WHOIS response cache

# ────────────────────────────────────────────────────────────
# Functions to load and save the WHOIS cache
# ────────────────────────────────────────────────────────────
def load_cache(path):
    """
    Read a JSON file of cached WHOIS lookups.
    Returns an empty dict if file doesn't exist yet.
    """
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def save_cache(path, cache):
    """
    Write the in-memory WHOIS cache dict back to disk as JSON.
    """
    with open(path, "w") as f:
        json.dump(cache, f)

# Initialize the cache at module load
whois_cache = load_cache(CACHE_FILE)

# ────────────────────────────────────────────────────────────
# Helper: extract domain from URL
# ────────────────────────────────────────────────────────────
def get_domain(url: str) -> str:
    """
    Given a full URL, parse and return the hostname (domain).
    If URL is malformed, returns empty string.
    """
    return urlparse(url).hostname or ""

# ────────────────────────────────────────────────────────────
# WHOIS lookup via WhoisXMLAPI, with local caching
# ────────────────────────────────────────────────────────────
def domain_age_days(domain: str) -> float:
    """
    Return the age of the domain in days by querying WhoisXMLAPI.
    Uses a simple JSON cache to avoid repeat API calls.
    Returns -1.0 on any error or if domain is empty.
    """
    # 1) If domain exists in cache, return it immediately
    if domain in whois_cache:
        return whois_cache[domain]
    # 2) Skip blank domains
    if not domain:
        whois_cache[domain] = -1.0
        save_cache(CACHE_FILE, whois_cache)
        return -1.0

    try:
        # 3) Build API request
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "apiKey": API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        # 4) Perform HTTP GET to fetch WHOIS data
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        # 5) Extract creation date string from JSON
        created_str = data.get("WhoisRecord", {}).get("createdDate")
        if not created_str:
            raise ValueError("No creation date returned")
        # 6) Parse into a timezone-aware datetime
        created_dt = datetime.strptime(created_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        # 7) Compute days between now and creation
        age = (datetime.now(timezone.utc) - created_dt).days
        # 8) Cache the result for future runs
        whois_cache[domain] = float(age)
    except Exception as e:
        # On error, store sentinel value -1.0
        whois_cache[domain] = -1.0
    # 9) Update disk cache
    save_cache(CACHE_FILE, whois_cache)
    return whois_cache[domain]

# ────────────────────────────────────────────────────────────
# TLS certificate inspection using cryptography
# ────────────────────────────────────────────────────────────
def tls_cert_days_valid(domain: str, timeout: float = CERT_TIMEOUT_SEC) -> float:
    """
    Connect to the domain on port 443, retrieve the SSL certificate in DER format,
    parse its expiration date, and return the remaining days until expiry.
    Returns -1.0 on any error (network, parse, etc.).
    """
    try:
        # 1) Open a raw socket to domain:443
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            # 2) Initiate TLS handshake
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # 3) Get the certificate in DER (binary) form
                der = ssock.getpeercert(binary_form=True)
        # 4) Load certificate with cryptography
        cert = x509.load_der_x509_certificate(der, default_backend())
        # 5) Extract the notValidAfter field (expiration)
        not_after = cert.not_valid_after  # timezone-aware UTC
        # 6) Compute the time delta"""
        now_utc = datetime.now(timezone.utc)
        delta = not_after - now_utc
        return float(delta.days)
    except Exception:
        # On any failure (timeout, invalid cert, etc.), return -1.0
        return -1.0

# ────────────────────────────────────────────────────────────
# Certificate validity flag from days remaining
# ────────────────────────────────────────────────────────────
def has_valid_cert(domain: str) -> int:
    """
    Return 1 if the TLS certificate is currently valid (days left > 0), else 0.
    """
    days = tls_cert_days_valid(domain)
    return 1 if days > 0 else 0

# ────────────────────────────────────────────────────────────
# Main script logic
# ────────────────────────────────────────────────────────────
def main():
    # 1) Load the CSV produced by extract_url_features
    df = pd.read_csv(INPUT_CSV)
    print(f"Loaded {len(df)} rows from {INPUT_CSV}")

    # 2) Add a 'domain' column by parsing the URL
    df["domain"] = df["url"].apply(get_domain)

    # 3) Compute domain age via the WHOIS API (with cache)
    print("Computing domain age via WhoisXMLAPI (cached)…")
    df["domain_age_days"] = df["domain"].apply(domain_age_days)

    # 4) Compute TLS certificate time-to-expiry
    print("Inspecting TLS certificates…")
    df["tls_days_valid"] = df["domain"].apply(tls_cert_days_valid)
    # 5) Create a boolean flag for valid certificates
    df["tls_valid_flag"] = df["domain"].apply(has_valid_cert)

    # 6) Ensure output folder exists, then write CSV
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"✔ Saved enriched features to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()

