import json
import os
from typing import Dict, Optional
from urllib.parse import urlparse

# Path to your local threat intel feed
THREAT_FEED_PATH = os.path.expanduser(
    "~/Documents/C-Sight/C-Sight/csight/detectors/urlhaus.abuse.ch.json" 
)

# Set of malicious domains (lazy loaded on first use)
malicious_hosts = set()

# These can have malware inside their storage, however it leads to flase positives in logs
# If you're getting false positives, add the domain to this list
# If you're downloading files from these domains, KNOW WHAT YOU'RE DOWNLOADING ALWAYS!
TRUSTED_DOMAINS = {
    "drive.google.com",
    "accounts.google.com",
    "storage.googleapis.com",
    "s3.amazonaws.com",
    # Add more safe domains here
}

# Lazy load the threat feed from URLHaus (05/31/25)
def load_malicious_hosts():
    if malicious_hosts:
        return  # Already loaded

    try:
        with open(THREAT_FEED_PATH, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
            for entry_list in raw_data.values():
                for entry in entry_list:
                    raw_url = entry.get("url", "")
                    if not raw_url:
                        continue
                    try:
                        parsed = urlparse(raw_url)
                        host = parsed.netloc.lower().strip()
                        if host:
                            malicious_hosts.add(host)
                    except Exception:
                        continue
    except Exception as e:
        print(f"❌ Failed to load threat feed: {e}")

# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we think it’s malicious, else None
def detect(packet_info: Dict) -> Optional[str]:
    load_malicious_hosts()

    hostname = ""

    # From TLS SNI (HTTPS)
    if packet_info.get("protocol") == "TLS":
        hostname = packet_info.get("tls_sni", "").lower().strip()

    # From HTTP Host header (plaintext HTTP)
    if packet_info.get("protocol") == "HTTP":
        hostname = packet_info.get("http_host", "").lower().strip()

    if not hostname or hostname in TRUSTED_DOMAINS:
        return None

    if hostname in malicious_hosts:
        return f"🚨 MALICIOUS DOMAIN ACCESS: {hostname}"

    return None
