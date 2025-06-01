import time
import math
from collections import defaultdict, deque
from typing import Dict, Optional
from config import load_config

CONFIG = load_config()

DETECTOR_CONFIG = CONFIG.get("detectors", {}).get("dns_tunneling_patterns", {})

# Detector constants
# Any single DNS label longer than this is suspicious
MAX_LABEL_LENGTH = DETECTOR_CONFIG.get("label_length", 50)
# Full domain longer than this is suspicious
MAX_DOMAIN_LENGTH = DETECTOR_CONFIG.get("domain_length", 200)
# Shannon entropy above this for the subdomain is suspect
ENTROPY_THRESHOLD = DETECTOR_CONFIG.get("entropy_threshold", 4.0)
# Number of DNS queries per minute to the same root
QUERY_RATE_THRESHOLD = DETECTOR_CONFIG.get("rate_threshold", 20)
# Time window (in seconds) for rate counting
WINDOW_SECONDS = DETECTOR_CONFIG.get("window", 60)
# DNS record types we care about
ALLOWED_RECORD_TYPES = DETECTOR_CONFIG.get(
    "allowed_record_types", ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "HTTPS"])

# Common DNS type codes
DNS_TYPE_MAP = {
    "1":   "A",
    "28":  "AAAA",
    "5":   "CNAME",
    "15":  "MX",
    "2":   "NS",
    "16":  "TXT",
    "6":   "SOA",
    "12":  "PTR",
    "65":  "HTTPS",
}

# DNS roots relevant to ignore
TRUSTED_DOH_ROOTS = set(DETECTOR_CONFIG.get("trusted_doh_roots", []))

# Tracks per-source IP per-root DNS queries in a sliding window
query_history = defaultdict(lambda: defaultdict(lambda: deque()))


# Shannon entropy - https://en.wikipedia.org/wiki/Entropy_(information_theory)
# Basically measures the randomness of a string (12dtashj.example.com > login.example.com)
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Split a domain into sublabels, root, and all labels
# abc.def.domain.com → ['abc', 'def', 'domain', 'com']
def split_labels(domain: str):
    labels = domain.strip('.').split('.')
    if len(labels) < 2:
        return [], domain, labels
    # assume root is last two labels (though not perfect for e.g. co.uk)
    sub_labels = labels[:-2]
    root = ".".join(labels[-2:])
    return sub_labels, root, labels


# Returns True if:
# 1) overall domain length is long
# 2) any label is long
# 3) any label has high entropy
# 4) record type is not in ALLOWED_RECORD_TYPES
def is_suspicious_dns(domain: str, record_type: str) -> bool:
    # Check 1
    if len(domain) >= MAX_DOMAIN_LENGTH:
        return True

    sub_labels, root, all_labels = split_labels(domain)

    # Check 2
    for lbl in all_labels:
        if len(lbl) >= MAX_LABEL_LENGTH:
            return True

    # Check 3 (see Shannon entropy above)
    for lbl in sub_labels:
        ent = shannon_entropy(lbl)
        if ent >= ENTROPY_THRESHOLD:
            return True

    # Check 4
    if record_type not in ALLOWED_RECORD_TYPES:
        # e.g. MANY NULL or unusual types == strong sign of tunneling
        return True

    return False


# Returns True if we've seen more than QUERY_RATE_THRESHOLD in the last WINDOW_SECONDS
def is_high_query_rate(src_ip: str, root: str) -> bool:
    # ignore trusted DNS roots
    if root in TRUSTED_DOH_ROOTS:
        return False

    now = time.time()
    dq = query_history[src_ip][root]

    # purge old timestamps
    while dq and (now - dq[0] > WINDOW_SECONDS):
        dq.popleft()

    # add current timestamp
    dq.append(now)

    # if we've seen more than QUERY_RATE_THRESHOLD in the last WINDOW_SECONDS
    if len(dq) > QUERY_RATE_THRESHOLD:
        return True
    return False


# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we think it’s a tunnel, else None
if not DETECTOR_CONFIG.get("enabled", True):
    def detect(packet_info: Dict) -> Optional[str]:
        return None
else:
    def detect(packet_info: Dict) -> Optional[str]:
        src_ip = packet_info.get("src_ip")
        domain = packet_info.get("dns_query", "").lower().strip(".")

        # Normalize record_type (map numeric codes back to letters)
        _raw_type = packet_info.get("record_type", "").strip()
        if _raw_type.isdigit():
            record_type = DNS_TYPE_MAP.get(_raw_type, f"UNKNOWN({_raw_type})")
        else:
            record_type = _raw_type.upper()

        if not src_ip or not domain:
            return None

        # Split into sublabels, root, and all labels
        sub_labels, root, _ = split_labels(domain)

        alerts = []

        # Rate‐based detection
        if is_high_query_rate(src_ip, root):
            alerts.append(
                f"⚠️ DNS TUNNEL-RATE: {src_ip} → {domain} (over {QUERY_RATE_THRESHOLD} q/min to {root})")

        # Pattern‐based detection
        if is_suspicious_dns(domain, record_type):
            alerts.append(
                f"⚠️ DNS TUNNEL-PATTERN: {src_ip} → {domain} ({record_type})")

        return " | ".join(alerts) if alerts else None
