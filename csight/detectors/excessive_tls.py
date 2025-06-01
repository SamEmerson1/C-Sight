import time
from collections import defaultdict, deque
from urllib.parse import urlparse
from typing import Dict, Optional

WINDOW = 30  # seconds
THRESHOLD = 15  # unique domains in time window

connection_history = defaultdict(lambda: deque())


# Given a hostname, returns the root domain
def get_domain_root(hostname: str) -> str:
    parts = hostname.lower().strip().split('.')
    if len(parts) >= 2:
        return ".".join(parts[-2:])  # crude but works
    return hostname


# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we've received "spammy" TLS connections, else None
def detect(packet_info: Dict) -> Optional[str]:
    if packet_info.get("protocol") != "TLS":
        return None

    src_ip = packet_info.get("src_ip")
    hostname = packet_info.get("tls_sni", "").lower().strip()

    if not src_ip or not hostname:
        return None

    root = get_domain_root(hostname)
    now = time.time()
    dq = connection_history[src_ip]

    # purge old
    while dq and (now - dq[0][1] > WINDOW):
        dq.popleft()

    # log current
    dq.append((root, now))

    # count unique roots in window
    unique = {entry[0] for entry in dq}
    if len(unique) > THRESHOLD:
        return f"⚠️ EXCESSIVE THIRD-PARTY TLS: {src_ip} hit {len(unique)} domains in {WINDOW}s"
    
    return None