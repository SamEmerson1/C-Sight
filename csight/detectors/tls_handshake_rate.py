# detectors/tls_handshake_rate.py
import time
from collections import defaultdict, deque
from typing import Dict, Optional

# Settings
WINDOW = 10  # seconds
RATE_THRESHOLD = 20  # handshakes in time window

tls_activity = defaultdict(lambda: deque())

# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we are getting a high TLS handshake rate, else None
def detect(packet_info: Dict) -> Optional[str]:
    if packet_info.get("protocol") != "TLS":
        return None

    src_ip = packet_info.get("src_ip")
    if not src_ip:
        return None

    now = time.time()
    dq = tls_activity[src_ip]

    # purge old
    while dq and (now - dq[0] > WINDOW):
        dq.popleft()

    dq.append(now)

    if len(dq) > RATE_THRESHOLD:
        return f"🚨 HIGH TLS HANDSHAKE RATE: {src_ip} initiated {len(dq)} TLS connections in {WINDOW}s"

    return None
