# detectors/tls_handshake_rate.py
import time
from collections import defaultdict, deque
from typing import Dict, Optional
from config import load_config

CONFIG = load_config()

DETECTOR_CONFIG = CONFIG.get("detectors", {}).get("tls_handshake_rate", {})

# Constants - Tune as needed
WINDOW_SECONDS = DETECTOR_CONFIG.get("window", 10)
RATE_THRESHOLD = DETECTOR_CONFIG.get("threshold", 20)

# History of TLS connections per source IP
tls_activity = defaultdict(lambda: deque())


# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we are getting a high TLS handshake rate, else None
if not DETECTOR_CONFIG.get("enabled", True):
    def detect(packet_info: Dict) -> Optional[str]:
        return None
else:
    def detect(packet_info: Dict) -> Optional[str]:
        if packet_info.get("protocol") != "TLS":
            return None

        src_ip = packet_info.get("src_ip")
        if not src_ip:
            return None

        now = time.time()
        dq = tls_activity[src_ip]

        # purge old
        while dq and (now - dq[0] > WINDOW_SECONDS):
            dq.popleft()

        dq.append(now)

        if len(dq) > RATE_THRESHOLD:
            return f"🚨 HIGH TLS HANDSHAKE RATE: {src_ip} initiated {len(dq)} TLS connections in {WINDOW_SECONDS}s"

        return None
