import time
from collections import defaultdict, deque
from typing import Dict, Optional

# Settings
WINDOW_SECONDS = 60
MAX_UNIQUE_DESTINATIONS = 30

# Tracks per-source IP QUIC destinations in a sliding window
quic_history = defaultdict(lambda: deque())

# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we think it’s abnormal, else None
def detect(packet_info: Dict) -> Optional[str]:
    if packet_info.get("protocol") != "QUIC":
        return None

    src_ip = packet_info.get("src_ip")
    dst_ip = packet_info.get("dst_ip")

    if not src_ip or not dst_ip:
        return None

    now = time.time()
    dq = quic_history[src_ip]

    # Remove old entries
    while dq and (now - dq[0][1] > WINDOW_SECONDS):
        dq.popleft()

    # Add current dst_ip + timestamp
    dq.append((dst_ip, now))

    # Check how many unique destinations in this window
    unique_dsts = {entry[0] for entry in dq}
    if len(unique_dsts) > MAX_UNIQUE_DESTINATIONS:
        return f"⚠️ ABNORMAL QUIC: {src_ip} contacted {len(unique_dsts)} unique IPs in {WINDOW_SECONDS}s"

    return None
