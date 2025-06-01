import time
from collections import defaultdict, deque
from typing import Dict, Optional

# Constants - Tune as needed
WINDOW_SECONDS = 60
NXDOMAIN_THRESHOLD = 20

# History of NXDOMAINs per source IP
nxdomain_history = defaultdict(lambda: deque())

# Common domains to ignore
TRUSTED_FAILURES = {
    "example.local",
    "internal.lan",
    # Add/adjust as needed
}

# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we detect an NXDOMAIN spike, else None
def detect(packet_info: Dict) -> Optional[str]:
    if (
        packet_info.get("protocol") != "DNS" or
        not packet_info.get("is_response", False) or
        packet_info.get("rcode") != "3"
    ):
        return None

    src_ip = packet_info.get("src_ip")
    domain = packet_info.get("query_name", "").lower().strip(".")
    rcode = packet_info.get("rcode")

    # We're only interested in NXDOMAIN (rcode 3)
    if rcode != "3" or not src_ip or not domain:
        return None

    if domain in TRUSTED_FAILURES:
        return None

    now = time.time()
    dq = nxdomain_history[src_ip]

    # Purge old NXDOMAINs outside our window
    while dq and (now - dq[0][1] > WINDOW_SECONDS):
        dq.popleft()

    # Record this NXDOMAIN
    dq.append((domain, now))

    # Check if we've passed the threshold
    if len(dq) > NXDOMAIN_THRESHOLD:
        unique_domains = {entry[0] for entry in dq}
        return (
            f"⚠️ NXDOMAIN SPIKE: {src_ip} triggered {len(dq)} NXDOMAINs in {WINDOW_SECONDS}s "
            f"({len(unique_domains)} unique domains)"
        )

    return None

# Because the packet capture stack is dropping responses, this is the code that I ran to test
# Uncomment it to test for yourself (might have to adjust the threshold)
'''
fake_packet = {
    "protocol": "DNS",
    "src_ip": "192.168.1.2",
    "rcode": "3",
    "is_response": True
}

# Feed 10 unique NXDOMAIN domains
for i in range(10):
    packet = fake_packet.copy()
    packet["query_name"] = f"fake{i}.test"
    result = detect(packet)
    if result:
        print(result)
'''
