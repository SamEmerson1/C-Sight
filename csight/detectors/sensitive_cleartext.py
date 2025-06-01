from typing import Dict, Optional
from config import load_config

CONFIG = load_config()

DETECTOR_CONFIG = CONFIG.get("detectors", {}).get("sensitive_cleartext", {})

# This is a list of the sensitive domains we want to ensure are safe
SENSITIVE_DOMAINS = set(DETECTOR_CONFIG.get("sensitive_domains", []))

# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we detect a sensitive domain and HTTP, else None
if not DETECTOR_CONFIG.get("enabled", True):
    def detect(packet_info: Dict) -> Optional[str]:
        return None
else:
    def detect(packet_info: Dict) -> Optional[str]:
        if packet_info.get("protocol") != "HTTP":
            return None

        hostname = packet_info.get("http_host", "").lower().strip()
        if not hostname:
            return None

        # Match if any sensitive domain is contained in the hostname (subdomains included)
        for sensitive in SENSITIVE_DOMAINS:
            if sensitive in hostname:
                return f"🚨 CLEARTEXT HTTP to sensitive domain: {hostname}"

        return None


# This is the test I ran for sensitive_cleartext to make sure it was working
# Uncomment to test
'''
fake_packet = {
    "protocol": "HTTP",
    "http_host": "login.live.com"
}
print(detect(fake_packet))  # Should alert
'''
