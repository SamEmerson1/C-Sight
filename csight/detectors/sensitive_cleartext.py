from typing import Dict, Optional

# This is a list of the sensitive domains we want to ensure are safe
SENSITIVE_DOMAINS = {
    "facebook.com",
    "login.live.com",
    "bankofamerica.com",
    "accounts.google.com",
    "apple.com",
    # Add/adjust as needed
}

# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we detect a sensitive domain and HTTP, else None
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