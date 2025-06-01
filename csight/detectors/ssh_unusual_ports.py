from typing import Optional, Dict

# Define known safe SSH ports (if any)
KNOWN_SSH_PORTS = {22}


# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if we are getting a weird SSH port connection, else None
def detect(packet_info: Dict) -> Optional[str]:
    if packet_info.get("protocol") != "SSH":
        return None

    src_port = int(packet_info.get("src_port", -1))
    dst_port = int(packet_info.get("dst_port", -1))

    if src_port not in KNOWN_SSH_PORTS and dst_port not in KNOWN_SSH_PORTS:
        return f"🚨 SSH traffic on unusual port! {packet_info['src_ip']}:{src_port} → {packet_info['dst_ip']}:{dst_port}"

    return None

# Another quick test to make sure it's working
# Uncomment to test
'''
packet1 = {
    "protocol": "SSH",
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.1",
    "src_port": "50234",
    "dst_port": "22",
}
print(detect(packet1))  # Not flagged

# Expected: YES alert (weird port 2222)
packet2 = {
    "protocol": "SSH",
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.1",
    "src_port": "50234",
    "dst_port": "2222",
}
print(detect(packet2)) # Flagged
'''