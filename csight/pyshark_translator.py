import socket
import pyshark
import psutil
from collections import deque

recent_logs = deque(maxlen=10)

# Get the local IP address
def get_active_local_ip():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == 'AF_INET' and not addr.address.startswith("127."):
                return addr.address
    return "127.0.0.1"


# Given a PyShark packet, returns a human-readable description
def format_packet(packet):
    # Check if the packet has an IP layer for sorting
    if 'ip' in packet:
        src = resolve_hostname(packet.ip.src)
        dst = resolve_hostname(packet.ip.dst)

        # Secure web browsing
        if 'tls' in packet and hasattr(packet.tls, 'handshake_extensions_server_name'):
            hostname = packet.tls.handshake_extensions_server_name
            return f"🔐 {src} is connecting to {hostname} securely."

        # Regular web browsing
        elif 'http' in packet and hasattr(packet.http, 'host'):
            hostname = packet.http.host
            return f"🌐 {src} is connecting to {hostname} insecurely."


        # SSH connection
        elif 'ssh' in packet or (packet.transport_layer == 'TCP' and packet[packet.transport_layer].dstport == '22'):
            return f"🔑 {src} is attempting to remotely access {dst} via SSH."
    
    # Fallback
    return None

# Start sniffing packets
def start_sniff(interface='en0'):
    capture = pyshark.LiveCapture(interface=interface)
    print("🔍 C-Sight: Listening for traffic...\n")

    # Continuously sniff packets (unless interrupted)
    for packet in capture.sniff_continuously():
        try:
            result = format_packet(packet)
            if result and result not in recent_logs:
                print(result)
                recent_logs.append(result)
        except Exception:
            continue
        
LOCAL_IP = get_active_local_ip()

# Given an IP address, returns its hostname
def resolve_hostname(ip):
    local_ip = socket.gethostbyname(socket.gethostname())
    if ip == LOCAL_IP:
        return "This device"

    elif ip.startswith("10.") or ip.startswith("192.168."):
        return "Another device on your network"

    return ip  # Don't even try reverse DNS (too slow)


# Run directly
if __name__ == "__main__":
    start_sniff(interface="en0")
