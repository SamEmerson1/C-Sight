import socket
import pyshark
from collections import deque

# Keeps a short list of recent logs to avoid too many repeat lines.
recent_logs = deque(maxlen=10)

# Just returns the IP address as a string.
def resolve_hostname(ip):
    return str(ip)

# Tries to make a simple, readable line out of a packet.
def format_packet(packet):
    # Only looking at IP packets.
    if 'ip' not in packet:
        return None

    src_ip = resolve_hostname(packet.ip.src)
    dst_ip = resolve_hostname(packet.ip.dst)

    # TLS (often HTTPS) - uses SNI to get the hostname.
    if 'tls' in packet and hasattr(packet.tls, 'handshake_extensions_server_name'):
        hostname = packet.tls.handshake_extensions_server_name
        return f"🔐 TLS: {src_ip} → {hostname}"

    # HTTP - uses the Host header for the website name.
    if 'http' in packet and hasattr(packet.http, 'host'):
        hostname = packet.http.host
        return f"🌐 HTTP: {src_ip} → {hostname}"

    # SSH - checks for the protocol or TCP port 22.
    is_ssh_protocol = 'ssh' in packet
    is_ssh_port = False
    if packet.transport_layer == 'TCP':
        if hasattr(packet.tcp, 'dstport') and packet.tcp.dstport == '22':
            is_ssh_port = True
        elif hasattr(packet.tcp, 'srcport') and packet.tcp.srcport == '22': # For SSH server replies
            is_ssh_port = True
            
    if is_ssh_protocol or is_ssh_port:
        return f"🔑 SSH: {src_ip} → {dst_ip}"

    return None


# Starts sniffing packets.
def start_sniff(interface='en0'): # Default interface is 'en0' (common for macOS).
    # Make sure TShark is installed and your interface name is correct.
    # You might need admin/sudo rights.
    try:
        capture = pyshark.LiveCapture(interface=interface)
        print(f"🔍 Listening for HTTPS, HTTP, and SSH traffic on {interface}...\n(Press Ctrl+C to stop)\n")

        for packet in capture.sniff_continuously():
            try:
                result = format_packet(packet)
                if result and result not in recent_logs:
                    print(result)
                    recent_logs.append(result)
            except AttributeError:
                # Some packets might not have all the bits we expect.
                continue
            except Exception:
                # General catch for other packet processing issues.
                continue
                
    except Exception as e: # For issues like wrong interface or permissions.
        print(f"Error starting capture: {e}")
        print("Check TShark install, interface name, and permissions.")


if __name__ == "__main__":
    # !!! IMPORTANT: Change "en0" if that's not your network interface.
    # Common ones: 'eth0', 'wlan0' (Linux), 'Ethernet', 'Wi-Fi' (Windows).
    start_sniff(interface="en0")