import pyshark
import pytricia
import json
import asyncio
from tqdm import tqdm
from collections import deque

# Keeps a short list of recent logs to avoid too many repeat lines.
recent_logs = deque(maxlen=10)

# Global trie for IP owner lookup
ip_trie = pytricia.PyTricia()

filename = "ipinfo_lite.json"


# Suppress EOFError on shutdown
def suppress_asyncio_eoferror(loop, context):
    if "exception" in context and isinstance(context["exception"], EOFError):
        return  # Silently ignore EOFError after capture shutdown
    loop.default_exception_handler(context)


# Loads CIDR → Org info from ipinfo_lite.json
def load_ip_owners(filepath="ipinfo_lite.json"):
    try:
        # Count the number of lines in the file
        with open(filepath, "r", encoding="utf-8") as f:
            total_lines = sum(1 for _ in f)

        with open(filepath, "r", encoding="utf-8") as f:
            for line in tqdm(f, total=total_lines, desc="📦 Loading IP database"):
                try:
                    entry = json.loads(line)
                    network = entry.get("network")
                    org = entry.get("as_name", "Unknown Org")
                    domain = entry.get("as_domain", "unknown.com")
                    label = f"{org} ({domain})"
                    ip_trie[network] = label
                except Exception:
                    continue  # Skip malformed lines

        print(f"\n✅ Loaded {len(ip_trie)} IP ownership entries.")

    except Exception as e:
        print(f"❌ Error loading IP data: {e}")


# Looks up who owns an IP (if known)
def get_owner_by_ip(ip):
    try:
        return ip_trie[ip]
    except KeyError:
        return None


# Tries to make a simple, readable line out of a packet.
def format_packet(packet):
    # Only looking at IP packets.
    if 'ip' not in packet:
        return None

    src_ip = packet.ip.src
    dst_ip = packet.ip.dst

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
        elif hasattr(packet.tcp, 'srcport') and packet.tcp.srcport == '22':  # For SSH server replies
            is_ssh_port = True

    if is_ssh_protocol or is_ssh_port:
        return f"🔑 SSH: {src_ip} → {dst_ip}"

    # QUIC - often used for HTTP/3, encrypted, usually on UDP port 443.
    if 'udp' in packet:
        if hasattr(packet.udp, 'dstport') and packet.udp.dstport == '443':
            owner = get_owner_by_ip(dst_ip)
            label = f"{dst_ip} ({owner})" if owner else dst_ip
            return f"🌀 QUIC: {src_ip} → {label} (UDP 443)"

    return None


# Starts sniffing packets.
# Default interface is 'en0' (common for macOS).
def start_sniff(interface='en0'):
    # Make sure TShark is installed and your interface name is correct.
    # You might need admin/sudo rights.
    try:
        capture = pyshark.LiveCapture(interface=interface)
        print(
            f"🔍 Listening for HTTPS, HTTP, SSH and QUIC traffic on {interface}...\n(Press Ctrl+C to stop)\n")

        try:
            for packet in capture.sniff_continuously():
                # Set the handler immediately
                asyncio.get_event_loop().set_exception_handler(suppress_asyncio_eoferror)
                try:
                    result = format_packet(packet)
                    if result and result not in recent_logs:
                        print(result)
                        recent_logs.append(result)
                except AttributeError:
                    continue
                except Exception:
                    continue

        except KeyboardInterrupt:
            print("\n🛑 Capture stopped by user (Ctrl+C). Cleaning up...")
        finally:
            try:
                capture.close()
            except Exception:
                pass  # Suppress EOFError on shutdown

    except Exception as e:
        print(f"❌ Error starting capture: {e}")
        print("Check TShark install, interface name, and permissions.")


if __name__ == "__main__":
    # !!! IMPORTANT: Change "en0" if that's not your network interface.
    # Common ones: 'eth0', 'wlan0' (Linux), 'Ethernet', 'Wi-Fi' (Windows).
    load_ip_owners("csight/ipinfo_lite.json")
    start_sniff(interface="en0")
