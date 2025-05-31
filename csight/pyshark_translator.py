import pyshark
import pytricia
import json
import ipaddress
import asyncio
import aiodns
from tqdm import tqdm
from collections import deque

# Keeps a short list of recent logs to avoid too many repeat lines.
recent_logs = deque(maxlen=10)

# Global trie for IP owner lookup
pt4 = pytricia.PyTricia(32)   # for IPv4
pt6 = pytricia.PyTricia(128)  # for IPv6

# Cache for reverse DNS lookups
reverse_dns_cache = {}

# Async DNS resolver
resolver = aiodns.DNSResolver()


# Looks up who owns an IP (if known)
async def reverse_dns(ip):
    if ip in reverse_dns_cache:
        return reverse_dns_cache[ip]
    try:
        result = await resolver.gethostbyaddr(ip)
        reverse_dns_cache[ip] = result.name
        return result.name
    except Exception:
        reverse_dns_cache[ip] = None
        return None


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
                    parsed = ipaddress.ip_network(network, strict=False)
                    if parsed.version == 4:
                        pt4[network] = label
                    else:
                        pt6[network] = label

                except Exception as e:
                    continue

    except Exception as e:
        print(f"❌ Error loading IP data: {e}")


# Looks up who owns an IP (if known)
def get_owner_by_ip(ip):
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.version == 4:
            return pt4.get(ip)
        else:
            return pt6.get(ip)
    except Exception:
        return None


# Tries to make a simple, readable line out of a packet.
async def format_packet(packet):
    # Only looking at IP (4 and 6) packets.
    if 'ip' in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
    elif 'ipv6' in packet:
        src_ip = packet.ipv6.src
        dst_ip = packet.ipv6.dst
    else:
        return None

    # TLS (often HTTPS) - uses SNI to get the hostname.
    if 'tls' in packet and hasattr(packet.tls, 'handshake_extensions_server_name'):
        hostname = packet.tls.handshake_extensions_server_name
        return f"🔐 TLS: {src_ip} → {hostname}"

    # HTTP - uses the Host header for the website name.
    if 'http' in packet and hasattr(packet.http, 'host'):
        hostname = packet.http.host
        return f"🌐 HTTP: {src_ip} → {hostname}"

    # DNS - uses the domain name in the query.
    if 'dns' in packet and hasattr(packet.dns, 'qry_name'):
        domain = packet.dns.qry_name
        return f"🧭 DNS Query: {src_ip} → looking up {domain}"

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
            if not owner:
                rdns_name = await reverse_dns(dst_ip)
                if rdns_name:
                    return f"🕵️ Reverse DNS: {src_ip} → {dst_ip} ({rdns_name})"
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

        loop = asyncio.get_event_loop()
        loop.set_exception_handler(suppress_asyncio_eoferror)

        async def process_packet(packet):
            try:
                result = await format_packet(packet)
                if result and result not in recent_logs:
                    print(result)
                    recent_logs.append(result)
            except Exception:
                pass

        for packet in capture.sniff_continuously():
            try:
                asyncio.ensure_future(process_packet(packet))
            except KeyboardInterrupt:
                break

    except KeyboardInterrupt:
        print("\n🛑 Capture stopped by user (Ctrl+C). Cleaning up...")
    except Exception as e:
        print(f"❌ Error starting capture: {e}")
        print("Check TShark install, interface name, and permissions.")


if __name__ == "__main__":
    # !!! IMPORTANT: Change "en0" if that's not your network interface.
    # Common ones: 'eth0', 'wlan0' (Linux), 'Ethernet', 'Wi-Fi' (Windows).
    load_ip_owners("csight/ipinfo_lite.json")
    start_sniff(interface="en0")
