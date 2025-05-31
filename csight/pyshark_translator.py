import os
import pyshark
import pytricia
import json
import ipaddress
import time
import datetime
import asyncio
import aiodns
from tqdm import tqdm


# Global trie for IP owner lookup
pt4 = pytricia.PyTricia(32)   # for IPv4
pt6 = pytricia.PyTricia(128)  # for IPv6

# Cache for reverse DNS lookups
reverse_dns_cache = {}

# Async DNS resolver
resolver = aiodns.DNSResolver()

# Stores recent sessions to suppress duplicate logs
# key: (src_ip, dst_ip, port, protocol)
# value: last_seen timestamp
active_sessions = {}
SESSION_TTL = 60  # seconds

# DNS-specific session tracking
active_dns_queries = {}
DNS_SESSION_TTL = 10  # seconds


# Stores all formatted log lines
session_logs = []


# Checks if a session is new
def is_new_session(src_ip, dst_ip, port, protocol):
    now = time.time()
    key = (src_ip, dst_ip, port, protocol)

    # Remove expired sessions
    expired_keys = [k for k, v in active_sessions.items()
                    if now - v > SESSION_TTL]
    for k in expired_keys:
        del active_sessions[k]

    # Check if session is new
    if key in active_sessions:
        return False  # Already seen
    else:
        active_sessions[key] = now
        return True


# Checks if a DNS query is new
def is_new_dns_query(src_ip, domain):
    now = time.time()
    key = (src_ip, domain, "DNS")

    # Remove expired DNS entries
    expired_keys = [k for k, v in active_dns_queries.items()
                    if now - v > DNS_SESSION_TTL]
    for k in expired_keys:
        del active_dns_queries[k]

    # Check if this domain lookup was already logged
    if key in active_dns_queries:
        return False
    else:
        active_dns_queries[key] = now
        return True


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
        if is_new_session(src_ip, dst_ip, 443, "TLS"):
            return f"🔐 TLS: {src_ip} → {hostname}"

    # HTTP - uses the Host header for the website name.
    if 'http' in packet and hasattr(packet.http, 'host'):
        hostname = packet.http.host
        if is_new_session(src_ip, dst_ip, 80, "HTTP"):
            return f"🌐 HTTP: {src_ip} → {hostname}"

    # DNS - uses the domain name in the query.
    if 'dns' in packet and hasattr(packet.dns, 'qry_name'):
        domain = packet.dns.qry_name
        if is_new_dns_query(src_ip, domain):
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
        if is_new_session(src_ip, dst_ip, 22, "SSH"):
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
            if is_new_session(src_ip, dst_ip, 443, "QUIC"):
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

        last_log_time = time.time()
        packet_counter = 0

        async def heartbeat():
            while True:
                await asyncio.sleep(10)
                since = int(time.time() - last_log_time)
                print(
                    f"📡 Still listening... ({since}s since last packet, total: {packet_counter})")

        heartbeat_task = loop.create_task(heartbeat())

        # Processes each packet.
        async def process_packet(packet):
            nonlocal last_log_time, packet_counter
            try:
                result = await format_packet(packet)
                if result:
                    print(result)
                    session_logs.append(result)
                    last_log_time = time.time()
                    packet_counter += 1
            except Exception:
                pass

        for packet in capture.sniff_continuously():
            try:
                asyncio.ensure_future(process_packet(packet))
            except KeyboardInterrupt:
                break

    except KeyboardInterrupt:
        print("\n🛑 Capture stopped by user (Ctrl+C). Cleaning up...")
        heartbeat_task.cancel()
        try:
            loop.run_until_complete(heartbeat_task)
        except asyncio.CancelledError:
            pass
        prompt_save_log()

    except Exception as e:
        print(f"❌ Error starting capture: {e}")
        print("Check TShark install, interface name, and permissions.")


# Asks the user if they want to save the log to a file.
def prompt_save_log():
    choice = input("💾 Save log to file? (y/n): ").strip().lower()
    if choice == 'y':
        # Create the "logs" directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"logs/log_{timestamp}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(session_logs))
        print(f"✅ Log saved to {filename}")
    else:
        print("🚫 Log not saved.")


if __name__ == "__main__":
    # !!! IMPORTANT: Change "en0" if that's not your network interface.
    # Common ones: 'eth0', 'wlan0' (Linux), 'Ethernet', 'Wi-Fi' (Windows).
    load_ip_owners("csight/ipinfo_lite.json")
    start_sniff(interface="en0")
