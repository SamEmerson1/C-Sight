import pyshark

# Human-readable label matcher (basic keyword check)
def categorize_hostname(hostname):
    keyword_map = {
        "youtube.com": "Streaming",
        "netflix.com": "Streaming",
        "google.com": "Search",
        "gstatic.com": "Google Services",
        "googleusercontent.com": "Google Cloud",
        "microsoft.com": "Productivity",
        "office365.com": "Productivity",
        "slack.com": "Communication",
        "icloud.com": "Apple Cloud",
        "akamai": "CDN",
        "github.com": "Developer Platform",
    }

    for keyword in keyword_map:
        if keyword in hostname:
            return keyword_map[keyword]

    return "Uncategorized"

# Given a PyShark packet, returns a human-readable description
def format_packet(packet):
    # Check if the packet has an IP layer for sorting
    if 'ip' in packet:
        src = packet.ip.src
        dst = packet.ip.dst
        protocol = packet.highest_layer

        # Secure web browsing
        if 'tls' in packet and hasattr(packet.tls, 'handshake_extensions_server_name'):
            hostname = packet.tls.handshake_extensions_server_name
            category = categorize_hostname(hostname)
            return f"🔐 {src} is connecting to {hostname} ({category}) over TLS."

        # Regular web browsing
        elif 'http' in packet and hasattr(packet.http, 'host'):
            hostname = packet.http.host
            category = categorize_hostname(hostname)
            return f"🌐 {src} is browsing {hostname} ({category}) over HTTP."

        # SSH connection
        elif 'ssh' in packet or (packet.transport_layer == 'TCP' and packet[packet.transport_layer].dstport == '22'):
            return f"🔑 {src} is attempting an SSH connection to {dst}."
        
        # Catch-all
        return None
    
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
            if result:
                print(result)
        except Exception:
            continue

# Run directly
if __name__ == "__main__":
    start_sniff(interface="en0")
