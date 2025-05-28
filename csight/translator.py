from scapy.all import IP, TCP, UDP, ICMP, DNS

# Given a raw packet, returns a human-readable description of what’s happening
def translate(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        # Secure web browsing (HTTPS)
        if TCP in packet and packet[TCP].dport == 443:
            return f"{src} is browsing a secure website (HTTPS)."
        
        # DNS request (e.g., translating a domain name to an IP)
        elif UDP in packet and packet[UDP].dport == 53:
            return f"{src} is requesting DNS info from {dst}."
        
        # ICMP ping (e.g., checking if a host is alive)
        elif ICMP in packet:
            return f"{src} is pinging {dst}."
        
        # Fallback for anything else
        else:
            return f"{src} is communicating with {dst} via {packet.proto}."
