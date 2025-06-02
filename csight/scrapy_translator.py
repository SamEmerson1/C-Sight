# DEPRECATED in favor of pyshark

from scapy.all import IP, TCP, UDP, ICMP, DNS
import socket
import platform

# Local hostname
LOCAL_HOSTNAME = platform.node()


# Given a raw packet, returns a human-readable description of what’s happening
def translate(packet):
    if IP in packet:
        src = simplify_hostname(resolve_hostname(packet[IP].src))
        dst = simplify_hostname(resolve_hostname(packet[IP].dst))

        # Secure web browsing (HTTPS)
        if TCP in packet and packet[TCP].dport == 443:
            return f"{src} is browsing a secure website hosted by {dst}."

        # Regular web browsing (HTTP)
        elif TCP in packet and packet[TCP].dport == 80:
            return f"{src} is browsing a non-secure website hosted by {dst}."

        # DNS request (e.g., translating a domain name to an IP)
        elif UDP in packet and packet[UDP].dport == 53 and packet.haslayer('DNS') and packet['DNS'].qd:
            try:
                domain = packet['DNS'].qd.qname.decode()
                return f"{src} is trying to resolve {domain} (DNS lookup)."
            except:
                return f"{src} sent a DNS request to {dst}, but we couldn't read the domain."

        # SSH connection
        elif TCP in packet and packet[TCP].dport == 22:
            return f"{src} is trying to remotely access {dst} via SSH."

        # ICMP ping (e.g., checking if a host is alive)
        elif ICMP in packet:
            return f"{src} is pinging {dst}."

        # Catch-all
        elif TCP in packet or UDP in packet:
            return f"{src} is communicating with {dst} using {packet.summary().split()[0]}."

        # Fallback
        else:
            return f"{src} is talking to {dst} using an unknown protocol."


# Given an IP address, returns its hostname
def resolve_hostname(ip):
    if ip.startswith("10.") or ip.startswith("192.168."):
        return LOCAL_HOSTNAME  # Local network, so just return the local hostname
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip  # If lookup fails, just return the original IP


# Given a hostname, returns a simplified version
def simplify_hostname(hostname):
    KNOWN_SERVICES = {
        "youtube.com": "YouTube",
        "googleusercontent.com": "Google Cloud",
        "1e100.net": "Google",
        "netflix.com": "Netflix",
        "icloud.com": "Apple iCloud",
        "microsoft.com": "Microsoft",
        "akamai.net": "Akamai CDN",
    }

    # If it's one of the known services, replace it with a friendly label
    for key in KNOWN_SERVICES:
        if key in hostname:
            return KNOWN_SERVICES[key]

    # Don't simplify local or numeric hostnames (like 10.0.0.206 or *.local)
    if hostname.startswith("10.") or hostname.endswith(".local"):
        return hostname

    return hostname.split('.')[0]
