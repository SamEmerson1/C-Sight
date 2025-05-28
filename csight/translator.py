from scapy.all import IP, TCP, UDP, ICMP, DNS
import socket


# Given a raw packet, returns a human-readable description of what’s happening
def translate(packet):
    if IP in packet:
        src = resolve_hostname(packet[IP].src)
        dst = resolve_hostname(packet[IP].dst)

        # Secure web browsing (HTTPS)
        if TCP in packet and packet[TCP].dport == 443:
            return f"{src} is browsing a secure website hosted by {dst}."
        
        # Regular web browsing (HTTP)
        elif TCP in packet and packet[TCP].dport == 80:
            return f"{src} is browsing a non-secure website hosted by {dst}."
        
        # DNS request (e.g., translating a domain name to an IP)
        elif UDP in packet and packet[UDP].dport == 53:
            return f"{src} is requesting DNS info from {dst}."
        
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
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip  # If lookup fails, just return the original IP

