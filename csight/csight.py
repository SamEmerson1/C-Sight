from scapy.all import sniff, IP, TCP, UDP, ICMP
from csight.scrapy_translator import translate

# Runs for each captured packet. Filters only IP traffic.
def handle_packet(packet):
    # Grab source and destination IPs from the IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Determine transport-level protocol
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "Other"
        
        # Send to translator to turn into plain-English summary
        summary = translate(packet)
        print(f"🧠 {summary}")


# Start sniffing packets from the network
sniff(
    iface="en0",       # Using Wi-Fi interface on a Mac
    prn=handle_packet, # Call this function on each packet
    store=0            # Avoiding storing packets on memory
)
