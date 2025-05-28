from scapy.all import sniff, IP

# Callback function that gets run for each packet captured
def handle_packet(packet):
    # Only processing packets that have an IP layer
    if IP in packet:
        src_ip = packet[IP].src   # Source IP
        dst_ip = packet[IP].dst   # Destination IP

        print(f"📦 Packet: {src_ip} → {dst_ip}")

# Start sniffing packets from the network
sniff(
    iface="en0",       # Using Wi-Fi interface on a Mac
    prn=handle_packet, # Call this function on each packet
    store=0            # Avoiding storing packets on memory
)
