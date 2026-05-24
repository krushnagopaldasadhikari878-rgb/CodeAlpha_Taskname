# Import required modules from Scapy
# Scapy is used for capturing and analyzing network packets
from scapy.all import sniff, IP, TCP, UDP, ICMP


# This function will process each captured packet
def process_packet(packet):

    # Check if the packet has an IP layer (basic requirement for network communication)
    if packet.haslayer(IP):

        # Extract IP layer information
        ip_layer = packet[IP]

        # Get source and destination IP addresses
        source_ip = ip_layer.src
        dest_ip = ip_layer.dst

        # Default protocol label
        protocol = "Other"

        # Initialize payload variable
        payload = b""

        print("\n==============================")

        # Display source and destination IPs
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {dest_ip}")

        # Check if packet uses TCP protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
            payload = bytes(packet[TCP].payload)  # Extract TCP payload

        # Check if packet uses UDP protocol
        elif packet.haslayer(UDP):
            protocol = "UDP"
            payload = bytes(packet[UDP].payload)  # Extract UDP payload

        # Check if packet uses ICMP protocol
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            payload = bytes(packet[ICMP].payload)  # Extract ICMP payload

        # Print detected protocol
        print(f"Protocol: {protocol}")

        # ---------------- PAYLOAD HANDLING ----------------
        # Try to convert payload into readable text (UTF-8)
        # If it fails, show HEX format instead

        if payload:
            try:
                readable_payload = payload.decode("utf-8")  # Convert bytes to text
                print(f"Payload: {readable_payload}")

            except:
                # If payload is not readable (encrypted/binary), show HEX format
                print(f"Payload (HEX): {payload.hex()}")

        else:
            print("Payload: None")


# Start message for user
print("Starting Network Sniffer... (Press CTRL+C to stop)\n")

# sniff() function captures live network packets
# prn=process_packet → sends each packet to our function
# store=False → prevents saving packets in memory (saves RAM)
sniff(prn=process_packet, store=False)