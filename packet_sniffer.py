from scapy.all import sniff, IP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst} | Protocol: {ip_layer.proto}")
        
        payload = bytes(packet[IP].payload)[:20]
        print(f"Payload (first20 bytes): {payload}")
        print("-" * 20)

def main():
    print("Starting Packet Sniffer...")
    packet_count = 5  
    
    try:
        captured_packets = sniff(filter="ip", count=packet_count)
        
        for packet in captured_packets:
            packet_callback(packet)
        
        print("Packet Sniffer Stopped.")
    
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()




