from scapy.all import sniff, IP

# List of blocked IPs (you can add more)
blocked_ips = ["192.168.1.100", "10.0.0.1"]

def packet_filter(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in blocked_ips or dst_ip in blocked_ips:
            print(f"[BLOCKED] Packet from {src_ip} to {dst_ip}")
        else:
            print(f"[ALLOWED] Packet from {src_ip} to {dst_ip}")

# Start sniffing packets (requires admin/root)
print("Firewall started... Press CTRL+C to stop.")
sniff(prn=packet_filter, store=0)