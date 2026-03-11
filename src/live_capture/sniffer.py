from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        if TCP in packet:
            print(f"[TCP] {packet[IP].src} → {packet[IP].dst}")
        elif UDP in packet:
            print(f"[UDP] {packet[IP].src} → {packet[IP].dst}")

print("Starting Live Packet Capture...")

sniff(
    iface=r"\Device\NPF_{F9EE38F5-659D-4984-862E-D7905ADB40AF}",
    prn=process_packet,
    store=False
)