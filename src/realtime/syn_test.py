from scapy.all import IP, TCP, send

target = "127.0.0.1"
sport = 44444
dport = 3000   # or 5000 (running local service)

pkt = IP(dst=target)/TCP(sport=sport, dport=dport, flags="S")
send(pkt, count=300, inter=0.002, verbose=0)


#$env:IDS_INTERFACE="\Device\NPF_Loopback"
#$env:IDS_BPF_FILTER="tcp"
#$env:IDS_SYN_THRESHOLD="8"
#$env:IDS_SYN_MIN_PACKETS="8"
#$env:IDS_SYN_ACK_MAX="9999"
#python src\live_capture\live_flow_ids.py
