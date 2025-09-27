from scapy.all import Ether, IP, TCP, Raw, sendp
import random
from secrets_loader import MY_IP, MY_MAC, MY_IFACE

def main(target_ip=MY_IP, target_port=443):
    print(f"[+] Sending Weak TLS ClientHello to {target_ip}:{target_port}")
    ether = Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(dst=target_ip)
    tcp = TCP(sport=random.randint(1024,65535), dport=target_port, flags="PA", seq=1000, ack=0)
    # Fake weak TLSv1.0 ClientHello (not full TLS, just visible in Wireshark)
    clienthello = Raw(b"\x16\x03\x01\x00\x2e" + b"\x01" * 45)
    pkt = ether / ip / tcp / clienthello
    sendp(pkt, iface=MY_IFACE, verbose=False)
    print("[+] TLS Weak ClientHello sent")

if __name__ == "__main__":
    main()
