from scapy.all import Ether, IP, TCP, Raw, sendp
import random
from secrets_loader import MY_IP, MY_MAC, MY_IFACE

def main(target_ip=MY_IP, target_port=21):
    print(f"[+] Sending FTP Anonymous Login packets to {target_ip}:{target_port}")
    ether = Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff")

    # USER anonymous
    ip = IP(dst=target_ip)
    tcp = TCP(sport=random.randint(1024,65535), dport=target_port, flags="PA", seq=1000, ack=0)
    payload1 = Raw(b"USER anonymous\r\n")
    pkt1 = ether / ip / tcp / payload1
    sendp(pkt1, iface=MY_IFACE, verbose=False)

    # PASS test@example.com
    tcp.seq += len(payload1.load)
    payload2 = Raw(b"PASS test@example.com\r\n")
    pkt2 = ether / ip / tcp / payload2
    sendp(pkt2, iface=MY_IFACE, verbose=False)

    print("[+] FTP Anonymous packets sent")

if __name__ == "__main__":
    main()
