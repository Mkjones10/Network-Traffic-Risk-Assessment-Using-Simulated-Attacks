from scapy.all import Ether, IP, ICMP, sendp
from secrets_loader import MY_IP, MY_MAC, MY_IFACE

def main(base_ip="10.0.0.", sweep_range=range(90,96)):
    print("[+] Starting ICMP Sweep...")
    ether = Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff")
    for i in sweep_range:
        ip = IP(dst=f"{base_ip}{i}")
        icmp = ICMP()
        pkt = ether / ip / icmp
        sendp(pkt, iface=MY_IFACE, verbose=False)
    print("[+] ICMP Sweep complete")

if __name__ == "__main__":
    main()
