from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
import sqlite3, time
from risk_engine import score_event   # uses NIST SP 800-30 scoring

DB = "network_logs.db"

def log_packet(pkt):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    src = pkt[IP].src if IP in pkt else "UNKNOWN"
    dst = pkt[IP].dst if IP in pkt else "UNKNOWN"

    proto, details, alert_type = "OTHER", "", None

    if TCP in pkt:
        proto = "TCP"
        if pkt[TCP].flags & 0x02:  # SYN
            details = "TCP SYN"
            alert_type = "SYN_FLOOD"
    elif UDP in pkt:
        proto = "UDP"
        if DNS in pkt:
            proto = "DNS"
            details = "DNS query/response"
            alert_type = "DNS_FLOOD"
        else:
            details = "UDP packet"
            alert_type = "UDP_FLOOD"
    elif ICMP in pkt:
        proto = "ICMP"
        details = "ICMP echo/request"
        alert_type = "ICMP_SWEEP"

    # Save packet data
    with sqlite3.connect(DB, timeout=5) as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO packets (timestamp, src_ip, dest_ip, protocol, details) VALUES (?, ?, ?, ?, ?)",
            (ts, src, dst, proto, details)
        )
        conn.commit()

    # Apply NIST risk scoring
    if alert_type:
        score_event(ts, src, dst, alert_type, notes=details)

def start_logger(iface, count=0, timeout=None):
    print(f"[+] Packet logger started on {iface}...")
    sniff(iface=iface, prn=log_packet, store=False, count=count, timeout=timeout)
    print("[+] Packet logger stopped.")

if __name__ == "__main__":
    from secrets_loader import MY_IFACE
    start_logger(MY_IFACE)
