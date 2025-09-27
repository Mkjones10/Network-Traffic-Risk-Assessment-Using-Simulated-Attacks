from packet_logger import start_logger
from risk_engine import score_event
from secrets_loader import MY_IP, MY_IFACE
import threading, time
import attacks.syn_flood as syn
import attacks.udp_flood as udp
import attacks.ping_sweep as ping
import attacks.slowloris as slow
import attacks.dns_flood as dns
import attacks.ftp_anonymous as ftp
import attacks.tls_weakcheck as tls

def main():
    print("[*] Running all simulated attacks...")

    # Start packet logger in background
    logger_thread = threading.Thread(target=start_logger, args=(MY_IFACE,), daemon=True)
    logger_thread.start()
    time.sleep(2)  # warm-up

    # SYN Flood
    syn.main(MY_IP, 8080)
    score_event(time.strftime("%Y-%m-%d %H:%M:%S"), "ATTACKER", MY_IP, "SYN_FLOOD", notes="Finished SYN Flood")

    # UDP Flood
    udp.main(MY_IP, 8080)
    score_event(time.strftime("%Y-%m-%d %H:%M:%S"), "ATTACKER", MY_IP, "UDP_FLOOD", notes="Finished UDP Flood")

    # ICMP Sweep
    base_ip = ".".join(MY_IP.split(".")[:3]) + "."
    ping.main(base_ip, range(90, 96))
    score_event(time.strftime("%Y-%m-%d %H:%M:%S"), "ATTACKER", MY_IP, "ICMP_SWEEP", notes="Finished ICMP sweep")

    # Slowloris
    slow.main(MY_IP, 8080)  # unchanged
    score_event(time.strftime("%Y-%m-%d %H:%M:%S"), "ATTACKER", MY_IP, "SLOWLORIS", notes="Finished Slowloris")

    # DNS Flood
    dns.main(MY_IP, 53)
    score_event(time.strftime("%Y-%m-%d %H:%M:%S"), "ATTACKER", MY_IP, "DNS_FLOOD", notes="Finished DNS Flood")

    # FTP Anonymous
    ftp.main(MY_IP, 21)
    score_event(time.strftime("%Y-%m-%d %H:%M:%S"), "ATTACKER", MY_IP, "FTP_ANON", notes="Finished FTP anonymous test")

    # TLS Weak check
    tls.main(MY_IP, 443)
    score_event(time.strftime("%Y-%m-%d %H:%M:%S"), "ATTACKER", MY_IP, "TLS_WEAK", notes="Finished TLS weak check")

    print("[+] Packet logger will stop shortly...")
    time.sleep(5)  # let logger flush
    # logger stops when program exits

    print("\n[*] All attacks completed. Run `python report_generator.py` to generate your risk report.")

if __name__ == "__main__":
    main()
