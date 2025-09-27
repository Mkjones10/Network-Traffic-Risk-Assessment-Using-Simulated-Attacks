"""
baseline_tests.py — Baseline latency/jitter (ICMP) and TCP connect times.
Uses only safe, low-rate probes to authorized targets.
"""

import platform, subprocess, time, socket, statistics, json
from db_utils import load_config

CFG = load_config()

def ping_once(host, timeout=2):
    # Cross-platform single ping
    sys = platform.system()
    if sys == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    t1 = time.time()
    ok = proc.returncode == 0
    rtt_ms = (t1 - t0) * 1000.0
    return ok, rtt_ms

def tcp_connect_time(host, port, timeout=2):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        ok = True
    except Exception:
        ok = False
    finally:
        s.close()
    t1 = time.time()
    return ok, (t1 - t0) * 1000.0

def run_baseline(hosts):
    results = {"icmp": [], "tcp": []}
    for h in hosts:
        ok, rtt = ping_once(h)
        results["icmp"].append({"host": h, "ok": ok, "rtt_ms": round(rtt, 2)})
        ok2, rt2 = tcp_connect_time(h, 80)
        results["tcp"].append({"host": h, "ok": ok2, "conn_ms": round(rt2, 2)})
    # Summaries
    icmps = [x["rtt_ms"] for x in results["icmp"] if x["ok"]]
    tcpms = [x["conn_ms"] for x in results["tcp"] if x["ok"]]
    summary = {
        "icmp": {
            "count": len(results["icmp"]),
            "ok": sum(1 for x in results["icmp"] if x["ok"]),
            "rtt_avg_ms": round(statistics.mean(icmps), 2) if icmps else None,
            "rtt_p95_ms": round(statistics.quantiles(icmps, n=20)[18], 2) if len(icmps) >= 20 else None
        },
        "tcp": {
            "count": len(results["tcp"]),
            "ok": sum(1 for x in results["tcp"] if x["ok"]),
            "conn_avg_ms": round(statistics.mean(tcpms), 2) if tcpms else None
        }
    }
    return {"results": results, "summary": summary}

if __name__ == "__main__":
    hosts = CFG.get("allowed_targets", ["127.0.0.1"])
    out = run_baseline(hosts)
    print(json.dumps(out, indent=2))
