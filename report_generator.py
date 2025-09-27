# report_generator.py
import sqlite3, time
from pathlib import Path
import matplotlib.pyplot as plt

# Mitigation recommendations + NIST alignment for each attack type
MITIGATIONS = {
    "SYN_FLOOD": {
        "steps": [
            "Enable SYN cookies on the host.",
            "Apply rate limiting for TCP connections.",
            "Use a firewall/IDS to detect and block floods."
        ],
        "nist": [
            "Function: Protect (PR), Detect (DE)",
            "Categories: PR.AC-5 (network integrity), DE.CM-1 (network monitoring)"
        ]
    },
    "UDP_FLOOD": {
        "steps": [
            "Rate limit UDP traffic.",
            "Filter unused UDP ports at the firewall.",
            "Deploy DDoS protection services."
        ],
        "nist": [
            "Function: Protect (PR), Detect (DE), Respond (RS)",
            "Categories: PR.PT-4 (network protections), DE.CM-7 (unauthorized connections), RS.AN-1 (incident analysis)"
        ]
    },
    "ICMP_SWEEP": {
        "steps": [
            "Disable ICMP responses on sensitive hosts.",
            "Limit ICMP echo requests using firewall rules."
        ],
        "nist": [
            "Function: Detect (DE)",
            "Categories: DE.CM-1 (network monitoring), DE.CM-7 (scan detection)"
        ]
    },
    "SLOWLORIS": {
        "steps": [
            "Use a reverse proxy (e.g., Nginx/HAProxy) with request timeouts.",
            "Limit max concurrent connections per client.",
            "Enable connection keep-alive limits."
        ],
        "nist": [
            "Function: Protect (PR), Detect (DE), Respond (RS)",
            "Categories: PR.AC-5 (application resilience), DE.CM-1 (connection anomaly detection), RS.MI-1 (mitigation)"
        ]
    },
    "DNS_FLOOD": {
        "steps": [
            "Rate limit incoming DNS queries.",
            "Use DNS rate-limiting extensions (RRL).",
            "Harden recursive resolvers and deploy DNSSEC."
        ],
        "nist": [
            "Function: Protect (PR), Detect (DE), Respond (RS)",
            "Categories: PR.PT-4 (communications protections), DE.CM-1 (DNS anomaly detection), RS.MI-1 (mitigation actions)"
        ]
    },
    "FTP_ANON": {
        "steps": [
            "Disable anonymous FTP logins.",
            "Use SFTP/FTPS instead of FTP.",
            "Restrict FTP access to trusted IPs only."
        ],
        "nist": [
            "Function: Protect (PR), Detect (DE)",
            "Categories: PR.AC-1 (identity management), PR.AC-3 (remote access), DE.CM-3 (activity monitoring)"
        ]
    },
    "TLS_WEAK": {
        "steps": [
            "Disable SSLv2/SSLv3, TLS 1.0, and weak ciphers.",
            "Enforce TLS 1.2 or 1.3 with strong cipher suites.",
            "Use properly signed certificates with modern algorithms."
        ],
        "nist": [
            "Function: Protect (PR), Detect (DE)",
            "Categories: PR.DS-2 (data-in-transit protection), PR.AC-5 (integrity), DE.CM-8 (vulnerability scanning)"
        ]
    }
}

DB = "network_logs.db"
OUT_DIR = Path("report_figures")
OUT_DIR.mkdir(exist_ok=True)

def plot_bar(data, title, xlabel, ylabel, filename):
    if not data:
        return None
    labels, values = zip(*data)
    plt.figure(figsize=(6, 4))
    plt.bar(labels, values)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    filepath = OUT_DIR / filename
    plt.savefig(filepath)
    plt.close()
    return filepath

def generate_report():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    # Risk severity counts (NIST SP 800-30: Very Low → Very High)
    cur.execute("""
        SELECT 
            SUM(CASE WHEN score >= 85 THEN 1 ELSE 0 END) as very_high,
            SUM(CASE WHEN score >= 67 AND score < 85 THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN score >= 34 AND score < 67 THEN 1 ELSE 0 END) as moderate,
            SUM(CASE WHEN score >= 15 AND score < 34 THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN score < 15 THEN 1 ELSE 0 END) as very_low
        FROM risks;
    """)
    very_high, high, moderate, low, very_low = cur.fetchone()
    severity_data = [
        ("Very High", very_high or 0),
        ("High", high or 0),
        ("Moderate", moderate or 0),
        ("Low", low or 0),
        ("Very Low", very_low or 0),
    ]
    severity_chart = plot_bar(severity_data, "Risk Severity (NIST SP 800-30)", "Severity", "Count", "severity.png")

    # Attack breakdown
    cur.execute("SELECT alert_type, COUNT(*) FROM risks GROUP BY alert_type;")
    attack_breakdown = cur.fetchall()
    attack_chart = plot_bar(attack_breakdown, "Attack Event Breakdown", "Attack Type", "Count", "attacks.png")

    # Raw packet breakdown
    cur.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol;")
    packet_breakdown = cur.fetchall()
    packet_chart = plot_bar(packet_breakdown, "Packet Breakdown", "Protocol", "Count", "packets.png")

    # Top 5 findings
    cur.execute("""
        SELECT alert_type, src_ip, dest_ip, score, notes, timestamp
        FROM risks
        ORDER BY score DESC
        LIMIT 5;
    """)
    top_findings = cur.fetchall()

    # Recent events
    cur.execute("""
        SELECT alert_type, src_ip, dest_ip, score, notes, timestamp
        FROM risks
        ORDER BY id DESC
        LIMIT 50;
    """)
    recent = cur.fetchall()

    conn.close()

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    report = []
    report.append(f"# Network Risk Assessment — Executive Brief\n")
    report.append(f"_Generated {ts}_\n")
    report.append("\n*Risk categories follow NIST SP 800-30 (Very Low → Very High).*")

    # Severity overview
    report.append("\n## Risk Severity Overview")
    if severity_chart:
        report.append(f"![]({severity_chart})")

    # Attack breakdown
    report.append("\n## Attack Event Breakdown")
    if attack_chart:
        report.append(f"![]({attack_chart})")

    # Raw packet breakdown
    report.append("\n## Raw Packet Breakdown")
    if packet_chart:
        report.append(f"![]({packet_chart})")

    # Top 5 findings
    report.append("\n## Top 5 Findings")
    if not top_findings:
        report.append("_No risk findings yet_")
    for row in top_findings:
        a_type, src, dst, score, notes, ts = row
        report.append(f"- **{a_type}** {src} → {dst} at {ts}: **Score {score}** ({notes})")

    # Recent events
    report.append("\n## Recent Events (last 50)")
    if not recent:
        report.append("_No recent events yet_")
    for row in recent:
        a_type, src, dst, score, notes, ts = row
        report.append(f"- {ts}: {a_type} {src} → {dst} (Score {score}) — {notes}")

    # Mitigation Recommendations
    report.append("\n## Mitigation Recommendations")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT alert_type FROM risks;")
    all_attack_types = [row[0] for row in cur.fetchall()]
    conn.close()

    for a_type in all_attack_types:
        if a_type in MITIGATIONS:
            report.append(f"\n### {a_type}")
            report.append("**Mitigation Steps:**")
            for step in MITIGATIONS[a_type]["steps"]:
                report.append(f"- {step}")
            report.append("**NIST CSF Alignment:**")
            for n in MITIGATIONS[a_type]["nist"]:
                report.append(f"- {n}")

    # Save report
    out_path = Path("executive_report.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report))

    print(f"[+] Executive report exported to {out_path}")
    print(f"[+] Charts saved in {OUT_DIR}/")

if __name__ == "__main__":
    generate_report()
