"""
report_generator.py — Generates a professional executive risk report
aligned with NIST SP 800-30 and MITRE ATT&CK.
"""

import sqlite3
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

from risk_engine import get_mitre_mapping, bucketize

MITIGATIONS = {
    "SYN_FLOOD": {
        "steps": [
            "Enable SYN cookies on all exposed hosts.",
            "Apply rate limiting for inbound TCP SYN connections at the firewall.",
            "Deploy an IDS/IPS rule to detect and block SYN flood patterns.",
            "Consider upstream DDoS scrubbing or a cloud-based DDoS protection service.",
        ],
        "nist": [
            "PR.AC-5  — Network integrity protection",
            "DE.CM-1  — Continuous network monitoring",
            "RS.MI-1  — Incident mitigation actions",
        ],
    },
    "UDP_FLOOD": {
        "steps": [
            "Rate-limit inbound UDP traffic at the perimeter firewall.",
            "Block unused UDP ports to reduce the attack surface.",
            "Deploy a DDoS protection service capable of absorbing volumetric floods.",
            "Enable anomaly-based detection for UDP traffic spikes.",
        ],
        "nist": [
            "PR.PT-4  — Communications and control network protection",
            "DE.CM-7  — Detection of unauthorized connections",
            "RS.AN-1  — Incident analysis",
        ],
    },
    "ICMP_SWEEP": {
        "steps": [
            "Restrict ICMP echo requests on sensitive hosts via firewall ACLs.",
            "Enable network scanning detection rules in your IDS/IPS.",
            "Log and alert on ICMP traffic exceeding baseline thresholds.",
        ],
        "nist": [
            "DE.CM-1  — Network monitoring",
            "DE.CM-7  — Unauthorized scan detection",
        ],
    },
    "SLOWLORIS": {
        "steps": [
            "Place a reverse proxy (Nginx or HAProxy) in front of all web services.",
            "Configure aggressive request timeout and keep-alive limits.",
            "Enforce maximum concurrent connection limits per source IP.",
            "Enable connection rate limiting at the load balancer.",
        ],
        "nist": [
            "PR.AC-5  — Application resilience and network integrity",
            "DE.CM-1  — Connection anomaly detection",
            "RS.MI-1  — Mitigation of detected incidents",
        ],
    },
    "DNS_FLOOD": {
        "steps": [
            "Enable DNS Response Rate Limiting (RRL) on all resolvers.",
            "Deploy DNSSEC to authenticate DNS responses.",
            "Rate-limit inbound DNS queries at the network perimeter.",
            "Harden recursive resolvers and restrict open resolution.",
        ],
        "nist": [
            "PR.PT-4  — Communications protections",
            "DE.CM-1  — DNS anomaly detection",
            "RS.MI-1  — Mitigation actions",
        ],
    },
    "FTP_ANON": {
        "steps": [
            "Disable anonymous FTP login on all servers immediately.",
            "Replace FTP with SFTP or FTPS for all file transfer requirements.",
            "Restrict FTP access to explicitly approved source IP addresses.",
            "Audit FTP server logs for historical anonymous access attempts.",
        ],
        "nist": [
            "PR.AC-1  — Identity and credential management",
            "PR.AC-3  — Remote access management",
            "DE.CM-3  — Personnel and user activity monitoring",
        ],
    },
    "TLS_WEAK": {
        "steps": [
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 across all services.",
            "Enforce TLS 1.2 at minimum; prefer TLS 1.3.",
            "Remove weak cipher suites (RC4, DES, 3DES, export-grade ciphers).",
            "Rotate to certificates signed with SHA-256 or stronger algorithms.",
            "Run regular TLS configuration scans (e.g., testssl.sh or SSLLabs).",
        ],
        "nist": [
            "PR.DS-2  — Data-in-transit protection",
            "PR.AC-5  — Network integrity",
            "DE.CM-8  — Vulnerability scanning",
        ],
    },
}

DISPLAY_NAMES = {
    "SYN_FLOOD":  "SYN Flood",
    "UDP_FLOOD":  "UDP Flood",
    "DNS_FLOOD":  "DNS Flood",
    "ICMP_SWEEP": "ICMP Sweep",
    "SLOWLORIS":  "Slowloris (HTTP Keep-Alive Exhaustion)",
    "FTP_ANON":   "Anonymous FTP Access",
    "TLS_WEAK":   "Weak TLS Configuration",
}

SEVERITY_COLORS = {
    "Very High": "#c0392b",
    "High":      "#e67e22",
    "Medium":    "#f1c40f",
    "Low":       "#2980b9",
    "Very Low":  "#7f8c8d",
}

DB      = "network_logs.db"
OUT_DIR = Path("report_figures")
OUT_DIR.mkdir(exist_ok=True)


def display_name(alert_type):
    return DISPLAY_NAMES.get(alert_type, alert_type)


def get_severity_label(score):
    mapping = {
        "VERY_HIGH": "Very High",
        "HIGH":      "High",
        "MEDIUM":    "Medium",
        "LOW":       "Low",
        "VERY_LOW":  "Very Low",
    }
    return mapping.get(bucketize(score), "Unknown")


def get_mitre_info(alert_type):
    mapping   = get_mitre_mapping(alert_type)
    primary   = mapping.get("primary",   [])
    secondary = mapping.get("secondary", [])
    if primary:
        p = primary[0]
        pid, pname, ptactic, purl = (
            p.get("id", "N/A"), p.get("name", "Unknown"),
            p.get("tactic", "Unknown"), p.get("url", ""),
        )
    else:
        pid, pname, ptactic, purl = "N/A", "Unknown", "Unknown", ""
    sec_entries = [
        {"id": s.get("id","N/A"), "name": s.get("name","Unknown"),
         "tactic": s.get("tactic","Unknown"), "url": s.get("url","")}
        for s in secondary
    ]
    return {"primary_id": pid, "primary_name": pname,
            "primary_tactic": ptactic, "primary_url": purl,
            "secondary": sec_entries}


def _apply_style():
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 10,
        "axes.titlesize": 12, "axes.titleweight": "bold",
        "axes.spines.top": False, "axes.spines.right": False,
        "figure.dpi": 150,
    })


def plot_severity_chart(data):
    _apply_style()
    labels = [d[0] for d in data]
    values = [d[1] for d in data]
    colors = [SEVERITY_COLORS.get(l, "#95a5a6") for l in labels]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(labels, values, color=colors, width=0.55, edgecolor="white")
    ax.set_title("Risk Severity Distribution")
    ax.set_xlabel("Severity Level")
    ax.set_ylabel("Event Count")
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    for bar, val in zip(bars, values):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height()+0.15,
                    str(val), ha="center", va="bottom", fontsize=9, fontweight="bold")
    plt.tight_layout()
    path = OUT_DIR / "severity.png"
    plt.savefig(path)
    plt.close()
    return path


def plot_attack_chart(data):
    _apply_style()
    if not data:
        return None
    labels, values = zip(*data)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    bars = ax.barh(labels, values, color="#2c3e50", edgecolor="white", height=0.55)
    ax.set_title("Attack Event Frequency by Type")
    ax.set_xlabel("Event Count")
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    for bar, val in zip(bars, values):
        ax.text(bar.get_width()+0.15, bar.get_y()+bar.get_height()/2,
                str(val), ha="left", va="center", fontsize=9)
    plt.tight_layout()
    path = OUT_DIR / "attacks.png"
    plt.savefig(path)
    plt.close()
    return path


def plot_packet_chart(data):
    _apply_style()
    if not data:
        return None
    labels, values = zip(*data)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(labels, values, color="#2980b9", edgecolor="white", width=0.55)
    ax.set_title("Raw Packet Distribution by Protocol")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Packet Count")
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    plt.tight_layout()
    path = OUT_DIR / "packets.png"
    plt.savefig(path)
    plt.close()
    return path


def generate_report():
    conn = sqlite3.connect(DB)
    cur  = conn.cursor()

    cur.execute("""
        SELECT
            SUM(CASE WHEN score >= 80 THEN 1 ELSE 0 END),
            SUM(CASE WHEN score >= 60 AND score < 80 THEN 1 ELSE 0 END),
            SUM(CASE WHEN score >= 40 AND score < 60 THEN 1 ELSE 0 END),
            SUM(CASE WHEN score >= 20 AND score < 40 THEN 1 ELSE 0 END),
            SUM(CASE WHEN score < 20 THEN 1 ELSE 0 END)
        FROM risks;
    """)
    row = cur.fetchone() or (0,0,0,0,0)
    very_high, high, medium, low, very_low = [x or 0 for x in row]

    severity_data    = [("Very High",very_high),("High",high),("Medium",medium),("Low",low),("Very Low",very_low)]

    cur.execute("SELECT alert_type, COUNT(*) FROM risks GROUP BY alert_type ORDER BY COUNT(*) DESC;")
    attack_breakdown = [(display_name(r[0]), r[1]) for r in cur.fetchall()]

    cur.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol ORDER BY COUNT(*) DESC;")
    packet_breakdown = cur.fetchall()

    cur.execute("SELECT alert_type, src_ip, dest_ip, score, notes, timestamp FROM risks ORDER BY score DESC, timestamp DESC LIMIT 5;")
    top_findings = cur.fetchall()

    cur.execute("SELECT alert_type, src_ip, dest_ip, score, notes, timestamp FROM risks ORDER BY id DESC LIMIT 50;")
    recent = cur.fetchall()

    cur.execute("SELECT DISTINCT alert_type FROM risks;")
    all_attack_types = [r[0] for r in cur.fetchall()]

    conn.close()

    severity_chart = plot_severity_chart(severity_data)
    attack_chart   = plot_attack_chart(attack_breakdown)
    packet_chart   = plot_packet_chart(packet_breakdown)

    ts    = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    a     = lines.append

    a("# Network Traffic Risk Assessment")
    a("## Executive Report")
    a("")
    a(f"**Generated:** {ts}  ")
    a("**Framework:** NIST SP 800-30 Rev. 1 — Qualitative Risk Scoring  ")
    a("**Threat Intel:** MITRE ATT&CK Enterprise Matrix  ")
    a("")
    a("---")
    a("")
    a("## Risk Scoring Methodology")
    a("")
    a("Risk scores are calculated using a qualitative likelihood x impact model, normalised to a 0-100 scale.")
    a("")
    a("| Score Range | Severity Level | Recommended Response                   |")
    a("|-------------|----------------|----------------------------------------|")
    a("| 80 - 100    | Very High      | Immediate remediation required          |")
    a("| 60 - 79     | High           | Prioritise remediation within 24 hours  |")
    a("| 40 - 59     | Medium         | Schedule remediation within 7 days      |")
    a("| 20 - 39     | Low            | Monitor and review                      |")
    a("| 0  - 19     | Very Low       | Informational — log and retain          |")
    a("")
    a("---")
    a("")
    a("## Risk Severity Overview")
    a("")
    a(f"![]({severity_chart.as_posix()})")
    a("")
    a("## Attack Event Breakdown")
    a("")
    a(f"![]({attack_chart.as_posix()})" if attack_chart else "_No attack data recorded._")
    a("")
    a("## Raw Packet Distribution")
    a("")
    a(f"![]({packet_chart.as_posix()})" if packet_chart else "_No packet data recorded._")
    a("")
    a("---")
    a("")
    a("## Top 5 Risk Findings")
    a("")

    if not top_findings:
        a("_No findings recorded._")
    else:
        for rank, (a_type, src, dst, score, notes, event_ts) in enumerate(top_findings, 1):
            m        = get_mitre_info(a_type)
            severity = get_severity_label(score)
            name     = display_name(a_type)
            a(f"### Finding {rank} — {name}")
            a("")
            a("| Field          | Detail                   |")
            a("|----------------|--------------------------|")
            a(f"| Timestamp      | {event_ts}               |")
            a(f"| Source IP      | {src}                    |")
            a(f"| Destination IP | {dst}                    |")
            a(f"| Risk Score     | {score} / 100            |")
            a(f"| Severity       | {severity}               |")
            a(f"| Notes          | {notes}                  |")
            a("")
            a("**MITRE ATT&CK — Primary Technique**")
            a("")
            a("| Field     | Detail                                      |")
            a("|-----------|---------------------------------------------|")
            a(f"| ID        | [{m['primary_id']}]({m['primary_url']})     |")
            a(f"| Technique | {m['primary_name']}                         |")
            a(f"| Tactic    | {m['primary_tactic']}                       |")
            if m["secondary"]:
                a("")
                a("**MITRE ATT&CK — Secondary Techniques**")
                a("")
                a("| ID | Technique | Tactic |")
                a("|---|---|---|")
                for s in m["secondary"]:
                    a(f"| [{s['id']}]({s['url']}) | {s['name']} | {s['tactic']} |")
            a("")

    a("---")
    a("")
    a("## Recent Events (Last 50)")
    a("")
    if not recent:
        a("_No recent events._")
    else:
        a("| Timestamp | Attack Type | Source IP | Destination IP | Score | Severity | MITRE ID | Tactic |")
        a("|---|---|---|---|---|---|---|---|")
        for a_type, src, dst, score, notes, event_ts in recent:
            m        = get_mitre_info(a_type)
            severity = get_severity_label(score)
            name     = display_name(a_type)
            mitre_cell = f"[{m['primary_id']}]({m['primary_url']})"
            a(f"| {event_ts} | {name} | {src} | {dst} | {score} | {severity} | {mitre_cell} | {m['primary_tactic']} |")

    a("")
    a("---")
    a("")
    a("## Mitigation Recommendations")
    a("")
    a("Recommendations are mapped to NIST CSF functions and MITRE ATT&CK techniques.")
    a("")

    if not all_attack_types:
        a("_No attack types recorded._")
    else:
        for a_type in all_attack_types:
            if a_type not in MITIGATIONS:
                continue
            m    = get_mitre_info(a_type)
            name = display_name(a_type)
            mit  = MITIGATIONS[a_type]
            a(f"### {name}")
            a("")
            a("**MITRE ATT&CK**")
            a("")
            a("| Field        | Detail                                      |")
            a("|--------------|---------------------------------------------|")
            a(f"| Primary ID   | [{m['primary_id']}]({m['primary_url']})     |")
            a(f"| Technique    | {m['primary_name']}                         |")
            a(f"| Tactic       | {m['primary_tactic']}                       |")
            if m["secondary"]:
                for s in m["secondary"]:
                    a(f"| Secondary ID | [{s['id']}]({s['url']}) — {s['name']} ({s['tactic']}) |")
            a("")
            a("**Mitigation Steps**")
            a("")
            for step in mit["steps"]:
                a(f"- {step}")
            a("")
            a("**NIST CSF Alignment**")
            a("")
            for n in mit["nist"]:
                a(f"- {n}")
            a("")
            a("---")
            a("")

    out_path = Path("executive_report.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Executive report written to {out_path}")
    print(f"[+] Charts saved to {OUT_DIR}/")


if __name__ == "__main__":
    generate_report()
