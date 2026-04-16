# Network Traffic Risk Assessment & Attack Simulation Framework

>  **SAFETY & DISCLAIMER — Read First**
>
> This project is for **educational and research purposes only**. Do **not** run it on production systems, public networks, or any environment where you do not have explicit written permission. Always restrict usage to controlled lab environments. Some modules require administrator/root privileges. **Never commit sensitive files (like `.secrets.json`) to version control.**

---

## Overview

This project simulates real-world network attacks, captures live traffic, and transforms raw packet data into risk-based security insights.

It demonstrates how a Security Operations Center (SOC) can move from:

**Detection → Analysis → Risk Prioritization → Executive Reporting**

aligned with the **NIST Cybersecurity Framework (CSF)**.

> Designed for learning, demonstration, and portfolio use — not for production deployment.

---

## Core Capabilities

###  Attack Simulation
Simulates common network-based threats:
- SYN Flood
- UDP Flood
- DNS Flood
- ICMP Sweep
- Slowloris
- FTP Anonymous Login
- Weak TLS Handshake

###  Packet Capture & Analysis
- Real-time packet sniffing via [Scapy](https://scapy.net/)
- Captures and logs network metadata
- Supports validation with Wireshark
- Enables protocol-level traffic inspection

###  Risk Scoring Engine
- **Likelihood × Impact** model
- Severity classification: Very Low → Very High
- NIST-aligned risk prioritization
- Converts raw detections into actionable risk insights

###  Data Layer
- SQLite-backed storage for packet logs, alerts, risk scores, and asset data

###  Executive Reporting
Generates `executive_report.md` with:
- Severity distribution
- Attack event counts
- Top 5 risk findings
- Mitigation strategies mapped to NIST CSF

---

## Architecture

```
Attack Simulation → Packet Capture (Scapy) → Risk Engine → SQLite DB → Executive Report
```

---

## Project Structure

```
├── attacks/
│   ├── dns_flood.py
│   ├── ftp_anonymous.py
│   ├── ping_sweep.py
│   ├── slowloris.py
│   ├── syn_flood.py
│   ├── tls_weakcheck.py
│   └── udp_flood.py
├── baseline_tests.py
├── clear_all_dbs.py
├── db_packets.py
├── db_utils.py
├── packet_logger.py
├── report_generator.py
├── risk_engine.py
├── run_all_attacks.py
├── secrets_loader.py
└── security_scan.py
```

---

## Setup & Usage

### 1. Install Dependencies

```bash
pip install scapy
```

### 2. Configure Secrets

Create a `.secrets.json` file in the project root. **Add it to `.gitignore` immediately — never commit real values.**

```json
{
  "MY_IP": "YOUR_IP_ADDRESS",
  "MY_MAC": "YOUR_MAC_ADDRESS",
  "MY_IFACE": "YOUR_INTERFACE_NAME"
}
```

| Key | Description | Example |
|---|---|---|
| `MY_IP` | IP of the machine running the tests | `192.168.1.50` |
| `MY_MAC` | NIC MAC address | `00:11:22:33:44:55` |
| `MY_IFACE` | Network interface name | `eth0`, `wlan0`, `Wi-Fi` |

> Tested on a Wi-Fi adapter. For Ethernet or virtual adapters, update `MY_IFACE` and run with elevated privileges if needed.

### 3. Initialize Database

```bash
python db_utils.py
```

### 4. Run Simulated Attacks *(Lab environments only)*

```bash
python run_all_attacks.py
```

This will start packet logging, execute all attack modules, and store and score events.

### 5. Generate Executive Report

```bash
python report_generator.py
```

Output: `executive_report.md`

### 6. Reset Database *(Optional)*

```bash
python clear_all_dbs.py
```

---

## Wireshark Validation Filters

Replace all placeholders with values from your `.secrets.json` before use.

| Attack | Wireshark Filter |
|---|---|
| SYN Flood | `ip.dst == YOUR_IP_ADDRESS and tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| UDP Flood | `ip.dst == YOUR_IP_ADDRESS and udp and not dns` |
| DNS Flood | `ip.dst == YOUR_IP_ADDRESS and udp.port == 53 and dns` |
| ICMP Sweep | `icmp.type == 8 and ip.dst >= YOUR_SUBNET_START and ip.dst <= YOUR_SUBNET_END` |
| Slowloris | `ip.dst == YOUR_IP_ADDRESS and tcp.port == 8080 and tcp.len < 50` |
| FTP Anonymous Login | `ip.dst == YOUR_IP_ADDRESS and tcp.port == 21 and ftp.request.command == "USER"` |
| Weak TLS Handshake | `ip.dst == YOUR_IP_ADDRESS and tcp.port == 443 and tls.handshake.version == 0x0301` |

To also filter by attacker MAC:
```
eth.src == YOUR_MAC_ADDRESS
```

> Replace `YOUR_SUBNET_START` / `YOUR_SUBNET_END` with numeric addresses, e.g. `10.0.0.90` and `10.0.0.95`.

---

## Example Report Output

The generated `executive_report.md` includes:
- Severity breakdown (Very Low → Very High)
- Attack event counts
- Top 5 findings with risk scores
- Likelihood × Impact analysis
- NIST CSF–aligned mitigation recommendations

---

## Troubleshooting

**Permission errors**
```bash
sudo python run_all_attacks.py
```

**Scapy sniffing issues** — Verify `MY_IFACE` is correct and your adapter supports packet sniffing.

**Secrets file errors** — Check JSON formatting and confirm `.secrets.json` is in the project root.

---

## .gitignore Recommendation

```
.secrets.json
*.db
```

---

## Why This Project Stands Out

This project directly demonstrates skills required for **SOC Analyst**, **Incident Response**, and **Cybersecurity Analyst** roles:

- Network traffic analysis at the packet level
- Attack simulation and detection
- Risk-based prioritization (beyond simple alerting)
- NIST CSF alignment for enterprise relevance
- Executive-level reporting of technical findings

---

## Future Enhancements

- [ ] SIEM integration (Splunk / ELK)
- [ ] Real-time alert dashboard (web UI)
- [ ] MITRE ATT&CK mapping
- [ ] ML-based anomaly detection
- [ ] Automated alert correlation

---

## Author

**Maxine Jones**
*Cybersecurity Analyst | Incident Response | Network Security*

-  Portfolio: [maxine-jones-portfolio.netlify.app](https://maxine-jones-portfolio.netlify.app/)
-  GitHub: [github.com/Mkjones10](https://github.com/Mkjones10)
