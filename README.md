Network Traffic Risk Assessment using Simulated Attacks

SAFETY & DISCLAIMER (Read first)
This code is for educational and research purposes only. Do not run it on production systems, public networks, or any environment where you do not have explicit permission. Always restrict usage to controlled lab environments. Running attack simulations may require root/administrator privileges — use caution. Never commit sensitive files (like .secrets.json) to version control.

Overview

This project simulates common network attacks, captures packets in real-time, scores risks using a likelihood × impact model, and generates executive reports aligned with the NIST Cybersecurity Framework (CSF).

The system is designed as a learning and demonstration tool for network security, not for use on production networks.

Features

Attack Simulation Modules

SYN Flood

UDP Flood

DNS Flood

ICMP Sweep

Slowloris

FTP Anonymous Login

Weak TLS Handshake

Packet Capture

Uses Scapy to sniff traffic and log packet metadata.

Applies NIST-aligned risk scoring.

Database

SQLite database stores packets, risks, alerts, and assets.

Reporting

Executive reports with severity breakdowns, top findings, and mitigation strategies.

Project Structure
├── attacks/

│     ├── dns_flood.py

│     ├── ftp_anonymous.py

│     ├── ping_sweep.py

│     ├── slowloris.py

│     ├── syn_flood.py

│     ├── tls_weakcheck.py

│     └── udp_flood.py


│
├── baseline_tests.py

├── clear_all_dbs.py

├── db_packets.py

├── db_utils.py

├── packet_logger.py

├── report_generator.py

├── risk_engine.py

├── run_all_attacks.py

├── secrets_loader.py

├── security_scan.py





Secrets File Requirement (PLACEHOLDERS — DO NOT commit real secrets)

You must create a .secrets.json file in the project root with your own IP address, MAC address, and network interface. Do not commit this file to version control. Use the example below and replace the placeholder values with your actual values:

{
  "MY_IP": "YOUR_IP_ADDRESS",
  "MY_MAC": "YOUR_MAC_ADDRESS",
  "MY_IFACE": "YOUR_INTERFACE_NAME"
}


MY_IP: replace YOUR_IP_ADDRESS with the IP address of the machine you will run the tests on (example format: 192.168.1.50).

MY_MAC: replace YOUR_MAC_ADDRESS with your NIC MAC address (example format: 00:11:22:33:44:55).

MY_IFACE: replace YOUR_INTERFACE_NAME with your interface name (e.g., Wi-Fi, eth0, wlan0).

Important: Treat .secrets.json like a secret — add it to .gitignore so it does not get pushed to GitHub.
Note: This project was tested using a Wi-Fi interface. Running on other interfaces (Ethernet, virtual adapters) may require adjusting the MY_IFACE value and/or running with elevated privileges.

Usage

Install dependencies (Python 3.x, Scapy):

pip install scapy


Create .secrets.json using the placeholder template above and fill with your local values.

Initialize databases (creates SQLite tables):

python db_utils.py


Run all simulated attacks (lab only — ensure you have permission):

python run_all_attacks.py


This script starts the packet logger, runs each attack module, and logs scored events.

Generate risk report:

python report_generator.py


Output file: executive_report.md

Optional: clear DBs between runs:

python clear_all_dbs.py

Verify attacks in Wireshark (placeholders — replace before using)

Use these Wireshark display filters to verify simulated attacks. Before using, replace YOUR_IP_ADDRESS with the IP you put in .secrets.json, and YOUR_MAC_ADDRESS with the MAC you put in .secrets.json. Example placeholders are shown below — do not use any real values in the README file.

SYN Flood

ip.dst == YOUR_IP_ADDRESS and tcp.flags.syn == 1 and tcp.flags.ack == 0


UDP Flood

ip.dst == YOUR_IP_ADDRESS and udp and not dns


DNS Flood

ip.dst == YOUR_IP_ADDRESS and udp.port == 53 and dns


ICMP Sweep

icmp.type == 8 and ip.dst >= YOUR_SUBNET_START and ip.dst <= YOUR_SUBNET_END


(Replace YOUR_SUBNET_START / YOUR_SUBNET_END with numeric addresses, e.g. 10.0.0.90 and 10.0.0.95.)

Slowloris

ip.dst == YOUR_IP_ADDRESS and tcp.port == 8080 and tcp.len < 50


FTP Anonymous Login

ip.dst == YOUR_IP_ADDRESS and tcp.port == 21 and ftp.request.command == "USER"


Weak TLS Handshake

ip.dst == YOUR_IP_ADDRESS and tcp.port == 443 and tls.handshake.version == 0x0301


Tip: If you want to filter by attacker MAC, add:

eth.src == YOUR_MAC_ADDRESS

Example Output (Executive Report)

Severity breakdown (Very Low → Very High)

Attack event counts

Top 5 findings with risk scores

Mitigation recommendations mapped to NIST CSF

Troubleshooting & Notes

If Scapy cannot send raw frames or sniff on your interface, run scripts with elevated privileges (e.g., sudo on Linux/macOS).

If .secrets.json is missing or malformed, secrets_loader.py will raise an error — check the path and JSON formatting.

The project was validated on a Wi-Fi adapter; if you test on another interface, set MY_IFACE accordingly.
