# db_packets.py
import sqlite3
import time
from pathlib import Path

DB_PACKETS = "packet_logs.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS packet_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    attack_type TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    size INTEGER,
    details TEXT
);
"""

def init_packet_db():
    """Initialize the packet logging database."""
    Path(DB_PACKETS).touch(exist_ok=True)
    conn = sqlite3.connect(DB_PACKETS)
    c = conn.cursor()
    c.execute(SCHEMA)
    conn.commit()
    conn.close()

def log_packet(attack_type, src_ip, dst_ip, protocol, size, details=""):
    """Log one packet event into the DB."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PACKETS)
    c = conn.cursor()
    c.execute(
        "INSERT INTO packet_events (timestamp, attack_type, src_ip, dst_ip, protocol, size, details) VALUES (?,?,?,?,?,?,?)",
        (ts, attack_type, src_ip, dst_ip, protocol, size, details)
    )
    conn.commit()
    conn.close()
