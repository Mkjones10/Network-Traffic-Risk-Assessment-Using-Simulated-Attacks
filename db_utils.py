"""
db_utils.py — SQLite schema + helpers
"""

import sqlite3
import json
from pathlib import Path

def load_config(path="config.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

CFG = load_config()
DB = CFG["db_path"]

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        protocol TEXT,
        details TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        type TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        message TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS risks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        alert_type TEXT,
        likelihood REAL,
        impact REAL,
        score REAL,
        notes TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_cidr TEXT,
        criticality TEXT,
        owner TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS baselines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        metric TEXT,
        scope TEXT,
        value REAL,
        window_sec INTEGER,
        last_updated TEXT
    )"""
]

def init_db():
    Path(DB).touch(exist_ok=True)
    with sqlite3.connect(DB, timeout=5) as conn:
        c = conn.cursor()
        for stmt in SCHEMA:
            c.execute(stmt)
        conn.commit()

def insert_packet(ts, src, dst, proto, details):
    with sqlite3.connect(DB, timeout=5) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO packets (timestamp, src_ip, dest_ip, protocol, details) VALUES (?,?,?,?,?)",
                  (ts, src, dst, proto, details))
        conn.commit()

def insert_alert(ts, a_type, src, dst, msg):
    with sqlite3.connect(DB, timeout=5) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO alerts (timestamp, type, src_ip, dest_ip, message) VALUES (?,?,?,?,?)",
                  (ts, a_type, src, dst, msg))
        conn.commit()

def fetchall(query, params=()):
    with sqlite3.connect(DB, timeout=5) as conn:
        c = conn.cursor()
        c.execute(query, params)
        return c.fetchall()
