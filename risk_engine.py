"""
risk_engine.py — Likelihood × Impact scoring to quantify business risk.
"""

import ipaddress
import sqlite3
import time
from db_utils import load_config

CFG = load_config()
DB = CFG["db_path"]
LIKELIHOOD = CFG["risk"]["likelihood"]
CRIT_MAP = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}

def _asset_impact_for(dest_ip: str) -> float:
    try:
        ip = ipaddress.ip_address(dest_ip)
    except Exception:
        return 0.5
    for a in CFG["assets"]:
        try:
            if ip in ipaddress.ip_network(a["cidr"], strict=False):
                return CRIT_MAP.get((a.get("criticality") or "MEDIUM").upper(), 0.5)
        except Exception:
            continue
    return 0.5

def _adjust_likelihood(alert_type: str, src_ip: str, dest_ip: str) -> float:
    # Hook: consult "baselines" to adjust likelihood if you add baseline logic later.
    return LIKELIHOOD.get(alert_type, 0.5)

def score_event(ts: str, src_ip: str, dest_ip: str, alert_type: str, notes: str = "") -> float:
    L = _adjust_likelihood(alert_type, src_ip, dest_ip)
    I = _asset_impact_for(dest_ip)
    score = round(L * I * 100.0, 1)
    conn = sqlite3.connect(DB); c = conn.cursor()
    c.execute("""INSERT INTO risks (timestamp, src_ip, dest_ip, alert_type, likelihood, impact, score, notes)
                 VALUES (?,?,?,?,?,?,?,?)""",
              (ts, src_ip, dest_ip, alert_type, L, I, score, notes))
    conn.commit(); conn.close()
    return score
