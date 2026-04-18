"""
risk_engine.py — NIST SP 800-30 qualitative likelihood x impact scoring
with full MITRE ATT&CK enrichment.

Scoring model:
    Likelihood : 1-5
    Impact     : 1-5
    Final score: ((likelihood * impact) / 25) * 100
"""

from __future__ import annotations

import ipaddress
import sqlite3
from typing import Any, Dict

from db_utils import load_config

CFG = load_config()
DB = CFG["db_path"]

DEFAULT_RISK_CFG = {
    "method": "nist_sp800_30_qualitative",
    "formula": "((likelihood * impact) / 25) * 100",
    "base_likelihood": {
        "SYN_FLOOD":  4,
        "UDP_FLOOD":  4,
        "DNS_FLOOD":  4,
        "ICMP_SWEEP": 3,
        "SLOWLORIS":  3,
        "FTP_ANON":   3,
        "TLS_WEAK":   2,
    },
    "asset_criticality_impact": {
        "LOW":      2,
        "MEDIUM":   3,
        "HIGH":     4,
        "CRITICAL": 5,
    },
    "scenario_impact_modifier": {
        "SYN_FLOOD":  4,
        "UDP_FLOOD":  4,
        "DNS_FLOOD":  4,
        "ICMP_SWEEP": 2,
        "SLOWLORIS":  4,
        "FTP_ANON":   4,
        "TLS_WEAK":   3,
    },
    "bucket_thresholds": {
        "VERY_LOW": 20,
        "LOW":      40,
        "MEDIUM":   60,
        "HIGH":     80,
    },
}

MITRE_MAPPING: Dict[str, Dict[str, Any]] = {
    "SYN_FLOOD": {
        "primary": [
            {
                "id":     "T1498",
                "name":   "Network Denial of Service",
                "tactic": "Impact",
                "url":    "https://attack.mitre.org/techniques/T1498",
            }
        ],
        "secondary": [],
    },
    "UDP_FLOOD": {
        "primary": [
            {
                "id":     "T1498",
                "name":   "Network Denial of Service",
                "tactic": "Impact",
                "url":    "https://attack.mitre.org/techniques/T1498",
            }
        ],
        "secondary": [],
    },
    "DNS_FLOOD": {
        "primary": [
            {
                "id":     "T1498",
                "name":   "Network Denial of Service",
                "tactic": "Impact",
                "url":    "https://attack.mitre.org/techniques/T1498",
            }
        ],
        "secondary": [
            {
                "id":     "T1595",
                "name":   "Active Scanning",
                "tactic": "Reconnaissance",
                "url":    "https://attack.mitre.org/techniques/T1595",
            }
        ],
    },
    "ICMP_SWEEP": {
        "primary": [
            {
                "id":     "T1018",
                "name":   "Remote System Discovery",
                "tactic": "Discovery",
                "url":    "https://attack.mitre.org/techniques/T1018",
            }
        ],
        "secondary": [
            {
                "id":     "T1595.001",
                "name":   "Scanning IP Blocks",
                "tactic": "Reconnaissance",
                "url":    "https://attack.mitre.org/techniques/T1595/001",
            }
        ],
    },
    "SLOWLORIS": {
        "primary": [
            {
                "id":     "T1499",
                "name":   "Endpoint Denial of Service",
                "tactic": "Impact",
                "url":    "https://attack.mitre.org/techniques/T1499",
            }
        ],
        "secondary": [
            {
                "id":     "T1498",
                "name":   "Network Denial of Service",
                "tactic": "Impact",
                "url":    "https://attack.mitre.org/techniques/T1498",
            }
        ],
    },
    "FTP_ANON": {
        "primary": [
            {
                "id":     "T1133",
                "name":   "External Remote Services",
                "tactic": "Initial Access",
                "url":    "https://attack.mitre.org/techniques/T1133",
            }
        ],
        "secondary": [
            {
                "id":     "T1078",
                "name":   "Valid Accounts",
                "tactic": "Defense Evasion / Persistence",
                "url":    "https://attack.mitre.org/techniques/T1078",
            }
        ],
    },
    "TLS_WEAK": {
        "primary": [
            {
                "id":     "T1562.010",
                "name":   "Downgrade Attack",
                "tactic": "Defense Evasion",
                "url":    "https://attack.mitre.org/techniques/T1562/010",
            }
        ],
        "secondary": [
            {
                "id":     "T1040",
                "name":   "Network Sniffing",
                "tactic": "Credential Access / Discovery",
                "url":    "https://attack.mitre.org/techniques/T1040",
            }
        ],
    },
}

LIKELIHOOD_LABELS = {
    1: "VERY_LOW",
    2: "LOW",
    3: "MODERATE",
    4: "HIGH",
    5: "VERY_HIGH",
}


def _risk_cfg() -> Dict[str, Any]:
    cfg = CFG.get("risk", {})
    merged = DEFAULT_RISK_CFG.copy()
    for key in (
        "base_likelihood",
        "asset_criticality_impact",
        "scenario_impact_modifier",
        "bucket_thresholds",
    ):
        merged[key] = {**DEFAULT_RISK_CFG.get(key, {}), **cfg.get(key, {})}
    merged["method"]  = cfg.get("method",  DEFAULT_RISK_CFG["method"])
    merged["formula"] = cfg.get("formula", DEFAULT_RISK_CFG["formula"])
    return merged


RISK_CFG = _risk_cfg()


def get_mitre_mapping(alert_type: str) -> Dict[str, Any]:
    return MITRE_MAPPING.get(alert_type, {"primary": [], "secondary": []})


def _asset_criticality_for(dest_ip: str) -> str:
    try:
        ip = ipaddress.ip_address(dest_ip)
    except ValueError:
        return "MEDIUM"
    for asset in CFG.get("assets", []):
        try:
            if ip in ipaddress.ip_network(asset["cidr"], strict=False):
                return (asset.get("criticality") or "MEDIUM").upper()
        except Exception:
            continue
    return "MEDIUM"


def _asset_impact_for(dest_ip: str) -> int:
    criticality = _asset_criticality_for(dest_ip)
    return int(RISK_CFG["asset_criticality_impact"].get(criticality, 3))


def _scenario_impact_for(alert_type: str) -> int:
    return int(RISK_CFG["scenario_impact_modifier"].get(alert_type, 3))


def _base_likelihood_for(alert_type: str) -> int:
    return int(RISK_CFG["base_likelihood"].get(alert_type, 3))


def _frequency_modifier(notes: str) -> int:
    n = (notes or "").lower()
    if any(t in n for t in ["sustained", "repeated", "flood", "burst", "high-volume"]):
        return 1
    if any(t in n for t in ["single", "isolated", "one-off"]):
        return -1
    return 0


def _confidence_modifier(alert_type: str, notes: str) -> int:
    n = (notes or "").lower()
    if alert_type in {"TLS_WEAK", "FTP_ANON"}:
        return -1
    if any(t in n for t in ["confirmed", "directly observed", "packet evidence"]):
        return 1
    return 0


def _adjust_likelihood(alert_type: str, src_ip: str, dest_ip: str, notes: str = "") -> int:
    base     = _base_likelihood_for(alert_type)
    modifier = _frequency_modifier(notes) + _confidence_modifier(alert_type, notes)
    return max(1, min(5, base + modifier))


def _calculate_impact(alert_type: str, dest_ip: str) -> int:
    return max(_asset_impact_for(dest_ip), _scenario_impact_for(alert_type))


def _normalize_score(likelihood: int, impact: int) -> float:
    return round(((likelihood * impact) / 25.0) * 100.0, 1)


def bucketize(score: float) -> str:
    t = RISK_CFG["bucket_thresholds"]
    if score < t["VERY_LOW"]: return "VERY_LOW"
    if score < t["LOW"]:      return "LOW"
    if score < t["MEDIUM"]:   return "MEDIUM"
    if score < t["HIGH"]:     return "HIGH"
    return "VERY_HIGH"


def score_event(
    ts: str,
    src_ip: str,
    dest_ip: str,
    alert_type: str,
    notes: str = "",
) -> float:
    likelihood = _adjust_likelihood(alert_type, src_ip, dest_ip, notes)
    impact     = _calculate_impact(alert_type, dest_ip)
    score      = _normalize_score(likelihood, impact)
    severity   = bucketize(score)
    mitre      = get_mitre_mapping(alert_type)
    primary    = mitre["primary"][0] if mitre.get("primary") else {}

    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO risks (
                timestamp, src_ip, dest_ip, alert_type,
                likelihood, impact, score, notes,
                severity_bucket,
                mitre_primary_id, mitre_primary_name, mitre_tactic
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ts, src_ip, dest_ip, alert_type,
                likelihood, impact, score, notes,
                severity,
                primary.get("id"),
                primary.get("name"),
                primary.get("tactic"),
            ),
        )
    except sqlite3.OperationalError:
        c.execute(
            """
            INSERT INTO risks (
                timestamp, src_ip, dest_ip, alert_type,
                likelihood, impact, score, notes
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (ts, src_ip, dest_ip, alert_type, likelihood, impact, score, notes),
        )
    conn.commit()
    conn.close()
    return score


def explain_score(alert_type: str, src_ip: str, dest_ip: str, notes: str = "") -> Dict[str, Any]:
    likelihood = _adjust_likelihood(alert_type, src_ip, dest_ip, notes)
    impact     = _calculate_impact(alert_type, dest_ip)
    score      = _normalize_score(likelihood, impact)
    return {
        "alert_type":        alert_type,
        "src_ip":            src_ip,
        "dest_ip":           dest_ip,
        "base_likelihood":   _base_likelihood_for(alert_type),
        "final_likelihood":  likelihood,
        "likelihood_label":  LIKELIHOOD_LABELS.get(likelihood, "UNKNOWN"),
        "asset_criticality": _asset_criticality_for(dest_ip),
        "asset_impact":      _asset_impact_for(dest_ip),
        "scenario_impact":   _scenario_impact_for(alert_type),
        "final_impact":      impact,
        "score":             score,
        "severity_bucket":   bucketize(score),
        "mitre":             get_mitre_mapping(alert_type),
        "notes":             notes,
    }
