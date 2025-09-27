"""
secrets_loader.py — Loads sensitive values (IP, MAC, IFACE) from .secrets.json safely.
"""

import json
from pathlib import Path

def load_secrets(path=".secrets.json"):
    if not Path(path).exists():
        raise FileNotFoundError(
            "Missing .secrets.json! Please create it with keys: MY_IP, MY_MAC, MY_IFACE."
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# Load secrets once
SECRETS = load_secrets()

# Standardized keys (must match your .secrets.json exactly)
MY_IP = SECRETS.get("MY_IP", "127.0.0.1")
MY_MAC = SECRETS.get("MY_MAC", None)
MY_IFACE = SECRETS.get("MY_IFACE", None)  # e.g., "Ethernet" or "Wi-Fi"
