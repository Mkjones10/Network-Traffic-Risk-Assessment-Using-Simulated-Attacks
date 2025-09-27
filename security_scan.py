"""
security_scan.py — Optional wrapper around nmap (if installed) to list open ports/services.
This is for corroboration in your report; keep scans to authorized lab targets only.
"""

import subprocess, json, shutil
from db_utils import load_config

CFG = load_config()

def nmap_available():
    return shutil.which("nmap") is not None

def scan_targets(targets):
    if not nmap_available():
        return {"error": "nmap not found in PATH"}
    # -sS requires privileges; -sT TCP connect scan is safer for labs.
    cmd = ["nmap", "-sT", "-Pn", "-T3", "-oX", "-", *targets]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()}
    return {"xml": proc.stdout}

if __name__ == "__main__":
    targets = CFG.get("allowed_targets", [])
    print(json.dumps(scan_targets(targets), indent=2))
