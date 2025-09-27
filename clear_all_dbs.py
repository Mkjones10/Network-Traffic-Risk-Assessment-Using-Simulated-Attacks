# clear_all_dbs.py
"""
Clears all data from network_logs.db and packets.db safely.
"""

import sqlite3
from pathlib import Path

DBS = ["network_logs.db", "packets.db"]

def clear_db(db_path):
    if not Path(db_path).exists():
        print(f"[!] {db_path} does not exist, skipping...")
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Get all tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cur.fetchall()]

    # Clear each table
    for t in tables:
        cur.execute(f"DELETE FROM {t};")
        conn.commit()
        print(f"[+] Cleared table {t} in {db_path}")

    conn.close()

def main():
    for db in DBS:
        clear_db(db)
    print("\n[*] All databases cleared.\n")

if __name__ == "__main__":
    main()