"""Generate clearly labelled synthetic traffic for checking the dashboard pipeline.

This does not sniff the network, block IPs, or send alerts externally. The
source addresses are reserved documentation addresses, not real attackers.
"""
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

DB_PATH = Path(__file__).resolve().parent / "logs" / "nids_alerts.db"

# Match the detector's Isolation Forest setup and normal burst range.
rng = np.random.default_rng(42)
baseline = rng.integers(5, 45, size=(200, 1))
model = IsolationForest(contamination=0.03, random_state=42)
model.fit(baseline)

# These are synthetic packet-per-second burst sizes. RFC 5737 TEST-NET
# addresses are used so the dashboard cannot mistake them for real sources.
observations = [
    ("192.0.2.10", 12), ("192.0.2.10", 24), ("192.0.2.10", 38),
    ("198.51.100.21", 18), ("198.51.100.21", 29),
    ("203.0.113.31", 120), ("203.0.113.31", 160),
    ("203.0.113.42", 220), ("203.0.113.42", 300),
]

if not DB_PATH.exists():
    raise SystemExit(f"Dashboard database not found: {DB_PATH}. Start dashboard.py first.")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("PRAGMA table_info(alerts)")
columns = {row[1] for row in cur.fetchall()}
required = {"timestamp", "source_ip", "attack_type", "severity", "country", "country_code", "status"}
if not required.issubset(columns):
    conn.close()
    raise SystemExit(f"Alerts table is missing columns: {', '.join(sorted(required - columns))}")

# Keep repeated runs tidy by replacing this script's earlier demo rows only.
cur.execute("DELETE FROM alerts WHERE status = 'SIMULATED' AND attack_type LIKE '%(DEMO)%'")
now = datetime.now()
for index, (source_ip, burst_size) in enumerate(observations):
    is_anomaly = model.predict(np.array([[burst_size]]))[0] == -1
    verdict = "DoS (DEMO)" if is_anomaly else "Normal Traffic (DEMO)"
    severity = "HIGH" if is_anomaly else "INFO"
    cur.execute(
        "INSERT INTO alerts (timestamp, source_ip, attack_type, severity, country, country_code, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            (now - timedelta(seconds=len(observations) - index)).strftime("%Y-%m-%d %H:%M:%S"),
            source_ip,
            verdict,
            severity,
            "Unknown (reserved demo IP)",
            "un",
            "SIMULATED",
        ),
    )
conn.commit()
cur.execute("SELECT attack_type, COUNT(*) FROM alerts WHERE status = 'SIMULATED' GROUP BY attack_type")
summary = cur.fetchall()
conn.close()

print("Inserted synthetic Isolation Forest classifications:")
for verdict, count in summary:
    print(f"  {verdict}: {count}")
print("Refresh the dashboard. All generated rows are marked SIMULATED and use reserved example IPs.")

