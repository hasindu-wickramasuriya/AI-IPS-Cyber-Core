"""SQLite alert storage shared by the detector and dashboard."""
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_DIR = ROOT / "logs"
DB_NAME = DB_DIR / "nids_alerts.db"


def init_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                attack_type TEXT,
                severity TEXT,
                country TEXT,
                country_code TEXT,
                status TEXT DEFAULT 'DETECTED'
            )
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        if "status" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'DETECTED'")


def log_alert(alert_data):
    init_db()
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            INSERT INTO alerts
                (timestamp, source_ip, attack_type, severity, country, country_code, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data["time"],
            alert_data["source"],
            alert_data["type"],
            alert_data.get("severity", "HIGH"),
            alert_data.get("country", "Unknown"),
            alert_data.get("country_code", "un"),
            alert_data.get("status", "DETECTED"),
        ))
