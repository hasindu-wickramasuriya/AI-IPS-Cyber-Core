"""Fill missing country fields using the bundled offline DB-IP database.

No alert IPs or other data are sent to a network service. Private, reserved,
and documentation addresses are skipped because they have no public country.
"""
import ipaddress
import sqlite3
from pathlib import Path

import maxminddb

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "logs" / "nids_alerts.db"
GEOIP_DB_PATH = ROOT / "geoip" / "dbip-country-lite-2026-11.mmdb"


def resolve_country(ip_address: str, reader):
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return None
    if not address.is_global:
        return None

    result = reader.get(str(address)) or {}
    country = result.get("country", {})
    name = country.get("names", {}).get("en")
    code = country.get("iso_code")
    return (name, code.lower()) if name and code else None


def main():
    if not DB_PATH.exists():
        raise SystemExit(f"Database not found: {DB_PATH}. Start dashboard.py first.")
    if not GEOIP_DB_PATH.exists():
        raise SystemExit(f"Offline GeoIP database not found: {GEOIP_DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    if not {"source_ip", "country", "country_code"}.issubset(columns):
        conn.close()
        raise SystemExit("The alerts table is missing geolocation columns.")

    rows = conn.execute(
        "SELECT DISTINCT source_ip FROM alerts "
        "WHERE country IS NULL OR country = '' OR country = 'Unknown' "
        "ORDER BY source_ip"
    ).fetchall()
    updated = 0
    skipped = 0
    with maxminddb.open_database(str(GEOIP_DB_PATH)) as reader:
        for (ip_address,) in rows:
            location = resolve_country(ip_address or "", reader)
            if location is None:
                skipped += 1
                print(f"Skipped {ip_address}: no public-country match in offline database")
                continue
            country, country_code = location
            conn.execute(
                "UPDATE alerts SET country = ?, country_code = ? WHERE source_ip = ?",
                (country, country_code, ip_address),
            )
            updated += 1
            print(f"Updated {ip_address}: {country}")
    conn.commit()
    conn.close()
    print(f"Done: updated {updated} public IP(s); skipped {skipped}.")
    print("Refresh the dashboard to see updated country names and flags.")


if __name__ == "__main__":
    main()
