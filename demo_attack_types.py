"""Safely simulate attack classifications for the dashboard UI.

Packets are created in memory and passed through detector.classify_packet.
This script does not send network traffic, change firewall rules, or contact
external services. All inserted rows are marked SIMULATED.
"""
import sqlite3
import time
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP

from detector import (
    AUTH_ATTEMPT_THRESHOLD,
    AUTH_WINDOW_SECONDS,
    BURST_THRESHOLD,
    PORT_SCAN_UNIQUE_PORTS,
    SYN_FLOOD_THRESHOLD,
    classify_packet,
)
from logger import init_db, log_alert

DB_PATH = Path(__file__).resolve().parent / "logs" / "nids_alerts.db"


def collect(packets, timestamps, wanted_prefix):
    found = None
    for packet, timestamp in zip(packets, timestamps):
        result = classify_packet(packet, now=timestamp)
        if result and result["type"].startswith(wanted_prefix):
            found = result
    if found is None:
        raise RuntimeError(f"Detector did not produce expected classification: {wanted_prefix}")
    return found


def main():
    init_db()
    base_time = time.time() - 120

    syn_flood_count = SYN_FLOOD_THRESHOLD
    syn_flood = collect(
        [
            IP(src="8.8.8.8", dst="192.0.2.10") / TCP(sport=40000 + i, dport=443, flags="S")
            for i in range(syn_flood_count)
        ],
        [base_time + i / syn_flood_count for i in range(syn_flood_count)],
        "SYN Flood",
    )

    port_scan = collect(
        [
            IP(src="203.0.113.20", dst="192.0.2.20") / TCP(sport=41000, dport=1000 + i, flags="S")
            for i in range(PORT_SCAN_UNIQUE_PORTS)
        ],
        [base_time + 2 + i * 0.2 for i in range(PORT_SCAN_UNIQUE_PORTS)],
        "Port Scan",
    )

    brute_force = collect(
        [
            IP(src="198.51.100.30", dst="192.0.2.30") / TCP(sport=42000 + i, dport=22, flags="S")
            for i in range(AUTH_ATTEMPT_THRESHOLD)
        ],
        [base_time + 5 + i * (AUTH_WINDOW_SECONDS / AUTH_ATTEMPT_THRESHOLD) for i in range(AUTH_ATTEMPT_THRESHOLD)],
        "Brute Force Suspected",
    )

    dos_count = BURST_THRESHOLD
    dos = collect(
        [
            IP(src="9.9.9.9", dst="192.0.2.40") / UDP(sport=43000 + (i % 1000), dport=53)
            for i in range(dos_count)
        ],
        [base_time + 70 + i / dos_count for i in range(dos_count)],
        "DoS Burst",
    )

    # The source IPs are examples, not real attackers or their real geolocation.
    samples = [syn_flood, port_scan, brute_force, dos]
    for event in samples:
        event["type"] += " (DEMO)"
        event["country"] = "Demo only (not geolocated)"
        event["country_code"] = "un"
        event["status"] = "SIMULATED"

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM alerts WHERE status='SIMULATED' AND attack_type LIKE '%(DEMO)%'")
    for event in samples:
        log_alert(event)

    print("Added simulated dashboard records using in-memory packets:")
    for event in samples:
        print(f"  {event['type']} from {event['source']} — {event['status']}")
    print("Refresh the dashboard. No packets were sent to the network.")


if __name__ == "__main__":
    main()
