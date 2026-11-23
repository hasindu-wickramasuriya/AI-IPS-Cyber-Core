"""Packet burst classification and local GeoIP lookup."""
import ipaddress
import os
import queue
import sqlite3
import subprocess
import time
from collections import defaultdict, deque
from pathlib import Path

import maxminddb
import numpy as np
from scapy.layers.inet import IP, TCP
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "logs" / "nids_alerts.db"
GEOIP_DB_PATH = ROOT / "geoip" / "dbip-country-lite-2026-11.mmdb"
# A conservative default reduces false positives from ordinary web traffic.
BURST_THRESHOLD = max(50, int(os.getenv("NIDS_BURST_THRESHOLD", "500")))
ALERT_COOLDOWN_SECONDS = 30
SYN_FLOOD_WINDOW_SECONDS = 1
SYN_FLOOD_THRESHOLD = max(50, int(os.getenv("NIDS_SYN_FLOOD_THRESHOLD", "200")))
PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_UNIQUE_PORTS = max(5, int(os.getenv("NIDS_PORT_SCAN_UNIQUE_PORTS", "12")))
AUTH_WINDOW_SECONDS = 60
AUTH_ATTEMPT_THRESHOLD = max(5, int(os.getenv("NIDS_AUTH_ATTEMPT_THRESHOLD", "10")))
AUTH_PORTS = {
    21, 22, 23, 25, 110, 143, 465, 587, 993, 995,
    2222, 3306, 3389, 5432, 5900, 6379, 27017,
}

dos_tracker = defaultdict(deque)
last_alert_by_ip = {}
last_normal_log_by_ip = {}
scan_tracker = defaultdict(deque)
syn_tracker = defaultdict(deque)
auth_tracker = defaultdict(deque)
last_special_alert = {}
_geoip_reader = None

# Train against the project's stated normal range (5-45 packets per second).
rng = np.random.default_rng(42)
baseline_normal_traffic = rng.integers(5, 45, size=(200, 1))
ai_classifier = IsolationForest(contamination=0.03, random_state=42)
ai_classifier.fit(baseline_normal_traffic)
print("[AI Core] Isolation Forest model ready.")


def get_country_from_ip(ip_address):
    """Return (country name, lower-case ISO code) using the bundled DB-IP file."""
    global _geoip_reader
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return "Unknown", "un"

    if address.is_loopback or address.is_link_local:
        return "Local Network", "local"
    if address.version == 4:
        private_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if any(address in network for network in private_ranges):
            return "Local Network", "local"
    elif address in ipaddress.ip_network("fc00::/7"):
        return "Local Network", "local"

    if not address.is_global or not GEOIP_DB_PATH.exists():
        return "Unknown", "un"

    try:
        if _geoip_reader is None:
            _geoip_reader = maxminddb.open_database(str(GEOIP_DB_PATH))
        result = _geoip_reader.get(str(address)) or {}
        country = result.get("country", {})
        name = country.get("names", {}).get("en")
        code = country.get("iso_code")
        if name and code:
            return name, code.lower()
    except Exception as exc:
        print(f"[GeoIP] Local database lookup failed: {exc}")
    return "Unknown", "un"


def block_ip_firewall(ip_address):
    """Add a Windows Firewall rule when explicitly enabled by environment."""
    try:
        address = ipaddress.ip_address(ip_address)
        if os.name != "nt":
            return False
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=NIDS_BLOCK_{address}", "dir=in", "action=block",
             f"remoteip={address}"],
            check=False,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except (ValueError, OSError) as exc:
        print(f"[Firewall] Could not block {ip_address}: {exc}")
        return False


def _make_event(source_ip, event_type, severity, status, now):
    country, country_code = get_country_from_ip(source_ip)
    return {
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        "source": source_ip,
        "type": event_type,
        "severity": severity,
        "country": country,
        "country_code": country_code,
        "status": status,
    }


def classify_packet(packet, now=None):
    """Classify network packets for SYN scans, auth bursts, and DoS bursts."""
    if IP not in packet:
        return None
    source_ip = packet[IP].src
    try:
        source_address = ipaddress.ip_address(source_ip)
    except ValueError:
        return None

    now = time.time() if now is None else now

    # TCP SYN-only packet: track scans across ports and floods against one host.
    is_syn_flood = False
    if TCP in packet:
        tcp = packet[TCP]
        flags = int(tcp.flags)
        is_new_connection = bool(flags & 0x02) and not bool(flags & 0x10)
        if is_new_connection:
            destination_ip = packet[IP].dst
            destination_port = int(tcp.dport)
            flow = (source_ip, destination_ip)

            syn_attempts = syn_tracker[flow]
            syn_attempts.append(now)
            while syn_attempts and now - syn_attempts[0] > SYN_FLOOD_WINDOW_SECONDS:
                syn_attempts.popleft()
            is_syn_flood = len(syn_attempts) >= SYN_FLOOD_THRESHOLD

            attempts = scan_tracker[flow]
            attempts.append((now, destination_port))
            while attempts and now - attempts[0][0] > PORT_SCAN_WINDOW_SECONDS:
                attempts.popleft()
            unique_ports = {port for _, port in attempts}
            if len(unique_ports) >= PORT_SCAN_UNIQUE_PORTS:
                alert_key = (source_ip, destination_ip, "port-scan")
                if now - last_special_alert.get(alert_key, 0) >= ALERT_COOLDOWN_SECONDS:
                    last_special_alert[alert_key] = now
                    return _make_event(
                        source_ip,
                        "Port Scan (TCP SYN sweep)",
                        "HIGH",
                        "DETECTED",
                        now,
                    )

            if destination_port in AUTH_PORTS:
                auth_key = (source_ip, destination_ip, destination_port)
                auth_attempts = auth_tracker[auth_key]
                auth_attempts.append(now)
                while auth_attempts and now - auth_attempts[0] > AUTH_WINDOW_SECONDS:
                    auth_attempts.popleft()
                alert_key = (source_ip, destination_ip, f"auth-{destination_port}")
                if (
                    len(auth_attempts) >= AUTH_ATTEMPT_THRESHOLD
                    and now - last_special_alert.get(alert_key, 0) >= ALERT_COOLDOWN_SECONDS
                ):
                    last_special_alert[alert_key] = now
                    return _make_event(
                        source_ip,
                        f"Brute Force Suspected (TCP/{destination_port} auth burst)",
                        "HIGH",
                        "DETECTED",
                        now,
                    )

            if is_syn_flood and source_address.is_global:
                alert_key = (source_ip, destination_ip, "syn-flood")
                if now - last_special_alert.get(alert_key, 0) >= ALERT_COOLDOWN_SECONDS:
                    last_special_alert[alert_key] = now
                    return _make_event(
                        source_ip,
                        "SYN Flood (TCP SYN burst)",
                        "HIGH",
                        "DETECTED",
                        now,
                    )

    source_times = dos_tracker[source_ip]
    source_times.append(now)
    while source_times and now - source_times[0] > 1.0:
        source_times.popleft()

    burst_size = len(source_times)
    if burst_size < 5:
        return None

    is_attack_checkpoint = (
        not is_syn_flood
        and burst_size >= BURST_THRESHOLD
        and (burst_size == BURST_THRESHOLD or burst_size % 100 == 0)
    )
    normal_log_due = now - last_normal_log_by_ip.get(source_ip, 0) >= 60
    is_normal_checkpoint = normal_log_due and (burst_size == 5 or burst_size % 10 == 0)
    if not is_attack_checkpoint and not is_normal_checkpoint:
        return None
    if is_attack_checkpoint and now - last_alert_by_ip.get(source_ip, 0) < ALERT_COOLDOWN_SECONDS:
        return None

    verdict = ai_classifier.predict(np.array([[burst_size]]))[0]
    now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

    if verdict == 1 and normal_log_due:
        country, country_code = get_country_from_ip(source_ip)
        last_normal_log_by_ip[source_ip] = now
        return {
            "time": now_text,
            "source": source_ip,
            "type": "Normal Traffic (Isolation Forest)",
            "severity": "INFO",
            "country": country,
            "country_code": country_code,
            "status": "OBSERVED",
            "burst_size": burst_size,
        }

    if burst_size < BURST_THRESHOLD or not source_address.is_global:
        return None
    if now - last_alert_by_ip.get(source_ip, 0) < ALERT_COOLDOWN_SECONDS:
        return None

    last_alert_by_ip[source_ip] = now
    country, country_code = get_country_from_ip(source_ip)
    status = "DETECTED"
    if os.getenv("NIDS_ENABLE_FIREWALL_BLOCKS") == "1":
        if block_ip_firewall(source_ip):
            status = "BLOCKED"

    return {
        "time": now_text,
        "source": source_ip,
        "type": "DoS Burst (Isolation Forest)",
        "severity": "HIGH",
        "country": country,
        "country_code": country_code,
        "status": status,
        "burst_size": burst_size,
    }


def process_packets(packet_queue, alert_callback):
    """Consume captured packets and send each detected alert to one callback."""
    while True:
        try:
            packet = packet_queue.get(timeout=0.25)
        except queue.Empty:
            continue
        alert = classify_packet(packet)
        if alert is not None:
            try:
                alert_callback(alert)
            except Exception as exc:
                print(f"[Detector] Could not publish classification: {exc}")
