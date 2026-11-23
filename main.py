"""Run the local dashboard and passive packet detector together."""
import os
import threading

from colorama import Fore, init

from dashboard import app, send_live_alert, socketio
from detector import BURST_THRESHOLD, process_packets
from logger import init_db, log_alert
from sniffer import launch_sniffer, packet_queue

init(autoreset=True)


def on_alert_detected(alert_data):
    color = Fore.RED if alert_data["severity"] != "INFO" else Fore.CYAN
    print(color + (
        f"[{alert_data['status']}] {alert_data['type']} from {alert_data['source']} "
        f"({alert_data['country']}); burst={alert_data['burst_size']}/sec"
    ))
    log_alert(alert_data)
    send_live_alert(alert_data)


if __name__ == "__main__":
    init_db()
    interface = os.getenv("NIDS_INTERFACE") or None
    launch_sniffer(interface=interface)

    detector_thread = threading.Thread(
        target=process_packets,
        args=(packet_queue, on_alert_detected),
        daemon=True,
    )
    detector_thread.start()

    print(Fore.GREEN + "Dashboard: http://127.0.0.1:5000")
    if interface:
        print(Fore.CYAN + f"Capture interface: {interface}")
    else:
        print(Fore.CYAN + "Capture interface: Scapy default (set NIDS_INTERFACE to choose one)")
    print(Fore.CYAN + f"DoS threshold: {BURST_THRESHOLD} packets/sec from one public source.")
    print(Fore.YELLOW + "Firewall blocking is off unless NIDS_ENABLE_FIREWALL_BLOCKS=1.")
    try:
        socketio.run(app, host="127.0.0.1", port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "Shutting down NIDS core.")
