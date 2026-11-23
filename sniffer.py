"""Scapy packet capture feeding the detector queue."""
import threading
from queue import Queue

from scapy.all import IP, conf, sniff

packet_queue = Queue()


def packet_callback(packet):
    if IP in packet:
        packet_queue.put(packet)


def start_sniffing(interface=None):
    label = interface or "default interface"
    print(f"[Sniffer] Capturing IPv4 packets on {label}")
    if "NotAvailableSocket" in getattr(conf.L2listen, "__name__", ""):
        print("[Sniffer] Npcap is missing (wpcap.dll unavailable); install Npcap to capture on Windows.")
        return
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as exc:
        print(f"[Sniffer] Capture failed on {label}: {exc}")


def launch_sniffer(interface=None):
    thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
    thread.start()
    return thread
