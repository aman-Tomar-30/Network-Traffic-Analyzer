"""
Session export: CSV packet log + PCAP capture for Wireshark.
"""

import csv
import re
from datetime import datetime

from scapy.all import wrpcap

import state


def sanitize_filename(name):
    """Sanitizes user input to construct a clean, valid file base name."""
    name = name.strip()
    if not name:
        return f"traffic_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Strip illegal characters for Windows/Unix file systems
    name = re.sub(r'[\\/*?:"<>|]', "_", name)

    # Strip explicit extensions if user entered them (we append .csv and .pcap automatically)
    if name.lower().endswith(".csv") or name.lower().endswith(".pcap"):
        name = name.rsplit(".", 1)[0]

    return name


def save_session_data(base_filename):
    """Exports session history to CSV and writes raw packet captures to PCAP for Wireshark."""
    with state.lock:
        if not state.all_captured_packets:
            return False, "No packets captured in this session."

        try:
            csv_file = f"{base_filename}.csv"
            pcap_file = f"{base_filename}.pcap"

            # 1. Export CSV Log
            fieldnames = [
                "Date",
                "Time",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Service",
                "Size (Bytes)",
            ]
            with open(csv_file, mode="w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(state.all_captured_packets)

            # 2. Export Wireshark PCAP File
            wrpcap(pcap_file, state.all_raw_packets)

            return True, f"Saved CSV ('{csv_file}') and PCAP ('{pcap_file}')"
        except Exception as e:
            return False, str(e)