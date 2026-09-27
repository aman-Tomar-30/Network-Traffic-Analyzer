"""
Mini-NIDS detection rules.

Isolated from capture.py so new rules can be added/tested without
touching the packet-processing pipeline itself. Each function takes
already-extracted fields (not the whole packet-processing state) so
it stays easy to unit test.
"""

from scapy.all import TCP

from config import COMMON_SERVICES


def check_alert_rules(packet, src_ip, dst_ip, dport, timestamp):
    """
    Run all NIDS rules against a single packet's extracted fields.

    Returns a formatted alert string if any rule matches, else None.
    Rules are checked in priority order and the first match wins,
    matching the original script's behavior.
    """

    # Rule 1: Flag TCP SYN Scan / Port Reconnaissance Probe
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        return f"[{timestamp}] SYN Probe: {src_ip} -> {dst_ip}:{dport}"

    # Rule 2: Flag Unencrypted Cleartext Transmissions
    if dport in (80, 21, 23):
        proto_name = "HTTP" if dport == 80 else ("FTP" if dport == 21 else "Telnet")
        return f"[{timestamp}] Cleartext {proto_name}: {src_ip} -> {dst_ip}"

    # Rule 3: Flag Non-Standard Dynamic High Ports (>1024)
    if dport and dport not in COMMON_SERVICES and dport > 1024:
        return f"[{timestamp}] High Port: {src_ip} -> {dst_ip}:{dport}"

    return None