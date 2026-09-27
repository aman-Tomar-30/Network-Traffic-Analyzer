"""
Packet capture pipeline.

Owns the Scapy sniff callback plus the two background threads that
feed `state`: the sniffer itself and the once-a-second rate calculator.
"""

import time
from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP, sniff

import state
from config import COMMON_SERVICES, FLAGGED_TRAFFIC_MAX, PACKET_BUFFER_MAX
from detection import check_alert_rules


def resolve_service(sport, dport):
    """Translate source/destination port numbers into standard application service names."""
    if dport in COMMON_SERVICES:
        return COMMON_SERVICES[dport]
    if sport in COMMON_SERVICES:
        return COMMON_SERVICES[sport]
    return f"Port {dport}" if dport else "Unknown"


def process_packet(packet):
    """Callback function triggered by Scapy for every sniffed network packet."""
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    pkt_len = len(packet)

    if state.TARGET_IP and (state.TARGET_IP not in (src_ip, dst_ip)):
        return

    date_str = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%H:%M:%S")

    protocol = "Other"
    service = "-"
    dport = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        dport = packet[TCP].dport
        service = resolve_service(packet[TCP].sport, dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dport = packet[UDP].dport
        service = resolve_service(packet[UDP].sport, dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        service = "Ping / Control"

    size_str = f"{pkt_len} B" if pkt_len < 1024 else f"{pkt_len / 1024:.1f} KB"

    with state.lock:
        state.total_packets += 1
        state.total_bytes += pkt_len
        state.packet_count_last_sec += 1

        state.ip_packets[src_ip] += 1
        state.ip_bytes[src_ip] += pkt_len
        state.protocol_counts[protocol] += 1
        state.unique_hosts.add(src_ip)
        state.unique_hosts.add(dst_ip)

        # MINI-NIDS DETECTION
        alert = check_alert_rules(packet, src_ip, dst_ip, dport, timestamp)
        if alert and alert not in state.flagged_traffic:
            state.flagged_traffic.append(alert)
            if len(state.flagged_traffic) > FLAGGED_TRAFFIC_MAX:
                state.flagged_traffic.pop(0)

        # Formatted tuple for UI table display
        state.packet_buffer.append(
            (date_str, timestamp, src_ip, dst_ip, protocol, service, size_str)
        )
        if len(state.packet_buffer) > PACKET_BUFFER_MAX:
            state.packet_buffer.pop(0)

        # Structured dictionary for CSV export
        state.all_captured_packets.append(
            {
                "Date": date_str,
                "Time": timestamp,
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Protocol": protocol,
                "Service": service,
                "Size (Bytes)": pkt_len,
            }
        )

        # Raw Scapy packet, retained for Wireshark PCAP export
        state.all_raw_packets.append(packet)


def calculate_rates():
    """Background worker thread that calculates packet throughput every second."""
    while True:
        time.sleep(1)
        with state.lock:
            state.current_packet_rate = state.packet_count_last_sec
            state.packet_count_last_sec = 0


def start_sniffer():
    """Starts packet capture in non-storing mode to save memory."""
    sniff(prn=process_packet, store=0)