"""
Shared application state.

This is intentionally the only module that owns mutable global data.
Every other module does `import state` and reads/writes attributes on
it (e.g. `state.total_packets += 1`) rather than importing individual
names -- that's what lets a plain module double as shared, mutable
state across threads without needing `global` statements everywhere
or passing a big object around.

All access to the counters/buffers below should be wrapped in
`with state.lock:` since they're written from the sniffer thread,
the rate-calculation thread, and read from the main UI thread.
"""

import threading
from collections import Counter

# Live capture buffers
packet_buffer = []          # Rolling window of tuples for the terminal UI table
all_captured_packets = []   # Full session history of dicts, for CSV export
all_raw_packets = []        # Full session history of raw Scapy packets, for PCAP export

# Running totals
total_packets = 0
total_bytes = 0

# Telemetry / host analytics
ip_packets = Counter()
ip_bytes = Counter()
protocol_counts = Counter()
unique_hosts = set()

# Rate measurement
packet_count_last_sec = 0
current_packet_rate = 0
status_message = "Listening for live packets..."

# Threat detection log
flagged_traffic = []

# Concurrency + capture filter
lock = threading.Lock()
TARGET_IP = ""