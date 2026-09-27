"""
Static configuration values for the Network Traffic Analyzer.

Keeping this separate makes it trivial to tweak known-service mappings
or add new ones without touching any capture/UI logic.
"""

# Well-known ports mapped to human-readable service names.
# Used by capture.resolve_service() and detection.check_alert_rules()
# to label traffic and decide what counts as a "non-standard" port.
COMMON_SERVICES = {
    80: "HTTP (Web)",
    443: "HTTPS (Web)",
    53: "DNS (Domain Lookup)",
    22: "SSH (Remote Access)",
    21: "FTP (File Transfer)",
    23: "Telnet",
    123: "NTP (Time Sync)",
    5353: "mDNS (Local Discovery)",
    1900: "SSDP (UPnP)",
    67: "DHCP",
    68: "DHCP",
}

# Rolling buffer sizes
PACKET_BUFFER_MAX = 100
FLAGGED_TRAFFIC_MAX = 5