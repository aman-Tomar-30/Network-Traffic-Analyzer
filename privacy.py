"""
Display-only IP privacy masking.

Used to blur IP addresses in the live terminal UI during public
broadcasts, recordings, or demos -- WITHOUT touching the underlying
data used for grouping/analytics or the CSV/PCAP export, so forensic
log integrity is preserved regardless of what's on screen.

Masking scheme: keep the network prefix (first two octets) visible
so traffic patterns/subnets are still readable, and replace the host
portion (last two octets) with a fixed placeholder.
    192.168.1.15  ->  192.168.xxx.xxx
"""

MASK_PLACEHOLDER = "xxx"


def mask_ip(ip: str) -> str:
    """Return a privacy-masked copy of an IPv4 address for display purposes.

    Non-IPv4-looking input (e.g. IPv6) is returned unchanged, since the
    octet-based scheme below doesn't apply to it.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return f"{parts[0]}.{parts[1]}.{MASK_PLACEHOLDER}.{MASK_PLACEHOLDER}"


def maybe_mask(ip: str, enabled: bool) -> str:
    """Convenience wrapper: mask only when the caller says masking is enabled."""
    return mask_ip(ip) if enabled else ip