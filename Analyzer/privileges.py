"""
Privilege verification.

Raw packet sniffing needs elevated privileges on every platform except
Windows (where scapy uses Npcap and handles this differently), so we
gate the whole program on this check before anything else runs.
"""

import os
import sys


def check_privileges():
    """Exit the program early if not running with the privileges raw sockets need."""
    if sys.platform != "win32":
        if os.geteuid() != 0:
            print("[!] Error: Raw packet sniffing requires administrative/root privileges.")
            print("    Please run this script using sudo: 'sudo python3 main.py'")
            sys.exit(1)