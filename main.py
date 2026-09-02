"""
Network Traffic Analyzer & Mini-NIDS Dashboard.

Entry point: wires together privilege checks, the capture threads,
the Rich Live dashboard, and the save-on-exit flow.

Run with:
    sudo python3 main.py
"""

import sys
import threading
import time
from datetime import datetime

from rich.console import Console
from rich.live import Live

import state
from capture import calculate_rates, start_sniffer
from export import sanitize_filename, save_session_data
from privileges import check_privileges
from ui import check_keyboard_input, generate_layout

# termios/tty are POSIX-only; guard the import so this still runs on Windows,
# where raw-mode terminal handling isn't needed/used anyway.
if sys.platform != "win32":
    import termios
    import tty

BANNER = r"""
  _  __      _                      _      _____           __  __ _             _                _
 | \|  | ___| |___      _____  _ __| | __ |_   _| __ __   / _|/ _(_) ___       / \   _ __   __ _| |_   _ _______ _ __
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /   | || '__/ _`\| |_| |_| |/ __|     / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <    | || | | (_| |  _|  _| | (__     / ___ \| | | | (_| | | |_| |/ /  __/ |
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\___|_||_|  \__,_|_| |_| |_|\___|___/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                                        |_____|                         |_____|                     |___/
"""


def print_banner():
    current_year = datetime.now().year
    print("\n****************************************************************")
    print(BANNER)
    print("****************************************************************")
    print(f"* Copyright © {current_year} Aman Tomar. All rights reserved.       *")
    print("* Network Traffic Analyzer & Mini-NIDS Dashboard               *")
    print("****************************************************************")
    print()


def run_dashboard(console):
    """Runs the Live UI loop until the user presses 'q'."""
    old_settings = None
    if sys.platform != "win32" and sys.stdin.isatty():
        try:
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            pass

    try:
        with Live(generate_layout(console), refresh_per_second=4, console=console) as live:
            while True:
                time.sleep(0.1)
                key = check_keyboard_input()
                if key == "q":
                    break
                live.update(generate_layout(console))
    except KeyboardInterrupt:
        pass
    finally:
        if old_settings and sys.platform != "win32":
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except Exception:
                pass


def prompt_save():
    """Asks the user whether to persist the session, then does so."""
    save_choice = (
        input("Do you want to save session log & PCAP captures? (y/n): ").strip().lower()
    )
    if save_choice in ("y", "yes"):
        raw_filename = input("Enter file base name (e.g., session_capture): ")
        clean_name = sanitize_filename(raw_filename)

        success, message = save_session_data(clean_name)
        if success:
            print(f"\n[✓] Successfully saved: {message}")
        else:
            print(f"\n[!] Save failed: {message}")
    else:
        print("\nSession ended without saving.")


def main():
    # 0. Check root privileges before touching sockets or threads
    check_privileges()

    console = Console()
    console.clear()

    print_banner()

    user_input = input(
        "Please enter an IP address to monitor (or press Enter for all): "
    ).strip()
    state.TARGET_IP = user_input

    print("\nLaunching interface... (Press 'q' inside dashboard to exit)")
    time.sleep(1.0)
    console.clear()

    threading.Thread(target=start_sniffer, daemon=True).start()
    threading.Thread(target=calculate_rates, daemon=True).start()

    run_dashboard(console)

    console.clear()
    console.print("[bold green]Capture stopped.[/bold green]\n")

    prompt_save()

    console.print("[bold green][✓] Session ended cleanly. All captures stopped.[/bold green]")


if __name__ == "__main__":
    main()