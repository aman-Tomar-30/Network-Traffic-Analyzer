"""
Terminal UI: non-blocking keyboard polling + the Rich dashboard layout.
"""

import select
import sys

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

import state
from privacy import maybe_mask


def check_keyboard_input():
    """Non-blocking keyboard reader to capture user key presses interactively."""
    if sys.platform == "win32":
        import msvcrt

        if msvcrt.kbhit():
            return msvcrt.getch().decode("utf-8", errors="ignore").lower()
    else:
        if sys.stdin.isatty():
            dr, _, _ = select.select([sys.stdin], [], [], 0)
            if dr:
                return sys.stdin.read(1).lower()
    return None


def generate_layout(console: Console) -> Layout:
    """Builds and updates the Rich UI layout structure with current telemetry data."""
    layout = Layout()

    term_height = console.height
    usable_height = term_height - 3

    top_panel_height = int(usable_height * (5 / 8))
    bottom_panel_height = usable_height - top_panel_height

    top_max_rows = max(5, top_panel_height - 3)
    bottom_max_rows = max(3, bottom_panel_height - 3)

    layout.split_column(
        Layout(name="top", ratio=5),
        Layout(name="bottom", ratio=3),
        Layout(name="footer", size=3),
    )
    layout["bottom"].split_row(
        Layout(name="top_talkers", ratio=3),
        Layout(name="telemetry", ratio=2),
    )

    with state.lock:
        mb_transferred = state.total_bytes / (1024 * 1024)

        # 1. TOP PANEL: Live Packet Stream Table
        top_table = Table(expand=True, show_edge=False)
        top_table.add_column("Date", style="dim green", width=11)
        top_table.add_column("Time", style="dim green", width=9)
        top_table.add_column("Source IP", style="green")
        top_table.add_column("Destination IP", style="green")
        top_table.add_column("Protocol", style="bold green", width=9)
        top_table.add_column("Service / Application", style="bright_green")
        top_table.add_column("Size", style="dim green", justify="right", width=9)

        visible_packets = state.packet_buffer[-top_max_rows:]
        for pkt in visible_packets:
            src_display = maybe_mask(pkt[2], state.mask_ips)
            dst_display = maybe_mask(pkt[3], state.mask_ips)
            top_table.add_row(pkt[0], pkt[1], src_display, dst_display, pkt[4], pkt[5], pkt[6])

        top_panel = Panel(
            top_table,
            title=(
                f"Live Packet Stream | Packets: {state.total_packets} | Data:"
                f" {mb_transferred:.2f} MB"
            ),
            border_style="green",
        )
        layout["top"].update(top_panel)

        # 2. BOTTOM LEFT PANEL: Top Network Generators
        talkers_table = Table(expand=True, show_edge=False)
        talkers_table.add_column("Active IP Address", style="bright_green")
        talkers_table.add_column("Packets", style="green", justify="right")
        talkers_table.add_column("Data", style="dim green", justify="right")
        talkers_table.add_column("Volume Bar", style="bright_green")

        max_bytes = max(state.ip_bytes.values()) if state.ip_bytes else 1

        for ip, p_count in state.ip_packets.most_common(bottom_max_rows):
            b_count = state.ip_bytes[ip]
            data_str = (
                f"{b_count / 1024:.1f} KB"
                if b_count < 1048576
                else f"{b_count / 1048576:.2f} MB"
            )

            bar_length = 10
            filled = int((b_count / max_bytes) * bar_length)
            bar = "█" * filled + "░" * (bar_length - filled)

            ip_display = maybe_mask(ip, state.mask_ips)
            talkers_table.add_row(ip_display, str(p_count), data_str, f"[{bar}]")

        talkers_panel = Panel(
            talkers_table, title="Top Network Generators", border_style="green"
        )
        layout["top_talkers"].update(talkers_panel)

        # 3. BOTTOM RIGHT PANEL: Telemetry & NIDS Watchlist
        avg_pkt_size = (
            (state.total_bytes // state.total_packets) if state.total_packets > 0 else 0
        )
        tcp_pct = (
            int((state.protocol_counts["TCP"] / state.total_packets) * 100)
            if state.total_packets > 0
            else 0
        )
        udp_pct = (
            int((state.protocol_counts["UDP"] / state.total_packets) * 100)
            if state.total_packets > 0
            else 0
        )
        icmp_pct = (
            int((state.protocol_counts["ICMP"] / state.total_packets) * 100)
            if state.total_packets > 0
            else 0
        )

        telemetry_text = (
            f"[bold green]Velocity:[/bold green] {state.current_packet_rate} pkts/sec\n"
        )
        telemetry_text += (
            "[bold green]Status:[/bold green] [bold black on green] ACTIVE CAPTURE"
            " [/bold black on green]\n"
        )
        telemetry_text += (
            f"[bold green]Unique Hosts Detected:[/bold green] {len(state.unique_hosts)}\n"
        )
        telemetry_text += (
            f"[bold green]Avg Packet Size:[/bold green] {avg_pkt_size} Bytes\n"
        )
        telemetry_text += (
            f"[bold green]Protocol Mix:[/bold green] TCP: {tcp_pct}% | UDP:"
            f" {udp_pct}% | ICMP: {icmp_pct}%\n"
        )
        telemetry_text += (
            f"[bold green]System Alert:[/bold green] [dim green]{state.status_message}[/dim"
            " green]\n\n"
        )
        telemetry_text += "[bold green]NIDS Threat Watchlist:[/bold green]\n"

        if state.flagged_traffic:
            for alert in state.flagged_traffic[-3:]:
                telemetry_text += f"[dim green]• {alert}[/dim green]\n"
        else:
            telemetry_text += "[dim green]No anomalies flagged...[/dim green]\n"

        telemetry_panel = Panel(
            telemetry_text, title="Telemetry & Threat Watchlist", border_style="green"
        )
        layout["telemetry"].update(telemetry_panel)

        # 4. FOOTER PANEL: Interactive Controls
        footer_grid = Table.grid(expand=True)
        footer_grid.add_column(justify="left")
        footer_grid.add_column(justify="right")
        mask_status = "ON" if state.mask_ips else "OFF"
        footer_grid.add_row(
            "[bold green]Press [bold bright_green]'q'[/bold bright_green] to stop capture"
            " | [bold bright_green]'m'[/bold bright_green] to toggle IP privacy masking"
            f" ({mask_status})[/bold green]",
            "[dim green]All rights reserved to Aman Tomar[/dim green]",
        )
        layout["footer"].update(Panel(footer_grid, border_style="green"))

    return layout