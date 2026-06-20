"""
Terminal User Interface for ftagent.

Uses the `rich` library to render a live dashboard showing real-time
traffic stats, protocol breakdown, top source IPs, top ports, and
attack status. Designed to mirror the nethawk TUI layout.

Enable with: ftagent --tui
"""
from __future__ import annotations

import collections
import shutil
import time

try:
    from rich.console import Console
    from rich.live import Live
    from rich.text import Text
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_bps(bps: float) -> str:
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.0f} Kbps"
    return f"{int(bps)} bps"


def _fmt_pps(pps: float) -> str:
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.1f}M pps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f}K pps"
    return f"{int(pps)} pps"


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _fmt_count(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


# ---------------------------------------------------------------------------
# Sparkline renderer
# ---------------------------------------------------------------------------

_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(history: list[float], width: int) -> Text:
    """Render a sparkline from PPS history values, colored by intensity."""
    text = Text()
    if not history:
        text.append("▁" * width, style="dim")
        return text

    display = history[-width:] if len(history) > width else history
    max_val = max(display) if display else 1
    if max_val == 0:
        max_val = 1

    for v in display:
        ratio = v / max_val
        idx = int(ratio * (len(_SPARK_CHARS) - 1))
        idx = min(idx, len(_SPARK_CHARS) - 1)

        if ratio > 0.8:
            color = "red"
        elif ratio > 0.6:
            color = "dark_orange"
        elif ratio > 0.4:
            color = "yellow"
        elif ratio > 0.2:
            color = "cyan"
        else:
            color = "green"

        text.append(_SPARK_CHARS[idx], style=color)

    # Pad left with dim bars if history is shorter than width
    pad = width - len(display)
    if pad > 0:
        text.append("▁" * pad, style="dim")

    return text


# ---------------------------------------------------------------------------
# Protocol bar renderer
# ---------------------------------------------------------------------------

def _proto_bar(label: str, pct: float, bar_width: int, color: str) -> Text:
    """Render one protocol bar: 'TCP   45.2%  ████████░░░░░░░'"""
    text = Text()
    filled = int(round(pct / 100 * bar_width))
    filled = min(filled, bar_width)
    empty = bar_width - filled

    text.append(f"  {label:<5} ", style="dim")
    text.append(f"{pct:5.1f}%  ", style="dim")
    text.append("█" * filled, style=color)
    text.append("░" * empty, style="dim")
    return text


# ---------------------------------------------------------------------------
# TUI Dashboard
# ---------------------------------------------------------------------------

class TUIDashboard:
    """Real-time terminal dashboard for the ftagent.

    Call ``snapshot()`` every tick to feed data, then ``render()``
    from a Rich Live context to produce the display.
    """

    def __init__(self):
        self.console = Console()
        self._history: collections.deque[float] = collections.deque(maxlen=120)
        self._start = time.monotonic()

        # Latest snapshot data (set each tick)
        self.interface: str = ""
        self.pps: float = 0.0
        self.bps: float = 0.0
        self.tcp_pct: float = 0.0
        self.udp_pct: float = 0.0
        self.icmp_pct: float = 0.0
        self.threshold: float = 0.0
        self.attacking: bool = False
        self.attack_type: str = ""
        self.conn_count: int = 0
        self.top_sources: list[dict] = []
        self.top_ports: list[dict] = []
        self.baseline_ready: bool = False
        self.unique_ips: int = 0

    def snapshot(self, agent) -> None:
        """Pull current stats from the agent object."""
        self.interface = agent.monitor.interface
        self.pps = agent.monitor.pps
        self.bps = agent.monitor.bps
        self.threshold = agent.threshold
        self.attacking = agent.attacking
        self.conn_count = agent.monitor.conn_count
        self.baseline_ready = agent.baseline.baseline_ready

        # Protocol breakdown from the agent's best source
        proto = agent._proto_breakdown()
        self.tcp_pct = proto.get("tcp", 0)
        self.udp_pct = proto.get("udp", 0)
        self.icmp_pct = proto.get("icmp", 0)

        # Top sources and ports from scapy analyser (available during attacks
        # and from background ring buffer at all times)
        self.top_sources = agent.analyser.top_src_ips(10)
        self.top_ports = agent.analyser.top_dst_ports(10)
        self.unique_ips = len(agent.analyser.src_ips)

        # Record PPS history for sparkline
        self._history.append(self.pps)

    def render(self) -> Panel:
        """Build the full dashboard as a single Rich Panel."""
        term_width = shutil.get_terminal_size((80, 24)).columns
        w = min(term_width, 120)
        inner = w - 4  # panel border + padding

        body = Text()

        body.append_text(self._render_header(inner))
        body.append("\n\n")

        body.append_text(self._render_sparkline(inner))
        body.append("\n\n")

        body.append_text(self._render_columns(inner))
        body.append("\n\n")

        body.append_text(self._render_status(inner))

        return Panel(
            body,
            title="[bold cyan]Flowtriq Agent[/bold cyan]",
            border_style="dim",
            width=w,
        )

    # -----------------------------------------------------------------------
    # Sub-renderers
    # -----------------------------------------------------------------------

    def _render_header(self, w: int) -> Text:
        uptime = time.monotonic() - self._start
        left = Text()
        left.append("◆ ftagent", style="bold cyan")
        left.append("  ", style="dim")
        left.append(self.interface, style="bold white")
        left.append(f"  {_fmt_duration(uptime)}", style="dim")

        right = Text()
        right.append(f"▲ {_fmt_bps(self.bps)}", style="bold white")
        right.append("  ", style="dim")
        right.append(_fmt_pps(self.pps), style="bold white")

        gap = max(1, w - len(left.plain) - len(right.plain))
        result = Text()
        result.append_text(left)
        result.append(" " * gap)
        result.append_text(right)
        return result

    def _render_sparkline(self, w: int) -> Text:
        chart_width = max(10, w - 2)
        title = Text("Traffic (last 60s)\n", style="bold cyan")
        line = _sparkline(list(self._history), chart_width)
        result = Text()
        result.append_text(title)
        result.append_text(line)
        return result

    def _render_columns(self, w: int) -> Text:
        col_w = max(20, (w - 4) // 3)

        proto_lines = self._render_protocols(col_w)
        src_lines = self._render_top_sources(col_w)
        port_lines = self._render_top_ports(col_w)

        # Pad all columns to the same height
        max_h = max(len(proto_lines), len(src_lines), len(port_lines))
        while len(proto_lines) < max_h:
            proto_lines.append(Text(" " * col_w))
        while len(src_lines) < max_h:
            src_lines.append(Text(" " * col_w))
        while len(port_lines) < max_h:
            port_lines.append(Text(" " * col_w))

        result = Text()
        for i in range(max_h):
            row = Text()
            row.append_text(self._pad_text(proto_lines[i], col_w))
            row.append(" ")
            row.append_text(self._pad_text(src_lines[i], col_w))
            row.append(" ")
            row.append_text(self._pad_text(port_lines[i], col_w))
            if i < max_h - 1:
                row.append("\n")
            result.append_text(row)

        return result

    def _render_protocols(self, w: int) -> list[Text]:
        lines: list[Text] = []
        lines.append(Text("Protocols", style="bold cyan"))
        lines.append(Text(""))

        bar_w = max(5, w - 16)
        lines.append(_proto_bar("TCP", self.tcp_pct, bar_w, "#7C7CFF"))
        lines.append(_proto_bar("UDP", self.udp_pct, bar_w, "#00D4AA"))
        lines.append(_proto_bar("ICMP", self.icmp_pct, bar_w, "#FFD700"))

        other = max(0, 100.0 - self.tcp_pct - self.udp_pct - self.icmp_pct)
        if other >= 0.1:
            lines.append(_proto_bar("Other", other, bar_w, "dim"))

        lines.append(Text(""))
        footer = Text()
        footer.append("  IPs ", style="dim")
        footer.append(_fmt_count(self.unique_ips), style="bold white")
        footer.append("  conns ", style="dim")
        footer.append(_fmt_count(self.conn_count), style="bold white")
        lines.append(footer)
        return lines

    def _render_top_sources(self, w: int) -> list[Text]:
        lines: list[Text] = []
        lines.append(Text("Top Sources", style="bold cyan"))
        lines.append(Text(""))

        if not self.top_sources:
            lines.append(Text("  waiting for data...", style="dim"))
            return lines

        for i, src in enumerate(self.top_sources[:8]):
            ip = src.get("ip", "?")
            if len(ip) > 18:
                ip = ip[:18]
            count = _fmt_count(src.get("count", 0))

            line = Text()
            line.append(f"  {i + 1:>2} ", style="dim")
            line.append(f"{ip:<18} ", style="bold white")
            line.append(f"{count}", style="dim")
            lines.append(line)

        return lines

    def _render_top_ports(self, w: int) -> list[Text]:
        lines: list[Text] = []
        lines.append(Text("Top Ports", style="bold cyan"))
        lines.append(Text(""))

        if not self.top_ports:
            lines.append(Text("  waiting for data...", style="dim"))
            return lines

        total = sum(p.get("count", 0) for p in self.top_ports) or 1
        for p in self.top_ports[:8]:
            port = p.get("port", 0)
            count = p.get("count", 0)
            pct = count / total * 100

            line = Text()
            line.append(f"  {port:<8}", style="bold white")
            line.append(f"{pct:5.1f}%", style="dim")
            lines.append(line)

        return lines

    def _render_status(self, w: int) -> Text:
        result = Text()

        if self.attacking:
            result.append("! ATTACK", style="bold red")
            result.append(" -- threshold ", style="dim")
            result.append(_fmt_pps(self.threshold), style="bold white")
        else:
            if self.baseline_ready:
                result.append("OK NORMAL", style="bold green")
                result.append(" -- threshold ", style="dim")
                result.append(_fmt_pps(self.threshold), style="bold white")
            else:
                result.append("~ LEARNING", style="bold yellow")
                result.append(" -- building baseline...", style="dim")

        footer = Text("q: quit", style="dim")
        gap = max(1, w - len(result.plain) - len(footer.plain))
        result.append(" " * gap)
        result.append_text(footer)
        return result

    @staticmethod
    def _pad_text(text: Text, width: int) -> Text:
        """Pad a Text object to a fixed width."""
        plain_len = len(text.plain)
        if plain_len < width:
            padded = text.copy()
            padded.append(" " * (width - plain_len))
            return padded
        return text


# ---------------------------------------------------------------------------
# TUI runner (called from agent main loop)
# ---------------------------------------------------------------------------

def run_tui(agent) -> None:
    """Run the agent main loop with TUI output instead of log lines.

    This replaces the normal ``agent.run()`` loop — it still calls
    ``_tick()`` every second but renders output through the TUI
    dashboard instead of scrolling log lines.
    """
    import logging
    import signal
    import sys
    import threading

    if not RICH_AVAILABLE:
        print("Error: 'rich' package is required for TUI mode. Install it with:")
        print("  pip install rich")
        sys.exit(1)

    dashboard = TUIDashboard()
    console = Console()

    # Suppress log output to stdout so it doesn't corrupt the TUI.
    # File logging continues to work normally.
    logger = logging.getLogger("ftagent")
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.StreamHandler) and handler.stream in (sys.stdout, sys.stderr):
            logger.removeHandler(handler)

    # Start all background threads exactly as agent.run() does, but
    # skip the main while-loop and the update check prompt (non-interactive).
    signal.signal(signal.SIGINT, agent._signal_handler)
    signal.signal(signal.SIGTERM, agent._signal_handler)

    threads = [
        threading.Thread(target=agent._heartbeat_loop, daemon=True,
                         name="heartbeat"),
        threading.Thread(target=agent._config_loop, daemon=True,
                         name="config"),
        threading.Thread(target=agent._command_poll_loop, daemon=True,
                         name="command-poll"),
    ]

    if agent.pcap.enabled:
        agent._sniffer_thread = threading.Thread(
            target=agent.pcap.background_ring, args=(agent.shutdown,),
            daemon=True, name="pcap-ring")
        threads.append(agent._sniffer_thread)
    else:
        agent._sniffer_thread = None

    from ftagent.agent import HealthCheckHandler
    health_port = agent.cfg.get("health_port", 9100)
    if health_port:
        health = HealthCheckHandler(agent, port=health_port)
        threads.append(threading.Thread(
            target=health.start, daemon=True, name="health-check"))

    if agent.flow:
        threads.append(threading.Thread(
            target=agent.flow.start, args=(agent.shutdown,),
            daemon=True, name="flow-collector"))

    if agent.cfg.get("auto_update", False):
        threads.append(threading.Thread(
            target=agent._auto_update_loop, daemon=True,
            name="auto-update"))

    for t in threads:
        t.start()

    # Same cleanup as agent.run()
    agent.sp_detector.cleanup_stale()
    try:
        import subprocess
        subprocess.run(
            ["nft", "delete", "table", "inet", "flowtriq_xdp"],
            capture_output=True, timeout=5)
    except Exception:
        pass

    import atexit

    def _atexit_cleanup():
        try:
            agent.sp_detector.cleanup_stale()
        except Exception:
            pass
        try:
            import subprocess as _sp
            _sp.run(
                ["nft", "delete", "table", "inet", "flowtriq_xdp"],
                capture_output=True, timeout=5)
        except Exception:
            pass

    atexit.register(_atexit_cleanup)

    agent._fetch_config()

    threading.Thread(
        target=agent._report_gre_tunnels, daemon=True,
        name="gre-tunnel-detect").start()

    if agent.l7 and agent.l7_enabled and not agent.l7_thread_running:
        agent.l7_thread_running = True
        l7t = threading.Thread(target=agent._l7_loop, daemon=True, name="l7-monitor")
        l7t.start()

    # ---------------------------------------------------------------
    # Main TUI loop
    # ---------------------------------------------------------------
    import time as _time

    dashboard._start = _time.monotonic()

    try:
        with Live(dashboard.render(), console=console, refresh_per_second=2,
                  screen=True) as live:
            last_watchdog = _time.monotonic()

            while not agent.shutdown.is_set():
                loop_start = _time.monotonic()

                try:
                    agent._tick()
                except Exception:
                    pass  # errors are still logged to file

                # Sniffer watchdog (same as agent.run)
                if (agent._sniffer_thread is not None
                        and loop_start - last_watchdog >= 60):
                    last_watchdog = loop_start
                    if not agent._sniffer_thread.is_alive():
                        agent._sniffer_thread = threading.Thread(
                            target=agent.pcap.background_ring,
                            args=(agent.shutdown,),
                            daemon=True, name="pcap-ring")
                        agent._sniffer_thread.start()

                # Periodic pcap cleanup
                if (agent.pcap.enabled
                        and loop_start - agent.pcap._last_cleanup >= 300):
                    agent.pcap._last_cleanup = loop_start
                    agent.pcap.cleanup_pcaps()

                # Update dashboard
                dashboard.snapshot(agent)
                live.update(dashboard.render())

                elapsed = _time.monotonic() - loop_start
                sleep_for = max(0, 1.0 - elapsed)
                agent.shutdown.wait(sleep_for)

    except KeyboardInterrupt:
        agent.shutdown.set()

    logger.info("Agent shutting down (TUI)")
