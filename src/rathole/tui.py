"""
rathole-tui — Full-screen terminal dashboard using Textual.

8 interactive tabs: Overview, Peers, Events, Interfaces, Blackhole,
Filters, Config, Console.  The Console tab appears when the daemon is
running in-process (``rathole -c rathole.toml``) and shows live log
output.  Connects to the daemon control socket for all data.

Requires: pip install rathole[tui]  (textual>=0.50)
"""

import sys
import json
import time
import argparse

from .rpc import send_command as rpc_send, DEFAULT_SOCKET, find_socket


def _check_textual():
    try:
        import textual  # noqa: F401
        return True
    except ImportError:
        return False


# ── Category colors (shared constant) ──────────────────────────

CATEGORY_COLORS = {
    "TRUSTED": "bold green",
    "NEUTRAL": "yellow",
    "SUSPECT": "red",
    "UNKNOWN": "dim",
}

SEVERITY_COLORS = {
    "INFO": "green",
    "NOTICE": "dark_goldenrod",
    "WARNING": "yellow",
    "ALERT": "red",
    "CRITICAL": "bold magenta",
}


def _copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard. Returns True on success."""
    import subprocess
    import platform as _plat

    system = _plat.system()
    if system == "Darwin":
        cmd = ["pbcopy"]
    elif system == "Windows":
        cmd = ["clip"]
    else:
        cmd = ["xclip", "-selection", "clipboard"]

    try:
        proc = subprocess.run(
            cmd, input=text.encode(), check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _build_tui(sock_path: str, refresh_interval: float = 5.0,
               log_handler=None, command_handler=None):
    """Build and return the TUI app (does NOT call app.run()).

    All Textual widget classes are defined inside this function to
    avoid import errors when textual is not installed.

    Args:
        sock_path: Path to the daemon control socket (used as fallback
            and by standalone ``rathole-tui``).
        refresh_interval: Seconds between automatic refreshes.
        log_handler: ``RingBufferHandler`` for the Console tab (unified mode).
        command_handler: Callable ``(cmd, args) -> dict`` for direct
            in-process dispatch.  When provided, the TUI skips the Unix
            socket entirely — no ``errno 57``, no serialization overhead.
    """

    # Import everything inside main to avoid import errors
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.screen import ModalScreen
    from textual.widgets import (
        Header, Footer, Static, DataTable, TabbedContent, TabPane,
        Label, Input, Button, Select, Switch, Collapsible,
    )
    from textual.reactive import reactive
    from textual import work
    from textual.binding import Binding

    # ── Health Bar Helper ──────────────────────────────────────

    def _health_bar(accept_pct: float, width: int = 16) -> str:
        filled = int(accept_pct / 100 * width)
        filled = max(0, min(width, filled))
        empty = width - filled
        if accept_pct >= 95:
            color = "green"
        elif accept_pct >= 80:
            color = "yellow"
        else:
            color = "red"
        return f"[{color}]{'█' * filled}[/][dim]{'░' * empty}[/]"

    # ── Sidebar Stats Widget ──────────────────────────────────

    class SidebarStats(Static):
        """Compact stats panel for the sidebar."""
        stats = reactive({})
        last_updated: str = ""
        connection_lost: bool = False

        def render(self) -> str:
            s = self.stats
            if not s:
                return "[dim]  Connecting...[/]"

            uptime = s.get("uptime", 0)
            h, m = int(uptime // 3600), int((uptime % 3600) // 60)
            dry_run = s.get("dry_run", False)

            # Mode indicator
            if dry_run:
                mode = "[cyan]● OBSERVING[/]"
            else:
                mode = "[green]● CONNECTED[/]"

            # Health bar
            total = s.get("total_accepted", 0) + s.get("total_dropped", 0) + s.get("total_throttled", 0)
            accept_pct = (s.get("total_accepted", 0) / max(1, total)) * 100

            if dry_run:
                health = "[dim]observing[/]"
            else:
                health = _health_bar(accept_pct, 16)

            # Node mode badge
            node_mode = s.get("node_mode", "client")
            has_i2p = bool(s.get("i2p_b32"))
            if node_mode == "gateway":
                mode_badge = "[bold cyan]GATEWAY[/]"
            elif has_i2p:
                mode_badge = "[bold cyan]GATEWAY[/] [dim]i2p[/]"
            else:
                mode_badge = "[bold green]CLIENT[/]"

            # I2P address (if available)
            i2p_b32 = s.get("i2p_b32")
            if i2p_b32:
                short = i2p_b32[:6] + "\u2026" + i2p_b32[-10:]
                i2p_line = f"\n  [dark_goldenrod]I2P[/] {short}"
            elif s.get("i2p_pending"):
                i2p_line = "\n  [dim]I2P connecting…[/]"
            else:
                i2p_line = ""

            sep = f"[dim]{'─' * 20}[/]"

            # Last updated / connection status
            if self.connection_lost:
                updated_line = "  [bold red]Connection lost[/]"
            elif self.last_updated:
                updated_line = f"  [dim]Updated {self.last_updated}[/]"
            else:
                updated_line = ""

            return (
                f"[bold]RATHOLE[/]\n"
                f"  {mode_badge}{i2p_line}\n"
                f"{sep}\n"
                f"  {mode}\n"
                f"  ↑ {h}h {m}m\n"
                f"{sep}\n"
                f"  {s.get('tracked_peers', 0):>5} peers\n"
                f"  {s.get('tracked_interfaces', 0):>5} intf\n"
                f"{sep}\n"
                f"  {health}\n"
                f"  {accept_pct:.0f}% accept\n"
                f"{sep}\n"
                f"  [green]{s.get('total_accepted', 0):>8,}[/] acc\n"
                f"  [red]{s.get('total_dropped', 0):>8,}[/] drp\n"
                f"  [yellow]{s.get('total_throttled', 0):>8,}[/] thr\n"
                f"  [magenta]{s.get('total_blackholed', 0):>8,}[/] blk\n"
                f"{sep}\n"
                f"{updated_line}"
            )

    # ── Status Bar Widget ────────────────────────────────────

    class StatusBar(Static):
        """Bottom status bar showing connection state, mode, dry-run, and filter count."""
        connected = reactive(False)
        dry_run = reactive(False)
        node_mode = reactive("client")
        filter_info = reactive("")

        def render(self) -> str:
            if self.connected:
                conn = "[green]● Connected[/]"
            else:
                conn = "[red]● Disconnected[/]"

            if self.node_mode == "gateway":
                mode_tag = "[cyan]GATEWAY[/]"
            else:
                mode_tag = "[green]CLIENT[/]"

            if self.dry_run:
                dr = "[cyan]Dry-run \\[ON][/]"
            else:
                dr = "[dim]Dry-run \\[OFF][/]"

            parts = [f" {conn}", mode_tag, dr]
            if self.filter_info:
                parts.append(self.filter_info)

            return "  │  ".join(parts)

    # ── Peer Action Modal ────────────────────────────────────

    class PeerActionScreen(ModalScreen[str]):
        """Modal popup for peer actions: blackhole, pin/unpin, details, copy hash."""

        CSS = """
        PeerActionScreen {
            align: center middle;
        }
        #peer-action-dialog {
            width: 64;
            height: auto;
            padding: 1 2;
            background: $surface;
            border: thick $primary;
        }
        #peer-action-hash {
            margin-bottom: 1;
            text-style: bold;
        }
        #peer-action-dialog Button {
            width: 100%;
            margin-bottom: 1;
        }
        """

        def __init__(self, peer_hash: str, pinned: bool = False):
            super().__init__()
            self._peer_hash = peer_hash
            self._pinned = pinned

        def compose(self) -> ComposeResult:
            with Vertical(id="peer-action-dialog"):
                yield Static(f"[bold]Peer Actions[/]")
                yield Static(f"[dim]{self._peer_hash}[/]", id="peer-action-hash")
                yield Button("View Details", id="action-details", variant="primary")
                yield Button("Blackhole", id="action-blackhole", variant="error")
                if self._pinned:
                    yield Button("Unpin", id="action-unpin", variant="warning")
                else:
                    yield Button("Pin Trusted", id="action-pin-trusted", variant="success")
                yield Button("Copy Hash", id="action-copy")
                yield Button("Cancel", id="action-cancel")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            bid = event.button.id
            if bid == "action-blackhole":
                self.dismiss("blackhole")
            elif bid == "action-pin-trusted":
                self.dismiss("pin_trusted")
            elif bid == "action-unpin":
                self.dismiss("unpin")
            elif bid == "action-details":
                self.dismiss("details")
            elif bid == "action-copy":
                self.dismiss("copy")
            else:
                self.dismiss("cancel")

        def key_escape(self) -> None:
            self.dismiss("cancel")

    # ── Blackhole Reason Modal ─────────────────────────────

    class BlackholeReasonScreen(ModalScreen[str]):
        """Modal to enter a reason before blackholing a peer."""

        CSS = """
        BlackholeReasonScreen {
            align: center middle;
        }
        #bh-reason-dialog {
            width: 64;
            height: auto;
            padding: 1 2;
            background: $surface;
            border: thick $error;
        }
        #bh-reason-dialog Static {
            margin-bottom: 1;
        }
        #bh-reason-dialog Input {
            margin-bottom: 1;
        }
        #bh-reason-dialog Horizontal {
            height: auto;
        }
        #bh-reason-dialog Button {
            margin-right: 1;
        }
        """

        def __init__(self, peer_hash: str):
            super().__init__()
            self._peer_hash = peer_hash

        def compose(self) -> ComposeResult:
            with Vertical(id="bh-reason-dialog"):
                yield Static(f"[bold red]Blackhole Peer[/]")
                yield Static(f"[dim]{self._peer_hash}[/]")
                yield Input(
                    value="manual via TUI",
                    placeholder="Reason for blackholing...",
                    id="bh-reason-text",
                )
                with Horizontal():
                    yield Button("Blackhole", id="bh-confirm", variant="error")
                    yield Button("Cancel", id="bh-cancel")

        def on_mount(self) -> None:
            self.query_one("#bh-reason-text", Input).focus()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "bh-confirm":
                reason = self.query_one("#bh-reason-text", Input).value.strip()
                self.dismiss(reason or "manual via TUI")
            else:
                self.dismiss("")

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Allow pressing Enter in the input to confirm."""
            if event.input.id == "bh-reason-text":
                reason = event.value.strip()
                self.dismiss(reason or "manual via TUI")

        def key_escape(self) -> None:
            self.dismiss("")

    # ── Reputation Detail Modal ────────────────────────────

    class ReputationDetailScreen(ModalScreen[str]):
        """Modal showing detailed reputation info for a peer."""

        CSS = """
        ReputationDetailScreen {
            align: center middle;
        }
        #rep-detail-dialog {
            width: 64;
            height: auto;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #rep-detail-dialog Static {
            margin-bottom: 0;
        }
        #rep-detail-close {
            margin-top: 1;
            width: 100%;
        }
        """

        def __init__(self, rep_data: dict):
            super().__init__()
            self._data = rep_data

        def compose(self) -> ComposeResult:
            d = self._data
            identity = d.get("identity", "?")
            score = d.get("score", 0.5)
            cat = d.get("category", "UNKNOWN")
            cat_color = CATEGORY_COLORS.get(cat, "white")
            accepts = d.get("accepts", 0)
            drops = d.get("drops", 0)
            pinned = d.get("pinned", False)
            total = accepts + drops
            ratio = f"{accepts}:{drops}" if drops > 0 else f"{accepts}:0"

            # Score bar
            bar_width = 20
            filled = int(score * bar_width)
            bar = f"[green]{'█' * filled}[/][dim]{'░' * (bar_width - filled)}[/]"

            pin_str = " [dim](pinned)[/]" if pinned else ""

            with Vertical(id="rep-detail-dialog"):
                yield Static(f"[bold]Reputation Detail[/]")
                yield Static(f"[dim]{identity}[/]")
                yield Static("")
                yield Static(f"  Score:    {bar} {score:.3f}")
                yield Static(f"  Category: [{cat_color}]{cat}[/]{pin_str}")
                yield Static(f"  Accepts:  [green]{accepts:,}[/]")
                yield Static(f"  Drops:    [red]{drops:,}[/]")
                yield Static(f"  Ratio:    {ratio}  ({total:,} total)")
                yield Button("Close", id="rep-detail-close")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            self.dismiss("close")

        def key_escape(self) -> None:
            self.dismiss("close")

    # ── Help Modal ──────────────────────────────────────────

    class HelpScreen(ModalScreen[str]):
        """Keybinding help modal."""

        CSS = """
        HelpScreen {
            align: center middle;
        }
        #help-dialog {
            width: 56;
            height: auto;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #help-close {
            margin-top: 1;
            width: 100%;
        }
        """

        def compose(self) -> ComposeResult:
            with Vertical(id="help-dialog"):
                yield Static("[bold]Keyboard Shortcuts[/]")
                yield Static("")
                yield Static("  [cyan]1-7[/]   Switch tabs (Overview → Config)")
                yield Static("  [cyan]q[/]     Quit")
                yield Static("  [cyan]r[/]     Refresh data")
                yield Static("  [cyan]d[/]     Toggle dry-run mode")
                yield Static("  [cyan]?[/]     Show this help")
                yield Static("")
                yield Static("[bold]Peers Tab[/]")
                yield Static("  [cyan]Enter[/]  Open peer action modal")
                yield Static("  [cyan]Click header[/]  Sort by column")
                yield Static("")
                yield Static("[bold]Blackhole Tab[/]")
                yield Static("  [cyan]Enter[/]  (select row for remove)")
                yield Button("Close", id="help-close")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            self.dismiss("close")

        def key_escape(self) -> None:
            self.dismiss("close")

    # ── Overview Tab ──────────────────────────────────────────

    class OverviewTab(VerticalScroll):
        """Overview dashboard with key stats and recent alerts."""

        def compose(self) -> ComposeResult:
            # Row 1: Security Posture (left) + Recent Alerts (right)
            with Horizontal(id="overview-top-row"):
                yield Static(id="overview-posture", classes="panel")
                yield Static(id="overview-alerts-panel", classes="panel-alert")
            # Row 2: Traffic Stats (left) + Reputation (right)
            with Horizontal(id="overview-mid-row"):
                yield Static(id="overview-traffic", classes="panel")
                yield Static(id="overview-reputation", classes="panel-info")
            # Row 3: Interfaces + Top Drops (full width)
            yield Static(id="overview-bottom", classes="panel")

        def on_mount(self) -> None:
            pass

    # ── Peers Tab ─────────────────────────────────────────────

    class PeersTab(Vertical):
        """Full peer table with reputation details."""

        def compose(self) -> ComposeResult:
            with Horizontal(id="peer-actions"):
                yield Input(placeholder="Filter by hash...", id="peer-filter")
                yield Button("Actions (Enter)", id="peer-action-btn", variant="primary")
            yield DataTable(id="peer-table")
            yield Static(id="peer-detail")

        def on_mount(self) -> None:
            table = self.query_one("#peer-table", DataTable)
            table.add_columns("Peer Hash", "Announces", "Drops", "Reputation", "Category")
            table.cursor_type = "row"

    # ── Events Tab ────────────────────────────────────────────

    class EventsTab(Vertical):
        """Scrollable event log with severity and type filtering."""

        def compose(self) -> ComposeResult:
            with Horizontal(id="event-filters"):
                yield Select(
                    [("All", ""), ("INFO", "INFO"), ("NOTICE", "NOTICE"),
                     ("WARNING", "WARNING"), ("ALERT", "ALERT"), ("CRITICAL", "CRITICAL")],
                    value="", prompt="Severity", id="event-severity-filter",
                )
                yield Select(
                    [("All Types", ""),
                     ("PACKET_DROPPED", "PACKET_DROPPED"),
                     ("PACKET_THROTTLED", "PACKET_THROTTLED"),
                     ("PACKET_BLACKHOLED", "PACKET_BLACKHOLED"),
                     ("SCAN_DETECTED", "SCAN_DETECTED"),
                     ("SYBIL_DETECTED", "SYBIL_DETECTED"),
                     ("REPUTATION_CHANGED", "REPUTATION_CHANGED"),
                     ("IDENTITY_BLACKHOLED", "IDENTITY_BLACKHOLED")],
                    value="", prompt="Type", id="event-type-filter",
                )
                yield Input(placeholder="Search events...", id="event-search")
            yield VerticalScroll(id="event-log")

    # ── Interfaces Tab ────────────────────────────────────────

    class InterfacesTab(Vertical):
        """Per-interface traffic breakdown with add-interface forms."""

        def compose(self) -> ComposeResult:
            with Horizontal(id="iface-add-form"):
                yield Input(placeholder="Host (e.g. 192.168.1.1)", id="iface-host-input")
                yield Input(placeholder="Port (e.g. 4242)", id="iface-port-input")
                yield Button("Connect TCP", id="iface-connect-btn", variant="success")
                yield Button("Listen TCP", id="tcp-server-btn", variant="primary")
            with Horizontal(id="i2p-add-form"):
                yield Input(placeholder="I2P B32 address", id="i2p-b32-input")
                yield Button("Connect I2P", id="i2p-connect-btn", variant="success")
                yield Button("Start I2P Server", id="i2p-server-btn", variant="primary")
            yield Static(id="i2p-b32-display")
            yield Button("Copy", id="i2p-b32-copy-btn", variant="default")
            yield DataTable(id="interface-table")
            # Gateway Registry section
            yield Static(id="registry-section-header")
            with Horizontal(id="registry-btn-form"):
                yield Button("Enable Registry", id="registry-toggle-btn", variant="success")
                yield Button("Refresh Gateways", id="registry-discover-btn", variant="primary")
                yield Button("Publish", id="registry-register-btn", variant="success")
                yield Button("Auto-connect OFF", id="registry-autoconnect-btn", variant="default")
            yield Static("[dim]  Select a gateway and press Enter to connect[/]",
                         id="registry-hint")
            yield DataTable(id="registry-table")

        def on_mount(self) -> None:
            table = self.query_one("#interface-table", DataTable)
            table.add_columns("Interface", "Packets", "Bytes", "Announces", "Links", "Pending", "Resources")
            reg_table = self.query_one("#registry-table", DataTable)
            reg_table.add_columns("Name", "B32", "Caps", "Mode", "Identity")
            reg_table.cursor_type = "row"

    # ── Blackhole Tab ─────────────────────────────────────────

    class BlackholeTab(Vertical):
        """Blackhole management with add/remove."""

        def compose(self) -> ComposeResult:
            yield Static(id="blackhole-count")
            with Horizontal(id="bh-add-form"):
                yield Input(placeholder="Identity hash to blackhole...", id="bh-identity-input")
                yield Input(placeholder="Reason (optional)", id="bh-reason-input")
                yield Button("Add", id="bh-add-btn", variant="error")
                yield Button("Remove Selected", id="bh-remove-btn", variant="warning")
            yield DataTable(id="blackhole-table")

        def on_mount(self) -> None:
            table = self.query_one("#blackhole-table", DataTable)
            table.add_columns("Identity", "Source", "Reason")
            table.cursor_type = "row"

    # ── Filters Tab ───────────────────────────────────────────

    class FiltersTab(VerticalScroll):
        """Interactive filter management — toggle and edit params."""

        def compose(self) -> ComposeResult:
            from .filter_meta import PIPELINE_ORDER, PIPELINE_LABELS, PIPELINE_FILTERS, FILTER_META

            for pkey in PIPELINE_ORDER:
                plabel = PIPELINE_LABELS.get(pkey, pkey.title())
                fnames = PIPELINE_FILTERS.get(pkey, [])
                if not fnames:
                    continue

                yield Static(f"[bold]▼ {plabel}[/]", classes="pipeline-header")

                for fname in fnames:
                    meta = FILTER_META.get(fname)
                    if not meta:
                        continue

                    label_text = meta.label
                    desc_text = meta.description

                    # Each filter wrapped in a bordered card
                    with Vertical(classes="filter-card", id=f"filter-{fname}-card"):
                        # Toggle row: switch + label
                        with Horizontal(classes="filter-row"):
                            yield Switch(value=False, id=f"filter-{fname}-switch")
                            yield Static(
                                f"[bold]{label_text}[/]  [dim]{desc_text}[/]",
                                classes="filter-label",
                            )

                        # Param row (hidden by default, shown when enabled)
                        if meta.params:
                            with Horizontal(id=f"filter-{fname}-params", classes="filter-params"):
                                for pk, pinfo in meta.params.items():
                                    if pinfo.type == "number":
                                        yield Static(f"{pinfo.label}:", classes="param-label")
                                        yield Input(
                                            placeholder="...",
                                            id=f"fparam-{fname}-{pk}",
                                            classes="param-input",
                                        )
                                    elif pinfo.type == "select":
                                        opts = [(str(o), str(o)) for o in pinfo.options]
                                        yield Static(f"{pinfo.label}:", classes="param-label")
                                        yield Select(
                                            opts,
                                            value=str(pinfo.options[0]) if pinfo.options else "",
                                            id=f"fparam-{fname}-{pk}",
                                            classes="param-select",
                                        )
                                    elif pinfo.type == "bool":
                                        yield Static(f"{pinfo.label}:", classes="param-label")
                                        yield Switch(
                                            value=False,
                                            id=f"fparam-{fname}-{pk}",
                                        )
                                yield Button("Apply", id=f"filter-{fname}-apply", classes="param-apply")

    # ── Config Tab ────────────────────────────────────────────

    class ConfigTab(Vertical):
        """Interactive config with presets, quick toggles, and tuning."""

        def compose(self) -> ComposeResult:
            # Controls panel — presets, toggles, quick settings
            from .presets import list_presets, DESCRIPTIONS
            all_presets = list_presets()
            options = [
                (p["name"].capitalize(), p["name"])
                for p in all_presets
            ]
            with Vertical(classes="panel", id="config-presets-panel"):
                with Horizontal(id="config-presets"):
                    yield Select(
                        options,
                        prompt="Select Preset", id="preset-select",
                    )
                    yield Button("Apply", id="preset-apply-btn", variant="primary")
                    yield Button("Show Diff", id="preset-diff-btn")

                with Horizontal(id="config-toggles"):
                    yield Button("Toggle Dry-Run", id="dryrun-toggle-btn", variant="warning")
                    yield Button("Reload Config", id="reload-btn")

                with Horizontal(id="config-quick-settings"):
                    yield Static("Auto-blackhole:", classes="cfg-label")
                    yield Switch(value=False, id="cfg-auto-blackhole")
                    yield Static("Adaptive:", classes="cfg-label")
                    yield Switch(value=False, id="cfg-adaptive")
                    yield Static("Response:", classes="cfg-label")
                    yield Select(
                        [("alert", "alert"), ("defensive", "defensive")],
                        value="alert", id="cfg-response-mode",
                        classes="cfg-select",
                    )

            # Config display — summary + collapsible sections
            with VerticalScroll(id="config-scroll"):
                yield Static(id="config-summary")
                for section in ("general", "filters", "reputation", "blackhole",
                                "adaptive", "correlator", "metrics", "eventstore", "alerts"):
                    with Collapsible(title=section.title(), collapsed=True,
                                     id=f"cfg-section-{section}"):
                        yield Static(id=f"cfg-section-{section}-content")

    # ── Console Tab (live daemon log output) ─────────────────

    class ConsoleTab(VerticalScroll):
        """Live daemon log output — visible only when running in unified mode."""

        def compose(self) -> ComposeResult:
            with Horizontal(id="console-controls"):
                yield Static("Level: ", classes="cfg-label")
                yield Select(
                    [("ALL", "ALL"), ("DEBUG", "DEBUG"), ("INFO", "INFO"),
                     ("WARNING", "WARNING"), ("ERROR", "ERROR")],
                    value="ALL", id="console-level-filter",
                )
                yield Button("Clear", id="console-clear-btn")
            yield Static(id="console-output")

    # ── Main App ──────────────────────────────────────────────

    class RatholeTUI(App):
        TITLE = "RATHOLE v1.0.0"
        theme = "gruvbox"

        CSS = """
        Screen {
            background: $surface;
        }

        /* ── Reusable panel classes ── */
        .panel {
            border: round $primary-darken-2;
            padding: 1 2;
            margin: 0 0 1 0;
            height: auto;
        }

        .panel-alert {
            border: round $error;
            padding: 1 2;
            margin: 0 0 1 0;
            height: auto;
        }

        .panel-info {
            border: round $accent;
            padding: 1 2;
            margin: 0 0 1 0;
            height: auto;
        }

        /* ── Sidebar ── */
        #sidebar {
            width: 22;
            dock: left;
            padding: 1;
            background: $boost;
            border-right: solid $primary-darken-2;
        }

        SidebarStats {
            height: auto;
        }

        /* ── Section headers ── */
        .section-header {
            height: 1;
            padding: 0 1;
            margin-top: 1;
            text-style: bold;
            color: $text;
            background: $primary-darken-3;
        }

        /* ── Peer actions / event filters / blackhole form / interface form ── */
        #peer-actions, #event-filters, #bh-add-form, #iface-add-form, #i2p-add-form, #registry-btn-form {
            height: 3;
            padding: 0 1;
        }

        #registry-section-header {
            height: auto;
            padding: 1 1 0 1;
        }

        #registry-hint {
            height: 1;
            padding: 0 1;
        }

        #registry-table {
            height: auto;
            max-height: 16;
        }

        #i2p-b32-display {
            height: auto;
            padding: 0 1;
        }

        #i2p-b32-copy-btn {
            display: none;
            width: auto;
            min-width: 8;
            margin: 0 1 1 1;
        }

        #config-presets, #config-toggles {
            height: 3;
            padding: 0 1;
        }

        #peer-actions Input, #event-filters Input, #bh-add-form Input, #iface-add-form Input, #i2p-add-form Input {
            width: 1fr;
        }

        #peer-actions Button, #bh-add-form Button, #iface-add-form Button, #i2p-add-form Button {
            margin-left: 1;
        }

        #config-presets Button, #config-toggles Button {
            margin-left: 1;
        }

        #config-presets Select {
            width: 24;
        }

        #config-quick-settings {
            height: 3;
            padding: 0 1;
        }

        .cfg-label {
            width: auto;
            padding: 0 1;
            content-align-vertical: middle;
        }

        .cfg-select {
            width: 16;
        }

        #event-filters Select {
            width: 22;
        }

        DataTable {
            height: 1fr;
            margin: 0 1;
        }

        #peer-detail {
            height: auto;
            max-height: 8;
            padding: 0 1;
            display: none;
        }

        #blackhole-count {
            height: 1;
            padding: 0 1;
            text-style: bold;
            color: $error;
        }

        /* ── Overview tab layout ── */
        #overview-top-row, #overview-mid-row {
            height: auto;
            margin: 0 1;
        }

        #overview-top-row .panel,
        #overview-top-row .panel-alert {
            width: 1fr;
            margin: 0 1 1 0;
        }

        #overview-mid-row .panel,
        #overview-mid-row .panel-info {
            width: 1fr;
            margin: 0 1 1 0;
        }

        #overview-bottom {
            margin: 0 1 1 1;
        }

        /* ── Filters tab ── */
        .pipeline-header {
            height: 1;
            padding: 0 1;
            margin-top: 1;
            text-style: bold;
            background: $primary-darken-3;
            border-bottom: solid $primary-darken-2;
        }

        .filter-card {
            border: round $primary-darken-3;
            padding: 0 1;
            margin: 0 1 1 1;
            height: auto;
        }

        .filter-card-disabled {
            border: round $surface-darken-1;
            padding: 0 1;
            margin: 0 1 1 1;
            height: auto;
            opacity: 0.7;
        }

        .filter-row {
            height: 3;
            padding: 0 0;
        }

        .filter-label {
            padding-left: 1;
            width: 1fr;
            content-align-vertical: middle;
        }

        .filter-params {
            height: auto;
            padding: 0 0 0 4;
            margin-bottom: 1;
        }

        .param-label {
            width: auto;
            padding-right: 1;
            content-align-vertical: middle;
        }

        .param-input {
            width: 16;
        }

        .param-select {
            width: 16;
        }

        .param-apply {
            margin-left: 1;
            width: auto;
        }

        /* ── Config tab ── */
        #config-presets-panel {
            margin: 0 1 1 1;
        }

        #config-summary {
            padding: 1 2;
            height: auto;
            border: round $primary-darken-2;
            margin: 0 0 1 0;
        }

        #config-scroll {
            height: 1fr;
        }

        #config-scroll Collapsible {
            margin: 0;
        }

        /* ── Event log ── */
        #event-log {
            height: 1fr;
        }

        #event-log Label {
            padding: 0 1;
        }

        /* ── Console tab ── */
        #console-controls {
            height: 3;
            padding: 0 1;
        }

        #console-controls Select {
            width: 16;
        }

        #console-controls Button {
            margin-left: 1;
        }

        #console-output {
            padding: 0 1;
            height: auto;
        }

        /* ── Status bar ── */
        StatusBar {
            dock: bottom;
            height: 1;
            padding: 0 1;
            background: $boost;
            border-top: solid $primary-darken-2;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("d", "toggle_dryrun", "Dry-run"),
            Binding("question_mark", "show_help", "Help"),
            Binding("1", "show_tab('overview')", "Overview", show=False),
            Binding("2", "show_tab('peers')", "Peers", show=False),
            Binding("3", "show_tab('events')", "Events", show=False),
            Binding("4", "show_tab('interfaces')", "Interfaces", show=False),
            Binding("5", "show_tab('blackhole')", "Blackhole", show=False),
            Binding("6", "show_tab('filters')", "Filters", show=False),
            Binding("7", "show_tab('config')", "Config", show=False),
            Binding("8", "show_tab('console')", "Console", show=False),
        ]

        # Map column headers to peer data keys for sorting.
        _PEER_COLUMN_MAP = {
            "Peer Hash": "peer",
            "Announces": "announces",
            "Drops": "drops",
            "Reputation": "reputation",
            "Category": "category",
        }

        def __init__(self, sock_path: str, refresh_interval: float = 5.0,
                     log_handler=None, command_handler=None):
            super().__init__()
            self.sock_path = sock_path
            self._refresh_interval = refresh_interval
            self._log_handler = log_handler  # RingBufferHandler from cli.py
            self._command_handler = command_handler  # Direct dispatch (unified mode)
            self._console_lines: list[str] = []
            self._reputation_data = {}
            self._peers_sort_key = "announces"
            self._peers_sort_reverse = True
            self._cached_peers: list = []
            self._last_total_packets = 0
            self._packet_history: list[int] = []
            self._last_peers_refresh: float = 0.0
            self._peers_refresh_interval: float = 60.0  # Peers tab updates every 60s
            self._force_peers_refresh: bool = True  # Force on first load
            # (prevent() context manager is used instead of a flag to suppress
            #  Switch.Changed / Select.Changed during programmatic updates)

        def _send(self, cmd: str, cmd_args: dict | None = None) -> dict:
            """Send command to the daemon.

            In unified mode (command_handler set), calls the daemon
            directly — no socket, no serialization, no errno 57.
            Falls back to Unix socket RPC for standalone rathole-tui.
            """
            if self._command_handler is not None:
                try:
                    return self._command_handler(cmd, cmd_args or {})
                except Exception as exc:
                    return {"ok": False, "error": f"Direct call failed: {exc}"}
            return rpc_send(self.sock_path, cmd, cmd_args)

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal():
                with Vertical(id="sidebar"):
                    yield SidebarStats(id="sidebar-stats")
                with TabbedContent():
                    with TabPane("Overview", id="overview"):
                        yield OverviewTab()
                    with TabPane("Peers", id="peers"):
                        yield PeersTab()
                    with TabPane("Events", id="events"):
                        yield EventsTab()
                    with TabPane("Interfaces", id="interfaces"):
                        yield InterfacesTab()
                    with TabPane("Blackhole", id="blackhole"):
                        yield BlackholeTab()
                    with TabPane("Filters", id="filters"):
                        yield FiltersTab()
                    with TabPane("Config", id="config"):
                        yield ConfigTab()
                    if self._log_handler is not None:
                        with TabPane("Console", id="console"):
                            yield ConsoleTab()
            yield StatusBar(id="status-bar")
            yield Footer()

        def on_mount(self) -> None:
            self.refresh_data()
            self.set_interval(self._refresh_interval, self.refresh_data)

        # ── Data Refresh ──────────────────────────────────────

        @work(thread=True)
        def refresh_data(self) -> None:
            """Fetch data from daemon and update all tabs."""
            # Status + peers + interfaces
            resp = self._send("status")
            if not resp.get("ok"):
                # Mark disconnected in status bar
                try:
                    self.call_from_thread(self._set_disconnected)
                except Exception:
                    pass
                return

            stats = resp.get("stats", {})
            peers = resp.get("peers", [])
            ifaces = resp.get("interfaces", [])

            self.call_from_thread(self._update_sidebar, stats)
            self.call_from_thread(self._update_overview, stats, peers, ifaces)

            # Peers tab only refreshes every 60s (or when forced by an action)
            now = time.monotonic()
            if self._force_peers_refresh or (now - self._last_peers_refresh >= self._peers_refresh_interval):
                self._last_peers_refresh = now
                self._force_peers_refresh = False
                self.call_from_thread(self._update_peers, peers)

            self.call_from_thread(self._update_interfaces, ifaces)
            self.call_from_thread(
                self._update_i2p_display,
                stats.get("i2p_b32"),
                stats.get("i2p_pending", False),
            )

            # Registry status + gateway list
            reg_resp = self._send("registry", {"action": "status"})
            if reg_resp.get("ok"):
                reg_data = reg_resp.get("registry", {})
                self.call_from_thread(self._update_registry, reg_data)
                # Auto-load cached gateway list (no HTTP call)
                if reg_data.get("enabled") and reg_data.get("discover"):
                    gw_resp = self._send("registry", {"action": "list"})
                    if gw_resp.get("ok"):
                        self.call_from_thread(
                            self._update_registry_table,
                            gw_resp.get("gateways", []),
                        )

            # Events
            event_resp = self._send("events", {"limit": 100})
            if event_resp.get("ok"):
                self.call_from_thread(self._update_events, event_resp.get("events", []))

            # Blackhole
            bh_resp = self._send("blackhole", {"action": "list"})
            if bh_resp.get("ok"):
                self.call_from_thread(self._update_blackhole, bh_resp.get("blackholed", []))

            # Reputation
            rep_resp = self._send("reputation")
            if rep_resp.get("ok"):
                self.call_from_thread(self._update_reputation_data, rep_resp.get("identities", []))

            # Filters
            filt_resp = self._send("filters", {"action": "list"})
            if filt_resp.get("ok"):
                self.call_from_thread(self._update_filters, filt_resp.get("pipelines", {}))

            # Config
            cfg_resp = self._send("config", {"action": "show"})
            if cfg_resp.get("ok"):
                self.call_from_thread(self._update_config, cfg_resp.get("config", {}))

            # Correlator (for overview alerts)
            corr_resp = self._send("correlator")
            if corr_resp.get("ok"):
                self.call_from_thread(
                    self._update_overview_alerts,
                    corr_resp.get("correlator", {}),
                )

            # Console (live daemon log output)
            if self._log_handler is not None:
                new_lines = self._log_handler.drain_new()
                if new_lines:
                    self.call_from_thread(self._update_console, new_lines)

        # ── Update Methods ────────────────────────────────────

        def _set_disconnected(self):
            """Mark the status bar and sidebar as disconnected."""
            try:
                bar = self.query_one("#status-bar", StatusBar)
                bar.connected = False
            except Exception:
                pass
            try:
                panel = self.query_one("#sidebar-stats", SidebarStats)
                panel.connection_lost = True
                panel.mutate_reactive(SidebarStats.stats)
            except Exception:
                pass

        def _update_sidebar(self, stats: dict):
            try:
                panel = self.query_one("#sidebar-stats", SidebarStats)
                panel.last_updated = time.strftime("%H:%M:%S")
                panel.connection_lost = False
                panel.stats = stats
            except Exception:
                pass
            # Update status bar
            try:
                bar = self.query_one("#status-bar", StatusBar)
                bar.connected = True
                bar.dry_run = stats.get("dry_run", False)
                bar.node_mode = stats.get("node_mode", "client")
            except Exception:
                pass

        def _update_overview(self, stats: dict, peers: list, ifaces: list):
            # ── Posture Panel (top-left) ──
            try:
                widget = self.query_one("#overview-posture", Static)
                total = stats.get("total_accepted", 0) + stats.get("total_dropped", 0) + stats.get("total_throttled", 0)
                accept_pct = (stats.get("total_accepted", 0) / max(1, total)) * 100
                dry_run = stats.get("dry_run", False)

                node_mode = stats.get("node_mode", "client")
                if node_mode == "gateway":
                    mode_badge = "[bold cyan]GATEWAY[/]"
                else:
                    mode_badge = "[bold green]CLIENT[/]"

                if dry_run:
                    mode_line = f"Mode:   [cyan]DRY-RUN[/]"
                    health_line = f"Health: [cyan]Observing[/] — {stats.get('total_dropped', 0)} would-be blocks"
                else:
                    mode_line = f"Mode:   [green]ACTIVE[/]"
                    health_line = f"Health: {_health_bar(accept_pct, 20)} {accept_pct:.1f}%"

                # Packet rate sparkline
                current_total = stats.get("total_packets", 0)
                delta = max(0, current_total - self._last_total_packets) if self._last_total_packets else 0
                self._last_total_packets = current_total
                if delta > 0 or self._packet_history:
                    self._packet_history.append(delta)
                    if len(self._packet_history) > 10:
                        self._packet_history = self._packet_history[-10:]
                spark_chars = " ▁▂▃▄▅▆▇█"
                if self._packet_history and max(self._packet_history) > 0:
                    mx = max(self._packet_history)
                    spark = "".join(
                        spark_chars[min(8, int(v / max(1, mx) * 8))]
                        for v in self._packet_history
                    )
                    rate_line = f"Rate:   [cyan]{spark}[/] ({delta:,}/cycle)"
                else:
                    rate_line = f"Rate:   [dim]waiting...[/]"

                lines = [
                    f"[bold]Security Posture[/]  {mode_badge}",
                    f"[dim]{'─' * 36}[/]",
                    mode_line,
                    health_line,
                    rate_line,
                    "",
                    f"[green]{stats.get('total_accepted', 0):,}[/] accepted  "
                    f"[red]{stats.get('total_dropped', 0):,}[/] dropped  "
                    f"[yellow]{stats.get('total_throttled', 0):,}[/] throttled  "
                    f"[magenta]{stats.get('total_blackholed', 0):,}[/] blackholed",
                ]
                widget.update("\n".join(lines))
            except Exception:
                pass

            # ── Traffic Panel (mid-left) ──
            try:
                widget = self.query_one("#overview-traffic", Static)
                uptime = stats.get("uptime", 0)
                h, m, s = int(uptime // 3600), int((uptime % 3600) // 60), int(uptime % 60)

                total_bytes = stats.get("total_bytes_in", 0)
                if total_bytes >= 1_073_741_824:
                    bytes_str = f"{total_bytes / 1_073_741_824:.1f} GB"
                elif total_bytes >= 1_048_576:
                    bytes_str = f"{total_bytes / 1_048_576:.1f} MB"
                elif total_bytes >= 1024:
                    bytes_str = f"{total_bytes / 1024:.1f} KB"
                else:
                    bytes_str = f"{total_bytes} B"

                peak_pkt = stats.get("peak_packet_rate", 0)
                peak_ann = stats.get("peak_announce_rate", 0)

                lines = [
                    f"[bold]Traffic[/]",
                    f"[dim]{'─' * 28}[/]",
                    f"Uptime:   [cyan]{h}h {m}m {s}s[/]",
                    f"Packets:  [cyan]{stats.get('total_packets', 0):,}[/]",
                    f"Bytes:    [cyan]{bytes_str}[/]",
                    f"Unique:   [cyan]{stats.get('unique_peers_seen', 0):,}[/] peers seen",
                ]
                if peak_pkt > 0 or peak_ann > 0:
                    lines.append("")
                    lines.append("[bold]Peak Rates[/]")
                    if peak_pkt > 0:
                        lines.append(f"  Packets:   [cyan]{peak_pkt:.1f}[/]/s")
                    if peak_ann > 0:
                        lines.append(f"  Announces: [cyan]{peak_ann:.1f}[/]/s")

                node_mode = stats.get("node_mode", "client")
                if node_mode == "gateway":
                    pph = stats.get("peers_per_hour", 0)
                    if pph > 0:
                        lines.append("")
                        lines.append(f"[bold]Gateway[/]  [cyan]{pph:.0f}[/] new peers/hr")

                widget.update("\n".join(lines))
            except Exception:
                pass

            # ── Reputation Panel (mid-right) ──
            try:
                widget = self.query_one("#overview-reputation", Static)
                rep_dist = stats.get("reputation_distribution", {})
                total_rep = max(1, sum(rep_dist.values()))
                bar_width = 16

                lines = [
                    "[bold]Reputation[/]",
                    f"[dim]{'─' * 28}[/]",
                ]
                for cat in ("TRUSTED", "NEUTRAL", "SUSPECT", "UNKNOWN"):
                    cnt = rep_dist.get(cat, 0)
                    color = CATEGORY_COLORS.get(cat, "dim")
                    bar_len = int(cnt / total_rep * bar_width) if cnt > 0 else 0
                    bar = f"[{color}]{'█' * bar_len}[/][dim]{'░' * (bar_width - bar_len)}[/]" if cnt > 0 else f"[dim]{'░' * bar_width}[/]"
                    lines.append(f"[{color}]{cat:<12}[/] {cnt:>4}  {bar}")

                widget.update("\n".join(lines))
            except Exception:
                pass

            # ── Bottom Panel: Top Drops + Interfaces ──
            try:
                widget = self.query_one("#overview-bottom", Static)
                filter_drops = stats.get("filter_effectiveness", {})
                if not filter_drops:
                    filter_drops = stats.get("filter_drops", {})
                top_filters = list(filter_drops.items())[:5]

                lines = []
                # Top drops
                if top_filters:
                    lines.append("[bold]Top Drops[/]")
                    for fname, count in top_filters:
                        lines.append(f"  [red]{fname:<20}[/] {count:>6,}")
                    lines.append("")

                # Interfaces
                lines.append(f"[bold]Interfaces[/] ({len(ifaces)})")
                for i in ifaces:
                    iname = i.get('interface', '?')
                    lines.append(
                        f"  {iname:<28} "
                        f"pkts=[cyan]{i.get('packets', 0):>6,}[/]  "
                        f"bytes=[cyan]{i.get('bytes', 0):>8,}[/]"
                    )

                widget.update("\n".join(lines))
            except Exception:
                pass


        def _update_overview_alerts(self, correlator: dict):
            """Update the recent alerts panel on the overview (top-right)."""
            try:
                widget = self.query_one("#overview-alerts-panel", Static)
                alerts = correlator.get("alerts", [])
                if not alerts:
                    widget.update("[bold]Recent Alerts[/]\n\n  [green]✓[/] [dim]No active alerts[/]")
                    return

                lines = [f"[bold]Recent Alerts[/] ({correlator.get('total_alerts', 0)} total)"]
                lines.append(f"[dim]{'─' * 32}[/]")
                for a in alerts[-5:]:
                    sev = a.get("severity", "").upper()
                    color = SEVERITY_COLORS.get(sev, "white")
                    resp_mark = " [green]✓[/]" if a.get("response_executed") else ""
                    lines.append(
                        f"[{color}]●[/] [{color}]{sev[:4]}[/] "
                        f"[bold]{a.get('pattern', '?')}[/] on {a.get('interface', '?')}"
                        f"{resp_mark}"
                    )
                    lines.append(f"  [dim]{a.get('description', '')}[/]")
                widget.update("\n".join(lines))
            except Exception:
                pass

        def _update_console(self, new_lines: list[str]):
            """Append new log lines to the Console tab."""
            try:
                widget = self.query_one("#console-output", Static)
            except Exception:
                return

            # Apply level filter
            try:
                level_filter = self.query_one("#console-level-filter", Select).value
            except Exception:
                level_filter = "ALL"

            level_tags = {
                "DEBUG": "[DEBUG",
                "INFO": "[INFO",
                "WARNING": "[WARNING",
                "ERROR": "[ERROR",
                "CRITICAL": "[CRITICAL",
            }

            for line in new_lines:
                if level_filter != "ALL":
                    # Only include lines at or above the selected level
                    levels_above = {
                        "DEBUG": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        "INFO": ["INFO", "WARNING", "ERROR", "CRITICAL"],
                        "WARNING": ["WARNING", "ERROR", "CRITICAL"],
                        "ERROR": ["ERROR", "CRITICAL"],
                    }
                    allowed = levels_above.get(level_filter, [])
                    if not any(level_tags.get(l, "") in line for l in allowed):
                        continue
                self._console_lines.append(line)

            # Keep bounded
            max_lines = 500
            if len(self._console_lines) > max_lines:
                self._console_lines = self._console_lines[-max_lines:]

            # Color-code log levels for display
            colored = []
            for line in self._console_lines:
                escaped = line.replace("[", "\\[")
                if "\\[ERROR" in escaped or "\\[CRITICAL" in escaped:
                    colored.append(f"[red]{escaped}[/]")
                elif "\\[WARNING" in escaped:
                    colored.append(f"[yellow]{escaped}[/]")
                elif "\\[DEBUG" in escaped:
                    colored.append(f"[dim]{escaped}[/]")
                else:
                    colored.append(escaped)

            widget.update("\n".join(colored))

            # Auto-scroll to bottom
            try:
                scroll = widget.parent
                if scroll is not None:
                    scroll.scroll_end(animate=False)
            except Exception:
                pass

        def _update_peers(self, peers: list):
            self._cached_peers = peers
            self._render_peers_table()

        def _render_peers_table(self):
            """Render the peers table from cached data with current sort/filter."""
            try:
                table = self.query_one("#peer-table", DataTable)
                table.clear()

                # Apply filter
                try:
                    filter_text = self.query_one("#peer-filter", Input).value.lower()
                except Exception:
                    filter_text = ""

                # Sort by user-selected column
                sort_key = self._peers_sort_key
                def _sort_value(p):
                    val = p.get(sort_key, 0)
                    if sort_key in ("announces", "drops"):
                        return int(val) if val else 0
                    if sort_key == "reputation":
                        return float(val) if val else 0.0
                    return str(val).lower() if val else ""

                for p in sorted(self._cached_peers, key=_sort_value, reverse=self._peers_sort_reverse):
                    peer_hash = p.get("peer", "?")
                    if filter_text and filter_text not in peer_hash.lower():
                        continue

                    cat = p.get("category", "UNKNOWN")
                    cat_color = CATEGORY_COLORS.get(cat, "white")
                    pin = " [dim]PIN[/]" if p.get("pinned") else ""
                    table.add_row(
                        peer_hash,
                        str(p.get("announces", 0)),
                        str(p.get("drops", 0)),
                        f"{p.get('reputation', 0.5):.3f}",
                        f"[{cat_color}]{cat}[/]{pin}",
                    )
            except Exception:
                pass

        def _update_events(self, events: list):
            try:
                log_widget = self.query_one("#event-log", VerticalScroll)
                log_widget.remove_children()

                # Get filter values
                try:
                    sev_filter = self.query_one("#event-severity-filter", Select).value
                except Exception:
                    sev_filter = ""
                try:
                    type_filter = self.query_one("#event-type-filter", Select).value
                except Exception:
                    type_filter = ""
                try:
                    search = self.query_one("#event-search", Input).value.lower()
                except Exception:
                    search = ""

                for e in events:
                    sev = e.get("severity", "INFO")
                    etype = e.get("event_type", "")
                    if sev_filter and sev != sev_filter:
                        continue
                    if type_filter and etype != type_filter:
                        continue
                    desc = e.get("description", "")
                    if search and search not in desc.lower() and search not in e.get("source", "").lower():
                        continue

                    color = SEVERITY_COLORS.get(sev, "white")
                    ts = time.strftime("%H:%M:%S", time.localtime(e.get("timestamp", 0)))
                    log_widget.mount(Label(
                        f"[dim]{ts}[/] [{color}]{sev[:4]}[/] "
                        f"[dim]\\[{e.get('source', '?')}][/] {desc}"
                    ))
            except Exception:
                pass

        def _update_interfaces(self, ifaces: list):
            try:
                table = self.query_one("#interface-table", DataTable)
                table.clear()
                for i in ifaces:
                    table.add_row(
                        i.get("interface", "?"),
                        f"{i.get('packets', 0):,}",
                        f"{i.get('bytes', 0):,}",
                        str(i.get("announces", 0)),
                        str(i.get("link_requests", 0)),
                        str(i.get("pending_links", 0)),
                        str(i.get("active_resources", 0)),
                    )
            except Exception:
                pass

        def _update_i2p_display(self, i2p_b32, i2p_pending=False):
            try:
                widget = self.query_one("#i2p-b32-display", Static)
                if i2p_b32:
                    widget.update(
                        f"\n[dark_goldenrod]Your I2P address:[/]\n"
                        f"[bold]{i2p_b32}[/]\n"
                    )
                elif i2p_pending:
                    widget.update(
                        "\n[dim]I2P tunnel establishing — B32 address will appear here…[/]\n"
                    )
                else:
                    widget.update("")
            except Exception:
                pass
            # Show/hide copy button
            try:
                btn = self.query_one("#i2p-b32-copy-btn", Button)
                btn.display = bool(i2p_b32)
            except Exception:
                pass

        def _update_registry(self, data: dict):
            try:
                header = self.query_one("#registry-section-header", Static)
                enabled = data.get("enabled", False)

                # Always show the toggle button row, but hide table/hint when disabled
                try:
                    self.query_one("#registry-btn-form").display = True
                except Exception:
                    pass

                # Update toggle button label/variant
                try:
                    toggle_btn = self.query_one("#registry-toggle-btn", Button)
                    if enabled:
                        toggle_btn.label = "Disable Registry"
                        toggle_btn.variant = "error"
                    else:
                        toggle_btn.label = "Enable Registry"
                        toggle_btn.variant = "success"
                except Exception:
                    pass

                if not enabled:
                    header.update("\n[bold]── Gateway Registry ──[/]\n[dim]Disabled[/]")
                    for wid in ("#registry-table", "#registry-hint"):
                        try:
                            self.query_one(wid).display = False
                        except Exception:
                            pass
                    # Hide action buttons when disabled
                    for wid in ("#registry-discover-btn", "#registry-register-btn", "#registry-autoconnect-btn"):
                        try:
                            self.query_one(wid).display = False
                        except Exception:
                            pass
                    return

                # Show registry section
                for wid in ("#registry-table", "#registry-hint", "#registry-discover-btn"):
                    try:
                        self.query_one(wid).display = True
                    except Exception:
                        pass

                parts = []
                if data.get("publish"):
                    if data.get("published"):
                        parts.append("Publish [green]●[/]")
                    elif not data.get("b32"):
                        parts.append("Publish [yellow]⏳[/] [dim]waiting for I2P[/]")
                    else:
                        parts.append("Publish [dim]○[/]")
                if data.get("auto_connect"):
                    parts.append(f"Auto-connect [green]ON[/]")
                discovered = data.get("discovered_count", 0)
                connected = data.get("connected_count", 0)
                parts.append(f"Discovered: {discovered}")
                if connected:
                    parts.append(f"Connected: {connected}")
                disc_age = data.get("last_discover_age")
                if disc_age is not None:
                    mins = int(disc_age // 60)
                    parts.append(f"Last query: {mins}m ago" if mins > 0 else "Last query: just now")
                status_line = " | ".join(parts) if parts else "[dim]disabled[/]"
                header.update(f"\n[bold]── Gateway Registry ──[/]\nStatus: {status_line}")

                # Update publish button as toggle
                try:
                    reg_btn = self.query_one("#registry-register-btn", Button)
                    reg_btn.display = True
                    if data.get("publish"):
                        reg_btn.label = "Unpublish"
                        reg_btn.variant = "warning"
                    else:
                        reg_btn.label = "Publish"
                        reg_btn.variant = "success"
                except Exception:
                    pass

                # Update auto-connect button
                try:
                    ac_btn = self.query_one("#registry-autoconnect-btn", Button)
                    ac_btn.display = True
                    if data.get("auto_connect"):
                        ac_btn.label = "Auto-connect ON"
                        ac_btn.variant = "success"
                    else:
                        ac_btn.label = "Auto-connect OFF"
                        ac_btn.variant = "default"
                except Exception:
                    pass
            except Exception:
                pass

        def _update_blackhole(self, entries: list):
            try:
                # Update count
                count_widget = self.query_one("#blackhole-count", Static)
                auto = sum(1 for e in entries if e.get("source") == "auto")
                manual = len(entries) - auto
                count_widget.update(
                    f"[bold]{len(entries)}[/] blackholed ([red]{auto}[/] auto, {manual} manual)"
                )

                table = self.query_one("#blackhole-table", DataTable)
                table.clear()
                for e in entries:
                    source = e.get("source", "?")
                    source_styled = f"[red]{source}[/]" if source == "auto" else source
                    table.add_row(
                        e.get("identity", "?"),
                        source_styled,
                        e.get("reason", ""),
                    )
            except Exception:
                pass

        def _update_reputation_data(self, identities: list):
            """Store reputation data for enrichment."""
            self._reputation_data = {i["identity"]: i for i in identities}

        def _update_filters(self, pipelines: dict):
            """Update filter switch states and param values from server data.

            Uses ``prevent(Switch.Changed, Select.Changed)`` to suppress
            events from programmatic updates, avoiding a feedback loop where
            the TUI re-sends the same value back to the daemon.
            """
            try:
                from .filter_meta import FILTER_META

                # Count active filters for status bar
                total = 0
                active = 0
                for pkey, filters in pipelines.items():
                    for f in filters:
                        total += 1
                        if f.get("enabled", False):
                            active += 1
                try:
                    bar = self.query_one("#status-bar", StatusBar)
                    bar.filter_info = f"{active}/{total} filters"
                except Exception:
                    pass

                with self.prevent(Switch.Changed, Select.Changed):
                    for pkey, filters in pipelines.items():
                        for f in filters:
                            fname = f["name"]
                            enabled = f.get("enabled", False)
                            config = f.get("config", {})

                            # Update enable/disable switch
                            try:
                                sw = self.query_one(f"#filter-{fname}-switch", Switch)
                                if sw.value != enabled:
                                    sw.value = enabled
                            except Exception:
                                pass

                            # Toggle card styling based on enabled state
                            try:
                                card = self.query_one(f"#filter-{fname}-card")
                                has_enabled = card.has_class("filter-card")
                                if enabled and not has_enabled:
                                    card.remove_class("filter-card-disabled")
                                    card.add_class("filter-card")
                                elif not enabled and has_enabled:
                                    card.remove_class("filter-card")
                                    card.add_class("filter-card-disabled")
                            except Exception:
                                pass

                            # Update param widgets (only if not focused)
                            meta = FILTER_META.get(fname)
                            if meta and meta.params:
                                try:
                                    params_row = self.query_one(f"#filter-{fname}-params")
                                    params_row.display = enabled
                                except Exception:
                                    pass

                                for pk, pinfo in meta.params.items():
                                    widget_id = f"fparam-{fname}-{pk}"
                                    try:
                                        if pinfo.type == "number":
                                            inp = self.query_one(f"#{widget_id}", Input)
                                            if not inp.has_focus and pk in config:
                                                inp.value = str(config[pk])
                                        elif pinfo.type == "select":
                                            sel = self.query_one(f"#{widget_id}", Select)
                                            if pk in config:
                                                sel.value = str(config[pk])
                                        elif pinfo.type == "bool":
                                            bsw = self.query_one(f"#{widget_id}", Switch)
                                            if pk in config:
                                                bsw.value = bool(config[pk])
                                    except Exception:
                                        pass
            except Exception:
                pass

        def _update_config(self, config: dict):
            try:
                # Quick settings summary at the top
                general = config.get("general", {})
                rep = config.get("reputation", {})
                adaptive = config.get("adaptive", {})
                correlator = config.get("correlator", {})

                # Update interactive quick-setting widgets — suppress events
                with self.prevent(Switch.Changed, Select.Changed):
                    try:
                        sw_bh = self.query_one("#cfg-auto-blackhole", Switch)
                        bh_val = bool(rep.get("auto_blackhole", False))
                        if sw_bh.value != bh_val:
                            sw_bh.value = bh_val
                    except Exception:
                        pass
                    try:
                        sw_ad = self.query_one("#cfg-adaptive", Switch)
                        ad_val = bool(adaptive.get("enabled", False))
                        if sw_ad.value != ad_val:
                            sw_ad.value = ad_val
                    except Exception:
                        pass
                    try:
                        sel_rm = self.query_one("#cfg-response-mode", Select)
                        rm_val = str(correlator.get("response_mode", "alert"))
                        if sel_rm.value != rm_val:
                            sel_rm.value = rm_val
                    except Exception:
                        pass

                dry_run = general.get("dry_run", False)
                dr_str = "[yellow]ON[/]" if dry_run else "[green]OFF[/]"
                resp_mode = correlator.get("response_mode", "alert")
                node_mode = general.get("node_mode", "client")
                if node_mode == "gateway":
                    mode_label = "[bold cyan]GATEWAY[/]"
                else:
                    mode_label = "[bold green]CLIENT[/]"

                # Update preset selector to show mode-appropriate presets
                try:
                    from .presets import list_presets as _lp
                    mode_presets = _lp(node_mode)
                    preset_options = [("Select Preset", "")] + [
                        (p["name"].capitalize(), p["name"])
                        for p in mode_presets
                    ]
                    sel = self.query_one("#preset-select", Select)
                    sel.set_options(preset_options)
                except Exception:
                    pass

                # Summary panel
                try:
                    summary = self.query_one("#config-summary", Static)
                    lines = [
                        f"[bold]Current Settings[/]",
                        f"[dim]{'─' * 40}[/]",
                        f"Node mode: {mode_label}   Dry-run: {dr_str}   Response: [cyan]{resp_mode}[/]",
                        "",
                        f"[bold]Reputation Tuning[/]",
                        f"  Accept reward:     [cyan]{rep.get('accept_reward', 0.005)}[/]",
                        f"  Drop penalty:      [cyan]{rep.get('drop_penalty', 0.015)}[/]",
                        f"  Decay rate:        [cyan]{rep.get('decay_rate', 0.02)}[/]",
                        f"  Auto-BH threshold: [cyan]{rep.get('auto_blackhole_score', 0.15)}[/]",
                    ]
                    summary.update("\n".join(lines))
                except Exception:
                    pass

                # Collapsible sections
                for section_key in ("general", "filters", "reputation", "blackhole",
                                    "adaptive", "correlator", "metrics", "eventstore", "alerts"):
                    try:
                        widget = self.query_one(f"#cfg-section-{section_key}-content", Static)
                        section_data = config.get(section_key, {})
                        if not section_data:
                            widget.update("[dim]No configuration for this section.[/]")
                            continue
                        section_lines = []
                        self._format_config_tree(section_data, section_lines, indent=0)
                        widget.update("\n".join(section_lines))
                    except Exception:
                        pass
            except Exception:
                pass

        def _format_config_tree(self, data, lines: list, indent: int = 0):
            """Recursively format config data."""
            pad = "  " * indent
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        lines.append(f"{pad}[bold]{k}[/]")
                        self._format_config_tree(v, lines, indent + 1)
                    elif isinstance(v, list):
                        if v:
                            lines.append(f"{pad}[cyan]{k}[/]: {v}")
                        else:
                            lines.append(f"{pad}[cyan]{k}[/]: [dim]\\[][/]")
                    elif isinstance(v, bool):
                        val = "[green]true[/]" if v else "[red]false[/]"
                        lines.append(f"{pad}[cyan]{k}[/]: {val}")
                    elif isinstance(v, (int, float)):
                        lines.append(f"{pad}[cyan]{k}[/]: [yellow]{v}[/]")
                    else:
                        val = str(v) if v else "[dim](empty)[/]"
                        lines.append(f"{pad}[cyan]{k}[/]: {val}")

        # ── Button Handlers ───────────────────────────────────

        # ── Peer Action Modal ─────────────────────────────────

        def _open_peer_action_modal(self) -> None:
            """Open the peer action modal for the currently selected peer."""
            try:
                table = self.query_one("#peer-table", DataTable)
                if table.cursor_row is not None:
                    row = table.get_row_at(table.cursor_row)
                    if row:
                        peer_hash = str(row[0])
                        # Check if peer is pinned via reputation data
                        rep = self._reputation_data.get(peer_hash, {})
                        pinned = rep.get("pinned", False)
                        self.push_screen(
                            PeerActionScreen(peer_hash, pinned=pinned),
                            self._on_peer_action_result,
                        )
            except Exception:
                pass

        def _on_peer_action_result(self, result: str) -> None:
            """Handle the result from the peer action modal."""
            if result == "cancel" or result is None:
                return
            # Get the selected peer hash
            try:
                table = self.query_one("#peer-table", DataTable)
                row = table.get_row_at(table.cursor_row)
                if not row:
                    return
                peer_hash = str(row[0])
            except Exception:
                return

            if result == "blackhole":
                # Show reason modal before blackholing
                self.push_screen(
                    BlackholeReasonScreen(peer_hash),
                    lambda reason, ph=peer_hash: self._on_blackhole_reason(ph, reason),
                )
            elif result == "pin_trusted":
                self._do_peer_pin_trusted(peer_hash)
            elif result == "unpin":
                self._do_peer_unpin(peer_hash)
            elif result == "details":
                self._do_peer_details(peer_hash)
            elif result == "copy":
                self._do_peer_copy_hash(peer_hash)

        def _on_blackhole_reason(self, peer_hash: str, reason: str) -> None:
            """Handle result from the blackhole reason modal."""
            if not reason:
                return  # Cancelled
            self._do_peer_blackhole(peer_hash, reason)

        @work(thread=True)
        def _do_peer_blackhole(self, peer_hash: str, reason: str = "manual via TUI") -> None:
            resp = self._send("blackhole", {"action": "add", "identity": peer_hash, "reason": reason})
            if resp.get("ok"):
                self.notify(f"Blackholed {peer_hash[:16]}...", severity="information")
                self._force_peers_refresh = True
                self.refresh_data()
            else:
                self.notify(f"Error: {resp.get('error', '?')}", severity="error")

        @work(thread=True)
        def _do_peer_pin_trusted(self, peer_hash: str) -> None:
            resp = self._send("reputation", {"action": "pin", "identity": peer_hash, "score": 1.0})
            if resp.get("ok"):
                self.notify(f"Pinned {peer_hash[:16]}... as TRUSTED", severity="information")
                self._force_peers_refresh = True
                self.refresh_data()
            else:
                self.notify(f"Error: {resp.get('error', '?')}", severity="error")

        def _do_peer_copy_hash(self, peer_hash: str) -> None:
            ok = _copy_to_clipboard(peer_hash)
            if ok:
                self.notify(f"Copied: {peer_hash[:16]}...", severity="information")
            else:
                self.notify(f"Hash: {peer_hash}", severity="information")

        @work(thread=True)
        def _do_peer_unpin(self, peer_hash: str) -> None:
            resp = self._send("reputation", {"action": "unpin", "identity": peer_hash})
            if resp.get("ok"):
                self.notify(f"Unpinned {peer_hash[:16]}...", severity="information")
                self._force_peers_refresh = True
                self.refresh_data()
            else:
                self.notify(f"Error: {resp.get('error', '?')}", severity="error")

        @work(thread=True)
        def _do_peer_details(self, peer_hash: str) -> None:
            resp = self._send("reputation", {"identity": peer_hash})
            if resp.get("ok"):
                self.call_from_thread(
                    self.push_screen,
                    ReputationDetailScreen(resp),
                )
            else:
                self.notify(f"Error: {resp.get('error', '?')}", severity="error")

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            """Handle Enter key on a DataTable row."""
            if event.data_table.id == "peer-table":
                row = event.data_table.get_row(event.row_key)
                if row:
                    peer_hash = str(row[0])
                    rep = self._reputation_data.get(peer_hash, {})
                    pinned = rep.get("pinned", False)
                    self.push_screen(
                        PeerActionScreen(peer_hash, pinned=pinned),
                        self._on_peer_action_result,
                    )
            elif event.data_table.id == "registry-table":
                row = event.data_table.get_row(event.row_key)
                if row:
                    identity_hash = str(row[5])  # Identity column (index 5)
                    self._handle_registry_connect(identity_hash)

        def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
            """Sort peers table when clicking a column header."""
            if event.data_table.id != "peer-table":
                return

            # Extract plain text from header label (strip Rich markup)
            import re
            label = str(event.label) if hasattr(event, "label") else ""
            clean_label = re.sub(r"\[.*?\]", "", label).strip()

            data_key = self._PEER_COLUMN_MAP.get(clean_label)
            if data_key is None:
                return

            if self._peers_sort_key == data_key:
                self._peers_sort_reverse = not self._peers_sort_reverse
            else:
                self._peers_sort_key = data_key
                self._peers_sort_reverse = True  # Default descending for new column

            self._render_peers_table()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = event.button.id or ""

            if button_id == "bh-add-btn":
                self._handle_blackhole_add()
            elif button_id == "bh-remove-btn":
                self._handle_blackhole_remove()
            elif button_id == "peer-action-btn":
                self._open_peer_action_modal()
            elif button_id == "preset-apply-btn":
                self._handle_preset_apply()
            elif button_id == "preset-diff-btn":
                self._handle_preset_diff()
            elif button_id == "dryrun-toggle-btn":
                self._handle_dryrun_toggle()
            elif button_id == "reload-btn":
                self._handle_reload()
            elif button_id == "iface-connect-btn":
                self._handle_interface_connect()
            elif button_id == "tcp-server-btn":
                self._handle_tcp_server()
            elif button_id == "i2p-connect-btn":
                self._handle_i2p_connect()
            elif button_id == "i2p-server-btn":
                self._handle_i2p_server()
            elif button_id == "i2p-b32-copy-btn":
                self._handle_i2p_copy()
            elif button_id == "registry-toggle-btn":
                self._handle_registry_toggle()
            elif button_id == "registry-discover-btn":
                self._handle_registry_discover()
            elif button_id == "registry-register-btn":
                self._handle_registry_publish_toggle()
            elif button_id == "registry-autoconnect-btn":
                self._handle_registry_autoconnect_toggle()
            elif button_id == "console-clear-btn":
                self._console_lines.clear()
                try:
                    self.query_one("#console-output", Static).update("")
                except Exception:
                    pass
            elif button_id.startswith("filter-") and button_id.endswith("-apply"):
                fname = button_id[len("filter-"):-len("-apply")]
                self._handle_filter_param_apply(fname)

        @work(thread=True)
        def _handle_blackhole_add(self) -> None:
            try:
                identity_input = self.query_one("#bh-identity-input", Input)
                reason_input = self.query_one("#bh-reason-input", Input)
                identity = identity_input.value.strip()
                reason = reason_input.value.strip() or "manual"

                if not identity:
                    self.notify("Identity hash required", severity="error")
                    return

                resp = self._send("blackhole", {"action": "add", "identity": identity, "reason": reason})
                if resp.get("ok"):
                    self.notify(f"Blackholed {identity[:16]}...", severity="information")
                    self.call_from_thread(lambda: identity_input.__setattr__("value", ""))
                    self.call_from_thread(lambda: reason_input.__setattr__("value", ""))
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_blackhole_remove(self) -> None:
            try:
                table = self.query_one("#blackhole-table", DataTable)
                if table.cursor_row is None:
                    self.notify("Select a row first", severity="warning")
                    return
                row = table.get_row_at(table.cursor_row)
                if not row:
                    self.notify("No row selected", severity="warning")
                    return
                identity = str(row[0])
                resp = self._send("blackhole", {"action": "remove", "identity": identity})
                if resp.get("ok"):
                    self.notify(f"Removed {identity[:16]}...", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_interface_connect(self) -> None:
            try:
                host_input = self.query_one("#iface-host-input", Input)
                port_input = self.query_one("#iface-port-input", Input)
                host = host_input.value.strip()
                port_str = port_input.value.strip()

                if not host:
                    self.notify("Host required", severity="error")
                    return
                if not port_str:
                    self.notify("Port required", severity="error")
                    return
                try:
                    port = int(port_str)
                    if not (1 <= port <= 65535):
                        raise ValueError
                except ValueError:
                    self.notify("Port must be 1-65535", severity="error")
                    return

                resp = self._send("add_interface", {"host": host, "port": port})
                if resp.get("ok"):
                    name = resp.get("name", f"{host}:{port}")
                    self.notify(f"Connected: {name}", severity="information")
                    self.call_from_thread(lambda: host_input.__setattr__("value", ""))
                    self.call_from_thread(lambda: port_input.__setattr__("value", ""))
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_i2p_connect(self) -> None:
            try:
                b32_input = self.query_one("#i2p-b32-input", Input)
                b32 = b32_input.value.strip()
                if not b32:
                    self.notify("B32 address required", severity="error")
                    return
                if not b32.endswith(".b32.i2p"):
                    b32 = b32 + ".b32.i2p"
                resp = self._send("add_i2p_peer", {"b32": b32})
                if resp.get("ok"):
                    name = resp.get("name", b32[:16])
                    self.notify(f"I2P peer added: {name}", severity="information")
                    self.call_from_thread(lambda: b32_input.__setattr__("value", ""))
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_tcp_server(self) -> None:
            try:
                host_input = self.query_one("#iface-host-input", Input)
                port_input = self.query_one("#iface-port-input", Input)
                listen_ip = host_input.value.strip() or "0.0.0.0"
                port_str = port_input.value.strip() or "4242"
                try:
                    port = int(port_str)
                    if not (1 <= port <= 65535):
                        raise ValueError
                except ValueError:
                    self.notify("Port must be 1-65535", severity="error")
                    return

                resp = self._send("add_tcp_server", {"listen_ip": listen_ip, "port": port})
                if resp.get("ok"):
                    name = resp.get("name", f"{listen_ip}:{port}")
                    self.notify(f"Listening: {name}", severity="information")
                    self.call_from_thread(lambda: host_input.__setattr__("value", ""))
                    self.call_from_thread(lambda: port_input.__setattr__("value", ""))
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_i2p_server(self) -> None:
            try:
                self.notify("Starting I2P server — this may take a moment...", severity="information")
                resp = self._send("add_i2p_server")
                if resp.get("ok"):
                    name = resp.get("name", "I2P Gateway")
                    b32 = resp.get("b32", "")
                    msg = f"I2P server started: {name}"
                    if b32:
                        msg += f" ({b32[:16]}...)"
                    else:
                        msg += " — B32 address will appear once tunnel is established"
                    self.notify(msg, severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        def _handle_i2p_copy(self) -> None:
            try:
                stats = self.query_one("#sidebar-stats", SidebarStats).stats
                b32 = stats.get("i2p_b32", "")
                if not b32:
                    self.notify("No B32 address available yet", severity="warning")
                    return

                if _copy_to_clipboard(b32):
                    self.notify("B32 address copied", severity="information")
                else:
                    self.notify(f"B32: {b32}", severity="information")
            except Exception as e:
                self.notify(f"Copy failed: {e}", severity="error")

        @work(thread=True)
        def _handle_registry_discover(self) -> None:
            try:
                resp = self._send("registry", {"action": "discover"})
                if resp.get("ok"):
                    gateways = resp.get("gateways", [])
                    self.call_from_thread(self._update_registry_table, gateways)
                    self.notify(f"Discovered {len(gateways)} gateways", severity="information")
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_registry_toggle(self) -> None:
            """Toggle registry enabled/disabled."""
            try:
                status_resp = self._send("registry", {"action": "status"})
                currently_enabled = status_resp.get("registry", {}).get("enabled", False)
                resp = self._send("registry", {
                    "action": "set_config",
                    "enabled": not currently_enabled,
                })
                if resp.get("ok"):
                    state = "enabled" if not currently_enabled else "disabled"
                    self.notify(f"Registry {state}", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_registry_publish_toggle(self) -> None:
            """Toggle publish on/off."""
            try:
                status_resp = self._send("registry", {"action": "status"})
                currently_publish = status_resp.get("registry", {}).get("publish", False)
                resp = self._send("registry", {
                    "action": "set_config",
                    "publish": not currently_publish,
                })
                if resp.get("ok"):
                    state = "publishing" if not currently_publish else "unpublished"
                    self.notify(f"Registry: {state}", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_registry_autoconnect_toggle(self) -> None:
            """Toggle auto-connect on/off."""
            try:
                status_resp = self._send("registry", {"action": "status"})
                currently_ac = status_resp.get("registry", {}).get("auto_connect", False)
                resp = self._send("registry", {
                    "action": "set_config",
                    "auto_connect": not currently_ac,
                })
                if resp.get("ok"):
                    state = "ON" if not currently_ac else "OFF"
                    self.notify(f"Auto-connect {state}", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        def _update_registry_table(self, gateways: list):
            try:
                table = self.query_one("#registry-table", DataTable)
                table.clear()

                # Get connected B32s to mark status
                connected_b32s = set()
                iface_resp = self._send("interfaces")
                if iface_resp.get("ok"):
                    for iface in iface_resp.get("interfaces", []):
                        name = iface.get("interface", "")
                        if "I2P" in name:
                            connected_b32s.add(name)

                for gw in gateways:
                    b32 = gw.get("b32", "")
                    b32_short = f"{b32[:12]}...{b32[-8:]}" if len(b32) > 24 else b32
                    caps = ", ".join(gw.get("capabilities", [])) or "-"
                    # Check if already connected (B32 substring in any interface name)
                    is_connected = any(b32[:8] in name for name in connected_b32s)
                    name_display = gw.get("node_name", "") or "unnamed"
                    if is_connected:
                        name_display = f"● {name_display}"

                    table.add_row(
                        name_display,
                        b32_short,
                        caps,
                        gw.get("node_mode", ""),
                        gw.get("identity_hash", "")[:16],
                    )

                # Update hint based on count
                try:
                    hint = self.query_one("#registry-hint", Static)
                    if gateways:
                        hint.update(f"[dim]  {len(gateways)} gateways available — select a row and press Enter to connect[/]")
                    else:
                        hint.update("[dim]  No gateways found — click Refresh Gateways to query the registry[/]")
                except Exception:
                    pass
            except Exception:
                pass

        @work(thread=True)
        def _handle_registry_connect(self, identity_hash: str) -> None:
            try:
                resp = self._send("registry", {
                    "action": "connect",
                    "identity_hash": identity_hash,
                })
                if resp.get("ok"):
                    name = resp.get("name", identity_hash[:16])
                    self.notify(f"Connected to {name}", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_preset_apply(self) -> None:
            try:
                select = self.query_one("#preset-select", Select)
                name = select.value
                if not name:
                    self.notify("Select a preset first", severity="warning")
                    return
                resp = self._send("presets", {"action": "apply", "name": name})
                if resp.get("ok"):
                    self.notify(f"✓ Applied preset: {name}", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_preset_diff(self) -> None:
            try:
                select = self.query_one("#preset-select", Select)
                name = select.value
                if not name:
                    self.notify("Select a preset first", severity="warning")
                    return
                resp = self._send("presets", {"action": "diff", "name": name})
                if resp.get("ok"):
                    diff = resp.get("diff", {})
                    if diff:
                        # Format diff as notification
                        parts = []
                        for section, values in diff.items():
                            if isinstance(values, dict):
                                for k, v in values.items():
                                    if isinstance(v, dict):
                                        for kk, vv in v.items():
                                            parts.append(f"{section}.{k}.{kk}={vv}")
                                    else:
                                        parts.append(f"{section}.{k}={v}")
                        self.notify(f"Diff for {name}: {', '.join(parts[:5])}", severity="information")
                    else:
                        self.notify(f"No differences from defaults", severity="information")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_dryrun_toggle(self) -> None:
            try:
                resp = self._send("dry-run")
                current = resp.get("dry_run", False)
                new_mode = "off" if current else "on"
                resp = self._send("dry-run", {"mode": new_mode})
                if resp.get("ok"):
                    state_str = "ON" if resp.get("dry_run") else "OFF"
                    self.notify(f"✓ Dry-run: {state_str}", severity="information")
                    self.refresh_data()
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        @work(thread=True)
        def _handle_reload(self) -> None:
            try:
                resp = self._send("reload")
                if resp.get("ok"):
                    self.notify("✓ Config reloaded", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        # ── Filter Toggle / Param Apply ──────────────────────

        def on_switch_changed(self, event: Switch.Changed) -> None:
            """Handle filter toggle switches and config switches."""
            sw_id = event.switch.id or ""
            if sw_id.startswith("filter-") and sw_id.endswith("-switch"):
                fname = sw_id[len("filter-"):-len("-switch")]
                self._handle_filter_toggle(fname, event.value)
            elif sw_id == "cfg-auto-blackhole":
                self._handle_config_set("reputation", "auto_blackhole", event.value)
            elif sw_id == "cfg-adaptive":
                self._handle_config_set("adaptive", "enabled", event.value)

        @work(thread=True)
        def _handle_filter_toggle(self, fname: str, enabled: bool) -> None:
            resp = self._send("filters", {"action": "update", "name": fname, "enabled": enabled})
            if resp.get("ok"):
                state = "ON" if enabled else "OFF"
                self.notify(f"Filter {fname}: {state}", severity="information")
                self.refresh_data()
            else:
                self.notify(f"Error: {resp.get('error', '?')}", severity="error")

        @work(thread=True)
        def _handle_filter_param_apply(self, fname: str) -> None:
            from .filter_meta import FILTER_META
            meta = FILTER_META.get(fname)
            if not meta or not meta.params:
                return

            params = {}
            for pk, pinfo in meta.params.items():
                widget_id = f"fparam-{fname}-{pk}"
                try:
                    if pinfo.type == "number":
                        inp = self.query_one(f"#{widget_id}", Input)
                        val = inp.value.strip()
                        if val:
                            try:
                                params[pk] = float(val) if "." in val else int(val)
                            except ValueError:
                                self.notify(
                                    f"Invalid number for {pinfo.label}: '{val}'",
                                    severity="error",
                                )
                                return
                    elif pinfo.type == "select":
                        sel = self.query_one(f"#{widget_id}", Select)
                        if sel.value:
                            params[pk] = str(sel.value)
                    elif pinfo.type == "bool":
                        bsw = self.query_one(f"#{widget_id}", Switch)
                        params[pk] = bsw.value
                except Exception:
                    pass

            if params:
                resp = self._send("filters", {"action": "update", "name": fname, "params": params})
                if resp.get("ok"):
                    self.notify(f"Updated {fname} params", severity="information")
                    self.refresh_data()
                else:
                    self.notify(f"Error: {resp.get('error', '?')}", severity="error")

        @work(thread=True)
        def _handle_config_set(self, section: str, key: str, value) -> None:
            resp = self._send("config", {"action": "set", "section": section, "key": key, "value": value})
            if resp.get("ok"):
                self.notify(f"Set {section}.{key}", severity="information")
                self.refresh_data()
            else:
                self.notify(f"Error: {resp.get('error', '?')}", severity="error")

        # ── Event filter changes trigger re-render ────────────

        def on_select_changed(self, event: Select.Changed) -> None:
            if event.select.id in ("event-severity-filter", "event-type-filter"):
                self.refresh_data()
            elif event.select.id == "cfg-response-mode":
                val = event.value
                if val:
                    self._handle_config_set("correlator", "response_mode", str(val))

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id in ("event-search", "peer-filter"):
                self.refresh_data()

        # ── Keybindings ───────────────────────────────────────

        def action_refresh(self) -> None:
            self.refresh_data()

        def action_show_tab(self, tab_id: str) -> None:
            try:
                tabs = self.query_one(TabbedContent)
                tabs.active = tab_id
            except Exception:
                pass

        def action_toggle_dryrun(self) -> None:
            self._handle_dryrun_toggle()

        def action_show_help(self) -> None:
            self.push_screen(HelpScreen())

    # ── Build ──────────────────────────────────────────────────

    return RatholeTUI(
        sock_path=sock_path,
        refresh_interval=refresh_interval,
        log_handler=log_handler,
        command_handler=command_handler,
    )


# ── Public API ──────────────────────────────────────────────────

def create_app(sock_path: str, refresh_interval: float = 5.0,
               log_handler=None, command_handler=None):
    """Create a RatholeTUI app instance (called by cli.py for unified mode).

    When *command_handler* is provided, the TUI dispatches commands
    directly to the in-process daemon instead of going through the
    Unix socket — eliminating all socket-related errors.
    """
    return _build_tui(sock_path, refresh_interval, log_handler,
                      command_handler=command_handler)


def main():
    """Entry point for standalone ``rathole-tui`` command."""
    parser = argparse.ArgumentParser(
        prog="rathole-tui",
        description="Terminal UI for the Rathole security suite",
    )
    parser.add_argument(
        "-s", "--socket",
        default=DEFAULT_SOCKET,
        help=f"Control socket path (default: {DEFAULT_SOCKET})",
    )
    parser.add_argument(
        "--refresh", type=float, default=5.0,
        help="Refresh interval in seconds (default: 5.0)",
    )
    args = parser.parse_args()

    # Auto-discover socket path from config if not explicitly overridden
    args.socket = find_socket(args.socket)

    if not _check_textual():
        print("Error: textual not installed. Install with: pip install rathole[tui]", file=sys.stderr)
        sys.exit(1)

    app = _build_tui(sock_path=args.socket, refresh_interval=args.refresh)
    app.run()


if __name__ == "__main__":
    main()
