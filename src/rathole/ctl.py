"""
rat — power-user CLI for the Rathole security suite.

Full control client using Rich for beautiful terminal output.
Supports --json for machine-readable output.

Commands:
  run [-c FILE] [--headless]          Start daemon + TUI
  setup [-o PATH]                     Interactive setup wizard
  status                              Overview dashboard
  peers [--sort F] [--limit N]        Peer table with reputation
  interfaces                          Per-interface breakdown
  events [--limit N] [--type T]       Event log with severity coloring
         [--severity S]
  blackhole list|add|remove           Blackhole management
  reputation [HASH]                   Identity reputation
  reputation pin HASH SCORE           Pin identity to score
  reputation unpin HASH               Remove pin
  config show [SECTION]               Show config
  config set SECTION KEY VALUE        Live config override
  config preset list|apply|diff       Preset management
  filters [--pipeline P]              Filter status with params
  filters toggle NAME on|off          Enable/disable a filter
  filters set NAME KEY VALUE          Change a filter parameter
  dry-run [on|off]                    Toggle dry-run mode
  adaptive                            Adaptive threshold status
  correlator                          Correlation engine status
  alerts                              Alert rules status
  reload                              Hot-reload configuration
  shutdown                            Graceful daemon stop
"""

import sys
import json
import time
import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.prompt import Prompt, Confirm

from .rpc import (
    send_command, check_response, RpcError, DEFAULT_SOCKET, find_socket,
    is_daemon_running, shutdown_and_wait,
)

console = Console()
_json_mode = False


# ── Severity Colors ─────────────────────────────────────────────

SEVERITY_STYLES = {
    "INFO": "green",
    "NOTICE": "blue",
    "WARNING": "yellow",
    "ALERT": "red",
    "CRITICAL": "bold magenta",
}

CATEGORY_STYLES = {
    "TRUSTED": "bold green",
    "NEUTRAL": "yellow",
    "SUSPECT": "red",
    "UNKNOWN": "dim",
}


# ── Communication ───────────────────────────────────────────────

def _send(cmd: str, args: dict | None = None, sock: str = DEFAULT_SOCKET) -> dict:
    """Send command to the daemon via control socket."""
    return send_command(sock, cmd, args)


def _check(resp: dict) -> dict:
    """Check response and exit on error."""
    if not resp.get("ok"):
        console.print(f"[red]Error:[/] {resp.get('error', 'unknown')}")
        sys.exit(1)
    return resp


def _output_json(data):
    """Print JSON and exit."""
    print(json.dumps(data, indent=2, default=str))


# ── Command Handlers ────────────────────────────────────────────

def _health_bar(accept_pct: float, width: int = 20) -> str:
    """Render a colored health bar based on accept percentage."""
    filled = int(accept_pct / 100 * width)
    filled = max(0, min(width, filled))
    empty = width - filled

    if accept_pct >= 95:
        color = "green"
    elif accept_pct >= 80:
        color = "yellow"
    else:
        color = "red"

    bar = f"[{color}]{'█' * filled}[/][dim]{'░' * empty}[/]"
    return f"{bar} {accept_pct:.1f}% accept"


def cmd_status(args):
    resp = _check(_send("status", sock=args.socket))
    stats = resp.get("stats", {})
    peers = resp.get("peers", [])
    ifaces = resp.get("interfaces", [])

    if _json_mode:
        _output_json(resp)
        return 0

    uptime = stats.get("uptime", 0)
    h, m, s = int(uptime // 3600), int((uptime % 3600) // 60), int(uptime % 60)
    total = stats.get("total_accepted", 0) + stats.get("total_dropped", 0) + stats.get("total_throttled", 0)
    accept_pct = (stats.get("total_accepted", 0) / max(1, total)) * 100

    # Mode indicator
    dry_run = stats.get("dry_run", False)
    if dry_run:
        mode_str = "[cyan]DRY-RUN[/]"
    else:
        mode_str = "[green]ACTIVE[/]"

    # Health bar
    if dry_run:
        health_str = f"  Health:   [cyan]Observing[/] — {stats.get('total_dropped', 0)} would-be blocks so far"
    else:
        health_str = f"  Health:   {_health_bar(accept_pct)}"

    lines = [
        f"  Mode:     {mode_str}",
        health_str,
        "",
        f"  Uptime:        {h}h {m}m {s}s",
        f"  Packets:       {stats.get('total_packets', 0):,}",
        f"  Accepted:      [green]{stats.get('total_accepted', 0):,}[/] ({accept_pct:.1f}%)",
        f"  Dropped:       [red]{stats.get('total_dropped', 0):,}[/]",
        f"  Throttled:     [yellow]{stats.get('total_throttled', 0):,}[/]",
        f"  Blackholed:    [magenta]{stats.get('total_blackholed', 0):,}[/]",
        f"  Peers:         {stats.get('tracked_peers', 0)}",
        f"  Interfaces:    {stats.get('tracked_interfaces', 0)}",
        f"  Destinations:  {stats.get('tracked_destinations', 0)}",
    ]
    console.print(Panel("\n".join(lines), title="RATHOLE STATUS", border_style="cyan"))

    if peers:
        table = Table(title="Top Peers", show_lines=False, padding=(0, 1))
        table.add_column("Peer", style="cyan", no_wrap=True)
        table.add_column("Announces", justify="right")
        table.add_column("Traffic", justify="right")
        table.add_column("Ratio", justify="right")
        table.add_column("Category")
        for p in sorted(peers, key=lambda x: x.get("announces", 0), reverse=True)[:10]:
            cat = p.get("category", "UNKNOWN")
            table.add_row(
                p["peer"][:16] + "...",
                str(p.get("announces", 0)),
                str(p.get("real_traffic", 0)),
                str(p.get("ratio", 0)),
                cat,
            )
        console.print(table)

    if ifaces:
        table = Table(title="Interfaces", show_lines=False, padding=(0, 1))
        table.add_column("Interface", style="cyan")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Pending", justify="right")
        for i in ifaces:
            table.add_row(
                i["interface"],
                f"{i.get('packets', 0):,}",
                f"{i.get('bytes', 0):,}",
                str(i.get("pending_links", 0)),
            )
        console.print(table)

    return 0


def cmd_peers(args):
    resp = _check(_send("peers", sock=args.socket))
    peers = resp.get("peers", [])

    if _json_mode:
        _output_json(resp)
        return 0

    if not peers:
        console.print("  [dim]No peers tracked yet.[/]")
        return 0

    sort_key = getattr(args, "sort", "announces") or "announces"
    reverse = sort_key != "peer"
    peers_sorted = sorted(peers, key=lambda x: x.get(sort_key, 0), reverse=reverse)
    limit = getattr(args, "limit", 0) or 0
    if limit > 0:
        peers_sorted = peers_sorted[:limit]

    table = Table(title=f"Peers ({len(peers)} tracked)", show_lines=False, padding=(0, 1))
    table.add_column("Peer", style="cyan", no_wrap=True)
    table.add_column("Announces", justify="right")
    table.add_column("Traffic", justify="right")
    table.add_column("Ratio", justify="right")
    table.add_column("Reputation", justify="right")
    table.add_column("Category")

    for p in peers_sorted:
        cat = p.get("category", "UNKNOWN")
        cat_style = CATEGORY_STYLES.get(cat, "")
        pin = " [dim]PIN[/]" if p.get("pinned") else ""
        table.add_row(
            p["peer"][:16] + "...",
            str(p.get("announces", 0)),
            str(p.get("real_traffic", 0)),
            str(p.get("ratio", 0)),
            f"{p.get('reputation', 0.5):.3f}",
            f"[{cat_style}]{cat}[/]{pin}",
        )
    console.print(table)
    return 0


def cmd_interfaces(args):
    resp = _check(_send("interfaces", sock=args.socket))
    ifaces = resp.get("interfaces", [])

    if _json_mode:
        _output_json(resp)
        return 0

    if not ifaces:
        console.print("  [dim]No interfaces tracked yet.[/]")
        return 0

    table = Table(title="Interfaces", show_lines=False, padding=(0, 1))
    table.add_column("Interface", style="cyan")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Announces", justify="right")
    table.add_column("Links", justify="right")
    table.add_column("Pending", justify="right")
    table.add_column("Resources", justify="right")

    for i in ifaces:
        table.add_row(
            i["interface"],
            f"{i.get('packets', 0):,}",
            f"{i.get('bytes', 0):,}",
            str(i.get("announces", 0)),
            str(i.get("link_requests", 0)),
            str(i.get("pending_links", 0)),
            str(i.get("active_resources", 0)),
        )
    console.print(table)
    return 0


def cmd_events(args):
    send_args = {"limit": args.limit}
    resp = _check(_send("events", send_args, sock=args.socket))
    events = resp.get("events", [])
    stats = resp.get("stats", {})

    if _json_mode:
        _output_json(resp)
        return 0

    # Apply client-side filters
    if hasattr(args, "severity") and args.severity:
        events = [e for e in events if e.get("severity", "").upper() == args.severity.upper()]
    if hasattr(args, "type") and args.type:
        events = [e for e in events if e.get("event_type", "").upper() == args.type.upper()]

    console.print(
        f"  [bold]Events[/] (total: {stats.get('total_emitted', 0)}, "
        f"buffered: {stats.get('buffered', 0)})\n"
    )

    for e in events:
        sev = e.get("severity", "INFO")
        style = SEVERITY_STYLES.get(sev, "")
        ts = time.strftime("%H:%M:%S", time.localtime(e.get("timestamp", 0)))
        src = e.get("source", "?")
        desc = e.get("description", "")
        console.print(f"  [dim]{ts}[/] [{style}]{sev[:4]}[/] [dim]\\[{src}][/] {desc}")

    return 0


def cmd_blackhole(args):
    action = args.action

    if action == "list":
        resp = _check(_send("blackhole", {"action": "list"}, sock=args.socket))
        entries = resp.get("blackholed", [])

        if _json_mode:
            _output_json(resp)
            return 0

        if not entries:
            console.print("  [dim]No blackholed identities.[/]")
            return 0

        table = Table(title=f"Blackholed Identities ({len(entries)})", show_lines=False, padding=(0, 1))
        table.add_column("Identity", style="red", no_wrap=True)
        table.add_column("Source", style="dim")
        table.add_column("Reason")
        for e in entries:
            table.add_row(
                e.get("identity", "?")[:32] + "...",
                e.get("source", "?"),
                e.get("reason", ""),
            )
        console.print(table)

    elif action == "add":
        if not args.identity:
            console.print("[red]Error:[/] --identity required")
            return 1
        resp = _check(_send("blackhole", {
            "action": "add", "identity": args.identity, "reason": args.reason or "manual",
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        if resp.get("added"):
            console.print(f"  [green]Added[/] {args.identity[:16]}... to blackhole")
        else:
            console.print(f"  [dim]{args.identity[:16]}... already blackholed[/]")

    elif action == "remove":
        if not args.identity:
            console.print("[red]Error:[/] --identity required")
            return 1
        resp = _check(_send("blackhole", {
            "action": "remove", "identity": args.identity,
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        if resp.get("removed"):
            console.print(f"  [green]Removed[/] {args.identity[:16]}... from blackhole")
        else:
            console.print(f"  [dim]{args.identity[:16]}... not in blackhole[/]")

    return 0


def cmd_reputation(args):
    # Check for pin/unpin subcommands
    if hasattr(args, "rep_action") and args.rep_action == "pin":
        if not args.identity:
            console.print("[red]Error:[/] identity hash required")
            return 1
        score = float(args.score)
        resp = _check(_send("reputation", {
            "action": "pin", "identity": args.identity, "score": score,
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print(f"  [green]Pinned[/] {args.identity[:16]}... to score {score:.3f}")
        return 0

    if hasattr(args, "rep_action") and args.rep_action == "unpin":
        if not args.identity:
            console.print("[red]Error:[/] identity hash required")
            return 1
        resp = _check(_send("reputation", {
            "action": "unpin", "identity": args.identity,
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print(f"  [green]Unpinned[/] {args.identity[:16]}...")
        return 0

    # Default: show reputation (all or specific)
    identity = getattr(args, "identity", "") or ""
    resp = _check(_send("reputation", {"identity": identity}, sock=args.socket))

    if _json_mode:
        _output_json(resp)
        return 0

    if identity:
        cat = resp.get("category", "UNKNOWN")
        score = resp.get("score", 0)
        cat_style = CATEGORY_STYLES.get(cat, "")
        pinned = "[dim] (PINNED)[/]" if resp.get("pinned") else ""

        lines = [
            f"  Score:     [bold]{score:.3f}[/]{pinned}",
            f"  Category:  [{cat_style}]{cat}[/]",
            f"  Accepts:   {resp.get('accepts', 0)}",
            f"  Drops:     {resp.get('drops', 0)}",
        ]
        console.print(Panel("\n".join(lines), title=f"Reputation: {identity[:32]}...", border_style="cyan"))
    else:
        identities = resp.get("identities", [])
        if not identities:
            console.print("  [dim]No identities tracked yet.[/]")
            return 0

        table = Table(title="Identity Reputation", show_lines=False, padding=(0, 1))
        table.add_column("Identity", style="cyan", no_wrap=True)
        table.add_column("Score", justify="right")
        table.add_column("Category")
        table.add_column("Accepts", justify="right")
        table.add_column("Drops", justify="right")
        table.add_column("Pinned")

        for i in identities:
            cat = i.get("category", "UNKNOWN")
            cat_style = CATEGORY_STYLES.get(cat, "")
            table.add_row(
                i["identity"][:16] + "...",
                f"{i.get('score', 0):.3f}",
                f"[{cat_style}]{cat}[/]",
                str(i.get("accepts", 0)),
                str(i.get("drops", 0)),
                "[dim]yes[/]" if i.get("pinned") else "",
            )
        console.print(table)

    return 0


def cmd_config(args):
    action = args.action

    if action == "show":
        resp = _check(_send("config", {"action": "show"}, sock=args.socket))
        config = resp.get("config", {})

        if _json_mode:
            _output_json(resp)
            return 0

        section = getattr(args, "section", "") or ""
        if section:
            if section in config:
                _print_config_tree(section, config[section])
            elif section in config.get("filters", {}):
                _print_config_tree(f"filters.{section}", config["filters"][section])
            else:
                console.print(f"  [red]Unknown section:[/] {section}")
                return 1
        else:
            for key, value in config.items():
                _print_config_tree(key, value)

    elif action == "set":
        if not args.section or not args.key or args.value is None:
            console.print("[red]Error:[/] SECTION KEY VALUE required")
            return 1
        try:
            val = json.loads(args.value)
        except json.JSONDecodeError:
            val = args.value
        resp = _check(_send("config", {
            "action": "set", "section": args.section, "key": args.key, "value": val,
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print(f"  [green]Set[/] {args.section}.{args.key} = {val}")

    elif action == "preset":
        return cmd_config_preset(args)

    return 0


def cmd_config_preset(args):
    """Handle config preset subcommands."""
    preset_action = getattr(args, "preset_action", "list") or "list"

    if preset_action == "list":
        resp = _check(_send("presets", {"action": "list"}, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        presets = resp.get("presets", [])
        table = Table(title="Available Presets", show_lines=True, padding=(0, 1))
        table.add_column("Name", style="bold cyan")
        table.add_column("Description")
        for p in presets:
            table.add_row(p["name"], p.get("description", ""))
        console.print(table)

    elif preset_action == "apply":
        name = getattr(args, "preset_name", "") or ""
        if not name:
            console.print("[red]Error:[/] preset name required")
            return 1
        resp = _check(_send("presets", {"action": "apply", "name": name}, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print(f"  [green]Applied preset:[/] [bold]{name}[/]")

    elif preset_action == "diff":
        name = getattr(args, "preset_name", "") or ""
        if not name:
            console.print("[red]Error:[/] preset name required")
            return 1
        resp = _check(_send("presets", {"action": "diff", "name": name}, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        diff = resp.get("diff", {})
        if diff:
            console.print(f"  [bold]Preset diff: {name}[/]\n")
            _print_config_tree(f"  {name}", diff)
        else:
            console.print(f"  [dim]No differences from defaults.[/]")

    return 0


def cmd_filters(args):
    # Check for toggle/set subcommands
    filter_action = getattr(args, "filter_action", "") or ""

    if filter_action == "toggle":
        name = getattr(args, "filter_name", "")
        mode = getattr(args, "mode", "")
        if not name or not mode:
            console.print("[red]Error:[/] filter NAME on|off required")
            return 1
        enabled = mode == "on"
        resp = _check(_send("filters", {
            "action": "update", "name": name, "enabled": enabled,
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        state_str = "[green]enabled[/]" if enabled else "[red]disabled[/]"
        console.print(f"  Filter [bold]{name}[/]: {state_str}")
        return 0

    if filter_action == "set":
        name = getattr(args, "filter_name", "")
        key = getattr(args, "param_key", "")
        value = getattr(args, "param_value", "")
        if not name or not key or value == "":
            console.print("[red]Error:[/] filter NAME KEY VALUE required")
            return 1
        try:
            val = json.loads(value)
        except json.JSONDecodeError:
            val = value
        resp = _check(_send("filters", {
            "action": "update", "name": name, "params": {key: val},
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print(f"  [green]Set[/] {name}.{key} = {val}")
        return 0

    # Default: list all filters
    resp = _check(_send("filters", {"action": "list"}, sock=args.socket))
    if _json_mode:
        _output_json(resp)
        return 0

    pipelines = resp.get("pipelines", {})
    pipeline_filter = getattr(args, "pipeline", "") or ""

    from .filter_meta import PIPELINE_ORDER, PIPELINE_LABELS, FILTER_META

    for pkey in PIPELINE_ORDER:
        if pipeline_filter and pkey != pipeline_filter:
            continue
        plabel = PIPELINE_LABELS.get(pkey, pkey.title())
        filters = pipelines.get(pkey, [])
        if not filters:
            continue

        table = Table(
            title=f"Pipeline: {plabel}",
            show_lines=False,
            padding=(0, 1),
            title_style="bold",
        )
        table.add_column("", width=1)
        table.add_column("Filter", style="bold")
        table.add_column("Parameters", no_wrap=False)

        for f in filters:
            fname = f["name"]
            enabled = f.get("enabled", False)
            config = f.get("config", {})
            meta = FILTER_META.get(fname)

            dot = "[green]●[/]" if enabled else "[dim]○[/]"
            label = meta.label if meta else fname
            desc = f"[dim]{meta.description}[/]" if meta else ""

            # Format parameters
            params_parts = []
            if meta and meta.params:
                for pk, pinfo in meta.params.items():
                    if pk in config:
                        params_parts.append(f"{pinfo.label}={config[pk]}")
            if not enabled:
                params_str = "[dim](disabled)[/]"
            elif params_parts:
                params_str = "  ".join(params_parts)
            else:
                params_str = ""

            table.add_row(dot, f"{label}\n{desc}" if desc else label, params_str)

        console.print(table)
        console.print()

    return 0


def cmd_dryrun(args):
    mode = getattr(args, "mode", "") or ""
    resp = _check(_send("dry-run", {"mode": mode}, sock=args.socket))

    if _json_mode:
        _output_json(resp)
        return 0

    dr = resp.get("dry_run")
    status = "[yellow]ON[/]" if dr else "[green]off[/]"
    console.print(f"  Dry-run: {status}")
    return 0


def cmd_adaptive(args):
    resp = _check(_send("adaptive", sock=args.socket))

    if _json_mode:
        _output_json(resp)
        return 0

    data = resp.get("adaptive", {})
    status = "[green]ENABLED[/]" if data.get("enabled") else "[dim]disabled[/]"
    learning = "learning" if data.get("learning") else "active"
    progress = data.get("learning_progress", 0)
    console.print(f"\n  [bold]Adaptive Thresholds[/] [{status}] ({learning}, {progress:.0%})")

    for iface, metrics in data.get("interfaces", {}).items():
        console.print(f"    [cyan]{iface}:[/]")
        for name, bl in metrics.items():
            console.print(
                f"      {name}: mean={bl['mean']:.1f} stddev={bl['stddev']:.1f} "
                f"alert={bl['alert_at']:.1f} block={bl['block_at']:.1f} ({bl['samples']} samples)"
            )
    return 0


def cmd_correlator(args):
    resp = _check(_send("correlator", sock=args.socket))

    if _json_mode:
        _output_json(resp)
        return 0

    data = resp.get("correlator", {})
    status = "[green]ENABLED[/]" if data.get("enabled") else "[dim]disabled[/]"
    console.print(f"\n  [bold]Attack Correlator[/] [{status}]")
    console.print(f"  Total alerts: {data.get('total_alerts', 0)}, Recent: {data.get('recent_alerts', 0)}")
    for a in data.get("alerts", []):
        sev = a.get("severity", "").upper()
        style = SEVERITY_STYLES.get(sev, "")
        console.print(
            f"    [{style}]{a.get('severity', '?')}[/] "
            f"\\[{a.get('pattern', '?')}] {a.get('interface', '?')}: {a.get('description', '')}"
        )
    return 0


def cmd_alerts(args):
    resp = _check(_send("alerts", sock=args.socket))

    if _json_mode:
        _output_json(resp)
        return 0

    data = resp.get("alerts", {})
    status = "[green]ENABLED[/]" if data.get("enabled") else "[dim]disabled[/]"
    console.print(f"\n  [bold]Alert Rules[/] [{status}]")
    for r in data.get("rules", []):
        console.print(
            f"    {r['name']}: action={r['action']} triggers={r['trigger_count']} "
            f"cooldown={r['cooldown']}s min_severity={r['min_severity']}"
        )
    recent = data.get("recent_firings", [])
    if recent:
        console.print(f"\n  Recent Firings:")
        for f in recent:
            esc = " [red]\\[ESCALATED][/]" if f.get("escalated") else ""
            console.print(f"    {f['rule']}{esc}")
    return 0


def cmd_registry(args):
    """Gateway registry management."""
    action = getattr(args, "reg_action", "") or "status"

    if action == "status":
        resp = _check(_send("registry", {"action": "status"}, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0

        data = resp.get("registry", {})
        status_parts = []
        if data.get("publish"):
            status_parts.append("[green]Publish[/]")
        if data.get("discover"):
            status_parts.append("[cyan]Discover[/]")
        if data.get("auto_connect"):
            status_parts.append("[yellow]Auto-connect[/]")
        status_str = " | ".join(status_parts) if status_parts else "[dim]disabled[/]"

        console.print(f"\n  [bold]Gateway Registry[/] [{status_str}]")

        if data.get("b32"):
            console.print(f"  B32: [bold]{data['b32']}[/]")
        if data.get("published"):
            console.print(f"  Published: [green]yes[/]")
        hb_age = data.get("last_heartbeat_age")
        if hb_age is not None:
            console.print(f"  Last heartbeat: {int(hb_age)}s ago")
        console.print(f"  Discovered: {data.get('discovered_count', 0)} gateways")
        console.print(f"  Auto-connected: {data.get('connected_count', 0)}")
        console.print(f"  URL: {data.get('url', '?')}")
        return 0

    elif action == "discover":
        resp = _check(_send("registry", {"action": "discover"}, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0

        gateways = resp.get("gateways", [])
        if not gateways:
            console.print("  [dim]No gateways found[/]")
            return 0

        table = Table(title=f"Discovered Gateways ({len(gateways)})")
        table.add_column("Name", style="bold")
        table.add_column("B32")
        table.add_column("Caps")
        table.add_column("Mode")
        table.add_column("Verified")
        table.add_column("Identity")

        for gw in gateways:
            b32 = gw.get("b32", "")
            b32_short = f"{b32[:12]}...{b32[-8:]}" if len(b32) > 24 else b32
            verified = "[green]✓[/]" if gw.get("verified") else "[dim]✗[/]"
            caps = ", ".join(gw.get("capabilities", [])) or "[dim]-[/]"
            table.add_row(
                gw.get("node_name", "") or "[dim]unnamed[/]",
                b32_short,
                caps,
                gw.get("node_mode", ""),
                verified,
                gw.get("identity_hash", "")[:16],
            )
        console.print(table)
        return 0

    elif action == "connect":
        identity_hash = getattr(args, "reg_identity", "")
        if not identity_hash:
            console.print("[red]Error:[/] identity hash required")
            return 1

        # Support partial hash match (8+ chars) against discovered list
        if len(identity_hash) < 64:
            if len(identity_hash) < 8:
                console.print("[red]Error:[/] partial hash must be at least 8 characters")
                return 1
            # Fetch discovered list and resolve partial match
            list_resp = _check(_send("registry", {"action": "list"}, sock=args.socket))
            gateways = list_resp.get("gateways", [])
            matches = [
                gw for gw in gateways
                if gw.get("identity_hash", "").startswith(identity_hash)
            ]
            if len(matches) == 0:
                console.print(f"[red]Error:[/] no gateway matches '{identity_hash}'")
                return 1
            if len(matches) > 1:
                console.print(f"[red]Error:[/] '{identity_hash}' is ambiguous ({len(matches)} matches)")
                return 1
            identity_hash = matches[0]["identity_hash"]

        resp = _check(_send("registry", {
            "action": "connect",
            "identity_hash": identity_hash,
        }, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print(f"  [green]Connected to {identity_hash[:16]}[/]")
        return 0

    elif action == "register":
        resp = _check(_send("registry", {"action": "register"}, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print("  [green]Registered[/]")
        return 0

    elif action == "deregister":
        resp = _check(_send("registry", {"action": "deregister"}, sock=args.socket))
        if _json_mode:
            _output_json(resp)
            return 0
        console.print("  [green]Deregistered[/]")
        return 0

    return 0


def cmd_reload(args):
    resp = _check(_send("reload", sock=args.socket))
    if _json_mode:
        _output_json(resp)
        return 0
    console.print(f"  [green]Config reloaded[/]")
    return 0


def cmd_shutdown(args):
    resp = _check(_send("shutdown", sock=args.socket))
    if _json_mode:
        _output_json(resp)
        return 0
    console.print(f"  [yellow]Shutdown signal sent — waiting for daemon to exit…[/]")

    # Wait for the daemon to actually stop
    stopped = not is_daemon_running(args.socket)
    if not stopped:
        import time
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            time.sleep(0.3)
            if not is_daemon_running(args.socket):
                stopped = True
                break

    if stopped:
        console.print(f"  [green]✓[/] Daemon stopped")
    else:
        console.print(f"  [red]✗[/] Daemon may still be running")
    return 0


# ── Run ──────────────────────────────────────────────────────

def cmd_run(args):
    """Start the Rathole daemon (+ TUI unless --headless).

    Equivalent to: rathole -c rathole.toml [--headless] [--dry-run] [-v]
    """
    config_path = Path(args.config)
    if not config_path.exists():
        console.print(
            f"[red]Error:[/] Config file not found: {args.config}\n\n"
            f"Run [bold]rat setup[/] to create one first."
        )
        return 1

    # Build argv as if 'rathole' was called directly, then invoke cli.main()
    argv = ["rathole", "-c", str(config_path)]
    if getattr(args, "headless", False):
        argv.append("--headless")
    if getattr(args, "dry_run", False):
        argv.append("--dry-run")
    if getattr(args, "verbose", False):
        argv.append("-v")

    sys.argv = argv
    from .cli import main as cli_main
    try:
        cli_main()
    except SystemExit as e:
        return e.code or 0
    except KeyboardInterrupt:
        pass
    return 0


# ── Reset ─────────────────────────────────────────────────────

def cmd_reset(args):
    """Wipe all Rathole data for a clean slate.

    Removes state, events DB, config, control socket, and optionally
    the Reticulum identity (the full ~/.reticulum/ directory).
    """

    console.print(Panel(
        "  [bold red]RATHOLE RESET[/]\n"
        "  Wipe all data for a fresh start",
        border_style="red",
    ))
    console.print()

    # ── Stop running daemon first ─────────────────────────────
    # Try the CLI-supplied socket, then auto-resolve from config
    sock = getattr(args, "socket", None) or find_socket()
    if is_daemon_running(sock):
        console.print("  [yellow]⚠[/]  Rathole daemon is running — shutting it down first…")
        stopped = shutdown_and_wait(sock, timeout=10.0)
        if stopped:
            console.print("  [green]✓[/] Daemon stopped")
        else:
            console.print("  [red]✗[/] Daemon may still be running — proceed with caution")
        console.print()

    # ── Resolve paths ────────────────────────────────────────

    # Rathole data dir
    rathole_dir = Path("~/.rathole").expanduser()

    # Config file — explicit flag or default
    config_path = Path(getattr(args, "config", "") or "rathole.toml")

    # Parse config once for all path resolution
    cfg = {}
    if config_path.exists():
        try:
            import tomllib
            with open(config_path, "rb") as f:
                cfg = tomllib.load(f)
        except Exception as e:
            console.print(f"  [yellow]⚠[/]  Could not parse {config_path}: {e}")
            console.print("  [dim]Using default paths.[/]")

    # Control socket — resolve from config if possible
    sock_path_str = DEFAULT_SOCKET
    cfg_sock = cfg.get("general", {}).get("control_socket", "")
    if cfg_sock:
        sock_path_str = cfg_sock

    # Also resolve data dir from state_file path
    sf = cfg.get("general", {}).get("state_file", "")
    if sf:
        resolved = Path(sf).expanduser()
        if resolved.parent != rathole_dir:
            rathole_dir = resolved.parent

    # Reticulum config dir
    rns_dir = Path("~/.reticulum").expanduser()
    rns_path = cfg.get("general", {}).get("reticulum_config_path", "")
    if rns_path:
        rns_dir = Path(rns_path).expanduser()

    # ── Show what will be deleted ────────────────────────────

    targets = []

    # 1. Data directory (~/.rathole/)
    if rathole_dir.exists():
        contents = list(rathole_dir.iterdir())
        size = 0
        for f in contents:
            try:
                if f.is_file():
                    size += f.stat().st_size
            except OSError:
                pass
        file_list = ", ".join(f.name for f in contents)
        targets.append(("data", rathole_dir, f"{file_list} ({_human_size(size)})"))
        console.print(f"  [red]✗[/] Data directory:  [bold]{rathole_dir}[/]")
        for f in contents:
            try:
                console.print(f"      {f.name}  [dim]({_human_size(f.stat().st_size)})[/]")
            except OSError:
                console.print(f"      {f.name}  [dim](unknown size)[/]")
    else:
        console.print(f"  [dim]·[/] Data directory:  {rathole_dir} [dim](not found)[/]")

    # 2. Config file
    if config_path.exists():
        size = config_path.stat().st_size
        targets.append(("config", config_path, f"{_human_size(size)}"))
        console.print(f"  [red]✗[/] Config file:     [bold]{config_path}[/]  [dim]({_human_size(size)})[/]")
    else:
        console.print(f"  [dim]·[/] Config file:     {config_path} [dim](not found)[/]")

    # 3. Control socket
    from .rpc import _is_tcp_address
    sock_is_file = not _is_tcp_address(sock_path_str)
    sock_file_exists = sock_is_file and Path(sock_path_str).exists()
    if sock_file_exists:
        targets.append(("socket", Path(sock_path_str), "stale socket"))
        console.print(f"  [red]✗[/] Control socket:  [bold]{sock_path_str}[/]")
    else:
        console.print(f"  [dim]·[/] Control socket:  {sock_path_str} [dim](not found)[/]")

    console.print()

    # 4. Reticulum directory (optional, ask separately)
    rns_exists = rns_dir.exists()
    if rns_exists:
        console.print(f"  [yellow]?[/] Reticulum dir:   [bold]{rns_dir}[/]")
        console.print(f"      [dim]Contains your node identity, keys, and RNS config.[/]")
        console.print(f"      [dim]Deleting this gives you a completely new identity.[/]")
    else:
        console.print(f"  [dim]·[/] Reticulum dir:   {rns_dir} [dim](not found)[/]")

    # 5. I2P (detect before any deletions happen)
    #    B32 destination keys live in <rns_dir>/storage/i2p/ (deleted with Reticulum).
    #    i2pd router data (router identity, netDb, peer profiles) is separate.
    from .i2p import detect_i2p_in_rns_config, find_i2pd_data_dir, find_rns_i2p_keydir, probe_sam_api

    rns_config_file = rns_dir / "config"
    has_i2p_config = detect_i2p_in_rns_config(rns_config_file)
    i2pd_dir = find_i2pd_data_dir()
    rns_i2p_keydir = find_rns_i2p_keydir(
        str(rns_dir) if rns_dir != Path.home() / ".reticulum" else None
    )
    i2p_detected = has_i2p_config or i2pd_dir is not None or rns_i2p_keydir is not None

    if i2p_detected:
        if rns_i2p_keydir:
            console.print(f"  [yellow]?[/] I2P B32 keys:     [bold]{rns_i2p_keydir}[/]")
            console.print(f"      [dim]Your B32 address — lives inside the Reticulum directory.[/]")
        if i2pd_dir:
            console.print(f"  [yellow]?[/] i2pd router data: [bold]{i2pd_dir}[/]")
            console.print(f"      [dim]I2P router identity, peer profiles, network database.[/]")
        if has_i2p_config and not rns_i2p_keydir and not i2pd_dir:
            console.print(f"  [dim]·[/] I2P:              [dim]Configured in RNS but no local data found[/]")

    console.print()

    if not targets and not rns_exists and not i2p_detected:
        console.print("  [green]Nothing to reset — already clean.[/]")
        return 0

    # ── Confirm ──────────────────────────────────────────────

    if not targets and rns_exists:
        console.print("  [dim]No Rathole data to remove.[/]")
        console.print()

    if targets:
        if not Confirm.ask("  [bold red]Delete all Rathole data?[/]", default=False):
            console.print("  [dim]Aborted.[/]")
            return 0

    # Delete Rathole data
    import shutil
    deleted = []
    for kind, path, desc in targets:
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            deleted.append((kind, path))
            console.print(f"  [green]✓[/] Removed {path}")
        except OSError as e:
            console.print(f"  [red]✗[/] Failed to remove {path}: {e}")

    # Ask about Reticulum separately (it's a bigger deal)
    if rns_exists:
        console.print()
        b32_warning = ""
        if rns_i2p_keydir:
            b32_warning = (
                "\n  [bold red]This includes your I2P B32 destination keys —"
                " your B32 address will be gone forever if not backed up.[/]"
            )
        if Confirm.ask(
            "  [bold yellow]Also delete Reticulum identity & config?[/]\n"
            f"  [dim]This will generate a new node identity on next start.[/]{b32_warning}",
            default=False,
        ):
            try:
                shutil.rmtree(rns_dir)
                deleted.append(("reticulum", rns_dir))
                console.print(f"  [green]✓[/] Removed {rns_dir}")
            except OSError as e:
                console.print(f"  [red]✗[/] Failed to remove {rns_dir}: {e}")

    # Ask about i2pd router data (separate from B32 keys)
    if i2pd_dir and i2pd_dir.exists():
        console.print()
        if Confirm.ask(
            "  [bold yellow]Also reset i2pd router data?[/]\n"
            "  [dim]Resets I2P router identity, peer profiles, and network database.\n"
            "  i2pd will rebuild its network presence on next start (may take a few minutes).[/]",
            default=False,
        ):
            try:
                shutil.rmtree(i2pd_dir)
                deleted.append(("i2p", i2pd_dir))
                console.print(f"  [green]✓[/] Removed {i2pd_dir}")
            except OSError as e:
                console.print(f"  [red]✗[/] Failed to remove {i2pd_dir}: {e}")

    # ── Stop i2pd if we deleted I2P-related data ────────────
    # Stale SAM sessions reference deleted keys and prevent new
    # tunnels from establishing. Stop i2pd now; setup will start
    # it fresh when the user re-enables I2P.
    deleted_kinds = {k for k, _ in deleted}
    i2p_data_deleted = ("reticulum" in deleted_kinds or "i2p" in deleted_kinds)
    if i2p_data_deleted and i2p_detected and probe_sam_api():
        console.print()
        from .i2p import stop_i2pd_service
        if stop_i2pd_service(console):
            console.print("  [green]✓[/] i2pd stopped (will start fresh during setup)")
        else:
            console.print("  [yellow]⚠[/]  Could not stop i2pd — stop it manually before running setup")

    # ── Summary ──────────────────────────────────────────────

    console.print()
    if deleted:
        kinds = [k for k, _ in deleted]
        console.print("[bold]── Reset Complete ──[/]\n")
        if "reticulum" in kinds and "i2p" in kinds:
            console.print("  All data wiped including Reticulum identity and i2pd router.")
            console.print("  New identities will be generated on next start.")
        elif "reticulum" in kinds:
            console.print("  All data wiped including Reticulum identity (and I2P B32 keys).")
            console.print("  A new identity will be generated on next start.")
        elif "i2p" in kinds:
            console.print("  Rathole data wiped. i2pd router data reset.")
            console.print("  i2pd will rebuild its network presence on next start.")
        else:
            console.print("  All Rathole data wiped. Reticulum identity preserved.")
        console.print()
        console.print("  [bold]Next step — set up your node:[/]")
        console.print("    [cyan]rat setup[/]")
        console.print()
        console.print("  [yellow]Do NOT start rathole before running setup.[/]")
    else:
        console.print("  [dim]Nothing was deleted.[/]")

    return 0


def _human_size(nbytes: int) -> str:
    """Format a byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(nbytes) < 1024:
            if unit == "B":
                return f"{nbytes} {unit}"
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"


# ── Setup Wizard ───────────────────────────────────────────────

def cmd_setup(args):
    """Interactive setup wizard — configures both Reticulum and Rathole."""

    console.print(Panel(
        "  [bold]RATHOLE SETUP[/]\n"
        "  Transport node security for Reticulum",
        border_style="cyan",
    ))
    console.print()

    # ─── Step 1: Node Mode ───────────────────────────────────────
    console.print("[bold]── Step 1: Node Mode ──[/]\n")

    console.print(Panel(
        "  [bold]1. Gateway[/] — Public transport hub\n"
        "     You're hosting a transport node on a server/VPS\n"
        "     that others connect TO. You have a public IP or\n"
        "     port-forwarded address. Hundreds of peers may\n"
        "     connect. Strong defenses and monitoring enabled.\n"
        "\n"
        "  [bold]2. Client[/]  — Contributing transport node\n"
        "     You're joining existing networks to help relay\n"
        "     traffic. You connect TO gateways and local peers.\n"
        "     Lower traffic volume, simpler security needs.",
        border_style="dim",
    ))

    mode_choice = Prompt.ask(
        "  What type of node are you running?",
        choices=["1", "2"],
        default="2",
    )
    node_mode = "gateway" if mode_choice == "1" else "client"
    mode_label = "Gateway" if node_mode == "gateway" else "Client"
    console.print(f"  [green]✓[/] Mode: [bold]{mode_label}[/]")
    console.print()

    # ─── Step 2: Reticulum config ────────────────────────────────
    console.print("[bold]── Step 2: Reticulum ──[/]\n")

    default_rns_dir = str(Path.home() / ".reticulum")
    rns_dir = Prompt.ask(
        "  Reticulum config directory",
        default=default_rns_dir,
    )
    rns_dir = Path(rns_dir).expanduser()
    rns_config_file = rns_dir / "config"

    # Check if RNS config exists
    if rns_config_file.exists():
        console.print(f"  [green]✓[/] Config found at {rns_config_file}")

        # Check transport status
        transport_enabled = _check_rns_transport(rns_config_file)
        if transport_enabled:
            console.print("  Transport mode: [green]✓ Enabled[/]")
        else:
            console.print("  Transport mode: [red]✗ Disabled[/]")
            if Confirm.ask("\n  Enable transport mode? (required for Rathole)", default=True):
                _set_rns_transport(rns_config_file, True)
                console.print("  [green]✓[/] Transport enabled in Reticulum config")
            else:
                console.print("  [yellow]⚠[/]  Rathole will auto-enable transport on startup")
    else:
        console.print(f"  [dim]No config found at {rns_config_file}[/]")
        console.print("  [dim]Creating config with transport enabled.[/]")
        _ensure_rns_config(rns_config_file)
        console.print(f"  [green]✓[/] Config created at {rns_config_file}")

    console.print()

    # ─── Step 3: Network Interfaces ──────────────────────────────
    console.print("[bold]── Step 3: Network Interfaces ──[/]\n")

    # Show existing interfaces if config exists
    existing_ifaces = []
    if rns_config_file.exists():
        existing_ifaces = _list_rns_interfaces(rns_config_file)
        if existing_ifaces:
            console.print("  Current interfaces in your RNS config:")
            for i, name in enumerate(existing_ifaces, 1):
                console.print(f"    {i}. {name}")
        else:
            console.print("  [dim]No interfaces configured yet.[/]")
    console.print()

    # macOS: Auto-configure ignored_devices for utun tunnel interfaces
    if rns_config_file.exists():
        _fix_darwin_autointerface(rns_config_file, console)

    # Mode-aware interface prompts
    if node_mode == "gateway":
        # Gateway: Lead with TCP Server
        console.print("  [dim]As a gateway, you'll want a TCP Server so others can connect.[/]")
        console.print()
        _setup_add_interfaces(rns_config_file, console, lead_with="server")
    else:
        # Client: Lead with TCP Client, suggest known gateway
        console.print("  [dim]As a client, connect to a gateway to join the network.[/]")
        console.print()
        _setup_add_interfaces(rns_config_file, console, lead_with="client")

    console.print()

    # I2P support (optional)
    i2p_enabled = _setup_i2p(rns_config_file, console, node_mode)

    console.print()

    # Gateway Registry (requires I2P)
    registry_enabled = False
    registry_publish = False
    registry_auto_connect = False
    registry_node_name = ""
    if i2p_enabled:
        registry_enabled, registry_publish, registry_auto_connect, registry_node_name = (
            _setup_registry(console, node_mode)
        )
        console.print()

    # ─── Step 4: Security Preset ─────────────────────────────────
    console.print("[bold]── Step 4: Security Preset ──[/]\n")

    from .presets import list_presets, MODE_PRESETS

    mode_presets = list_presets(node_mode)

    # Build display panel and choice map
    preset_lines = []
    preset_map = {}
    recommended = "balanced" if node_mode == "gateway" else "standard"
    default_choice = "1"

    for i, preset in enumerate(mode_presets, 1):
        name = preset["name"]
        desc = preset["description"]
        rec = " [dim](recommended)[/]" if name == recommended else ""
        preset_lines.append(f"  [bold]{i}. {name}[/]{rec}\n     {desc}")
        preset_map[str(i)] = name
        if name == recommended:
            default_choice = str(i)

    console.print(Panel("\n\n".join(preset_lines), border_style="dim"))

    preset_choice = Prompt.ask(
        "  Choose a preset",
        choices=list(preset_map.keys()),
        default=default_choice,
    )
    preset_name = preset_map[preset_choice]
    console.print(f"  [green]✓[/] Selected: [bold]{preset_name}[/]")
    console.print()

    # ─── Step 5: Options ─────────────────────────────────────────
    console.print("[bold]── Step 5: Options ──[/]\n")

    is_observe = preset_name in ("observe", "relaxed")

    enable_adaptive = Confirm.ask(
        "  Enable adaptive learning?\n"
        "  [dim]Watches your network to learn normal patterns,[/]\n"
        "  [dim]then auto-sets thresholds based on your actual traffic.[/]",
        default=not is_observe,
    )

    dry_run = Confirm.ask(
        "\n  Start in dry-run mode?\n"
        "  [dim]Logs everything but blocks nothing. Good for the first run.[/]",
        default=is_observe,
    )

    if node_mode == "gateway":
        enable_metrics = Confirm.ask(
            "\n  Enable Prometheus metrics endpoint?\n"
            "  [dim]Exposes metrics at http://127.0.0.1:9777/metrics[/]",
            default=True,
        )
        enable_eventstore = Confirm.ask(
            "\n  Enable persistent event history?\n"
            "  [dim]Stores security events in SQLite for later analysis.[/]",
            default=True,
        )
    else:
        enable_metrics = False
        enable_eventstore = False

    default_sock = DEFAULT_SOCKET
    sock_path = Prompt.ask(
        "\n  Control socket address",
        default=default_sock,
    )

    console.print()

    # ─── Generate config ─────────────────────────────────────────
    from .presets import apply_preset

    config = apply_preset(preset_name)

    # Apply user choices (override preset defaults)
    config["general"]["node_mode"] = node_mode
    config["general"]["dry_run"] = dry_run
    config["general"]["control_socket"] = sock_path
    config["general"]["reticulum_config_path"] = str(rns_dir) if str(rns_dir) != default_rns_dir else ""
    config["adaptive"]["enabled"] = enable_adaptive
    config["metrics"]["enabled"] = enable_metrics
    config["eventstore"]["enabled"] = enable_eventstore
    if registry_enabled:
        config["registry"]["enabled"] = True
        config["registry"]["publish"] = registry_publish
        config["registry"]["auto_connect"] = registry_auto_connect
        if registry_node_name:
            config["registry"]["node_name"] = registry_node_name

    # Determine output path
    output_path = getattr(args, "output", "") or "rathole.toml"
    output_path = Path(output_path)

    # Guard against overwriting existing config
    if output_path.exists() and not getattr(args, "force", False):
        if not Confirm.ask(
            f"  Config file [bold]{output_path}[/] exists. Overwrite?",
            default=False,
        ):
            console.print("  [dim]Aborted — existing config preserved.[/]")
            return 0

    # Write TOML
    _write_toml(config, output_path, preset_name)

    # ─── Done ────────────────────────────────────────────────────
    console.print("[bold]── Done! ──[/]\n")
    console.print(f"  [green]✓[/] Node mode:   [bold]{mode_label}[/]")
    console.print(f"  [green]✓[/] Preset:      [bold]{preset_name}[/]")
    console.print(f"  [green]✓[/] Config:      [bold]{output_path}[/]")
    if rns_config_file.exists():
        console.print(f"  [green]✓[/] Reticulum:   [bold]{rns_config_file}[/]")
    console.print()

    # Offer to auto-start (replaces this process with the unified daemon+TUI)
    if Confirm.ask("  Start Rathole now?", default=True):
        import os

        # If a daemon is already running, shut it down gracefully first
        # (e.g. user ran "rat setup" without explicitly stopping first)
        resolved_sock = sock_path or DEFAULT_SOCKET
        if is_daemon_running(resolved_sock):
            console.print()
            console.print("  [yellow]⚠[/]  Existing daemon running — shutting it down…")
            stopped = shutdown_and_wait(resolved_sock, timeout=10.0)
            if stopped:
                console.print("  [green]✓[/] Previous daemon stopped")
            else:
                console.print("  [red]✗[/] Previous daemon may still be running — continuing anyway")

        console.print()
        console.print("  [green]Launching Rathole…[/]")
        console.print()
        try:
            launch_args = [sys.executable, "-m", "rathole.cli", "-c", str(output_path)]
            if sys.platform == "win32":
                # os.execvp doesn't replace the process on Windows —
                # use subprocess and exit cleanly instead
                import subprocess
                subprocess.Popen(launch_args)
                raise SystemExit(0)
            else:
                os.execvp(sys.executable, launch_args)
        except SystemExit:
            raise
        except Exception as e:
            console.print(f"  [red]✗[/] Failed to start: {e}")
            console.print(f"\n  Start manually:")
            console.print(f"    [cyan]rathole -c {output_path}[/]")
    else:
        console.print(f"\n  Start Rathole:")
        console.print(f"    [cyan]rathole -c {output_path}[/]")

    return 0


def _ensure_rns_config(config_file: Path):
    """Create a minimal RNS config file if it doesn't exist."""
    if config_file.exists():
        return
    try:
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(
            "[reticulum]\n"
            "  enable_transport = Yes\n"
            "\n"
            "[interfaces]\n"
        )
    except OSError as e:
        console.print(f"  [red]✗[/] Failed to create {config_file}: {e}")
        raise SystemExit(1)


def _setup_add_interfaces(rns_config_file: Path, console, lead_with: str = "client"):
    """Interactive loop to add TCP interfaces during setup.

    Args:
        lead_with: "server" for gateway mode (TCP Server first),
                   "client" for client mode (TCP Client first).
    """
    if lead_with == "server":
        opt1_label = "TCP Server — Listen for incoming connections"
        opt2_label = "TCP Client — Connect to an existing node"
        opt1_mode, opt2_mode = "server", "client"
    else:
        opt1_label = "TCP Client — Connect to a gateway"
        opt2_label = "TCP Server — Listen for connections"
        opt1_mode, opt2_mode = "client", "server"

    add_interfaces = True
    while add_interfaces:
        choice = Prompt.ask(
            f"  Add a TCP interface?\n"
            f"    [bold]1[/]. {opt1_label}\n"
            f"    [bold]2[/]. {opt2_label}\n"
            f"    [bold]3[/]. Skip — Use existing interfaces only\n\n"
            f"  Choice",
            choices=["1", "2", "3"],
            default="3" if lead_with == "server" else "1",
        )

        if choice in ("1", "2"):
            mode = opt1_mode if choice == "1" else opt2_mode
            if mode == "server":
                listen_addr = Prompt.ask("  Listen address", default="0.0.0.0")
                listen_port = Prompt.ask("  Listen port", default="4242")
                try:
                    port = int(listen_port)
                    if not (1 <= port <= 65535):
                        raise ValueError("out of range")
                except ValueError:
                    console.print("  [red]Invalid port number (must be 1–65535)[/]")
                    continue
                iface_name = f"TCP Server {listen_addr}:{port}"
                _ensure_rns_config(rns_config_file)
                _add_rns_tcp_interface(
                    rns_config_file, "server",
                    name=iface_name, address=listen_addr, port=port,
                )
                console.print(f"  [green]✓[/] TCP Server added ({listen_addr}:{port})")
            else:
                default_host = "rns.ratspeak.org" if lead_with == "client" else ""
                target_addr = Prompt.ask("  Gateway address (IP or hostname)", default=default_host)
                target_port = Prompt.ask("  Gateway port", default="4242")
                try:
                    port = int(target_port)
                    if not (1 <= port <= 65535):
                        raise ValueError("out of range")
                except ValueError:
                    console.print("  [red]Invalid port number (must be 1–65535)[/]")
                    continue
                iface_name = f"TCP Client {target_addr}:{port}"
                _ensure_rns_config(rns_config_file)
                _add_rns_tcp_interface(
                    rns_config_file, "client",
                    name=iface_name, address=target_addr, port=port,
                )
                console.print(f"  [green]✓[/] TCP Client added ({target_addr}:{port})")

            if not Confirm.ask("\n  Add another interface?", default=False):
                add_interfaces = False
        else:
            add_interfaces = False


def _setup_i2p(rns_config_file: Path, console, node_mode: str) -> bool:
    """Ask whether to enable I2P support and handle install/config.

    Installs i2pd if needed, starts the service (non-blocking), and
    writes an I2PInterface to the RNS config. SAM API readiness and
    tunnel establishment are runtime concerns handled by the daemon.

    Returns True if I2P was successfully configured.
    """
    from .i2p import ensure_i2pd_ready, add_rns_i2p_interface

    console.print("  [dim]I2P lets you connect to the network without exposing your IP.[/]")
    console.print("  [dim]Requires i2pd (auto-installed if needed). Peer connections are added in the TUI.[/]")
    console.print()

    if not Confirm.ask("  Enable I2P support?", default=False):
        return False

    console.print()
    if not ensure_i2pd_ready(console):
        console.print("  [yellow]i2pd could not be installed — I2P will not be available[/]")
        return False

    connectable = (node_mode == "gateway")
    iface_name = "I2P Gateway" if connectable else "I2P Interface"
    _ensure_rns_config(rns_config_file)
    add_rns_i2p_interface(rns_config_file, iface_name, connectable=connectable)
    console.print(f"  [green]✓[/] I2P interface configured ({iface_name})")
    if connectable:
        console.print("  [dim]Your B32 address will appear in the TUI Interfaces tab once the tunnel is up[/]")
    console.print("  [dim]Add I2P peers anytime from the TUI Interfaces tab[/]")
    return True


def _setup_registry(console, node_mode: str) -> tuple[bool, bool, bool, str]:
    """Ask whether to enable the Gateway Registry.

    Returns (enabled, publish, auto_connect, node_name).
    """
    console.print("[bold]── Gateway Registry ──[/]\n")
    console.print("  [dim]The registry lets I2P-enabled Rathole nodes find each other.[/]")
    console.print("  [dim]Requires I2P to be enabled.[/]")
    console.print()

    if not Confirm.ask("  Enable gateway registry?", default=True):
        return False, False, False, ""

    publish = False
    if node_mode == "gateway":
        publish = Confirm.ask(
            "\n  Publish this node to the registry?\n"
            "  [dim]Other nodes can discover and connect to you.[/]",
            default=True,
        )

    auto_connect = Confirm.ask(
        "\n  Auto-discover and connect to gateways?",
        default=(node_mode == "client"),
    )

    node_name = Prompt.ask(
        "\n  Node name (optional, shown in registry)",
        default="",
    )

    console.print(f"\n  [green]✓[/] Registry enabled"
                   + (f" — publishing" if publish else "")
                   + (f", auto-connect" if auto_connect else ""))

    return True, publish, auto_connect, node_name


def _check_rns_transport(config_file: Path) -> bool:
    """Check if transport is enabled in an RNS config file."""
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file))
        rns_section = cfg.get("reticulum", {})
        val = rns_section.get("enable_transport", "No")
        return str(val).lower() in ("yes", "true", "1")
    except Exception:
        # If configobj isn't installed, try simple text scan
        try:
            text = config_file.read_text()
            for line in text.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("enable_transport") and "=" in stripped:
                    val = stripped.split("=", 1)[1].strip()
                    return val in ("yes", "true", "1")
        except Exception:
            pass
    return False


def _set_rns_transport(config_file: Path, enabled: bool):
    """Set transport mode in an RNS config file."""
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file))
        if "reticulum" not in cfg:
            cfg["reticulum"] = {}
        cfg["reticulum"]["enable_transport"] = "Yes" if enabled else "No"
        cfg.write()
    except ImportError:
        # Fallback: simple text replacement
        text = config_file.read_text()
        lines = text.splitlines()
        found = False
        for i, line in enumerate(lines):
            if line.strip().lower().startswith("enable_transport"):
                lines[i] = f"  enable_transport = {'Yes' if enabled else 'No'}"
                found = True
                break
        if not found:
            # Insert after [reticulum] section header
            for i, line in enumerate(lines):
                if line.strip().lower() == "[reticulum]":
                    lines.insert(i + 1, f"  enable_transport = {'Yes' if enabled else 'No'}")
                    found = True
                    break
        if not found:
            # No [reticulum] section at all — prepend one
            lines.insert(0, "[reticulum]")
            lines.insert(1, f"  enable_transport = {'Yes' if enabled else 'No'}")
            found = True
        if found:
            config_file.write_text("\n".join(lines) + "\n")


def _list_rns_interfaces(config_file: Path) -> list[str]:
    """List interface names from an RNS config file."""
    interfaces = []
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file))
        ifaces = cfg.get("interfaces", {})
        for name in ifaces:
            interfaces.append(name)
    except ImportError:
        # Fallback: scan for [[interface_name]] sections under [interfaces]
        try:
            text = config_file.read_text()
            in_interfaces = False
            for line in text.splitlines():
                stripped = line.strip()
                if stripped == "[interfaces]":
                    in_interfaces = True
                    continue
                if in_interfaces and stripped.startswith("[") and not stripped.startswith("[["):
                    break  # New top-level section
                if in_interfaces and stripped.startswith("[[") and stripped.endswith("]]"):
                    name = stripped[2:-2].strip()
                    interfaces.append(name)
        except Exception:
            pass
    return interfaces


def _add_rns_tcp_interface(config_file: Path, mode: str, name: str, address: str, port: int):
    """Add a TCP interface to an RNS config file."""
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file))
        if "interfaces" not in cfg:
            cfg["interfaces"] = {}

        iface_cfg = {}
        if mode == "server":
            iface_cfg["type"] = "TCPServerInterface"
            iface_cfg["listen_ip"] = address
            iface_cfg["listen_port"] = str(port)
        else:
            iface_cfg["type"] = "TCPClientInterface"
            iface_cfg["target_host"] = address
            iface_cfg["target_port"] = str(port)
        iface_cfg["enabled"] = "yes"

        cfg["interfaces"][name] = iface_cfg
        cfg.write()
    except ImportError:
        # Fallback: append text
        entry = f"\n  [[{name}]]\n"
        if mode == "server":
            entry += f"    type = TCPServerInterface\n"
            entry += f"    listen_ip = {address}\n"
            entry += f"    listen_port = {port}\n"
        else:
            entry += f"    type = TCPClientInterface\n"
            entry += f"    target_host = {address}\n"
            entry += f"    target_port = {port}\n"
        entry += f"    enabled = yes\n"

        text = config_file.read_text()
        if "[interfaces]" in text:
            # Append before the next top-level section or at EOF
            text += entry
        else:
            text += "\n[interfaces]\n" + entry
        config_file.write_text(text)


def _get_rns_config_path(args) -> Path:
    """Resolve the RNS config file path.

    Priority:
        1. --rns-config flag (if present)
        2. reticulum_config_path from ./rathole.toml
        3. ~/.reticulum/config
    """
    # 1. Explicit flag
    if hasattr(args, "rns_config") and args.rns_config:
        return Path(args.rns_config)

    # 2. Try rathole.toml
    toml_path = Path("rathole.toml")
    if toml_path.exists():
        try:
            import tomllib
            with open(toml_path, "rb") as f:
                cfg = tomllib.load(f)
            rns_path = cfg.get("general", {}).get("reticulum_config_path", "")
            if rns_path:
                return Path(rns_path) / "config"
        except Exception:
            pass

    # 3. Default
    return Path.home() / ".reticulum" / "config"


def _fix_darwin_autointerface(config_file: Path, console):
    """On macOS, add utun* tunnel interfaces to AutoInterface's ignored_devices.

    macOS creates utun0-utunN for VPN, iCloud Private Relay, and network
    extensions.  AutoInterface tries multicast on them and gets intermittent
    Errno 55 ("No buffer space available") warnings.

    This modifies the RNS config's [[Default Interface]] (or any AutoInterface
    section) to add ignored_devices for all current utun* interfaces.
    """
    import platform
    if platform.system() != "Darwin":
        return

    import socket
    if not hasattr(socket, "if_nameindex"):
        return

    utun_ifs = sorted(
        name for _, name in socket.if_nameindex()
        if name.startswith("utun")
    )
    if not utun_ifs:
        return

    # Read current config and find AutoInterface sections
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file))
        ifaces = cfg.get("interfaces", {})
        patched = False
        for iface_name, iface_cfg in ifaces.items():
            if not isinstance(iface_cfg, dict):
                continue
            if iface_cfg.get("type") != "AutoInterface":
                continue

            existing = iface_cfg.get("ignored_devices", [])
            if isinstance(existing, str):
                existing = [s.strip() for s in existing.split(",") if s.strip()]

            missing = [u for u in utun_ifs if u not in existing]
            if not missing:
                continue

            new_list = existing + missing
            iface_cfg["ignored_devices"] = ", ".join(new_list)
            patched = True
            console.print(
                f"  [green]✓[/] [{iface_name}] ignoring macOS tunnel interfaces: "
                f"{', '.join(missing)}"
            )

        if patched:
            cfg.write()
    except ImportError:
        # Fallback without configobj: text-based patching
        try:
            text = config_file.read_text()
            lines = text.splitlines()
            new_lines = []
            in_auto = False
            already_has = False
            insert_after = -1

            for i, line in enumerate(lines):
                stripped = line.strip()
                # Detect start of an interface section
                if stripped.startswith("[[") and stripped.endswith("]]"):
                    in_auto = False
                    already_has = False
                # Detect AutoInterface type
                if stripped.startswith("type") and "=" in stripped:
                    val = stripped.split("=", 1)[1].strip()
                    if val == "AutoInterface":
                        in_auto = True
                        insert_after = i
                if in_auto and stripped.startswith("ignored_devices"):
                    already_has = True
                    # Merge missing utun interfaces
                    _, _, existing_str = line.partition("=")
                    existing = [s.strip() for s in existing_str.split(",") if s.strip()]
                    missing = [u for u in utun_ifs if u not in existing]
                    if missing:
                        new_list = existing + missing
                        indent = line[:len(line) - len(line.lstrip())]
                        line = f"{indent}ignored_devices = {', '.join(new_list)}"
                        console.print(
                            f"  [green]✓[/] AutoInterface: added tunnel ignores: "
                            f"{', '.join(missing)}"
                        )
                new_lines.append(line)

            if in_auto and not already_has and insert_after >= 0:
                # No ignored_devices line existed — insert one
                indent = "    "
                ignore_line = f"{indent}ignored_devices = {', '.join(utun_ifs)}"
                new_lines.insert(insert_after + 1, ignore_line)
                console.print(
                    f"  [green]✓[/] AutoInterface: ignoring macOS tunnel interfaces: "
                    f"{', '.join(utun_ifs)}"
                )

            config_file.write_text("\n".join(new_lines) + "\n")
        except Exception:
            pass  # Don't break setup over this


def _remove_rns_interface(config_file: Path, name: str) -> bool:
    """Remove a named interface section from an RNS config file.

    Returns True if the interface was found and removed.
    """
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file))
        ifaces = cfg.get("interfaces", {})
        if name in ifaces:
            del ifaces[name]
            cfg.write()
            return True
        return False
    except ImportError:
        # Fallback: text-based removal
        try:
            text = config_file.read_text()
            lines = text.splitlines()
            result = []
            skip = False
            found = False
            for line in lines:
                stripped = line.strip()
                if stripped == f"[[{name}]]":
                    skip = True
                    found = True
                    continue
                if skip:
                    # Stop skipping at the next section header
                    if stripped.startswith("[[") or (stripped.startswith("[") and not stripped.startswith("[[")):
                        skip = False
                        result.append(line)
                    # Skip indented content under the removed interface
                    continue
                result.append(line)
            if found:
                config_file.write_text("\n".join(result) + "\n")
            return found
        except Exception:
            return False


def cmd_network(args):
    """Manage RNS network interfaces."""
    rns_config = _get_rns_config_path(args)

    action = getattr(args, "net_action", None)

    if action is None:
        # List interfaces + transport status
        if not rns_config.exists():
            console.print(f"[red]RNS config not found:[/] {rns_config}")
            return 1

        transport_on = _check_rns_transport(rns_config)
        ifaces = _list_rns_interfaces(rns_config)

        if _json_mode:
            _output_json({
                "config_file": str(rns_config),
                "transport_enabled": transport_on,
                "interfaces": ifaces,
            })
            return 0

        transport_str = "[green]enabled[/]" if transport_on else "[red]disabled[/]"
        console.print(Panel(
            f"[bold]RNS Config:[/] {rns_config}\n"
            f"[bold]Transport:[/]  {transport_str}",
            title="[bold]Network[/]",
            border_style="blue",
        ))

        if ifaces:
            table = Table(title="Interfaces", border_style="blue")
            table.add_column("Name", style="cyan")
            for name in ifaces:
                table.add_row(name)
            console.print(table)
        else:
            console.print("[dim]No interfaces configured.[/]")
        return 0

    elif action == "add":
        mode = args.net_mode  # "server" or "client"
        target = args.net_target  # "host:port"

        if ":" not in target:
            console.print("[red]Error:[/] Target must be host:port (e.g. 0.0.0.0:4242)")
            return 1

        host, port_str = target.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            console.print(f"[red]Error:[/] Invalid port: {port_str}")
            return 1

        if not rns_config.exists():
            console.print(f"[red]RNS config not found:[/] {rns_config}")
            return 1

        # Generate interface name
        if mode == "server":
            name = f"TCP Server {host}:{port}"
        else:
            name = f"TCP Client {host}:{port}"

        _add_rns_tcp_interface(rns_config, mode, name, host, port)

        # Ensure transport is enabled
        if not _check_rns_transport(rns_config):
            _set_rns_transport(rns_config, True)
            console.print("[yellow]Transport was disabled — enabled automatically.[/]")

        console.print(f"[green]✓[/] Added [cyan]{name}[/] to {rns_config}")
        console.print("[dim]Restart Rathole to activate the new interface.[/]")
        return 0

    elif action == "remove":
        name = args.net_name

        if not rns_config.exists():
            console.print(f"[red]RNS config not found:[/] {rns_config}")
            return 1

        if _remove_rns_interface(rns_config, name):
            console.print(f"[green]✓[/] Removed [cyan]{name}[/] from {rns_config}")
            console.print("[dim]Restart Rathole to apply the change.[/]")
        else:
            console.print(f"[red]Interface not found:[/] {name}")
            console.print("[dim]Available interfaces:[/]")
            for iface in _list_rns_interfaces(rns_config):
                console.print(f"  {iface}")
            return 1
        return 0

    return 0


def _write_toml(config: dict, path: Path, preset_name: str):
    """Write a config dict as a TOML file with comments."""
    lines = [
        "# Rathole configuration",
        f"# Generated by rat setup (preset: {preset_name})",
        "# Change settings via `rat` or the TUI — no need to edit this file",
        "",
    ]

    def _write_section(key: str, value, prefix: str = ""):
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            lines.append(f"[{full_key}]")
            for k, v in value.items():
                if isinstance(v, dict):
                    _write_section(k, v, prefix=full_key)
                    lines.append("")
                else:
                    _write_value(k, v)
            lines.append("")
        else:
            _write_value(key, value)

    def _write_value(key: str, value):
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"')
        elif isinstance(value, (int, float)):
            lines.append(f"{key} = {value}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key} = []")
            else:
                items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                lines.append(f"{key} = [{items}]")

    for section_name, section_value in config.items():
        if isinstance(section_value, dict):
            _write_section(section_name, section_value)
        else:
            _write_value(section_name, section_value)

    path.write_text("\n".join(lines) + "\n")


# ── Helpers ─────────────────────────────────────────────────────

def _print_config_tree(name: str, data, indent: int = 0):
    """Print a config section as an indented tree."""
    prefix = "  " * indent
    if isinstance(data, dict):
        console.print(f"{prefix}[bold]{name}[/]")
        for k, v in data.items():
            _print_config_tree(k, v, indent + 1)
    elif isinstance(data, list):
        if data:
            console.print(f"{prefix}[cyan]{name}[/]: {data}")
        else:
            console.print(f"{prefix}[cyan]{name}[/]: [dim]\\[][/]")
    else:
        if isinstance(data, bool):
            val = "[green]true[/]" if data else "[red]false[/]"
        elif isinstance(data, (int, float)):
            val = f"[yellow]{data}[/]"
        else:
            val = str(data) if data else "[dim](empty)[/]"
        console.print(f"{prefix}[cyan]{name}[/]: {val}")


# ── Main ────────────────────────────────────────────────────────

def main():
    global _json_mode

    parser = argparse.ArgumentParser(
        prog="rat",
        description="Rathole — transport node security suite for Reticulum",
    )
    parser.add_argument(
        "-s", "--socket",
        default=DEFAULT_SOCKET,
        help=f"Control socket path (default: {DEFAULT_SOCKET})",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── setup ──
    setup_p = sub.add_parser("setup", help="Interactive setup wizard — configure Reticulum + Rathole")
    setup_p.add_argument("-o", "--output", default="rathole.toml",
                         help="Output path for rathole.toml (default: ./rathole.toml)")
    setup_p.add_argument("--force", action="store_true",
                         help="Overwrite existing config without prompting")

    # ── reset ──
    reset_p = sub.add_parser("reset", help="Wipe all Rathole data for a fresh start")
    reset_p.add_argument("-c", "--config", default="rathole.toml",
                         help="Config file to resolve paths from (default: ./rathole.toml)")

    # ── status ──
    sub.add_parser("status", help="Dashboard overview: stats, top peers, interfaces")

    # ── peers ──
    peers_p = sub.add_parser("peers", help="Full peer table with reputation")
    peers_p.add_argument("--sort", choices=["announces", "real_traffic", "ratio", "reputation", "peer"],
                         default="announces", help="Sort column")
    peers_p.add_argument("--limit", type=int, default=0, help="Max rows (0 = all)")

    # ── interfaces ──
    sub.add_parser("interfaces", help="Per-interface traffic breakdown")

    # ── events ──
    events_p = sub.add_parser("events", help="Security event log")
    events_p.add_argument("--limit", "-n", type=int, default=50, help="Number of events")
    events_p.add_argument("--type", "-t", default="", help="Filter by event type")
    events_p.add_argument("--severity", default="", help="Filter by severity")

    # ── blackhole ──
    bh_p = sub.add_parser("blackhole", help="Blackhole management")
    bh_p.add_argument("action", choices=["list", "add", "remove"], help="Action")
    bh_p.add_argument("--identity", "-i", default="", help="Identity hash")
    bh_p.add_argument("--reason", "-r", default="", help="Reason for blackhole")

    # ── reputation ──
    rep_p = sub.add_parser("reputation", help="Identity reputation")
    rep_sub = rep_p.add_subparsers(dest="rep_action")

    # reputation (no subcommand) — show all or specific
    rep_p.add_argument("identity", nargs="?", default="", help="Identity hash (omit for all)")

    # reputation pin HASH SCORE
    rep_pin = rep_sub.add_parser("pin", help="Pin identity to a fixed score")
    rep_pin.add_argument("identity", help="Identity hash")
    rep_pin.add_argument("score", type=float, help="Score to pin (0.0-1.0)")

    # reputation unpin HASH
    rep_unpin = rep_sub.add_parser("unpin", help="Remove operator pin")
    rep_unpin.add_argument("identity", help="Identity hash")

    # ── config ──
    cfg_p = sub.add_parser("config", help="Live config inspection/override")
    cfg_p.add_argument("action", choices=["show", "set", "preset"], help="Action")
    cfg_p.add_argument("section", nargs="?", default="", help="Config section (for show/set)")
    cfg_p.add_argument("key", nargs="?", default="", help="Config key (for set)")
    cfg_p.add_argument("value", nargs="?", default=None, help="Config value (for set)")
    cfg_p.add_argument("--preset-action", dest="preset_action",
                       choices=["list", "apply", "diff"], default="list",
                       help="Preset subcommand")
    cfg_p.add_argument("--preset-name", dest="preset_name", default="",
                       help="Preset name (for apply/diff)")

    # ── filters ──
    filt_p = sub.add_parser("filters", help="Filter status and management")
    filt_p.add_argument("--pipeline", "-p", default="", help="Filter by pipeline name")
    filt_sub = filt_p.add_subparsers(dest="filter_action")

    filt_toggle = filt_sub.add_parser("toggle", help="Enable/disable a filter")
    filt_toggle.add_argument("filter_name", help="Filter name")
    filt_toggle.add_argument("mode", choices=["on", "off"], help="on or off")

    filt_set = filt_sub.add_parser("set", help="Change a filter parameter")
    filt_set.add_argument("filter_name", help="Filter name")
    filt_set.add_argument("param_key", help="Parameter key")
    filt_set.add_argument("param_value", help="Parameter value")

    # ── network ──
    net_p = sub.add_parser("network", help="Manage RNS network interfaces")
    net_p.add_argument("--rns-config", default="", help="Path to RNS config file")
    net_sub = net_p.add_subparsers(dest="net_action")

    net_add = net_sub.add_parser("add", help="Add a TCP interface")
    net_add.add_argument("net_mode", choices=["server", "client"],
                         help="server (public gateway) or client (connect to gateway)")
    net_add.add_argument("net_target", help="host:port (e.g. 0.0.0.0:4242 or rns.example.org:4242)")

    net_rm = net_sub.add_parser("remove", help="Remove a named interface")
    net_rm.add_argument("net_name", help="Interface name (from 'rat network')")

    # ── registry ──
    reg_p = sub.add_parser("registry", help="Gateway registry management")
    reg_sub = reg_p.add_subparsers(dest="reg_action")
    reg_sub.add_parser("discover", help="Query registry for gateways")
    reg_connect = reg_sub.add_parser("connect", help="Connect to a discovered gateway")
    reg_connect.add_argument("reg_identity", help="Identity hash (or unique 8+ char prefix)")
    reg_sub.add_parser("register", help="Publish this node to the registry")
    reg_sub.add_parser("deregister", help="Remove this node from the registry")

    # ── run ──
    run_p = sub.add_parser("run", help="Start Rathole daemon + TUI (shortcut for rathole -c rathole.toml)")
    run_p.add_argument("-c", "--config", default="rathole.toml",
                       help="Config file (default: ./rathole.toml)")
    run_p.add_argument("--headless", action="store_true",
                       help="Daemon only, no TUI")
    run_p.add_argument("--dry-run", action="store_true",
                       help="Log verdicts without blocking")
    run_p.add_argument("-v", "--verbose", action="store_true",
                       help="Enable debug logging")

    # ── simple commands ──
    dr_p = sub.add_parser("dry-run", help="Toggle dry-run mode")
    dr_p.add_argument("mode", nargs="?", choices=["on", "off"], help="on/off (omit to show)")

    sub.add_parser("adaptive", help="Adaptive threshold engine status")
    sub.add_parser("correlator", help="Attack correlation engine status")
    sub.add_parser("alerts", help="Alert rules status")
    sub.add_parser("reload", help="Hot-reload configuration")
    sub.add_parser("shutdown", help="Gracefully stop the daemon")

    args = parser.parse_args()

    # Auto-discover socket path from config if not explicitly overridden
    args.socket = find_socket(args.socket)

    # Set global modes
    _json_mode = args.json

    handlers = {
        "run": cmd_run,
        "setup": cmd_setup,
        "reset": cmd_reset,
        "status": cmd_status,
        "peers": cmd_peers,
        "interfaces": cmd_interfaces,
        "events": cmd_events,
        "blackhole": cmd_blackhole,
        "reputation": cmd_reputation,
        "config": cmd_config,
        "filters": cmd_filters,
        "network": cmd_network,
        "registry": cmd_registry,
        "dry-run": cmd_dryrun,
        "adaptive": cmd_adaptive,
        "correlator": cmd_correlator,
        "alerts": cmd_alerts,
        "reload": cmd_reload,
        "shutdown": cmd_shutdown,
    }

    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()
