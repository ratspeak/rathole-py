"""I2P integration utilities for Rathole.

Probe, install, validate, and configure I2P (i2pd) for use with
Reticulum's I2PInterface. No runtime RNS dependency except
get_i2p_b32_from_transport() which lazy-imports.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path


def probe_sam_api(host: str = "127.0.0.1", port: int = 7656, timeout: float = 3.0) -> bool:
    """TCP connect to SAM API. Returns True if reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def detect_i2pd_installed() -> bool:
    """Check if i2pd binary is on PATH."""
    return shutil.which("i2pd") is not None


def detect_platform() -> str:
    """Returns 'macos', 'windows', 'debian', 'arch', or 'unknown'."""
    if platform.system() == "Darwin":
        return "macos"
    if platform.system() == "Windows":
        return "windows"
    if Path("/etc/debian_version").exists():
        return "debian"
    if Path("/etc/arch-release").exists():
        return "arch"
    return "unknown"


def install_i2pd(console) -> bool:
    """Auto-install i2pd with user confirmation.

    Uses Rich console for prompts. Returns True if install succeeded.
    """
    from rich.prompt import Confirm

    plat = detect_platform()

    if plat == "macos":
        cmd = ["brew", "install", "i2pd"]
        desc = "brew install i2pd"
        needs_sudo = False
    elif plat == "windows":
        # Try winget first, then chocolatey
        if shutil.which("winget"):
            cmd = ["winget", "install", "PurpleI2P.i2pd"]
            desc = "winget install PurpleI2P.i2pd"
        elif shutil.which("choco"):
            cmd = ["choco", "install", "i2pd", "-y"]
            desc = "choco install i2pd -y"
        else:
            console.print(
                "  [yellow]No package manager found (winget or chocolatey).[/]\n"
                "  Install i2pd manually: https://i2pd.readthedocs.io/en/latest/user-guide/install/\n"
                "  Then re-run setup."
            )
            return False
        needs_sudo = False
    elif plat == "debian":
        cmd = ["sudo", "apt", "install", "-y", "i2pd"]
        desc = "sudo apt install -y i2pd"
        needs_sudo = True
    elif plat == "arch":
        cmd = ["sudo", "pacman", "-S", "--noconfirm", "i2pd"]
        desc = "sudo pacman -S --noconfirm i2pd"
        needs_sudo = True
    else:
        console.print(
            "  [yellow]Could not detect package manager.[/]\n"
            "  Install i2pd manually: https://i2pd.readthedocs.io/en/latest/user-guide/install/\n"
            "  Then re-run setup."
        )
        return False

    console.print(f"  i2pd not found. Install command: [bold]{desc}[/]")
    if needs_sudo:
        console.print("  [dim](sudo will prompt for your password)[/]")

    if not Confirm.ask("  Install i2pd now?", default=True):
        console.print("  [dim]Skipped i2pd install[/]")
        return False

    try:
        result = subprocess.run(cmd, check=False)
        if result.returncode == 0:
            console.print("  [green]i2pd installed successfully[/]")
            return True
        else:
            console.print(f"  [red]Install failed (exit code {result.returncode})[/]")
            return False
    except FileNotFoundError:
        console.print("  [red]Package manager not found[/]")
        return False


def start_i2pd_service_nonblocking(console) -> None:
    """Start i2pd service without waiting for SAM API.

    i2pd can take 30s–3min to bootstrap, especially after a data reset.
    Setup should not block on this — the daemon handles the wait.
    """
    plat = detect_platform()

    if plat == "macos":
        cmd = ["brew", "services", "start", "i2pd"]
    elif plat == "windows":
        cmd = ["net", "start", "i2pd"]
    else:
        cmd = ["sudo", "systemctl", "enable", "--now", "i2pd"]

    try:
        subprocess.run(cmd, check=False, capture_output=True)
        console.print("  [green]✓[/] i2pd service started (SAM API will be ready shortly)")
    except FileNotFoundError:
        console.print("  [yellow]Could not start i2pd service — start it manually[/]")


def stop_i2pd_service(console) -> bool:
    """Stop i2pd service to clear stale SAM sessions.

    Used during reset after deleting I2P keys/data. Setup will
    start i2pd fresh when the user re-enables I2P.
    Returns True if i2pd was stopped (SAM API no longer reachable).
    """
    import time

    plat = detect_platform()

    if plat == "macos":
        cmd = ["brew", "services", "stop", "i2pd"]
    elif plat == "windows":
        cmd = ["net", "stop", "i2pd"]
    else:
        cmd = ["sudo", "systemctl", "stop", "i2pd"]

    console.print("  Stopping i2pd…")
    try:
        subprocess.run(cmd, check=False, capture_output=True)
    except FileNotFoundError:
        console.print("  [yellow]Could not stop service automatically[/]")
        return False

    # Verify SAM is gone
    for _ in range(10):
        if not probe_sam_api():
            return True
        time.sleep(0.5)

    return not probe_sam_api()


_I2PD_CONF_PATHS = [
    Path.home() / ".i2pd" / "i2pd.conf",
    Path("/etc/i2pd/i2pd.conf"),
    Path("/opt/homebrew/etc/i2pd/i2pd.conf"),
    Path("/usr/local/etc/i2pd/i2pd.conf"),
]


def ensure_sam_enabled() -> bool:
    """Check i2pd.conf for SAM API, enable if explicitly disabled.

    i2pd enables SAM by default in recent versions. Only patches
    if [sam] section exists with enabled = false.

    Returns True if SAM is (or was made) enabled, False if config
    could not be found or patched.
    """
    for conf_path in _I2PD_CONF_PATHS:
        if not conf_path.exists():
            continue

        try:
            text = conf_path.read_text()
        except OSError:
            continue

        # Look for [sam] section with enabled = false
        sam_match = re.search(
            r"^\[sam\]\s*\n((?:(?!\[).)*)",
            text,
            re.MULTILINE | re.DOTALL,
        )
        if not sam_match:
            # No [sam] section — i2pd defaults to SAM enabled
            return True

        sam_block = sam_match.group(1)
        if re.search(r"^\s*enabled\s*=\s*false", sam_block, re.MULTILINE | re.IGNORECASE):
            # SAM explicitly disabled — try to enable
            new_block = re.sub(
                r"^(\s*enabled\s*=\s*)false",
                r"\1true",
                sam_block,
                flags=re.MULTILINE | re.IGNORECASE,
            )
            new_text = text[:sam_match.start(1)] + new_block + text[sam_match.end(1):]
            try:
                conf_path.write_text(new_text)
                return True
            except OSError:
                return False

        # [sam] exists but enabled is not false — it's fine
        return True

    # No config file found — i2pd defaults enable SAM
    return True


def ensure_i2pd_ready(console) -> bool:
    """Ensure i2pd is installed and started. Does NOT block on SAM readiness.

    Setup's job is to install i2pd, kick it off, and write the config.
    Whether SAM is reachable is a runtime concern — the daemon and TUI
    handle the async tunnel establishment.

    Returns True if i2pd is installed and was started (or was already
    running). Returns False only if i2pd could not be installed.
    """
    # Already running?
    if probe_sam_api():
        console.print("  [green]i2pd running[/]")
        return True

    # Installed but not running?
    if detect_i2pd_installed():
        console.print("  [dim]i2pd found — starting service[/]")
        ensure_sam_enabled()
        start_i2pd_service_nonblocking(console)
        return True

    # Try to install
    if not install_i2pd(console):
        return False
    ensure_sam_enabled()
    start_i2pd_service_nonblocking(console)
    return True


def detect_i2p_in_rns_config(config_file: Path) -> bool:
    """Check if an RNS config file contains any I2PInterface sections."""
    if not config_file.exists():
        return False
    try:
        text = config_file.read_text()
        return "I2PInterface" in text
    except OSError:
        return False


# i2pd router data directory — contains the router identity, peer
# profiles, netDb, and tunnel keys.  NOT the application-layer B32
# destination keys (those live in ~/.reticulum/storage/i2p/).
_I2PD_DATA_DIRS = [
    Path.home() / ".i2pd",                       # Linux default / manual
    Path("/var/lib/i2pd"),                        # Linux system package
    Path("/opt/homebrew/var/lib/i2pd"),            # macOS Homebrew (ARM)
    Path("/usr/local/var/lib/i2pd"),               # macOS Homebrew (Intel)
]


def find_i2pd_data_dir() -> Path | None:
    """Return the first i2pd data directory that exists, or None."""
    for d in _I2PD_DATA_DIRS:
        if d.is_dir():
            return d
    return None


def find_rns_i2p_keydir(rns_config_path: str | None = None) -> Path | None:
    """Return the RNS I2P key storage directory if it exists.

    RNS stores I2P destination keys (which determine the B32 address)
    at <storagepath>/i2p/.  These are created by I2PController on first
    server tunnel setup and persist across restarts.
    """
    if rns_config_path:
        d = Path(rns_config_path) / "storage" / "i2p"
    else:
        d = Path.home() / ".reticulum" / "storage" / "i2p"
    if d.is_dir() and any(d.iterdir()):
        return d
    return None


_B32_PATTERN = re.compile(r"^[a-z2-7]{52}\.b32\.i2p$", re.IGNORECASE)


def validate_b32_address(address: str) -> bool:
    """Validate an I2P B32 address.

    Must be 52 base32 chars [a-z2-7] followed by .b32.i2p.
    Case-insensitive, strips whitespace.
    """
    return bool(_B32_PATTERN.match(address.strip()))


def has_i2p_interface() -> bool:
    """Check if any connectable I2P interface exists (even if B32 is not yet set)."""
    try:
        import RNS
        for iface in RNS.Transport.interfaces:
            if "I2P" in type(iface).__name__ and getattr(iface, "connectable", False):
                return True
    except Exception:
        pass
    return False


def get_i2p_b32_from_transport() -> str | None:
    """Get this node's I2P B32 address from running RNS transport.

    Scans Transport.interfaces for an I2PInterface with connectable=True
    and a b32 attribute. Returns the full B32 address or None.
    """
    try:
        import RNS
        for iface in RNS.Transport.interfaces:
            type_name = type(iface).__name__
            if "I2P" in type_name:
                if getattr(iface, "connectable", False):
                    b32 = getattr(iface, "b32", None)
                    if b32:
                        addr = str(b32)
                        if not addr.endswith(".b32.i2p"):
                            addr += ".b32.i2p"
                        return addr
    except Exception:
        pass
    return None


def add_rns_i2p_interface(
    config_file: Path,
    name: str,
    connectable: bool = False,
    peers: list[str] | None = None,
):
    """Write an I2PInterface section to an RNS config file.

    Uses configobj if available, falls back to text append.
    """
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file))
        if "interfaces" not in cfg:
            cfg["interfaces"] = {}

        iface_cfg = {
            "type": "I2PInterface",
            "enabled": "yes",
            "connectable": "yes" if connectable else "no",
        }
        if peers:
            iface_cfg["peers"] = ", ".join(peers)

        cfg["interfaces"][name] = iface_cfg
        cfg.write()
    except ImportError:
        # Text fallback
        entry = f"\n  [[{name}]]\n"
        entry += "    type = I2PInterface\n"
        entry += "    enabled = yes\n"
        entry += f"    connectable = {'yes' if connectable else 'no'}\n"
        if peers:
            entry += f"    peers = {', '.join(peers)}\n"

        text = config_file.read_text()
        if "[interfaces]" in text:
            text += entry
        else:
            text += "\n[interfaces]\n" + entry
        config_file.write_text(text)
