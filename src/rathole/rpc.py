"""
Shared RPC client for communicating with the Rathole daemon.

Both rat and rathole-tui use this module to send commands
over the control socket. Centralizes connection logic, error
handling, and the default socket path.

On macOS/Linux the control socket is a Unix domain socket
(AF_UNIX). On Windows it is a TCP localhost connection.
The format of the address determines the transport:
  - Path (e.g. "/tmp/rathole.sock") → AF_UNIX
  - host:port (e.g. "127.0.0.1:4242") → AF_INET (TCP)
"""

import json
import os
import socket
import sys


def _default_socket() -> str:
    """Return the platform-appropriate default control socket address."""
    if sys.platform == "win32":
        return "127.0.0.1:4242"
    return "/tmp/rathole.sock"


DEFAULT_SOCKET = _default_socket()


def _is_tcp_address(addr: str) -> bool:
    """Return True if *addr* looks like a TCP host:port rather than a file path.

    Distinguishes '127.0.0.1:4242' (TCP) from '/tmp/rathole.sock' (Unix)
    and 'C:\\Users\\...' (Windows path, not TCP).
    """
    if not addr or addr.startswith("/"):
        return False
    # Windows drive letter: C:\... — not a TCP address
    if len(addr) >= 3 and addr[1] == ":" and addr[2] in ("/", "\\"):
        return False
    return ":" in addr


def find_socket(explicit: str | None = None) -> str:
    """Resolve the control socket path.

    Priority:
        1. Explicit path (from -s flag) — if it differs from DEFAULT_SOCKET
        2. control_socket from ./rathole.toml (if the file exists)
        3. DEFAULT_SOCKET fallback

    Returns the resolved socket path string.
    """
    # 1. Explicit override from CLI (only if user actually set -s)
    if explicit and explicit != DEFAULT_SOCKET:
        return explicit

    # 2. Try reading control_socket from local rathole.toml
    toml_path = os.path.join(os.getcwd(), "rathole.toml")
    if os.path.isfile(toml_path):
        try:
            import tomllib
            with open(toml_path, "rb") as f:
                cfg = tomllib.load(f)
            sock = cfg.get("general", {}).get("control_socket", "")
            if sock:
                return sock
        except Exception:
            pass

    # 3. Default
    return DEFAULT_SOCKET


class RpcError(Exception):
    """Raised when the daemon returns an error response."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def send_command(
    sock_path: str,
    cmd: str,
    args: dict | None = None,
    timeout: float = 10.0,
) -> dict:
    """
    Send a JSON-RPC command to the daemon and return the response.

    Args:
        sock_path: Control socket address — a Unix socket path or host:port.
        cmd: Command name (e.g. "status", "peers", "blackhole").
        args: Optional arguments dict.
        timeout: Socket timeout in seconds.

    Returns:
        Response dict from the daemon.
    """
    if _is_tcp_address(sock_path):
        try:
            host, port_str = sock_path.rsplit(":", 1)
            port = int(port_str)
        except (ValueError, AttributeError):
            return {"ok": False, "error": f"Invalid TCP address: {sock_path}"}
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    client.settimeout(timeout)
    try:
        if _is_tcp_address(sock_path):
            client.connect((host, port))
        else:
            client.connect(sock_path)
        msg = json.dumps({"cmd": cmd, "args": args or {}})
        client.sendall(msg.encode())
        client.shutdown(socket.SHUT_WR)
        data = b""
        max_response = 10 * 1024 * 1024  # 10 MB cap
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > max_response:
                return {"ok": False, "error": "Response too large"}
        return json.loads(data.decode())
    except ConnectionRefusedError:
        return {"ok": False, "error": "Cannot connect — is rathole running?"}
    except FileNotFoundError:
        return {"ok": False, "error": f"Socket not found: {sock_path}"}
    except socket.timeout:
        return {"ok": False, "error": "Connection timed out"}
    except json.JSONDecodeError:
        return {"ok": False, "error": "Invalid response from daemon"}
    except OSError as e:
        return {"ok": False, "error": f"Socket error: {e}"}
    finally:
        client.close()


def is_daemon_running(sock_path: str | None = None) -> bool:
    """Check whether a Rathole daemon is reachable on the control socket.

    Sends a lightweight ``status`` probe.  Returns True if the daemon
    responds with ``{"ok": true, ...}``, False otherwise (not running,
    socket missing, connection refused, timeout, etc.).
    """
    path = sock_path or find_socket()
    resp = send_command(path, "status", timeout=3.0)
    return resp.get("ok", False)


def shutdown_and_wait(
    sock_path: str | None = None,
    timeout: float = 10.0,
    poll_interval: float = 0.3,
) -> bool:
    """Send a shutdown command and wait for the daemon to exit.

    Returns True if the daemon is confirmed stopped within *timeout*
    seconds, False if it's still responding after the deadline.
    """
    import time

    path = sock_path or find_socket()

    # Send the shutdown signal
    resp = send_command(path, "shutdown", timeout=3.0)
    if not resp.get("ok"):
        # Daemon might already be gone — that's fine
        return not is_daemon_running(path)

    # Poll until the socket stops responding
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        if not is_daemon_running(path):
            return True

    return False


def check_response(resp: dict) -> dict:
    """
    Check a daemon response and raise RpcError on failure.

    Returns the response dict on success.
    """
    if not resp.get("ok"):
        raise RpcError(resp.get("error", "Unknown error"))
    return resp
