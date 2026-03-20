"""CLI entry point for Rathole — daemon + TUI in a single command.

By default, starts the daemon in a background thread and opens the
full-screen TUI with a Console tab showing live log output.  Use
``--headless`` for server deployments without a terminal.

If textual is not installed the TUI is skipped automatically.
"""

import sys
import logging
import argparse
import threading
import collections
from pathlib import Path

from .config import load_config
from .daemon import RatholeDaemon


# ── Ring-buffer log handler ──────────────────────────────────────

class RingBufferHandler(logging.Handler):
    """Logging handler that stores formatted records in a bounded deque.

    Used to feed daemon log output into the TUI Console tab.
    Thread-safe: ``emit()`` can be called from any thread.
    """

    def __init__(self, maxlen: int = 2000):
        super().__init__()
        self.records: collections.deque[str] = collections.deque(maxlen=maxlen)
        self._lock_buf = threading.Lock()
        self._cursor = 0  # monotonic counter for drain tracking
        self._total = 0

    def emit(self, record):
        try:
            msg = self.format(record)
        except Exception:
            msg = repr(record)
        with self._lock_buf:
            self.records.append(msg)
            self._total += 1

    def get_lines(self) -> list[str]:
        """Return all buffered lines (newest last)."""
        with self._lock_buf:
            return list(self.records)

    def drain_new(self) -> list[str]:
        """Return lines added since the last drain call."""
        with self._lock_buf:
            available = len(self.records)
            new_count = self._total - self._cursor
            if new_count <= 0:
                return []
            # If more were added than the buffer can hold, clamp
            if new_count > available:
                new_count = available
            self._cursor = self._total
            return list(self.records)[-new_count:] if new_count < available else list(self.records)


# ── Logging setup ────────────────────────────────────────────────

def setup_logging(level: str, log_file: str = "", ring_handler: RingBufferHandler | None = None):
    """Configure logging for the daemon.

    When ``ring_handler`` is provided (TUI mode), logs go to the ring
    buffer instead of stderr so they appear in the Console tab.
    A file handler is still added if ``log_file`` is set.
    """
    fmt = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    handlers: list[logging.Handler] = []

    if ring_handler is not None:
        ring_handler.setFormatter(logging.Formatter(fmt, datefmt))
        handlers.append(ring_handler)
    elif not log_file:
        # Only add stderr if no ring handler and no log file
        handlers.append(logging.StreamHandler(sys.stderr))

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        datefmt=datefmt,
        handlers=handlers,
    )


# ── TUI availability check ──────────────────────────────────────

def _has_textual() -> bool:
    try:
        import textual  # noqa: F401
        return True
    except ImportError:
        return False


# ── Main ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="rathole",
        description="Rathole — transport node security suite for Reticulum",
    )
    parser.add_argument(
        "-c", "--config",
        default="rathole.toml",
        help="Path to config file (default: rathole.toml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log filter verdicts without actually blocking announces",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run daemon only, no TUI (for servers without a terminal)",
    )
    args = parser.parse_args()

    # Guard: fail fast if config file doesn't exist
    config_path = Path(args.config)
    if not config_path.exists():
        print(
            f"Error: Config file not found: {args.config}\n"
            f"\n"
            f"Run 'rat setup' to create a configuration, then start:\n"
            f"  rat setup\n"
            f"  rathole -c {args.config}\n",
            file=sys.stderr,
        )
        sys.exit(1)

    config = load_config(args.config)

    # CLI overrides
    if args.dry_run:
        config.raw["general"]["dry_run"] = True
    if args.verbose:
        config.raw["general"]["log_level"] = "DEBUG"

    use_tui = not args.headless and _has_textual()

    # ── Headless mode (daemon only, blocking) ────────────────────
    if not use_tui:
        setup_logging(
            config.general.get("log_level", "INFO"),
            config.general.get("log_file", ""),
        )
        daemon = RatholeDaemon(config)
        try:
            daemon.start()
        except KeyboardInterrupt:
            daemon.stop()
        except SystemExit:
            raise
        except Exception as e:
            logging.getLogger("rathole").critical("Fatal error: %s", e, exc_info=True)
            daemon.stop()
            sys.exit(1)
        return

    # ── TUI mode (daemon in background thread + TUI on main) ────

    # Set up ring buffer so logs flow into the TUI Console tab
    ring = RingBufferHandler()
    setup_logging(
        config.general.get("log_level", "INFO"),
        config.general.get("log_file", ""),
        ring_handler=ring,
    )

    daemon = RatholeDaemon(config)

    # Init on main thread (Reticulum registers signal handlers internally)
    try:
        daemon.init(install_signals=False)
    except SystemExit:
        raise
    except Exception as e:
        logging.getLogger("rathole").critical("Failed to initialize: %s", e, exc_info=True)
        daemon.stop()
        sys.exit(1)

    # Maintenance loop in background thread
    daemon_thread = threading.Thread(
        target=daemon.run,
        name="rathole-daemon",
        daemon=True,
    )
    daemon_thread.start()

    # Launch the TUI on the main thread
    from .tui import create_app

    from .rpc import DEFAULT_SOCKET
    sock_path = config.general.get("control_socket", DEFAULT_SOCKET)
    app = create_app(
        sock_path=sock_path,
        log_handler=ring,
        command_handler=daemon.handle_command,
    )

    try:
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        daemon.stop()
        daemon_thread.join(timeout=5.0)

        # Flush streams before interpreter finalization to avoid
        # "could not acquire lock for BufferedWriter" from daemon threads.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass


if __name__ == "__main__":
    main()
