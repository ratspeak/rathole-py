"""
SQLite event store — persistent queryable history for security events.

Uses WAL mode (following RustRat pattern) for concurrent read/write.
Events are stored with full indexing for efficient querying by type,
severity, interface, identity, and time range.

Auto-prunes events older than retention period (default 7 days).

Config keys (under [eventstore]):
  - enabled: Enable persistent event storage (default false)
  - path: Database file path (default ~/.rathole/events.db)
  - retention_days: Days to retain events (default 7)
  - prune_interval: Seconds between prune runs (default 3600)
"""

import time
import sqlite3
import logging
import threading
from pathlib import Path

from .events import SecurityEvent, EventType, EventSeverity

log = logging.getLogger("rathole.eventstore")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT DEFAULT '',
    interface_name TEXT DEFAULT '',
    identity_hash TEXT DEFAULT '',
    destination_hash TEXT DEFAULT '',
    description TEXT DEFAULT '',
    details TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_interface ON events(interface_name);
CREATE INDEX IF NOT EXISTS idx_events_identity ON events(identity_hash);

CREATE TABLE IF NOT EXISTS hourly_stats (
    hour TEXT NOT NULL,
    event_type TEXT NOT NULL,
    count INTEGER DEFAULT 0,
    PRIMARY KEY (hour, event_type)
);
"""


class EventStore:
    """
    SQLite-backed persistent event store.

    Thread-safe — uses a single writer with WAL mode for concurrent reads.
    """

    def __init__(self, config: dict):
        self._enabled = config.get("enabled", False)
        self._path = str(Path(config.get("db_path", "~/.rathole/events.db")).expanduser())
        self._retention_days = config.get("retention_days", 7)
        self._prune_interval = config.get("prune_interval", 3600)

        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._last_prune: float = 0.0

        if self._enabled:
            self._init_db()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def store(self, event: SecurityEvent):
        """Store a single event."""
        if not self._enabled or self._conn is None:
            return

        import json
        with self._lock:
            try:
                self._conn.execute(
                    """INSERT INTO events
                       (timestamp, event_type, severity, source, interface_name,
                        identity_hash, destination_hash, description, details)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.timestamp,
                        event.event_type.name,
                        event.severity.name,
                        event.source,
                        event.interface_name,
                        event.identity_hash,
                        event.destination_hash,
                        event.description,
                        json.dumps(event.details),
                    ),
                )
                self._conn.commit()

                # Update hourly stats
                hour = time.strftime("%Y-%m-%dT%H", time.gmtime(event.timestamp))
                self._conn.execute(
                    """INSERT INTO hourly_stats (hour, event_type, count)
                       VALUES (?, ?, 1)
                       ON CONFLICT(hour, event_type)
                       DO UPDATE SET count = count + 1""",
                    (hour, event.event_type.name),
                )
                self._conn.commit()
            except sqlite3.Error as e:
                log.error("Failed to store event: %s", e)

    def query(
        self,
        event_type: str | None = None,
        severity: str | None = None,
        interface_name: str = "",
        identity_hash: str = "",
        since: float = 0.0,
        limit: int = 100,
    ) -> list[dict]:
        """Query stored events with filters."""
        if not self._enabled or self._conn is None:
            return []

        import json
        conditions = []
        params = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if interface_name:
            conditions.append("interface_name = ?")
            params.append(interface_name)
        if identity_hash:
            conditions.append("identity_hash = ?")
            params.append(identity_hash)
        if since > 0:
            conditions.append("timestamp > ?")
            params.append(since)

        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        with self._lock:
            try:
                cursor = self._conn.execute(
                    f"""SELECT timestamp, event_type, severity, source,
                               interface_name, identity_hash, destination_hash,
                               description, details
                        FROM events WHERE {where}
                        ORDER BY timestamp DESC LIMIT ?""",
                    params,
                )
                return [
                    {
                        "timestamp": row[0],
                        "event_type": row[1],
                        "severity": row[2],
                        "source": row[3],
                        "interface_name": row[4],
                        "identity_hash": row[5],
                        "destination_hash": row[6],
                        "description": row[7],
                        "details": json.loads(row[8]) if row[8] else {},
                    }
                    for row in cursor.fetchall()
                ]
            except sqlite3.Error as e:
                log.error("Event query failed: %s", e)
                return []

    def hourly_stats(self, hours: int = 24) -> list[dict]:
        """Get hourly event counts for the last N hours."""
        if not self._enabled or self._conn is None:
            return []

        cutoff = time.strftime(
            "%Y-%m-%dT%H",
            time.gmtime(time.time() - hours * 3600),
        )

        with self._lock:
            try:
                cursor = self._conn.execute(
                    """SELECT hour, event_type, count FROM hourly_stats
                       WHERE hour >= ? ORDER BY hour""",
                    (cutoff,),
                )
                return [
                    {"hour": row[0], "event_type": row[1], "count": row[2]}
                    for row in cursor.fetchall()
                ]
            except sqlite3.Error as e:
                log.error("Hourly stats query failed: %s", e)
                return []

    def prune(self):
        """Remove events older than retention period."""
        if not self._enabled or self._conn is None:
            return

        now = time.monotonic()
        if now - self._last_prune < self._prune_interval:
            return

        cutoff = time.time() - (self._retention_days * 86400)
        with self._lock:
            try:
                cursor = self._conn.execute(
                    "DELETE FROM events WHERE timestamp < ?", (cutoff,),
                )
                if cursor.rowcount > 0:
                    log.info("Pruned %d old events", cursor.rowcount)
                self._conn.commit()
            except sqlite3.Error as e:
                log.error("Event pruning failed: %s", e)

        self._last_prune = now

    def close(self):
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def event_count(self) -> int:
        """Total number of stored events."""
        if not self._enabled or self._conn is None:
            return 0
        with self._lock:
            try:
                cursor = self._conn.execute("SELECT COUNT(*) FROM events")
                return cursor.fetchone()[0]
            except sqlite3.Error:
                return 0

    def _init_db(self):
        """Initialize the SQLite database."""
        try:
            path = Path(self._path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            log.info("Event store initialized at %s", self._path)
        except (sqlite3.Error, OSError) as e:
            log.error("Failed to initialize event store: %s", e)
            self._conn = None
            self._enabled = False
