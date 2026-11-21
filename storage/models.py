"""SQLite models and shared storage API. Python standard library only."""
from __future__ import annotations
import json
import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Mapping, Any, Callable
from normalizer.schema import normalize_event

DDL = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    source_type TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    username TEXT,
    hostname TEXT,
    action TEXT NOT NULL,
    severity TEXT NOT NULL,
    dst_port INTEGER,
    process_name TEXT,
    command_line TEXT,
    signature TEXT,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp_utc ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (status IN ('New', 'In Progress', 'Closed')),
    assigned_analyst TEXT,
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS incident_events (
    incident_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, event_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ingested_files (
    digest TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    stored_events INTEGER NOT NULL,
    imported_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

COLUMNS = (
    "timestamp_utc", "source_type", "src_ip", "dst_ip", "username",
    "hostname", "action", "severity", "dst_port", "process_name",
    "command_line", "signature", "raw_json"
)


def connect(db_path: str | Path = "data/soc.db") -> sqlite3.Connection:
    path = Path(db_path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(DDL)
    conn.commit()


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Atomic unit of work, including when called inside another transaction.

    SQLite connection context managers COMMIT on leaving even when nested;
    use a savepoint so a caller's transaction cannot be committed early.
    """
    if conn.in_transaction:
        conn.execute("SAVEPOINT soc_nested_write")
        try:
            yield
        except BaseException:
            conn.execute("ROLLBACK TO SAVEPOINT soc_nested_write")
            conn.execute("RELEASE SAVEPOINT soc_nested_write")
            raise
        else:
            conn.execute("RELEASE SAVEPOINT soc_nested_write")
    else:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()


def _digest_prefix(source: str, *, year: int | None = None,
                   tz: str | None = None) -> bytes:
    options = {
        "source": source,
        "year": year if source == "auth_log" else None,
        "tz": tz if source == "auth_log" else None,
    }
    return json.dumps(options, sort_keys=True).encode("utf-8") + b"\0"


def file_digest(source: str, data: bytes, *, year: int | None = None,
                tz: str | None = None) -> str:
    """Same content+parser-options fingerprint for CLI and dashboard uploads."""
    return hashlib.sha256(_digest_prefix(source, year=year, tz=tz) + data).hexdigest()


def file_digest_path(source: str, path: str | Path, *, year: int | None = None,
                     tz: str | None = None) -> str:
    """Stream file hash; do not read a large log completely into memory."""
    digest = hashlib.sha256(_digest_prefix(source, year=year, tz=tz))
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ingest_file(conn: sqlite3.Connection, source: str, digest: str,
                records_factory: Callable[[], Iterable[Mapping[str, Any]]],
                after_insert: Callable[[], None] | None = None) -> tuple[int, bool]:
    """Exactly-once per file and parsing configuration, atomically.

    The events, optional incident update and fingerprint are ALL committed
    together. On any failure all changes roll back. Returns (stored, duplicate).
    The factory is not called at all for a duplicate file.
    """
    with transaction(conn):
        if conn.execute("SELECT 1 FROM ingested_files WHERE digest=?", (digest,)).fetchone():
            return 0, True
        stored = insert_events(conn, records_factory())
        if after_insert is not None:
            after_insert()
        conn.execute(
            "INSERT INTO ingested_files(digest, source, stored_events) VALUES (?, ?, ?)",
            (digest, source, stored),
        )
        return stored, False


def insert_events(conn: sqlite3.Connection,
                  records: Iterable[Mapping[str, Any]], batch_size: int = 500) -> int:
    """Validate and persist events with executemany; returns inserted row count."""
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    statement = f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({', '.join('?' for _ in COLUMNS)})"
    buffer: list[tuple] = []
    total = 0
    def flush() -> int:
        if not buffer:
            return 0
        conn.executemany(statement, buffer)
        n = len(buffer)
        buffer.clear()
        return n
    with transaction(conn):
        for raw in records:
            record = normalize_event(raw)
            buffer.append(tuple(
                json.dumps(record['raw'], ensure_ascii=False, default=str) if col == 'raw_json' else record[col]
                for col in COLUMNS
            ))
            if len(buffer) >= batch_size:
                total += flush()
        total += flush()
    return total


def list_events(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all stored normalized events, ordered by event timestamp."""
    rows = conn.execute("SELECT * FROM events ORDER BY timestamp_utc, id").fetchall()
    result = []
    for row in rows:
        event = dict(row)
        event["raw"] = json.loads(event.pop("raw_json"))
        result.append(event)
    return result


def insert_incident(conn: sqlite3.Connection, record: Mapping[str, Any]) -> int:
    """An engine result needs rule_id, title, severity, first/last seen and event_ids."""
    event_ids = list(dict.fromkeys(int(x) for x in record.get("event_ids", [])))
    if not event_ids:
        raise ValueError("incident must reference at least one event_id")
    allowed = ("rule_id", "title", "severity", "first_seen_utc", "last_seen_utc")
    for key in allowed:
        if not record.get(key):
            raise ValueError(f"Missing incident field: {key}")
    with transaction(conn):
        cur = conn.execute(
            """INSERT INTO incidents
               (rule_id,title,severity,status,assigned_analyst,first_seen_utc,last_seen_utc,summary)
               VALUES (?,?,?,?,?,?,?,?)""",
            (record["rule_id"],record["title"],record["severity"],
             record.get("status", "New"),record.get("assigned_analyst"),
             record["first_seen_utc"],record["last_seen_utc"],record.get("summary")),
        )
        incident_id = int(cur.lastrowid)
        conn.executemany(
            "INSERT INTO incident_events(incident_id,event_id) VALUES (?,?)",
            [(incident_id, event_id) for event_id in event_ids],
        )
    return incident_id


def set_incident_status(conn: sqlite3.Connection, incident_id: int,
                        status: str, assigned_analyst: str | None = None) -> None:
    if status not in ("New", "In Progress", "Closed"):
        raise ValueError("Invalid incident status")
    with conn:
        conn.execute(
            "UPDATE incidents SET status=?,assigned_analyst=? WHERE incident_id=?",
            (status, assigned_analyst, incident_id),
        )


def counts(conn: sqlite3.Connection) -> tuple[int, int]:
    return (
        conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
    )
