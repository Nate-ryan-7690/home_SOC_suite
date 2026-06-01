# ============================================================
# db.py — Night's Watch Home SOC Suite
# All database interactions go through this module.
# No other module touches SQLite directly.
#
# This abstraction means switching from SQLite to PostgreSQL
# in the future requires changes only in this file.
# ============================================================

import sqlite3
import json
import os
from datetime import datetime, timedelta
from contextlib import contextmanager
import config


@contextmanager
def get_connection():
    """Context manager — commit on success, rollback on error."""
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe concurrent access
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _migrate(conn):
    """Idempotent schema migrations. Each ALTER TABLE is wrapped so a
    column that already exists does not abort the run."""
    for stmt in (
        "ALTER TABLE alerts ADD COLUMN analyst_comment TEXT",
        "ALTER TABLE alerts ADD COLUMN reviewed_at      TEXT",
    ):
        try:
            conn.execute(stmt)
        except Exception:
            pass   # column already exists -- safe to ignore


def initialize():
    """Create all tables and indexes if they don't exist.
    Safe to call on every engine startup."""
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS raw_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                collector_name      TEXT NOT NULL,
                raw_payload         TEXT NOT NULL,
                observed_at         DATETIME,
                recorded_at         DATETIME NOT NULL,
                source_host         TEXT,
                raw_event_hash      TEXT UNIQUE,
                normalized_event_id TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                event_id          TEXT PRIMARY KEY,
                schema_version    TEXT,
                collector_name    TEXT,
                source_host       TEXT,
                observed_at       DATETIME,
                ingested_at       DATETIME,
                event_type        TEXT,
                subtype           TEXT,
                actor             TEXT,
                process_path      TEXT,
                destination       TEXT,
                base_severity     TEXT,
                trust_level       TEXT,
                parser_confidence REAL,
                ingest_status     TEXT,
                correlated_at     DATETIME
            );

            CREATE TABLE IF NOT EXISTS detections (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id          INTEGER,
                window_type      TEXT,
                matched_entities TEXT,   -- JSON array of event_ids
                score_factors    TEXT,   -- JSON dict
                confidence       REAL,
                evidence_refs    TEXT,   -- JSON array of event_ids
                created_at       DATETIME
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id         TEXT PRIMARY KEY,
                rule_id          INTEGER,
                severity_current TEXT,
                confidence       REAL,
                status           TEXT DEFAULT 'NEW',
                explanation      TEXT,
                linked_case      TEXT,
                created_at       DATETIME,
                updated_at       DATETIME
            );

            CREATE TABLE IF NOT EXISTS collector_health (
                collector_name         TEXT PRIMARY KEY,
                last_seen              DATETIME,
                last_file_offset       INTEGER DEFAULT 0,
                expected_rate_per_hour REAL,
                last_event_count       INTEGER DEFAULT 0,
                status                 TEXT DEFAULT 'UNKNOWN',
                session_context        TEXT
            );

            CREATE TABLE IF NOT EXISTS baselines (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                collector_name   TEXT,
                baseline_key     TEXT,
                baseline_value   TEXT,
                approved_at      DATETIME,
                version          INTEGER DEFAULT 1
            );

            -- Indexes for correlation query performance
            CREATE INDEX IF NOT EXISTS idx_events_observed_at
                ON events(observed_at);
            CREATE INDEX IF NOT EXISTS idx_events_collector
                ON events(collector_name);
            CREATE INDEX IF NOT EXISTS idx_events_actor
                ON events(actor);
            CREATE INDEX IF NOT EXISTS idx_events_severity
                ON events(base_severity);
            CREATE INDEX IF NOT EXISTS idx_raw_hash
                ON raw_events(raw_event_hash);
            CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status);
        """)
        _migrate(conn)


# ============================================================
# RAW EVENTS
# ============================================================

def insert_raw_event(collector_name, raw_payload, observed_at,
                     source_host, raw_event_hash):
    """Returns True if inserted, False if duplicate (already ingested)."""
    with get_connection() as conn:
        try:
            conn.execute("""
                INSERT INTO raw_events
                    (collector_name, raw_payload, observed_at,
                     recorded_at, source_host, raw_event_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (collector_name, raw_payload, observed_at,
                  datetime.now().isoformat(), source_host, raw_event_hash))
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate hash — already ingested


def insert_raw_events_batch(events: list) -> int:
    """Insert a list of raw event dicts in a single transaction.
    Each dict must have: collector_name, raw_payload, observed_at,
                         source_host, raw_event_hash.
    Returns count of rows actually inserted (duplicates skipped via
    INSERT OR IGNORE — raw_event_hash has a UNIQUE constraint)."""
    if not events:
        return 0
    recorded_at = datetime.now().isoformat()
    rows = [
        (e['collector_name'], e['raw_payload'], e['observed_at'],
         recorded_at, e['source_host'], e['raw_event_hash'])
        for e in events
    ]
    with get_connection() as conn:
        before = conn.total_changes
        conn.executemany("""
            INSERT OR IGNORE INTO raw_events
                (collector_name, raw_payload, observed_at,
                 recorded_at, source_host, raw_event_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, rows)
        return conn.total_changes - before


# ============================================================
# NORMALIZED EVENTS
# ============================================================

def get_pending_raw_events():
    """Return all raw_events not yet normalized (no event_id stamp).
    Called by normalizer.py each cycle."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM raw_events WHERE normalized_event_id IS NULL"
        ).fetchall()


def mark_raw_event_normalized(raw_id, event_id):
    """Stamp a raw_event row with the event_id it was normalized into.
    This is the integrity link — recompute event_id from raw_event_hash
    at any time to verify the events table has not been tampered with."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE raw_events SET normalized_event_id = ? WHERE id = ?",
            (event_id, raw_id)
        )


def insert_event(event: dict):
    with get_connection() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO events
                (event_id, schema_version, collector_name, source_host,
                 observed_at, ingested_at, event_type, subtype, actor,
                 process_path, destination, base_severity, trust_level,
                 parser_confidence, ingest_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["event_id"],          event.get("schema_version"),
            event["collector_name"],    event.get("source_host"),
            event.get("observed_at"),   event.get("ingested_at"),
            event.get("event_type"),    event.get("subtype"),
            event.get("actor"),         event.get("process_path"),
            event.get("destination"),   event.get("base_severity"),
            event.get("trust_level"),   event.get("parser_confidence"),
            event.get("ingest_status"),
        ))


def insert_events_batch(events: list):
    """Insert a list of normalized event dicts in a single transaction.
    Duplicates silently ignored (INSERT OR IGNORE on event_id)."""
    if not events:
        return
    rows = [(
        e["event_id"],          e.get("schema_version"),
        e["collector_name"],    e.get("source_host"),
        e.get("observed_at"),   e.get("ingested_at"),
        e.get("event_type"),    e.get("subtype"),
        e.get("actor"),         e.get("process_path"),
        e.get("destination"),   e.get("base_severity"),
        e.get("trust_level"),   e.get("parser_confidence"),
        e.get("ingest_status"),
    ) for e in events]
    with get_connection() as conn:
        conn.executemany("""
            INSERT OR IGNORE INTO events
                (event_id, schema_version, collector_name, source_host,
                 observed_at, ingested_at, event_type, subtype, actor,
                 process_path, destination, base_severity, trust_level,
                 parser_confidence, ingest_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)


def mark_raw_events_normalized_batch(pairs: list):
    """Stamp raw_events rows with their normalized_event_id in one transaction.
    pairs = list of (raw_id, event_id) tuples."""
    if not pairs:
        return
    ts = datetime.now().isoformat()
    with get_connection() as conn:
        conn.executemany(
            "UPDATE raw_events SET normalized_event_id = ? WHERE id = ?",
            [(event_id, raw_id) for raw_id, event_id in pairs]
        )


def get_uncorrelated_events():
    """Return all events not yet processed by the correlator.
    Called by correlator.run_all() each cycle."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM events WHERE correlated_at IS NULL"
        ).fetchall()


def mark_event_correlated(event_id):
    """Stamp an event row with the time it was processed by the correlator.
    Prevents single-event rules from re-firing on the same event."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE events SET correlated_at = ? WHERE event_id = ?",
            (datetime.now().isoformat(), event_id)
        )


def mark_events_correlated_batch(event_ids: list):
    """Stamp a list of event_ids as correlated in a single transaction."""
    if not event_ids:
        return
    ts = datetime.now().isoformat()
    with get_connection() as conn:
        conn.executemany(
            "UPDATE events SET correlated_at = ? WHERE event_id = ?",
            [(ts, eid) for eid in event_ids]
        )


def count_detections():
    """Returns total number of rows in the detections table."""
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]


def count_alerts():
    """Returns total number of rows in the alerts table."""
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def get_raw_events_for_integrity_check():
    """Return collector_name, raw_event_hash, normalized_event_id for every
    raw_events row where both hash fields are populated.  Used by Rule 18
    Part C to recompute and verify the integrity chain."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT collector_name, raw_event_hash, normalized_event_id
            FROM   raw_events
            WHERE  raw_event_hash      IS NOT NULL
              AND  normalized_event_id IS NOT NULL
        """).fetchall()
        return [dict(r) for r in rows]


def get_all_collector_health():
    """Return all collector_health rows as a list of dicts. Used by Rule 18."""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM collector_health").fetchall()
        return [dict(r) for r in rows]


def count_recent_alerts(seconds, reference_time=None):
    """Count alerts with created_at within the last N seconds.

    reference_time: optional datetime — defaults to utcnow().
    Pass an explicit value in tests to control the clock."""
    _now   = reference_time or datetime.now()
    cutoff = (_now - timedelta(seconds=seconds)).strftime('%Y-%m-%d %H:%M:%S')
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= ?", (cutoff,)
        ).fetchone()[0]


def get_events_in_window(window_seconds, collector_name=None,
                         event_type=None, severity=None, reference_time=None):
    """Fetch normalized events within a time window. Used by correlator.

    reference_time: optional datetime — defaults to utcnow().
    Pass an explicit value in tests so events with fixed observed_at
    values fall inside the window without depending on wall clock time."""
    _now   = reference_time or datetime.now()
    # strftime, not isoformat — observed_at values use space separator
    # ('2026-03-20 03:00:00'). isoformat() produces 'T' separator which
    # compares incorrectly in SQLite string ordering (space < 'T' in ASCII).
    cutoff = (_now - timedelta(seconds=window_seconds)).strftime('%Y-%m-%d %H:%M:%S')
    query  = "SELECT * FROM events WHERE observed_at >= ?"
    params = [cutoff]
    if collector_name:
        query += " AND collector_name = ?"
        params.append(collector_name)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if severity:
        query += " AND base_severity = ?"
        params.append(severity)
    with get_connection() as conn:
        return conn.execute(query, params).fetchall()


def get_harbinger_events_by_parent(parent_fragment, window_seconds, reference_time=None):
    """Return normalized PROCESS events for Harbinger-logged processes whose raw
    log line contains parent_fragment (case-insensitive LIKE match).

    Used by Rule 9 to find WMI-spawned processes.  The parent process name is
    present in the Harbinger raw log ('Parent: WmiPrvSE (PID)') but is not in
    the normalized schema — so this function JOINs events to raw_events via
    normalized_event_id to access it without changing the schema.
    """
    _now   = reference_time or datetime.now()
    cutoff = (_now - timedelta(seconds=window_seconds)).strftime('%Y-%m-%d %H:%M:%S')
    with get_connection() as conn:
        return conn.execute("""
            SELECT e.* FROM events e
            JOIN raw_events r ON r.normalized_event_id = e.event_id
            WHERE e.event_type = 'PROCESS'
              AND e.observed_at >= ?
              AND LOWER(r.raw_payload) LIKE LOWER(?)
        """, (cutoff, f'%{parent_fragment}%')).fetchall()


def get_harbinger_scripting_spawn_bad_parent(
    bad_parents, scripting_engines, window_seconds,
    exclude_cmd_fragment=None, reference_time=None
):
    """Return Harbinger PROCESS events where a scripting engine was spawned
    by a known-bad parent process within window_seconds.

    bad_parents: list of parent names matched case-insensitively against
                 'Parent: <name>' in the raw log line.
    scripting_engines: list of child process names matched against actor field.
    exclude_cmd_fragment: optional -- skip events whose CMD contains this string
                          (used to exclude the suite launcher).

    Used by Rules 43, 44, 45, 46, 48.
    """
    _now   = reference_time or datetime.now()
    cutoff = (_now - timedelta(seconds=window_seconds)).strftime('%Y-%m-%d %H:%M:%S')

    parent_clauses = " OR ".join(
        "LOWER(r.raw_payload) LIKE ?" for _ in bad_parents
    )
    parent_params = [
        f"%parent: {p.lower().replace('.exe', '')}%" for p in bad_parents
    ]

    engine_clauses = " OR ".join(
        "LOWER(e.actor) LIKE ?" for _ in scripting_engines
    )
    engine_params = [
        f"%{e.lower().replace('.exe', '')}%" for e in scripting_engines
    ]

    exclude_clause = ""
    exclude_params = []
    if exclude_cmd_fragment:
        exclude_clause = "AND LOWER(r.raw_payload) NOT LIKE ?"
        exclude_params = [f"%{exclude_cmd_fragment.lower()}%"]

    with get_connection() as conn:
        return conn.execute(f"""
            SELECT e.* FROM events e
            JOIN raw_events r ON r.normalized_event_id = e.event_id
            WHERE e.collector_name = 'harbinger'
              AND e.event_type = 'PROCESS'
              AND e.observed_at >= ?
              AND ({parent_clauses})
              AND ({engine_clauses})
              {exclude_clause}
        """, [cutoff] + parent_params + engine_params + exclude_params).fetchall()


def get_harbinger_obfuscated_cmd(
    window_seconds, exclude_cmd_fragment=None, reference_time=None
):
    """Return Harbinger PROCESS events where the command line contains
    encoded, hidden, or obfuscated execution flags.

    Triggers (any sufficient):
      - -EncodedCommand or shorthand -enc
      - -WindowStyle Hidden combined with -ExecutionPolicy Bypass
      - -WindowStyle Hidden combined with -NonInteractive and -NoProfile

    exclude_cmd_fragment: skip events whose CMD contains this string
                          (suite launcher exclusion).

    Used by Rule 47.
    """
    _now   = reference_time or datetime.now()
    cutoff = (_now - timedelta(seconds=window_seconds)).strftime('%Y-%m-%d %H:%M:%S')

    exclude_clause = ""
    exclude_params = []
    if exclude_cmd_fragment:
        exclude_clause = "AND LOWER(r.raw_payload) NOT LIKE ?"
        exclude_params = [f"%{exclude_cmd_fragment.lower()}%"]

    with get_connection() as conn:
        return conn.execute(f"""
            SELECT e.* FROM events e
            JOIN raw_events r ON r.normalized_event_id = e.event_id
            WHERE e.collector_name = 'harbinger'
              AND e.event_type = 'PROCESS'
              AND e.observed_at >= ?
              AND (
                  LOWER(r.raw_payload) LIKE '%-encodedcommand%'
                  OR LOWER(r.raw_payload) LIKE '% -enc %'
                  OR (    LOWER(r.raw_payload) LIKE '%-windowstyle hidden%'
                      AND LOWER(r.raw_payload) LIKE '%-executionpolicy bypass%')
                  OR (    LOWER(r.raw_payload) LIKE '%-windowstyle hidden%'
                      AND LOWER(r.raw_payload) LIKE '%-noninteractive%'
                      AND LOWER(r.raw_payload) LIKE '%-noprofile%')
              )
              {exclude_clause}
        """, [cutoff] + exclude_params).fetchall()


# ============================================================
# DETECTIONS
# ============================================================

def insert_detection(detection: dict):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO detections
                (rule_id, window_type, matched_entities,
                 score_factors, confidence, evidence_refs, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            detection["rule_id"],
            detection["window_type"],
            json.dumps(detection.get("matched_entities", [])),
            json.dumps(detection.get("score_factors", {})),
            detection["confidence"],
            json.dumps(detection.get("evidence_refs", [])),
            datetime.now().isoformat(),
        ))


# ============================================================
# ALERTS
# ============================================================

def insert_alert(alert: dict):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_connection() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO alerts
                (alert_id, rule_id, severity_current, confidence,
                 status, explanation, linked_case, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["alert_id"],          alert["rule_id"],
            alert["severity_current"],  alert["confidence"],
            alert.get("status", "NEW"), alert["explanation"],
            alert.get("linked_case"),   now, now,
        ))


def get_active_alerts():
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM alerts WHERE status = 'NEW' ORDER BY created_at DESC"
        ).fetchall()


def update_alert_status(alert_id, status):
    with get_connection() as conn:
        conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
            (status, datetime.now().isoformat(), alert_id),
        )


def get_alert_by_id(alert_id):
    """Return a single alert row by its ID, or None if not found."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?",
            (alert_id,)
        ).fetchone()


def update_alert_classify(alert_id, status, analyst_comment=None):
    """Set analyst classification (RESOLVED / FALSE_POSITIVE / MONITOR).
    Records reviewed_at timestamp and optional analyst comment.
    COALESCE ensures a None comment does not overwrite an existing one."""
    now = datetime.now().isoformat()
    with get_connection() as conn:
        conn.execute(
            """UPDATE alerts
               SET status          = ?,
                   analyst_comment = COALESCE(?, analyst_comment),
                   reviewed_at     = ?,
                   updated_at      = ?
               WHERE alert_id      = ?""",
            (status, analyst_comment, now, now, alert_id),
        )


# ============================================================
# COLLECTOR HEALTH + FILE OFFSETS
# ============================================================

def get_file_offset(collector_name):
    """Returns last byte offset so the parser never re-reads processed lines."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT last_file_offset FROM collector_health WHERE collector_name = ?",
            (collector_name,)
        ).fetchone()
        return row["last_file_offset"] if row else 0


def get_session_context(collector_name):
    """Returns stored session context for a collector.
    Used by log_parser to persist the Sentinel session date across parse cycles."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT session_context FROM collector_health WHERE collector_name = ?",
            (collector_name,)
        ).fetchone()
        return row["session_context"] if row else None


def update_collector_health(collector_name, offset, event_count, status,
                             session_context=None):
    """Update collector health record.
    session_context: optional — only overwrites stored value when explicitly provided.
    COALESCE ensures an existing session date is never wiped by a None update."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO collector_health
                (collector_name, last_seen, last_file_offset,
                 last_event_count, status, session_context)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(collector_name) DO UPDATE SET
                last_seen        = excluded.last_seen,
                last_file_offset = excluded.last_file_offset,
                last_event_count = excluded.last_event_count,
                status           = excluded.status,
                session_context  = COALESCE(excluded.session_context, session_context)
        """, (collector_name, datetime.now().isoformat(),
              offset, event_count, status, session_context))


# ============================================================
# RETENTION ENFORCEMENT
# Call once per campaign cycle to purge expired records.
# ============================================================

def enforce_retention():
    with get_connection() as conn:
        if config.RETENTION_RAW_EVENTS:
            cutoff = (datetime.now() - timedelta(
                days=config.RETENTION_RAW_EVENTS)).isoformat()
            conn.execute(
                "DELETE FROM raw_events WHERE recorded_at < ?", (cutoff,))

        if config.RETENTION_EVENTS:
            cutoff = (datetime.now() - timedelta(
                days=config.RETENTION_EVENTS)).isoformat()
            conn.execute(
                "DELETE FROM events WHERE ingested_at < ?", (cutoff,))

        if config.RETENTION_DETECTIONS:
            cutoff = (datetime.now() - timedelta(
                days=config.RETENTION_DETECTIONS)).isoformat()
            conn.execute(
                "DELETE FROM detections WHERE created_at < ?", (cutoff,))
        # alerts: no deletion — RETENTION_ALERTS is None
