# ============================================================
# health_db.py — Collector Heartbeat Database
# Night's Watch Home SOC Suite
#
# Separate from hocsoc.db — liveness data must not be mixed
# with forensic evidence. Two independent stores = two targets
# for an attacker attempting to hide collector suppression.
#
# Tables:
#   collector_status     — current snapshot, one row per collector,
#                          upserted every engine cycle
#   collector_heartbeats — append-only history, 48h retention
#
# The JSON health files (written by collector runspaces) are the
# ground truth. This database is the engine's derived cache of
# what it observed. Discrepancy between the two is itself a signal.
# ============================================================

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

import config


# ============================================================
# CONNECTION
# ============================================================

@contextmanager
def get_connection():
    conn = sqlite3.connect(config.HEALTH_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# SCHEMA
# ============================================================

def initialize():
    """Create tables if they don't exist. Safe to call on every startup."""
    os.makedirs(os.path.dirname(config.HEALTH_DB_PATH), exist_ok=True)
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS collector_status (
                collector_name   TEXT PRIMARY KEY,
                last_heartbeat   DATETIME,
                last_recorded    DATETIME,
                lag_seconds      REAL,
                heartbeat_cycle  INTEGER DEFAULT 0,
                uptime           TEXT,
                status           TEXT DEFAULT 'UNKNOWN',
                health_file_path TEXT
            );

            CREATE TABLE IF NOT EXISTS collector_heartbeats (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                collector_name   TEXT NOT NULL,
                heartbeat_ts     DATETIME,
                recorded_at      DATETIME NOT NULL,
                lag_seconds      REAL,
                heartbeat_cycle  INTEGER,
                uptime           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_heartbeats_collector_ts
                ON collector_heartbeats(collector_name, recorded_at);
        """)


# ============================================================
# WRITES
# ============================================================

def upsert_collector_status(collector_name, heartbeat_ts, last_recorded,
                             cycle, uptime, status, lag_seconds=None):
    """Upsert the current snapshot row for a collector.
    Called every engine cycle for every collector regardless of
    whether the health file was readable."""
    health_file = config.HEALTH_FILES.get(collector_name)
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO collector_status
                (collector_name, last_heartbeat, last_recorded, lag_seconds,
                 heartbeat_cycle, uptime, status, health_file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(collector_name) DO UPDATE SET
                last_heartbeat   = excluded.last_heartbeat,
                last_recorded    = excluded.last_recorded,
                lag_seconds      = excluded.lag_seconds,
                heartbeat_cycle  = excluded.heartbeat_cycle,
                uptime           = excluded.uptime,
                status           = excluded.status,
                health_file_path = excluded.health_file_path
        """, (
            collector_name,
            heartbeat_ts.isoformat() if heartbeat_ts else None,
            last_recorded.isoformat(),
            lag_seconds,
            cycle,
            uptime,
            status,
            health_file,
        ))


def insert_heartbeat(collector_name, heartbeat_ts, recorded_at,
                     cycle, uptime, lag_seconds):
    """Append one history row. Called only when the health file was
    successfully read — UNKNOWN states do not produce history rows."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO collector_heartbeats
                (collector_name, heartbeat_ts, recorded_at,
                 lag_seconds, heartbeat_cycle, uptime)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            collector_name,
            heartbeat_ts.isoformat() if heartbeat_ts else None,
            recorded_at.isoformat(),
            lag_seconds,
            cycle,
            uptime,
        ))


# ============================================================
# READS
# ============================================================

def get_all_collector_status():
    """Return all collector_status rows as list of dicts.
    Used by Rule 18 and the dashboard."""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM collector_status").fetchall()
        return [dict(r) for r in rows]


def get_collector_status(collector_name):
    """Return single collector status dict or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM collector_status WHERE collector_name = ?",
            (collector_name,)
        ).fetchone()
        return dict(row) if row else None


# ============================================================
# RETENTION
# ============================================================

def enforce_retention():
    """Purge collector_heartbeats older than HEARTBEAT_RETENTION_HOURS.
    collector_status rows are never purged — one row per collector always."""
    cutoff = (datetime.now() - timedelta(
        hours=config.HEARTBEAT_RETENTION_HOURS)).isoformat()
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM collector_heartbeats WHERE recorded_at < ?",
            (cutoff,)
        )
