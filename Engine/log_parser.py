# ============================================================
# log_parser.py — Night's Watch Home SOC Suite
# Reads collector log files, extracts raw events, stores in SQLite.
# Handles per-collector format differences and log rotation.
#
# Collector format reference:
#   Standard : [yyyy-MM-dd HH:mm:ss] [SEVERITY] Message
#   Sentinel : [HH:mm:ss] [SEVERITY] Message (date from session header)
#   Watchman : Standard format, but observed_at = Time: field in message
# ============================================================

import os
import re
import hashlib
from datetime import datetime

import config
import db


# ============================================================
# REGEX PATTERNS
# ============================================================

# Standard: [2026-03-20 19:00:00] [SEVERITY] Message
STANDARD_RE = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[([^\]]+)\] (.+)$'
)

# Sentinel: [19:00:00] [SEVERITY] Message
SENTINEL_RE = re.compile(
    r'^\[(\d{2}:\d{2}:\d{2})\] \[([^\]]+)\] (.+)$'
)

# Sentinel session header
SENTINEL_HEADER_RE = re.compile(
    r'^--- Network Security Log Started: (\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'
)

# Watchman actual event time embedded in message
WATCHMAN_TIME_RE = re.compile(
    r'Time: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
)

# Structural / header lines — not events, skip them
SKIP_PREFIXES = (
    '---',
    'SNAPSHOT:',
    'BASELINE PORT:',
    'Format:',
    '----',
)


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _hash(line):
    """SHA256 of raw log line — used for deduplication."""
    return hashlib.sha256(line.encode('utf-8', errors='replace')).hexdigest()


def _is_structural(line):
    """Returns True if line is a header or separator, not an event."""
    return any(line.startswith(p) for p in SKIP_PREFIXES)


def _scan_sentinel_header(log_path):
    """Scan Sentinel log from byte 0 to find the session start date.
    Called on first run and after log rotation.
    Returns 'yyyy-MM-dd' string or None if header not found."""
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                m = SENTINEL_HEADER_RE.match(line.strip())
                if m:
                    return datetime.strptime(
                        m.group(1), '%m/%d/%Y %H:%M:%S'
                    ).strftime('%Y-%m-%d')
    except (OSError, ValueError):
        pass
    return None


def _parse_line(collector_name, line, session_date=None):
    """Parse a single log line.
    Returns dict with observed_at, severity, message — or None on no match."""

    if collector_name == 'sentinel':
        m = SENTINEL_RE.match(line)
        if not m:
            return None
        time_str, severity, message = m.groups()
        observed_at = f"{session_date} {time_str}" if session_date else None
        return {'observed_at': observed_at, 'severity': severity,
                'message': message}

    # Standard format — all other collectors
    m = STANDARD_RE.match(line)
    if not m:
        return None
    timestamp, severity, message = m.groups()

    if collector_name == 'watchman':
        # observed_at = actual event time (Time: field).
        # The outer timestamp is when Watchman logged it — can be days later
        # for historical events loaded at startup. Rule 4 needs the real time.
        time_match = WATCHMAN_TIME_RE.search(message)
        observed_at = time_match.group(1) if time_match else timestamp
    else:
        observed_at = timestamp

    return {'observed_at': observed_at, 'severity': severity,
            'message': message}


# ============================================================
# CORE PARSER
# ============================================================

def parse_log_file(collector_name, log_path):
    """Read new lines from a log file since last stored offset.

    Returns:
        events             — list of raw_event dicts
        final_offset       — byte offset after last processed line
        new_session_context — date string if new Sentinel header found,
                              None otherwise (db COALESCE preserves existing)
    """
    stored_offset = db.get_file_offset(collector_name)
    current_size  = os.path.getsize(log_path)

    # Log rotation: file is smaller than stored offset
    # Reset to 0 so the new file is read from the start
    if current_size < stored_offset:
        stored_offset = 0

    # No new data since last cycle
    if current_size == stored_offset:
        return [], stored_offset, None

    # Sentinel session date resolution
    session_date        = None
    new_session_context = None

    if collector_name == 'sentinel':
        if stored_offset == 0:
            # First run or post-rotation: scan file for session header
            session_date        = _scan_sentinel_header(log_path)
            new_session_context = session_date  # will be persisted to DB
        else:
            # Resume: load previously stored date
            session_date = db.get_session_context('sentinel')

    # Read and parse new lines — capped at INGEST_LINE_CAP per cycle.
    # If the cap is hit the offset is saved at the break point so the
    # next cycle continues from where this one stopped.  Large backlogs
    # (e.g. first-run Bulwark) are drained incrementally without blocking
    # the main loop for minutes at a time.
    events       = []
    final_offset = stored_offset
    lines_read   = 0

    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        f.seek(stored_offset)

        while True:
            if lines_read >= config.INGEST_LINE_CAP:
                break

            line = f.readline()
            if not line:
                break

            final_offset = f.tell()
            lines_read  += 1
            line         = line.rstrip('\r\n')

            if not line or _is_structural(line):
                continue

            parsed = _parse_line(collector_name, line, session_date)
            if parsed is None:
                continue

            events.append({
                'collector_name': collector_name,
                'raw_payload':    line,
                'observed_at':    parsed['observed_at'],
                'source_host':    config.SOURCE_HOST,
                'raw_event_hash': _hash(line),
            })

    return events, final_offset, new_session_context


# ============================================================
# INGEST FUNCTIONS
# ============================================================

def ingest_collector(collector_name):
    """Parse and store new events from one collector's log file.
    Returns count of new events inserted (duplicates excluded)."""

    log_path = config.LOG_FILES.get(collector_name)
    if not log_path:
        return 0

    # Log file missing — collector is silent
    # Silence is a signal, not a reliability bug — mark accordingly
    if not os.path.exists(log_path):
        db.update_collector_health(
            collector_name,
            offset=db.get_file_offset(collector_name),
            event_count=0,
            status='SILENT'
        )
        return 0

    events, final_offset, new_session_context = parse_log_file(
        collector_name, log_path
    )

    count = db.insert_raw_events_batch(events)

    db.update_collector_health(
        collector_name,
        offset=final_offset,
        event_count=count,
        status='ACTIVE',
        session_context=new_session_context,  # None = COALESCE keeps existing
    )
    return count


def ingest_all():
    """Ingest new lines from all collector log files.
    Returns dict mapping collector_name to new event count."""
    results = {}
    for collector_name in config.LOG_FILES:
        results[collector_name] = ingest_collector(collector_name)
    return results


# ============================================================
# ARCHIVE INGESTION — first-run catch-up
# TODO: Scan config.ARCHIVE_DIR for rotated log files predating
# the engine's first run. Each archive ingested once, tracked in
# collector_health to prevent re-ingestion.
# ============================================================
