# ============================================================
# engine.py — Night's Watch Home SOC Suite
# Main correlation engine — Program 1 (The Brain).
#
# Run as:  python engine.py
# Requires: Administrator elevation (collectors write Admin-only logs)
#
# Pipeline each cycle:
#   0. read_health_files()         — read all 12 health JSONs → hocsoc_health.db
#   1. log_parser.ingest_all()     — read new lines from all collector logs
#   2. normalizer.normalize_pending() — map raw_events -> events table
#   3. correlator.run_all()        — apply all 17 implemented rules
#   4. alert_manager.process_new_alerts() — write NEW alerts to Alert_Log.txt
#   5. db.enforce_retention()      — purge events older than retention window
#
# Poll interval: config.ENGINE_POLL_INTERVAL (default 300s / 5 min)
# Engine log:    Logs/Engine_Log.txt  (one status line per cycle)
# Alert log:     Logs/Alert_Log.txt   (one line per alert)
#
# Shutdown: Ctrl+C — logs clean shutdown and exits.
# ============================================================

import json
import os
import sys
import time
from datetime import datetime

import config
import db
import health_db
import log_parser
import normalizer
import correlator
import alert_manager


# ============================================================
# ENGINE LOG
# Separate from Alert_Log — records cycle health, not alerts.
# ============================================================

ENGINE_LOG = os.path.join(config.LOG_DIR, 'Engine_Log.txt')


def _log(severity: str, message: str):
    ts   = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] [{severity}] {message}"
    print(line)
    os.makedirs(os.path.dirname(ENGINE_LOG), exist_ok=True)
    with open(ENGINE_LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


# ============================================================
# HEALTH FILE READER
# Step 0 of each cycle — reads all 12 collector health JSONs,
# updates hocsoc_health.db, and returns count of successful reads.
# Never raises — unreadable/missing files upsert UNKNOWN status.
# ============================================================

def read_health_files():
    """Read all collector health JSON files into health_db.
    Returns count of files successfully parsed."""
    now     = datetime.now()
    success = 0

    for collector_name, health_file in config.HEALTH_FILES.items():
        try:
            if not os.path.exists(health_file):
                health_db.upsert_collector_status(
                    collector_name=collector_name,
                    heartbeat_ts=None,
                    last_recorded=now,
                    cycle=0,
                    uptime=None,
                    status='UNKNOWN',
                )
                continue

            with open(health_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            ts_str = data.get('timestamp')
            try:
                heartbeat_ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            except (TypeError, ValueError):
                heartbeat_ts = None

            if heartbeat_ts is None:
                lag    = None
                status = 'UNKNOWN'
            else:
                lag    = (now - heartbeat_ts).total_seconds()
                status = 'ACTIVE' if lag <= config.HEARTBEAT_SILENCE_THRESHOLD else 'DOWN'

            cycle  = data.get('cycle', 0)
            uptime = data.get('uptime')

            health_db.upsert_collector_status(
                collector_name=collector_name,
                heartbeat_ts=heartbeat_ts,
                last_recorded=now,
                cycle=cycle,
                uptime=uptime,
                status=status,
                lag_seconds=lag,
            )

            if heartbeat_ts is not None:
                health_db.insert_heartbeat(
                    collector_name=collector_name,
                    heartbeat_ts=heartbeat_ts,
                    recorded_at=now,
                    cycle=cycle,
                    uptime=uptime,
                    lag_seconds=lag,
                )

            success += 1

        except Exception:
            # Never crash the cycle — unreadable file → UNKNOWN
            health_db.upsert_collector_status(
                collector_name=collector_name,
                heartbeat_ts=None,
                last_recorded=now,
                cycle=0,
                uptime=None,
                status='UNKNOWN',
            )

    return success


# ============================================================
# SINGLE CYCLE
# ============================================================

def run_cycle():
    """Execute one full pipeline cycle. Returns summary dict."""
    cycle_start = datetime.now()

    # 0. Collector heartbeats
    health_read = read_health_files()

    # 1. Ingest
    ingest_counts = log_parser.ingest_all()
    total_ingested = sum(ingest_counts.values())

    # 2. Normalize
    normalized = normalizer.normalize_pending()

    # 3. Correlate
    corr = correlator.run_all()

    # 4. Alert output
    am = alert_manager.process_new_alerts()

    # 5. Retention
    db.enforce_retention()
    health_db.enforce_retention()

    elapsed = (datetime.now() - cycle_start).total_seconds()

    return {
        'health_read':    health_read,
        'ingested':       total_ingested,
        'ingest_detail':  ingest_counts,
        'normalized':     normalized,
        'events_corr':    corr['events_processed'],
        'new_detections': corr['new_detections'],
        'new_alerts':     corr['new_alerts'],
        'alerts_written': am['alerts_written'],
        'flood_active':   am['flood_active'],
        'elapsed_s':      round(elapsed, 2),
    }


# ============================================================
# STARTUP CHECKS
# ============================================================

def startup():
    """Initialize DB, verify log directory, log engine start."""
    db.initialize()
    health_db.initialize()

    os.makedirs(config.LOG_DIR, exist_ok=True)

    _log('OK', (
        f"Engine started. "
        f"DB: {config.DB_PATH}. "
        f"Poll interval: {config.ENGINE_POLL_INTERVAL}s. "
        f"Collectors monitored: {len(config.LOG_FILES)}."
    ))

    # Log which collectors have existing log files vs missing
    missing = [
        name for name, path in config.LOG_FILES.items()
        if not os.path.exists(path)
    ]
    if missing:
        _log('SUSPICIOUS', (
            f"COLLECTOR_SILENT at startup: {', '.join(missing)}. "
            f"Log files not found — collector may not be running."
        ))
    else:
        _log('OK', f"All {len(config.LOG_FILES)} collector log files present.")


# ============================================================
# MAIN LOOP
# ============================================================

def main():
    startup()

    cycle = 0
    while True:
        cycle += 1
        try:
            summary = run_cycle()

            # Build a concise status line — only log detail when something happened
            parts = [f"cycle={cycle}"]
            if summary['health_read'] < len(config.HEALTH_FILES):
                parts.append(f"health={summary['health_read']}/{len(config.HEALTH_FILES)}")
            parts.append(f"ingested={summary['ingested']}")
            parts.append(f"normalized={summary['normalized']}")
            if summary['new_detections']:
                parts.append(f"detections={summary['new_detections']}")
            if summary['new_alerts']:
                parts.append(f"alerts={summary['new_alerts']}")
            if summary['flood_active']:
                parts.append('FLOOD_ACTIVE')
            parts.append(f"elapsed={summary['elapsed_s']}s")

            severity = 'SUSPICIOUS' if summary['flood_active'] else 'OK'
            _log(severity, ' | '.join(parts))

            # Per-collector ingest detail — only log non-zero counts
            active = {k: v for k, v in summary['ingest_detail'].items() if v > 0}
            if active:
                detail = ', '.join(f"{k}={v}" for k, v in active.items())
                _log('OK', f"Ingest detail: {detail}")

            # Catch-up warning — collectors that hit the line cap still have backlog
            capped = [
                k for k, v in summary['ingest_detail'].items()
                if v >= config.INGEST_LINE_CAP
            ]
            if capped:
                _log('OK', f"Catch-up in progress: {', '.join(capped)} (backlog > {config.INGEST_LINE_CAP} lines)")

        except Exception as exc:
            _log('CRITICAL', f"Cycle {cycle} failed: {type(exc).__name__}: {exc}")
            # Never crash — log and continue

        time.sleep(config.ENGINE_POLL_INTERVAL)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        _log('OK', 'Engine stopped by operator (KeyboardInterrupt). Clean shutdown.')
        sys.exit(0)
