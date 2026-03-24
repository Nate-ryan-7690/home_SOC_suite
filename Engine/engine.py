# ============================================================
# engine.py — Night's Watch Home SOC Suite
# Main correlation engine — Program 1 (The Brain).
#
# Run as:  python engine.py
# Requires: Administrator elevation (collectors write Admin-only logs)
#
# Pipeline each cycle:
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

import os
import sys
import time
from datetime import datetime

import config
import db
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
# SINGLE CYCLE
# ============================================================

def run_cycle():
    """Execute one full pipeline cycle. Returns summary dict."""
    cycle_start = datetime.now()

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

    elapsed = (datetime.now() - cycle_start).total_seconds()

    return {
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
