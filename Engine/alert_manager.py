# ============================================================
# alert_manager.py — Night's Watch Home SOC Suite
# Writes new alerts to Alert_Log.txt and marks them LOGGED.
#
# Called by engine.py each cycle, after correlator.run_all().
# Never called directly.
#
# Responsibilities:
#   1. Fetch all NEW alerts from the DB.
#   2. Check for active alert flood (Rule 18 Part B signal).
#   3. Write each alert to Alert_Log.txt in the standard log format.
#   4. Mark each alert LOGGED so it is never written twice.
#   5. Return a summary dict for engine logging.
#
# Alert status lifecycle:
#   NEW      — created by correlator, not yet written to log file
#   LOGGED   — written to Alert_Log.txt this cycle
#   ACK      — acknowledged by analyst (set manually or via dashboard)
#
# Log format (matches all other collector logs — parseable by log_parser.py):
#   [yyyy-MM-dd HH:mm:ss UTC] [SEVERITY] explanation
#
# Flood suppression:
#   If Rule 18 has raised an alert flood signal (rule_id=18 alert with
#   FLOOD in the explanation) in the current NEW batch, individual alert
#   lines are suppressed.  A single summary line is written instead.
#   All alerts are still marked LOGGED — they remain in the DB for triage.
# ============================================================

import os
from datetime import datetime

import config
import db


# ============================================================
# ALERT LOG PATH
# Separate from individual collector logs — one file for all alerts.
# ============================================================

ALERT_LOG = config.ALERT_LOG


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _append(line: str):
    """Append one line to Alert_Log.txt. Creates the file if absent."""
    os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    with open(ALERT_LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


def _timestamp():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')


def _format_alert(alert, ts: str) -> str:
    """Render one alert row as a standard log line."""
    sev  = alert['severity_current'] if alert['severity_current'] else 'UNKNOWN'
    conf = alert['confidence'] if alert['confidence'] is not None else 0.0
    expl = alert['explanation'] or '(no explanation)'
    return f"[{ts} UTC] [{sev}] [conf:{conf:.0%}] {expl}"


# ============================================================
# MAIN ENTRY POINT — called by engine.py each cycle
# ============================================================

def process_new_alerts(reference_time=None):
    """Fetch all NEW alerts, write to Alert_Log.txt, mark LOGGED.

    Returns a summary dict:
        alerts_written  — alerts written to log (may be 0 during flood suppression)
        alerts_logged   — alerts marked LOGGED in DB (always == len(new))
        flood_active    — True if a Rule 18 flood signal was present
    """
    new_alerts = db.get_active_alerts()
    if not new_alerts:
        return {'alerts_written': 0, 'alerts_logged': 0, 'flood_active': False}

    ts = _timestamp()

    # Flood check — Rule 18 Part B raises an alert with 'FLOOD' in the explanation.
    # If present, suppress individual lines to avoid compounding the noise.
    flood_active = any(
        a['rule_id'] == 18 and a['explanation'] and 'FLOOD' in a['explanation']
        for a in new_alerts
    )

    written = 0

    if flood_active:
        # Write the Rule 18 flood alert only, suppress all others.
        for alert in new_alerts:
            if alert['rule_id'] == 18 and alert['explanation'] and 'FLOOD' in alert['explanation']:
                _append(_format_alert(alert, ts))
                written += 1
                break
        # Single suppression notice.
        suppressed = len(new_alerts) - written
        if suppressed > 0:
            _append(
                f"[{ts} UTC] [MEDIUM] [Alert Manager] "
                f"Flood suppression active — {suppressed} alert(s) held in DB. "
                f"Resolve Rule 18 flood condition before reviewing individual alerts."
            )
    else:
        # Normal operation — write every alert.
        for alert in new_alerts:
            _append(_format_alert(alert, ts))
            written += 1

    # Mark all NEW alerts as LOGGED regardless of flood suppression.
    # They remain in the DB with full detail for triage.
    for alert in new_alerts:
        db.update_alert_status(alert['alert_id'], 'LOGGED')

    return {
        'alerts_written': written,
        'alerts_logged':  len(new_alerts),
        'flood_active':   flood_active,
    }
