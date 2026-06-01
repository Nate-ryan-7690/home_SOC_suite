# ============================================================
# app.py — Night's Watch Home SOC Dashboard
# Program 2 — The Dashboard
#
# Run as: python app.py  (requires Administrator elevation)
# Reads SQLite only — never writes to hocsoc.db
# Steward panel reads Config\Steward_Status.json directly
#
# Requires Flask: pip install flask
# ============================================================

import os
import re
import json
import sqlite3
import subprocess
from datetime import datetime
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ============================================================
# USER CONFIGURATION — change these if your layout differs
# ============================================================

# SOC root — default is Desktop\SOC. Change if installed elsewhere.
ROOT_PATH     = os.path.join(os.path.expanduser("~"), "Desktop", "SOC")

# PowerShell 7+ executable. Two common locations:
#   Windows Store install (default): ~\AppData\Local\Microsoft\WindowsApps\pwsh.exe
#   MSI/direct install:              C:\Program Files\PowerShell\7\pwsh.exe
PWSH          = os.path.join(os.path.expanduser("~"), "AppData", "Local",
                             "Microsoft", "WindowsApps", "pwsh.exe")

# Dashboard port — change if 5000 is already in use on your machine
DASHBOARD_PORT = 7001

# ============================================================
# DERIVED PATHS — do not edit below unless structure changed
# ============================================================
DB_PATH                     = os.path.join(ROOT_PATH, "Engine", "hocsoc.db")
ANALYST_DB_PATH             = os.path.join(ROOT_PATH, "Dashboard", "analyst.db")
SCRIPTS_PATH                = os.path.join(ROOT_PATH, "Scripts")
LOG_PATH                    = os.path.join(ROOT_PATH, "Logs")
CONFIG_PATH                 = os.path.join(ROOT_PATH, "Config")
REPORTS_PATH                = os.path.join(ROOT_PATH, "Reports")
STATUS_FILE                 = os.path.join(CONFIG_PATH, "Steward_Status.json")
HEARTBEAT_SILENCE_THRESHOLD = 60   # seconds — matches engine config

HEALTH_FILES = {
    "sentinel":        os.path.join(CONFIG_PATH, "Sentinel_Health.json"),
    "bulwark":         os.path.join(CONFIG_PATH, "Bulwark_Health.json"),
    "steward":         os.path.join(CONFIG_PATH, "Steward_Health.json"),
    "cityguard":       os.path.join(CONFIG_PATH, "CityGuard_Health.json"),
    "watchman":        os.path.join(CONFIG_PATH, "Watchman_Health.json"),
    "registry_warden": os.path.join(CONFIG_PATH, "RegistryWarden_Health.json"),
    "harbinger":       os.path.join(CONFIG_PATH, "Harbinger_Health.json"),
    "bloodhound":      os.path.join(CONFIG_PATH, "Bloodhound_Health.json"),
    "warden":          os.path.join(CONFIG_PATH, "Warden_Health.json"),
    "seceventlog":     os.path.join(CONFIG_PATH, "SecEventLog_Health.json"),
    "doh_detector":    os.path.join(CONFIG_PATH, "DoHDetector_Health.json"),
    "sysmonwatcher":   os.path.join(CONFIG_PATH, "SysmonWatcher_Health.json"),
    "engine":          os.path.join(CONFIG_PATH, "Engine_Health.json"),
}

# Maps COLLECTORS .ps1 filenames → HEALTH_FILES keys
COLLECTOR_HEALTH_MAP = {
    "Warden.ps1":         "warden",
    "Sentinel.ps1":       "sentinel",
    "Bulwark.ps1":        "bulwark",
    "Steward.ps1":        "steward",
    "CITYGUARD.ps1":      "cityguard",
    "Watchman.ps1":       "watchman",
    "Registry_Warden.ps1":"registry_warden",
    "Harbinger.ps1":      "harbinger",
    "Bloodhound.ps1":     "bloodhound",
    "SecEventLog.ps1":    "seceventlog",
    "DOH_Detector.ps1":   "doh_detector",
    "SysmonWatcher.ps1":  "sysmonwatcher",
}

STATUS_FRESHNESS_THRESHOLD = 15  # seconds — dot goes red within 15s of collector stopping

# ============================================================
# COLLECTOR DEFINITIONS
# Order = launch sequence
# ============================================================
COLLECTORS = [
    "Warden.ps1",
    "Sentinel.ps1",
    "Bulwark.ps1",
    "Steward.ps1",
    "CITYGUARD.ps1",
    "Watchman.ps1",
    "Registry_Warden.ps1",
    "Harbinger.ps1",
    "Bloodhound.ps1",
    "SecEventLog.ps1",
    "DOH_Detector.ps1",
    "SysmonWatcher.ps1",
]

ANALYST_SCRIPTS = [
    "Investigator.ps1",
    "Crow.ps1",
    "Ledger.ps1",
    "Castellan.ps1",
]

QUIET_COLLECTORS = [
    "cityguard", "watchman", "registry_warden", "seceventlog",
    "doh_detector", "bloodhound", "harbinger", "warden", "sysmonwatcher",
]


# ============================================================
# DB HELPER — read only
# ============================================================
def db_query(sql, params=()):
    """Execute a read-only query against hocsoc.db.
    Returns list of dicts. Returns [] if DB unavailable."""
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def analyst_query(sql, params=()):
    """Read from analyst.db. Returns list of dicts, [] if unavailable."""
    try:
        conn = sqlite3.connect(ANALYST_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def analyst_write(sql, params=()):
    """Write to analyst.db only. hocsoc.db is never modified by the dashboard."""
    try:
        conn = sqlite3.connect(ANALYST_DB_PATH)
        conn.execute(sql, params)
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def analyst_db_init():
    """Create analyst.db and classifications table on first run."""
    try:
        conn = sqlite3.connect(ANALYST_DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS classifications (
                alert_id        TEXT PRIMARY KEY,
                status          TEXT NOT NULL DEFAULT 'NEW',
                analyst_comment TEXT,
                reviewed_at     TEXT,
                updated_at      TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass


# ============================================================
# PROCESS STATUS — ground truth for green/red dots
# ============================================================
def _health_json_active(health_key):
    """Return True if the named health JSON exists and was written within STATUS_FRESHNESS_THRESHOLD."""
    path = HEALTH_FILES.get(health_key)
    if not path or not os.path.exists(path):
        return False
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        ts  = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
        lag = (datetime.now() - ts).total_seconds()
        return lag <= STATUS_FRESHNESS_THRESHOLD
    except Exception:
        return False


def get_running_scripts():
    """Return set of script filenames currently running, based on health JSON freshness."""
    running = set()
    for script, key in COLLECTOR_HEALTH_MAP.items():
        if _health_json_active(key):
            running.add(script)
    return running


def get_engine_running():
    """Return True if engine health JSON is fresh."""
    return _health_json_active("engine")


# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def index():
    return render_template("index.html", collectors=COLLECTORS)


@app.route("/api/status")
def api_status():
    """Collector process status — green/red dots. Called every 10s."""
    running = get_running_scripts()
    status = {script: (script in running) for script in COLLECTORS}
    status["engine"] = get_engine_running()
    return jsonify(status)


@app.route("/api/debug/procs")
def api_debug_procs():
    """Raw pwsh CommandLine output for debugging dot status."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "$cls = (Get-CimInstance Win32_Process -Filter \"Name='pwsh.exe'\").CommandLine; "
             "$cls -join \"`n\""],
            capture_output=True, text=True, timeout=15
        )
        return jsonify({"stdout": result.stdout, "stderr": result.stderr,
                        "returncode": result.returncode})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/heartbeat")
def api_heartbeat():
    """Collector liveness from health JSON files written by each collector.
    Reads files directly — no engine dependency. Status computed against
    current time so dots go red immediately when a collector stops writing.
    Called every 5s."""
    now    = datetime.now()
    result = {}
    for name, path in HEALTH_FILES.items():
        try:
            if not os.path.exists(path):
                result[name] = {"status": "UNKNOWN", "last_heartbeat": None,
                                "lag_seconds": None, "cycle": 0, "uptime": None}
                continue
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            ts_str = data.get('timestamp')
            hb_ts  = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            lag    = (now - hb_ts).total_seconds()
            result[name] = {
                "status":         "ACTIVE" if lag <= HEARTBEAT_SILENCE_THRESHOLD else "DOWN",
                "last_heartbeat": ts_str,
                "lag_seconds":    round(lag, 1),
                "cycle":          data.get('cycle', 0),
                "uptime":         data.get('uptime'),
            }
        except Exception:
            result[name] = {"status": "UNKNOWN", "last_heartbeat": None,
                            "lag_seconds": None, "cycle": 0, "uptime": None}
    return jsonify(result)


@app.route("/api/steward")
def api_steward():
    """Live Steward snapshot from Steward_Status.json. Called every 60s."""
    try:
        with open(STATUS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception:
        return jsonify(None)


@app.route("/api/sentinel")
def api_sentinel():
    """Latest Sentinel outbound connections from SQLite. Called every 60s."""
    rows = db_query("""
        SELECT actor, destination, base_severity, observed_at
        FROM   events
        WHERE  collector_name = 'sentinel'
          AND  event_type     = 'NETWORK'
          AND  subtype        = 'OUTBOUND'
        ORDER  BY observed_at DESC
        LIMIT  20
    """)
    return jsonify(rows)


@app.route("/api/alerts")
def api_alerts():
    """Active alerts for feed. Excludes RESOLVED and FALSE_POSITIVE.
    Merges hocsoc.db alert data with analyst.db classifications."""
    rows = db_query("""
        SELECT alert_id, rule_id, severity_current,
               confidence, explanation, created_at
        FROM   alerts
        ORDER  BY created_at DESC
        LIMIT  50
    """)
    if not rows:
        return jsonify([])
    ids = [r["alert_id"] for r in rows]
    placeholders = ",".join("?" * len(ids))
    classes = analyst_query(
        f"SELECT * FROM classifications WHERE alert_id IN ({placeholders})",
        tuple(ids)
    )
    class_map = {c["alert_id"]: c for c in classes}
    result = []
    for row in rows:
        cls = class_map.get(row["alert_id"], {})
        status = cls.get("status", "NEW")
        if status in ("RESOLVED", "FALSE_POSITIVE"):
            continue
        row["status"]          = status
        row["analyst_comment"] = cls.get("analyst_comment")
        row["reviewed_at"]     = cls.get("reviewed_at")
        result.append(row)
    return jsonify(result[:20])


@app.route("/api/alert/<alert_id>")
def api_alert_detail(alert_id):
    """Full detail for a single alert including analyst classification.
    Used by the review modal."""
    rows = db_query(
        "SELECT alert_id, rule_id, severity_current, confidence, explanation, created_at "
        "FROM alerts WHERE alert_id = ?",
        (alert_id,)
    )
    if not rows:
        return jsonify({"error": "not found"}), 404
    row = rows[0]
    cls_rows = analyst_query(
        "SELECT * FROM classifications WHERE alert_id = ?", (alert_id,)
    )
    cls = cls_rows[0] if cls_rows else {}
    row["status"]          = cls.get("status", "NEW")
    row["analyst_comment"] = cls.get("analyst_comment")
    row["reviewed_at"]     = cls.get("reviewed_at")
    return jsonify(row)


@app.route("/api/alert/<alert_id>/classify", methods=["POST"])
def api_alert_classify(alert_id):
    """Write analyst classification to analyst.db. hocsoc.db is not touched.
    Body: {"status": "RESOLVED|FALSE_POSITIVE|MONITOR", "analyst_comment": "..."}"""
    body    = request.get_json(silent=True) or {}
    status  = body.get("status", "").upper()
    comment = body.get("analyst_comment") or None
    if status not in ("RESOLVED", "FALSE_POSITIVE", "MONITOR"):
        return jsonify({"ok": False, "error": "invalid status"}), 400
    now = datetime.now().isoformat()
    ok = analyst_write(
        """INSERT INTO classifications
               (alert_id, status, analyst_comment, reviewed_at, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(alert_id) DO UPDATE SET
               status          = excluded.status,
               analyst_comment = COALESCE(excluded.analyst_comment, analyst_comment),
               reviewed_at     = excluded.reviewed_at,
               updated_at      = excluded.updated_at""",
        (alert_id, status, comment, now, now)
    )
    return jsonify({"ok": ok})


@app.route("/api/quiet")
def api_quiet():
    """SUSPICIOUS/CRITICAL events from quiet collectors in the last hour."""
    placeholders = ",".join("?" * len(QUIET_COLLECTORS))
    rows = db_query(f"""
        SELECT collector_name, actor, subtype,
               base_severity, observed_at
        FROM   events
        WHERE  collector_name IN ({placeholders})
          AND  base_severity  IN ('SUSPICIOUS','CRITICAL')
          AND  observed_at    >= datetime('now', '-1 hour')
        ORDER  BY observed_at DESC
        LIMIT  50
    """, tuple(QUIET_COLLECTORS))
    return jsonify(rows)


@app.route("/api/quiet/counts")
def api_quiet_counts():
    """Session event counts per quiet collector."""
    placeholders = ",".join("?" * len(QUIET_COLLECTORS))
    rows = db_query(f"""
        SELECT collector_name, COUNT(*) as total
        FROM   events
        WHERE  collector_name IN ({placeholders})
        GROUP  BY collector_name
    """, tuple(QUIET_COLLECTORS))
    return jsonify({r["collector_name"]: r["total"] for r in rows})


# ============================================================
# ACTION ROUTES
# ============================================================
@app.route("/api/launch/auditor/<mode>", methods=["POST"])
def launch_auditor(mode):
    if mode not in ("Morning", "Evening"):
        return jsonify({"ok": False, "error": "Invalid mode"}), 400
    script = os.path.join(SCRIPTS_PATH, "Auditor.ps1")
    subprocess.Popen([
        PWSH, "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", script,
        "-Mode", mode
    ])
    return jsonify({"ok": True})


@app.route("/api/launch/collector/<name>", methods=["POST"])
def launch_collector(name):
    if name not in COLLECTORS:
        return jsonify({"ok": False, "error": "Unknown collector"}), 400
    script = os.path.join(SCRIPTS_PATH, name)
    subprocess.Popen([
        PWSH, "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", script
    ])
    return jsonify({"ok": True})


@app.route("/api/launch/engine", methods=["POST"])
def launch_engine():
    script = os.path.join(SCRIPTS_PATH, "Launch_Engine.ps1")
    subprocess.Popen([
        PWSH, "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", script
    ])
    return jsonify({"ok": True})


@app.route("/api/stop/all", methods=["POST"])
def stop_all():
    """Stop all SOC collector and engine processes."""
    try:
        subprocess.run(
            ["powershell", "-Command",
             # Kill collector pwsh windows
             "Get-CimInstance Win32_Process -Filter \"Name='pwsh.exe'\" | "
             "Where-Object { $_.CommandLine -match 'SOC\\\\Scripts' } | "
             "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; "
             # Kill engine pwsh window
             "Get-CimInstance Win32_Process -Filter \"Name='pwsh.exe'\" | "
             "Where-Object { $_.CommandLine -match 'engine\\.py' } | "
             "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; "
             # Kill engine python process
             "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
             "Where-Object { $_.CommandLine -match 'engine\\.py' } | "
             "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"],
            timeout=15
        )
        # Remove PID file so engine dot goes red immediately
        pid_file = os.path.join(ROOT_PATH, "Config", "Engine.pid")
        try:
            os.remove(pid_file)
        except FileNotFoundError:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/launch/weekly", methods=["POST"])
def launch_weekly():
    """Run all analyst scripts that exist, sequentially."""
    launched = []
    for script_name in ANALYST_SCRIPTS:
        script_path = os.path.join(SCRIPTS_PATH, script_name)
        if os.path.exists(script_path):
            subprocess.Popen([
                PWSH, "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-File", script_path
            ])
            launched.append(script_name)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"ok": True, "launched": launched, "timestamp": ts})


@app.route("/api/shutdown", methods=["POST"])
def shutdown():
    """Terminate the Flask server. Called after End Day is complete."""
    os._exit(0)


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    analyst_db_init()
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=False, threaded=True)
