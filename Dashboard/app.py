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
from flask import Flask, jsonify, render_template

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
DASHBOARD_PORT = 5000

# ============================================================
# DERIVED PATHS — do not edit below unless structure changed
# ============================================================
DB_PATH       = os.path.join(ROOT_PATH, "Engine", "hocsoc.db")
SCRIPTS_PATH  = os.path.join(ROOT_PATH, "Scripts")
LOG_PATH      = os.path.join(ROOT_PATH, "Logs")
CONFIG_PATH   = os.path.join(ROOT_PATH, "Config")
REPORTS_PATH  = os.path.join(ROOT_PATH, "Reports")
STATUS_FILE   = os.path.join(CONFIG_PATH, "Steward_Status.json")

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


# ============================================================
# PROCESS STATUS — ground truth for green/red dots
# ============================================================
def get_running_scripts():
    """Return set of script filenames currently running as pwsh processes."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
             "$cls  = @((Get-CimInstance Win32_Process -Filter \"Name='pwsh.exe'\").CommandLine); "
             "$cls += @((Get-CimInstance Win32_Process -Filter \"Name='python.exe'\").CommandLine); "
             "($cls | Where-Object { $_ }) -join \"`n\""],
            capture_output=True, encoding='utf-8', errors='replace', timeout=15
        )
        lines = result.stdout.lower()
        running = set()
        for script in COLLECTORS + ANALYST_SCRIPTS:
            if script.lower() in lines:
                running.add(script)
        return running
    except Exception:
        return set()


def get_engine_running():
    """Check engine status via PID file written by Launch_Engine.ps1."""
    pid_file = os.path.join(CONFIG_PATH, "Engine.pid")
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        result = subprocess.run(
            ["powershell", "-Command",
             f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == str(pid)
    except Exception:
        return False


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
    """Last 20 engine alerts for scrollable feed. Called every 60s."""
    rows = db_query("""
        SELECT alert_id, rule_id, severity_current,
               confidence, explanation, created_at
        FROM   alerts
        ORDER  BY created_at DESC
        LIMIT  20
    """)
    return jsonify(rows)


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
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=False, threaded=True)
