# ============================================================
# config.py — Night's Watch Home SOC Suite
# Single source of truth for all constants and thresholds.
# Every other module imports from here. Nothing is hardcoded
# below this file.
#
# IMPORTANT: Rotate threshold values periodically.
# A threshold-aware adversary lives in the gaps.
# ============================================================

import os
import socket

# ============================================================
# USER CONFIGURATION
# Set ROOT_PATH to your SOC installation folder.
# ============================================================
ROOT_PATH = os.path.join(os.path.expanduser("~"), "Desktop", "SOC")

# ============================================================
# PATHS
# ============================================================
LOG_DIR     = os.path.join(ROOT_PATH, "Logs")
ARCHIVE_DIR = os.path.join(LOG_DIR, "Archives")
CONFIG_DIR  = os.path.join(ROOT_PATH, "Config")
ENGINE_DIR  = os.path.join(ROOT_PATH, "Engine")
DB_PATH     = os.path.join(ENGINE_DIR, "hocsoc.db")
ALERT_LOG   = os.path.join(LOG_DIR, "Alert_Log.txt")

LOG_FILES = {
    "sentinel":        os.path.join(LOG_DIR, "Network_Watchdog_Log.txt"),
    "bulwark":         os.path.join(LOG_DIR, "Bulwark_Log.txt"),
    "steward":         os.path.join(LOG_DIR, "Steward_Log.txt"),
    "cityguard":       os.path.join(LOG_DIR, "CityGuard_Log.txt"),
    "watchman":        os.path.join(LOG_DIR, "Watchman_Log.txt"),
    "registry_warden": os.path.join(LOG_DIR, "RegistryWarden_Log.txt"),
    "harbinger":       os.path.join(LOG_DIR, "Harbinger_Log.txt"),
    "bloodhound":      os.path.join(LOG_DIR, "Bloodhound_Log.txt"),
    "warden":          os.path.join(LOG_DIR, "Warden_Log.txt"),
    "seceventlog":     os.path.join(LOG_DIR, "SecEventLog_Log.txt"),
    "doh_detector":    os.path.join(LOG_DIR, "DoHDetector_Log.txt"),
    "sysmonwatcher":   os.path.join(LOG_DIR, "SysmonWatcher_Log.txt"),
}

# ============================================================
# ENGINE POLL INTERVALS (seconds)
# Rotate these values periodically.
# ============================================================
ENGINE_POLL_INTERVAL      = 60    # Main loop — full pipeline cycle (1 min, temporary for backlog drain)
INGEST_LINE_CAP           = 5000  # Max lines per collector per cycle (catch-up guard)
SHORT_POLL_INTERVAL       = 30    # Rules 3, 4, 6, 8, 13, 17, 19
OPERATIONAL_POLL_INTERVAL = 300   # Rules 2, 11, 14, 15
CAMPAIGN_POLL_INTERVAL    = 3600  # Rules 12, 20

# ============================================================
# CORRELATION WINDOWS (seconds)
# How far back each rule tier looks into SQLite.
# ============================================================
SHORT_WINDOW       = 600      # 10 minutes
OPERATIONAL_WINDOW = 86400    # 24 hours
CAMPAIGN_WINDOW    = 604800   # 7 days

# ============================================================
# DATA RETENTION (days)
# ============================================================
RETENTION_RAW_EVENTS  = 90
RETENTION_EVENTS      = 365
RETENTION_DETECTIONS  = 365
RETENTION_ALERTS      = None   # indefinite — user managed

# ============================================================
# AFTER HOURS WINDOW — consistent with all collectors
# ============================================================
AFTER_HOURS_START = 0    # 00:00
AFTER_HOURS_END   = 6    # 06:00

# ============================================================
# SEVERITY LEVELS — fixed, do not change order
# ============================================================
SEVERITY_OK         = "OK"
SEVERITY_UNKNOWN    = "UNKNOWN"
SEVERITY_SUSPICIOUS = "SUSPICIOUS"
SEVERITY_CRITICAL   = "CRITICAL"

# ============================================================
# TRUSTED ZONES
# Processes from these paths are lower-trust but not
# automatically CRITICAL. Checked before high-risk paths —
# most specific match wins.
# ============================================================
TRUSTED_ZONES = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs"),
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
]

# ============================================================
# HIGH RISK PATHS
# Process launches from these paths trigger elevated severity.
# Note: AppData\Local\Programs is trusted (above).
# AppData\Local\Temp and AppData\Roaming are not.
# ============================================================
HIGH_RISK_PATHS = [
    os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
    os.path.join(os.path.expanduser("~"), "AppData", "Roaming"),
    os.path.join(os.path.expanduser("~"), "Downloads"),
    r"C:\Users\Public",
    r"C:\ProgramData",
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
]

# ============================================================
# LOLBIN LIST — Rule 6
# Trusted Windows binaries that should not make outbound
# network connections under normal circumstances.
#
# ACTIVE LIST: High-frequency targets seen in real-world attacks.
# Sourced from project red team analysis and the LOLBAS Project.
#
# EXTENDED LIST: Additional binaries documented by the LOLBAS
# Project but less commonly seen in attacks against home/SMB
# targets. Uncomment any entry to add it to active monitoring.
#
# Full reference: https://lolbas-project.github.io
# New LOLBins are added regularly — check periodically.
# Rotate this list periodically — a threshold-aware adversary
# will stay off binaries they know you are watching.
# ============================================================
LOLBIN_LIST = [
    # --- Core execution / download / bypass ---
    "mshta.exe",      "wscript.exe",     "cscript.exe",    "regsvr32.exe",
    "rundll32.exe",   "certutil.exe",    "bitsadmin.exe",  "msiexec.exe",
    "wmic.exe",       "cmd.exe",         "powershell.exe", "pwsh.exe",
    # --- Build / compile tools abused for execution ---
    "msbuild.exe",    "installutil.exe", "regasm.exe",     "regsvcs.exe",
    # --- Scripting / HTA / config ---
    "cmstp.exe",      "xwizard.exe",     "forfiles.exe",
    # --- Network transfer ---
    "ftp.exe",        "curl.exe",        "wget.exe",
    # --- Archive / file manipulation ---
    "esentutl.exe",   "expand.exe",      "extrac32.exe",   "makecab.exe",
    "msdeploy.exe",   "diantz.exe",
    # --- Search / recon ---
    "findstr.exe",    "hh.exe",
    # --- Scheduled task / service abuse ---
    "sc.exe",         "schtasks.exe",    "pcalua.exe",
    # --- Misc execution ---
    "replace.exe",    "rpcping.exe",     "runscripthelper.exe",
    "scriptrunner.exe", "syncappvpublishingserver.exe", "msdt.exe",
]

# --- EXTENDED LOLBIN LIST (LOLBAS Project — uncomment to activate) ---
# Reference each entry at https://lolbas-project.github.io/<binaryname>
# before enabling — confirm it applies to your environment first.
#
# LOLBIN_LIST_EXTENDED = [
#     # --- Compilers / interpreters (BYOI vectors) ---
#     "csc.exe",               # C# compiler — compile and run arbitrary code
#     "vbc.exe",               # VB compiler
#     "jsc.exe",               # JScript compiler
#     "ilasm.exe",             # IL assembler
#     "aspnet_compiler.exe",   # ASP.NET compiler
#     "microsoft.workflow.compiler.exe",  # workflow execution
#     "rcsi.exe",              # Roslyn C# interactive
#     "dotnet.exe",            # .NET CLI
#
#     # --- Scripting / execution ---
#     "bash.exe",              # WSL bash — can run Linux binaries on Windows
#     "wsl.exe",               # WSL launcher
#     "msxsl.exe",             # XSLT transformation — can execute JScript
#     "odbcconf.exe",          # ODBC config — can load DLLs
#     "infdefaultinstall.exe", # INF file execution
#     "ieexec.exe",            # IE execution proxy
#     "ie4uinit.exe",          # IE init — can execute commands
#     "pcwrun.exe",            # Program Compatibility Wizard
#     "runexehelper.exe",      # execution helper
#     "te.exe",                # Test execution engine
#     "atbroker.exe",          # Assistive Technology broker
#     "control.exe",           # Control Panel host — can load DLLs
#     "gpscript.exe",          # Group Policy script runner
#
#     # --- Download / transfer ---
#     "certreq.exe",           # certificate request — can download files
#     "desktopimgdownldr.exe", # desktop image downloader
#     "finger.exe",            # finger protocol — can exfiltrate data
#     "dfsvc.exe",             # ClickOnce application runner
#     "squirrel.exe",          # Electron updater — can download and run
#     "mavinject.exe",         # DLL injection into running process
#
#     # --- Recon / enumeration ---
#     "reg.exe",               # registry query and modification
#     "regedit.exe",           # registry editor
#     "ldifde.exe",            # LDAP data interchange — AD recon
#     "dnscmd.exe",            # DNS server management
#     "ntdsutil.exe",          # AD DS utility — NTDS.dit extraction
#     "secedit.exe",           # security configuration
#     "diskshadow.exe",        # VSS — can extract NTDS.dit via shadow copy
#     "mmc.exe",               # Microsoft Management Console
#     "wab.exe",               # Windows Address Book
#
#     # --- Forensic / debugging vectors ---
#     "cdb.exe",               # Windows debugger — can run shellcode
#     "vsjitdebugger.exe",     # VS JIT debugger
#     "ttdinject.exe",         # Time Travel Debugging injection
#     "tttracer.exe",          # Time Travel Debugger tracer
#     "adplus.exe",            # ADPlus debugging tool
#     "psr.exe",               # Problem Steps Recorder — screen capture
#
#     # --- Scheduled / service management ---
#     "sdbinst.exe",           # SDB shim installer — persistence mechanism
#     "cmdl32.exe",            # AutoDial manager — download files
#     "usoClient.exe",         # Update Session Orchestrator
#     "bginfo.exe",            # BGInfo — can execute VBScript
#
#     # --- SQL / database ---
#     "sqlps.exe",             # SQL Server PowerShell
#     "sqltoolsps.exe",        # SQL tools PowerShell
#
#     # --- Tracker / build tools ---
#     "tracker.exe",           # file dependency tracker — DLL side-load
# ]

# ============================================================
# INTERPRETER LIST — Rule 21 (BYOI / Interpreter Lockdown)
# Language runtimes and scripting hosts that should not be
# spawned from high-risk or unknown paths.
# Overlap with LOLBIN_LIST is intentional — different rule,
# different signal: Rule 6 watches network activity, Rule 21
# watches the spawn event itself.
# ============================================================
INTERPRETER_LIST = [
    # --- Python ---
    "python.exe",     "pythonw.exe",
    # --- JVM ---
    "java.exe",       "javaw.exe",
    # --- Node / JavaScript ---
    "node.exe",       "nodejs.exe",
    # --- Ruby / Perl / PHP ---
    "ruby.exe",       "perl.exe",         "php.exe",
    # --- .NET scripting (also in LOLBIN_LIST) ---
    "powershell.exe", "pwsh.exe",
    "wscript.exe",    "cscript.exe",
    "mshta.exe",
    # --- WSL / Linux-on-Windows ---
    "bash.exe",       "wsl.exe",
    # --- XSLT / XML execution ---
    "msxsl.exe",
]

# ============================================================
# HOLLOWING TARGETS — Rule 7 (Process Hollowing)
# Well-known Windows system binary names that should only ever
# run from trusted system paths (System32, SysWOW64, Windows).
# Seeing these names from any other path = masquerade / hollowing.
# Rule 7 fires when one of these is found outside a trusted path
# AND the same actor makes an outbound network connection.
# ============================================================
HOLLOWING_TARGETS = [
    "svchost.exe",    "lsass.exe",      "csrss.exe",     "winlogon.exe",
    "wininit.exe",    "services.exe",   "smss.exe",      "explorer.exe",
    "spoolsv.exe",    "taskhostw.exe",  "taskhost.exe",  "dllhost.exe",
    "conhost.exe",    "lsm.exe",
]

# ============================================================
# NEVER-NET BINARIES — Rule 16 (Contextual Integrity Violation)
# System processes that have NO legitimate reason to make
# outbound network connections, even when running from their
# correct trusted path. Any outbound connection from these
# processes indicates injection, hollowing-after-load, or a
# credential-dumping tool operating under their cover.
# Rule 16 fires when one of these is seen (from a TRUSTED path)
# AND a network connection from the same actor is present.
# Distinct from Rule 7: same binary, right path, wrong behaviour.
# ============================================================
NEVER_NET_BINARIES = [
    "lsass.exe",   "csrss.exe",  "wininit.exe",
    "smss.exe",    "lsm.exe",
]

# ============================================================
# BRUTE FORCE THRESHOLDS — consistent with SecEventLog.ps1
# ============================================================
BRUTE_FORCE_USER_THRESHOLD = 5
BRUTE_FORCE_IP_THRESHOLD   = 10

# ============================================================
# BURST CONNECTION THRESHOLD — Rule 11
# Minimum outbound NETWORK events from the same actor within
# SHORT_WINDOW to constitute a burst pattern.
# Rotate periodically — a threshold-aware adversary paces
# connections just below this value.
# ============================================================
BURST_CONNECTION_THRESHOLD = 3

# ============================================================
# C2 BEACON THRESHOLD — Rule 2
# Minimum discrete Bulwark CONNECTION_END sessions from the
# same (actor, destination) pair within OPERATIONAL_WINDOW
# to constitute a beacon frequency signal.
# Trusted-path processes require double this count before
# alerting — routine update checks are frequent.
# Rotate periodically.
# ============================================================
C2_BEACON_MIN_SESSIONS = 3

# ============================================================
# ENGINE HEALTH — Rule 18
# COLLECTOR_SILENCE_THRESHOLD: seconds without a new event
#   before a collector is considered silent and an alert fires.
# ENGINE_FLOOD_THRESHOLD: alerts generated within 60 seconds
#   that trigger ENGINE_FLOOD_DETECTED.
# Rotate both periodically — a threshold-aware adversary can
# pace below these values.
# ============================================================
COLLECTOR_SILENCE_THRESHOLD = 1800   # 30 minutes
ENGINE_FLOOD_THRESHOLD      = 50     # alerts per 60 seconds

# ============================================================
# RESOURCE EXFILTRATION PAIRING WINDOW — Rule 1
# Maximum seconds between a resource spike (CPU/RAM) and an
# outbound network event from the same actor for the pair to
# be considered correlated.
# ============================================================
RESOURCE_EXFIL_WINDOW = 300   # 5 minutes

# ============================================================
# KNOWN SYNC CLIENTS — Rule 22 (Cloud API Anomaly)
# Process names of legitimate cloud storage sync clients.
# After-hours network connections from processes NOT in this
# list are flagged. Zero-trust: start small, extend during
# the baseline month as legitimate sync clients are confirmed.
# Process names are matched case-insensitively, .exe optional.
# ============================================================
KNOWN_SYNC_CLIENTS = [
    # Microsoft OneDrive
    "onedrive",
    "onedrive.sync.service",
    "filecoauth",
    # Google Drive (Desktop)
    "googledrivefs",
    # Dropbox
    "dropbox",
    # Windows Update / delivery optimisation (legitimate background transfer)
    "svchost",
    "musnotification",
    "wuauclt",
]

# ============================================================
# RULE WEIGHTS — risk scoring model
# Higher = more contribution to risk score.
# Rotate periodically — static weights are attackable.
# ============================================================
RULE_WEIGHTS = {
    1:  0.8,   2:  0.9,   3:  1.0,   4:  1.0,
    5:  0.7,   6:  1.0,   7:  1.0,   8:  1.0,
    9:  0.8,   10: 1.0,   11: 0.8,   12: 0.6,
    13: 1.0,   14: 0.7,   15: 0.8,   16: 1.0,
    17: 1.0,   18: 0.5,   19: 1.0,   20: 0.5,
    21: 0.8,   22: 0.7,   23: 1.0,   24: 1.0,
    25: 0.8,   26: 0.9,
    # Sysmon rules — Phase 7A
    27: 1.0,   # Delayed Initial Access (Harbinger + Sentinel watchlist)
    28: 1.0,   # Browser Debugger Attachment (EID 10)
    29: 0.9,   # High-Risk Path Launch (EID 1)
    30: 1.0,   # AMSI Provider Tampered (EID 12)
    31: 0.9,   # Unmanaged PS Host / DLL Hijack (EID 7)
    32: 1.0,   # WMI Persistence Binding (EID 19/20/21)
    33: 1.0,   # Remote Thread Injection (EID 8)
    34: 1.0,   # LSASS Process Access (EID 10)
    35: 1.0,   # Raw Disk Read (EID 9)
    36: 0.9,   # Unsigned Driver Loaded (EID 6)
    37: 1.0,   # C2 Named Pipe (EID 17/18)
    38: 0.7,   # Downloaded Executable (EID 11/15)
    39: 1.0,   # Process Hollowing Confirmed (EID 25)
}

# ============================================================
# SYSTEM
# ============================================================
SOURCE_HOST    = socket.gethostname()
SCHEMA_VERSION = "1.0"
