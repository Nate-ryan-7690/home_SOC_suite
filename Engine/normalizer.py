# ============================================================
# normalizer.py — Night's Watch Home SOC Suite
# Maps raw_events → normalized events schema.
#
# Call normalize_pending() from engine.py after each ingest cycle.
# It pulls unprocessed raw_events, normalizes each one, writes to
# the events table, and stamps the source row with normalized_event_id.
#
# The normalized_event_id is deterministic:
#   SHA256(collector_name + ":" + raw_event_hash)[:32]
# This means you can always recompute it from raw_events and verify
# that the events table has not been tampered with (Rule 26).
#
# Regex confidence levels (see per-normalizer comments):
#   CONFIRMED — format verified against real collector output
#   INFERRED  — format derived from architecture docs / CLAUDE.md
#               Must be validated once real logs are collected
# ============================================================

import hashlib
import re
from datetime import datetime

import config
import db

SCHEMA_VERSION = config.SCHEMA_VERSION


# ============================================================
# PER-COLLECTOR MESSAGE REGEX
# Each pattern matches the message portion only (after the
# timestamp+severity prefix has been stripped).
# ============================================================

# --- Harbinger (CONFIRMED — verified against live Harbinger_Log.txt) ---
# STARTUP: svchost.exe | PID: 1700 | Parent: services.exe (1492) | Path: C:\... | CMD: ...
# NEW PROCESS: bash.exe | PID: 1234 | Parent: claude (999) | Path:  | CMD:
# Path can be empty (kernel/protected processes). CMD field always present — stripped.
HARBINGER_RE = re.compile(
    r'^(STARTUP|NEW PROCESS): (.+?) \| PID: \d+ \| Parent: .+ \| Path: (.*?)(?:\s*\| CMD:.*)?$'
)

# --- Sentinel (CONFIRMED — format verified in Sentinel.ps1 review) ---
# NEW: chrome -> 1.2.3.4 (Berlin, DE) | PATH: C:\Program Files\...\chrome.exe
SENTINEL_NEW_RE = re.compile(
    r'^NEW: (.+?) -> ([\d\.]+) \(.+?\) \| PATH: (.+)$'
)
# TELEMETRY_GAP: chrome -> <geo_failed> (geo lookup failed)
SENTINEL_GAP_RE = re.compile(
    r'^TELEMETRY_GAP: (.+?) -> (.+?) '
)

# --- Bulwark (PORT format CONFIRMED against live Bulwark_Log.txt) ---
# Severity field carries direction: [PORT OPEN] or [PORT CLOSE]
# Message format: "PORT OPENED: 52518 | Process: Agent | Path: C:\..."
# Path may be empty (kernel/system processes often have no path).
BULWARK_PORT_RE = re.compile(
    r'^PORT (OPENED|CLOSED): (\d+) \| Process: (.+?) \| Path: (.*)$'
)
# Connection session tracking (CONFIRMED — matches Bulwark.ps1 Section 2 after session tracker rewrite)
# CONNECTION_START: Process=chrome | Remote=142.250.185.78:443 | Location=Mountain View, US | Path: C:\...
# CONNECTION_END:   Process=chrome | Remote=142.250.185.78:443 | Location=Mountain View, US | Cycles=570 | Duration=47m30s | Started=2026-03-25 21:00:00 | Path: C:\...
# Remote field: greedy (.+) matches IP (including IPv6 colons); last :(\d+) captures port.
BULWARK_CONN_START_RE = re.compile(
    r'^CONNECTION_START: Process=(.+?) \| Remote=(.+):(\d+) \| Location=(.+?) \| Path: (.*)$'
)
BULWARK_CONN_END_RE = re.compile(
    r'^CONNECTION_END: Process=(.+?) \| Remote=(.+):(\d+) \| Location=(.+?) \| Cycles=(\d+) \| Duration=(.+?) \| Started=(.+?) \| Path: (.*)$'
)

# --- Steward (CONFIRMED against Steward_Log.txt and Steward.ps1 source) ---
# Per-process:  "HIGH CPU: chrome at 72% | RAM: 145 MB"   (line 268/316 Steward.ps1)
# System CPU:   "HIGH CPU: System at 99%"                  (line 307 Steward.ps1)
# System RAM:   "HIGH RAM: System at 95%"                  (line 308 Steward.ps1)
# Disk I/O is display-only — never written to the log file.
STEWARD_PROC_RE    = re.compile(r'^HIGH CPU: (.+?) at ([\d\.]+)% \| RAM: ([\d\.]+) MB$')
STEWARD_SYS_CPU_RE = re.compile(r'^HIGH CPU: (.+?) at ([\d\.]+)%$')
STEWARD_SYS_RAM_RE = re.compile(r'^HIGH RAM: (.+?) at ([\d\.]+)%$')

# --- CityGuard (CONFIRMED — test_parser.py uses this exact format) ---
# NEW TASK: \Temp\evil.exe | Action: C:\Temp\evil.exe
# TASK DELETED: \TaskName
# TASK MODIFIED: \TaskName | Old Action: ... | New Action: ...
CITYGUARD_RE = re.compile(
    r'^(NEW TASK|TASK DELETED|TASK MODIFIED): (.+?)(?:\s*\|.*)?$'
)
CITYGUARD_ACTION_RE = re.compile(r'Action: (.+?)(?:\s*\||$)')

# --- Watchman (CONFIRMED — format verified in Watchman.ps1 review) ---
# EventID 1 | System woke from sleep | Time: 2026-03-20 01:34:14
WATCHMAN_RE = re.compile(
    r'^EventID (\d+) \| (.+?) \| Time: '
)
_WATCHMAN_SUBTYPES = {
    '1':    'WAKE',
    '42':   'SLEEP',
    '107':  'WAKE',
    '41':   'UNEXPECTED_SHUTDOWN',
    '1074': 'CLEAN_SHUTDOWN',
    '6005': 'BOOT',
    '6006': 'SHUTDOWN',
}

# --- Registry_Warden (INFERRED — skeleton not yet complete) ---
REGISTRY_RE = re.compile(
    r'^(NEW VALUE|DELETED VALUE|MODIFIED VALUE|NEW KEY|DELETED KEY): (.+?)(?:\s*\|.*)?$'
)

# --- SecEventLog (CONFIRMED against SecEventLog.ps1 source) ---
# All messages use a KEYWORD: key=value | key=value format.
# Keywords map to event_type: ACCOUNT | AUTH | SYSTEM (see normalizer).
SECEVENTLOG_KEYWORD_RE = re.compile(
    r'^(LOGON_SUCCESS|LOGON_FAIL|USER_LOGOFF|ACCOUNT_LOGOFF|'
    r'EXPLICIT_CRED_LOGON|SPECIAL_PRIV_LOGON|'
    r'ACCOUNT_CREATED|ACCOUNT_DELETED|ACCOUNT_ENABLED|ACCOUNT_CHANGED|'
    r'ACCOUNT_LOCKED_OUT|PASSWORD_CHANGE_ATTEMPT|PASSWORD_RESET_ATTEMPT|'
    r'GROUP_MEMBER_ADDED|SERVICE_INSTALLED|AUDIT_POLICY_CHANGED|'
    r'NTLM_CREDENTIAL_VALIDATION|RDP_SESSION_RECONNECTED|RDP_SESSION_DISCONNECTED|'
    r'USER_GROUP_ENUM|LOCAL_GROUP_ENUM): (.+)$'
)
_SECEVENTLOG_ACCOUNT_SUBTYPES = {
    'ACCOUNT_CREATED', 'ACCOUNT_DELETED', 'ACCOUNT_ENABLED', 'ACCOUNT_CHANGED',
    'ACCOUNT_LOCKED_OUT', 'PASSWORD_CHANGE_ATTEMPT', 'PASSWORD_RESET_ATTEMPT',
    'GROUP_MEMBER_ADDED',
}
_SECEVENTLOG_SYSTEM_SUBTYPES = {'SERVICE_INSTALLED', 'AUDIT_POLICY_CHANGED'}

# --- Bloodhound (INFERRED — collector not yet built) ---
BLOODHOUND_RE = re.compile(
    r'^QUERY: (.+?) \|.*?Process: (.+?) \| Path: (.+)$'
)

# --- DoH Detector (CONFIRMED against DoH_Detector.ps1 source) ---
# DOH_CONN_NEW: Process=chrome | Path=C:\...\chrome.exe | PID=1234 | Resolver=8.8.8.8 | LocalPort=52000
# DOH_CONN_AT_STARTUP: same structure
# DOH_CONN_ENDED: Process=chrome | PID=1234 | Resolver=8.8.8.8 | Duration=12s  (skipped — OK/informational)
# Resolver may be IPv4 or IPv6 — character class covers both.
DOH_CONN_RE = re.compile(
    r'^(DOH_CONN_NEW|DOH_CONN_AT_STARTUP): Process=(.+?) \| Path=(.+?) \| PID=\d+ \| Resolver=([\d\.:a-fA-F]+) \| LocalPort=\d+$'
)

# --- SysmonWatcher (CONFIRMED against SysmonWatcher.ps1 source) ---
# SYSMON_EIDx_LABEL: key=val | key=val | ...
# EID prefix maps to event_type; label suffix is used as subtype directly.
SYSMONWATCHER_RE = re.compile(r'^(SYSMON_EID(\d+)_([A-Z0-9_]+)): (.+)$')

# --- Warden (CONFIRMED against Warden.ps1 source) ---
# FIM violations: INTEGRITY_VIOLATION, FILE_MISSING, WARDEN_SELF_INTEGRITY
WARDEN_FIM_RE = re.compile(
    r'^(INTEGRITY_VIOLATION|FILE_MISSING|WARDEN_SELF_INTEGRITY): (.+)$'
)
# Log tampering: LOG_DELETED, LOG_TRUNCATED
WARDEN_LOG_TAMPER_RE = re.compile(
    r'^(LOG_DELETED|LOG_TRUNCATED): (.+)$'
)
# Collector health (process-level check — complements Rule 18 ingest-rate check)
WARDEN_COLLECTOR_RE = re.compile(
    r'^COLLECTOR_DOWN: (.+?) not found in running processes$'
)
# Administrative (no Rule 19 alert — FIM not yet initialised)
WARDEN_MANIFEST_RE = re.compile(
    r'^MANIFEST_MISSING: '
)


# ============================================================
# SEVERITY AND MESSAGE EXTRACTION
# ============================================================

_STANDARD_PREFIX_RE = re.compile(
    r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[([^\]]+)\] (.+)$'
)
_SENTINEL_PREFIX_RE = re.compile(
    r'^\[\d{2}:\d{2}:\d{2}\] \[([^\]]+)\] (.+)$'
)

def _extract_severity_and_message(raw_payload):
    """Returns (severity_str, message_str) from a raw log line.
    Falls back to UNKNOWN severity if the prefix does not match."""
    m = _STANDARD_PREFIX_RE.match(raw_payload) \
        or _SENTINEL_PREFIX_RE.match(raw_payload)
    if m:
        return m.group(1), m.group(2)
    return 'UNKNOWN', raw_payload


# ============================================================
# TRUST LEVEL ASSIGNMENT
# Path-based only — behavioral trust comes after baseline.
# HIGH_RISK checked first: most specific match wins.
# ============================================================

def _assign_trust_level(process_path):
    if not process_path:
        return 'UNKNOWN'
    path_lower = process_path.lower()
    for p in config.HIGH_RISK_PATHS:
        if p and path_lower.startswith(p.lower()):
            return 'HIGH_RISK'
    for p in config.TRUSTED_ZONES:
        if p and path_lower.startswith(p.lower()):
            return 'TRUSTED'
    return 'UNKNOWN'


# ============================================================
# DETERMINISTIC EVENT ID
# Recomputable from raw_events for integrity verification.
# ============================================================

def _make_event_id(raw_event_hash, collector_name):
    return hashlib.sha256(
        f"{collector_name}:{raw_event_hash}".encode('utf-8')
    ).hexdigest()[:32]


# ============================================================
# PER-COLLECTOR NORMALIZERS
# Each returns a fields dict or None on parse failure.
# ============================================================

def _normalize_harbinger(message, severity):
    m = HARBINGER_RE.match(message)
    if not m:
        return None
    subtype, actor, process_path = m.groups()
    return {
        'event_type':   'PROCESS',
        'subtype':      subtype,
        'actor':        actor,
        'process_path': process_path.strip() or None,  # empty string → NULL in DB
        'destination':  None,
    }


def _normalize_sentinel(message, severity):
    m = SENTINEL_NEW_RE.match(message)
    if m:
        actor, destination, process_path = m.groups()
        return {
            'event_type':   'NETWORK',
            'subtype':      'OUTBOUND',
            'actor':        actor,
            'process_path': process_path,
            'destination':  destination,
        }
    m = SENTINEL_GAP_RE.match(message)
    if m:
        return {
            'event_type':   'NETWORK',
            'subtype':      'TELEMETRY_GAP',
            'actor':        m.group(1),
            'process_path': None,
            'destination':  m.group(2),
        }
    return None


def _normalize_bulwark(message, severity):
    m = BULWARK_PORT_RE.match(message)
    if m:
        _verb, port, actor, process_path = m.groups()
        # Direction comes from severity field ([PORT OPEN] / [PORT CLOSE]),
        # not from the verb in the message (OPENED/CLOSED are equivalent signals).
        sev_upper = severity.upper()
        subtype   = 'PORT_OPEN' if 'OPEN' in sev_upper else 'PORT_CLOSE'
        return {
            'event_type':   'PORT',
            'subtype':      subtype,
            'actor':        actor,
            'process_path': process_path or None,
            'destination':  port,
        }
    m = BULWARK_CONN_START_RE.match(message)
    if m:
        actor, ip, _port, _location, process_path = m.groups()
        return {
            'event_type':   'NETWORK',
            'subtype':      'CONNECTION_START',
            'actor':        actor,
            'process_path': process_path or None,
            'destination':  ip,
        }
    m = BULWARK_CONN_END_RE.match(message)
    if m:
        actor, ip, _port, _location, _cycles, _duration, _started, process_path = m.groups()
        return {
            'event_type':   'NETWORK',
            'subtype':      'CONNECTION_END',
            'actor':        actor,
            'process_path': process_path or None,
            'destination':  ip,
        }
    return None


def _normalize_steward(message, severity):
    # Per-process entry — actor name and RAM both present
    m = STEWARD_PROC_RE.match(message)
    if m:
        actor, _cpu_pct, _ram_mb = m.groups()
        return {
            'event_type':   'RESOURCE',
            'subtype':      'CPU',
            'actor':        actor,
            'process_path': None,   # Steward never logs path to file
            'destination':  None,
        }
    # System-level CPU total — no RAM field
    m = STEWARD_SYS_CPU_RE.match(message)
    if m:
        actor, _cpu_pct = m.groups()
        return {
            'event_type':   'RESOURCE',
            'subtype':      'CPU',
            'actor':        actor,
            'process_path': None,
            'destination':  None,
        }
    # System-level RAM total
    m = STEWARD_SYS_RAM_RE.match(message)
    if m:
        actor, _ram_pct = m.groups()
        return {
            'event_type':   'RESOURCE',
            'subtype':      'RAM',
            'actor':        actor,
            'process_path': None,
            'destination':  None,
        }
    return None


def _normalize_cityguard(message, severity):
    m = CITYGUARD_RE.match(message)
    if not m:
        return None
    subtype      = m.group(1)
    task_name    = m.group(2).strip()
    action_match = CITYGUARD_ACTION_RE.search(message)
    process_path = action_match.group(1).strip() if action_match else None
    return {
        'event_type':   'SCHEDULED_TASK',
        'subtype':      subtype,
        'actor':        task_name,
        'process_path': process_path,
        'destination':  None,
    }


def _normalize_watchman(message, severity):
    m = WATCHMAN_RE.match(message)
    if not m:
        return None
    event_id = m.group(1)
    return {
        'event_type':   'POWER',
        'subtype':      _WATCHMAN_SUBTYPES.get(event_id, f'EVENTID_{event_id}'),
        'actor':        None,
        'process_path': None,
        'destination':  None,
    }


def _normalize_registry_warden(message, severity):
    m = REGISTRY_RE.match(message)
    if not m:
        return None
    subtype, key = m.group(1), m.group(2).strip()
    return {
        'event_type':   'REGISTRY',
        'subtype':      subtype,
        'actor':        key,
        'process_path': None,
        'destination':  None,
    }


def _normalize_seceventlog(message, severity):
    # CONFIRMED against SecEventLog.ps1 source — keyword-prefix format.
    m = SECEVENTLOG_KEYWORD_RE.match(message)
    if not m:
        return None
    keyword, detail = m.group(1), m.group(2)

    # event_type classification
    if keyword in _SECEVENTLOG_ACCOUNT_SUBTYPES:
        event_type = 'ACCOUNT'
    elif keyword in _SECEVENTLOG_SYSTEM_SUBTYPES:
        event_type = 'SYSTEM'
    else:
        event_type = 'AUTH'

    # actor: first matching user field in priority order
    # \b ensures we don't match 'User' inside 'NewUser', 'TargetUser', etc.
    actor = None
    for field in ('NewUser', 'TargetUser', 'User', 'Member', 'AccountName'):
        fm = re.search(rf'\b{field}=([^|]+)', detail)
        if fm:
            actor = fm.group(1).strip()
            break

    # destination: source IP from Source= or Address= fields
    # Stops at space so geo string "(Country | ...)" is excluded.
    src = re.search(r'(?:Source|Address)=([\d\.a-fA-F:]+)', detail)
    destination = src.group(1) if src else None
    if destination in ('N/A', '-', '::', ''):
        destination = None

    return {
        'event_type':   event_type,
        'subtype':      keyword,
        'actor':        actor,
        'process_path': None,
        'destination':  destination,
    }


def _normalize_bloodhound(message, severity):
    m = BLOODHOUND_RE.match(message)
    if not m:
        return None
    domain, actor, process_path = m.groups()
    return {
        'event_type':   'DNS',
        'subtype':      'QUERY',
        'actor':        actor,
        'process_path': process_path,
        'destination':  domain,
    }


def _normalize_doh_detector(message, severity):
    # CONFIRMED format — verified against DoH_Detector.ps1 source.
    # DOH_CONN_ENDED and OK startup lines return None (informational, not actionable).
    m = DOH_CONN_RE.match(message)
    if not m:
        return None
    _verb, actor, process_path, resolver = m.groups()
    return {
        'event_type':   'NETWORK',
        'subtype':      'DOH_CONNECTION',
        'actor':        actor,
        'process_path': process_path.strip() or None,
        'destination':  resolver,
    }


def _sysmon_kv(detail, key):
    """Extract value from 'key=val | key2=val2' style string. Returns None if absent."""
    m = re.search(rf'{re.escape(key)}=([^|]+)', detail)
    return m.group(1).strip() if m else None


def _normalize_sysmonwatcher(message, severity):
    # CONFIRMED — format matches SysmonWatcher.ps1 Write-Log calls.
    m = SYSMONWATCHER_RE.match(message)
    if not m:
        return None
    _label, eid_str, subtype_raw, detail = m.groups()
    eid = int(eid_str)

    _EID_TYPE = {
        1: 'PROCESS',  5: 'PROCESS',  25: 'PROCESS',
        6: 'DRIVER',
        7: 'DLL',
        8: 'INJECTION',
        9: 'DISK',
        10: 'PROCESS_ACCESS',
        11: 'FILE',    15: 'FILE',
        12: 'REGISTRY',
        17: 'PIPE',    18: 'PIPE',
        19: 'WMI',     20: 'WMI',     21: 'WMI',
    }
    event_type = _EID_TYPE.get(eid, 'UNKNOWN')
    subtype    = subtype_raw

    if eid in (1, 5, 25):
        actor        = _sysmon_kv(detail, 'Process')
        process_path = _sysmon_kv(detail, 'Path')
        destination  = None
    elif eid == 6:
        actor        = _sysmon_kv(detail, 'Driver')
        process_path = _sysmon_kv(detail, 'Path')
        destination  = None
    elif eid == 7:
        actor        = _sysmon_kv(detail, 'Process')
        # DLL_HIJACK/DLL_USERPATH: Path= is the DLL path (trust-level relevant).
        # UNMANAGED_PWSH: ProcessPath= is the loading process path.
        process_path = _sysmon_kv(detail, 'Path') or _sysmon_kv(detail, 'ProcessPath')
        destination  = None
    elif eid == 8:
        actor        = _sysmon_kv(detail, 'Source')
        process_path = None
        destination  = _sysmon_kv(detail, 'Target')
    elif eid == 9:
        actor        = _sysmon_kv(detail, 'Process')
        process_path = _sysmon_kv(detail, 'Path')
        destination  = _sysmon_kv(detail, 'Device')
    elif eid == 10:
        actor        = _sysmon_kv(detail, 'Source')
        process_path = _sysmon_kv(detail, 'SourcePath')
        destination  = _sysmon_kv(detail, 'Target')
    elif eid in (11, 15):
        actor        = _sysmon_kv(detail, 'Process')
        process_path = _sysmon_kv(detail, 'Path')
        destination  = None
    elif eid == 12:
        actor        = _sysmon_kv(detail, 'Process')
        process_path = None
        destination  = _sysmon_kv(detail, 'Key')
    elif eid in (17, 18):
        actor        = _sysmon_kv(detail, 'Process')
        process_path = _sysmon_kv(detail, 'Path')
        destination  = _sysmon_kv(detail, 'PipeName')
    elif eid in (19, 20, 21):
        actor        = _sysmon_kv(detail, 'User')
        process_path = None
        destination  = None
    else:
        actor        = None
        process_path = None
        destination  = None

    return {
        'event_type':   event_type,
        'subtype':      subtype,
        'actor':        actor,
        'process_path': process_path or None,
        'destination':  destination or None,
    }


def _normalize_warden(message, severity):
    # CONFIRMED against Warden.ps1 source — four distinct message formats.
    m = WARDEN_FIM_RE.match(message)
    if m:
        _verb, detail = m.groups()
        return {
            'event_type':   'INTEGRITY',
            'subtype':      'FIM_VIOLATION',
            'actor':        detail.strip(),
            'process_path': None,
            'destination':  None,
        }
    m = WARDEN_LOG_TAMPER_RE.match(message)
    if m:
        _verb, detail = m.groups()
        return {
            'event_type':   'INTEGRITY',
            'subtype':      'LOG_TAMPER',
            'actor':        detail.strip(),
            'process_path': None,
            'destination':  None,
        }
    m = WARDEN_COLLECTOR_RE.match(message)
    if m:
        return {
            'event_type':   'INTEGRITY',
            'subtype':      'COLLECTOR_DOWN',
            'actor':        m.group(1),
            'process_path': None,
            'destination':  None,
        }
    if WARDEN_MANIFEST_RE.match(message):
        return {
            'event_type':   'INTEGRITY',
            'subtype':      'MANIFEST_MISSING',
            'actor':        None,
            'process_path': None,
            'destination':  None,
        }
    return None


# Lookup by collector_name (lowercased at call site)
_NORMALIZERS = {
    'harbinger':       _normalize_harbinger,
    'sentinel':        _normalize_sentinel,
    'bulwark':         _normalize_bulwark,
    'steward':         _normalize_steward,
    'cityguard':       _normalize_cityguard,
    'watchman':        _normalize_watchman,
    'registry_warden': _normalize_registry_warden,
    'seceventlog':     _normalize_seceventlog,
    'bloodhound':      _normalize_bloodhound,
    'doh_detector':    _normalize_doh_detector,
    'warden':          _normalize_warden,
    'sysmonwatcher':   _normalize_sysmonwatcher,
}


# ============================================================
# CORE NORMALIZER
# ============================================================

def normalize_raw_event(raw_event):
    """Normalize one raw_event row into the canonical event schema.
    Returns a normalized event dict.

    parser_confidence reflects how well the message matched its collector pattern:
      1.0 — full regex match, all fields extracted
      0.5 — known collector, regex did not match (format may differ from expected)
      0.4 — unknown collector (no normalizer registered)
    """
    collector   = raw_event['collector_name'].lower()
    raw_payload = raw_event['raw_payload']
    raw_hash    = raw_event['raw_event_hash']

    severity, message = _extract_severity_and_message(raw_payload)

    normalizer_fn = _NORMALIZERS.get(collector)

    if normalizer_fn is None:
        fields     = {'event_type': 'UNKNOWN', 'subtype': None,
                      'actor': None, 'process_path': None, 'destination': None}
        confidence = 0.4
    else:
        fields = normalizer_fn(message, severity)
        if fields is None:
            fields     = {'event_type': 'UNKNOWN', 'subtype': None,
                          'actor': None, 'process_path': None, 'destination': None}
            confidence = 0.5
        else:
            confidence = 1.0

    trust_level = _assign_trust_level(fields.get('process_path'))
    event_id    = _make_event_id(raw_hash, collector)

    return {
        'event_id':          event_id,
        'schema_version':    SCHEMA_VERSION,
        'collector_name':    raw_event['collector_name'],
        'source_host':       raw_event['source_host'],
        'observed_at':       raw_event['observed_at'],
        'ingested_at':       datetime.utcnow().isoformat(),
        'event_type':        fields['event_type'],
        'subtype':           fields.get('subtype'),
        'actor':             fields.get('actor'),
        'process_path':      fields.get('process_path'),
        'destination':       fields.get('destination'),
        'base_severity':     severity,
        'trust_level':       trust_level,
        'parser_confidence': confidence,
        'ingest_status':     'OK',
    }


# ============================================================
# BATCH ENTRY POINT — called by engine.py each cycle
# ============================================================

def normalize_pending():
    """Normalize all raw_events not yet stamped with a normalized_event_id.
    Inserts normalized events and stamps raw_events in two batch transactions
    (one per table) rather than one transaction per row.
    Returns count of events written to the events table."""
    pending = db.get_pending_raw_events()
    if not pending:
        return 0

    normalized_events = []
    stamp_pairs       = []   # (raw_id, event_id)

    for raw in pending:
        normalized = normalize_raw_event(raw)
        if normalized:
            normalized_events.append(normalized)
            stamp_pairs.append((raw['id'], normalized['event_id']))

    db.insert_events_batch(normalized_events)
    db.mark_raw_events_normalized_batch(stamp_pairs)
    return len(normalized_events)
