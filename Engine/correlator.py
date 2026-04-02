# ============================================================
# correlator.py — Night's Watch Home SOC Suite
# Applies correlation rules to normalized events and produces
# detections and alerts.
#
# Architecture:
#   Tier 1 — Single-event rules (no time window).
#             Run once per event — events are stamped correlated_at
#             after processing so they are never re-evaluated.
#   Tier 2 — Short-window rules (config.SHORT_WINDOW = 10 min).
#             Run each cycle against all events in the window.
#   Tier 3 — Operational-window rules (config.OPERATIONAL_WINDOW = 24h).
#   Tier 4 — Campaign-window rules (config.CAMPAIGN_WINDOW = 7 days).
#
# Alert deduplication:
#   alert_id is deterministic — SHA256(rule_id + sorted evidence IDs)[:16].
#   db.insert_alert uses INSERT OR IGNORE, so the same detection never
#   produces a second alert row regardless of how many times the rule fires.
#
# To add a new rule:
#   1. Write a _rule_N(event) or _rule_N(events) function.
#   2. Append it to the appropriate _TIER_N_RULES list.
#   3. Add a test in test_correlator.py.
#   No other changes needed.
# ============================================================

import hashlib
import os
from collections import defaultdict
from datetime import datetime, timedelta

import config
import db
import health_db


# ============================================================
# SHARED LOOKUP SETS  (built once at import — O(1) membership)
# ============================================================

_LOLBIN_SET      = {b.lower() for b in config.LOLBIN_LIST}
_INTERPRETER_SET = {i.lower() for i in config.INTERPRETER_LIST}
_HOLLOWING_SET   = {h.lower() for h in config.HOLLOWING_TARGETS}
_NEVER_NET_SET   = {n.lower() for n in config.NEVER_NET_BINARIES}


# ============================================================
# HELPERS
# ============================================================

def _make_alert_id(rule_id, *evidence_ids):
    """Deterministic alert ID — same rule + same evidence always hashes to the
    same ID.  INSERT OR IGNORE in db.insert_alert prevents duplicates."""
    key = f"rule_{rule_id}:" + ":".join(sorted(str(e) for e in evidence_ids))
    return hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]


def _parse_dt(observed_at_str):
    """Parse an observed_at string to datetime. Returns None on failure."""
    if not observed_at_str:
        return None
    try:
        return datetime.fromisoformat(observed_at_str)
    except (ValueError, TypeError):
        return None


def _is_after_hours(observed_at_str):
    """Return True if the event time falls in the after-hours window
    defined by config.AFTER_HOURS_START and config.AFTER_HOURS_END."""
    dt = _parse_dt(observed_at_str)
    if dt is None:
        return False
    return config.AFTER_HOURS_START <= dt.hour < config.AFTER_HOURS_END


def _summarise(items, limit=3):
    """Truncate a list to a readable string with overflow count.
    e.g. ['a','b','c','d'] → 'a, b, c (+1 more)'"""
    tail = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(items[:limit]) + tail


def _actors_match(actor_a, actor_b):
    """Return True if two actor strings refer to the same binary.

    Cross-source normalisation: Harbinger logs 'evil.exe', Sentinel logs
    'evil'.  Strip the .exe suffix from both sides before comparing.
    """
    if not actor_a or not actor_b:
        return False
    a = actor_a.lower().strip()
    b = actor_b.lower().strip()
    a_bare = a[:-4] if a.endswith('.exe') else a
    b_bare = b[:-4] if b.endswith('.exe') else b
    return a_bare == b_bare


def _actor_matches(actor, process_path, name_set):
    """Return True if the event actor or process binary is in name_set.

    Handles actors logged without the .exe suffix — Sentinel logs 'powershell',
    Harbinger logs 'powershell.exe'.  Both match 'powershell.exe' in the set.
    """
    if not actor:
        return False
    actor_lower = actor.lower().strip()
    if actor_lower in name_set:
        return True
    if (actor_lower + '.exe') in name_set:
        return True
    if process_path:
        basename = os.path.basename(process_path).lower()
        if basename in name_set:
            return True
    return False


# ============================================================
# TIER 1 — SINGLE-EVENT RULES
# ============================================================

def _rule_6(event):
    """Rule 6 — LOLBin Network Activity  (CRITICAL)

    A LOLBin (Living Off the Land Binary) made an outbound network connection.
    LOLBins are trusted Windows binaries documented for abuse in C2, download,
    lateral movement, and proxy activity (LOLBAS Project).

    Single-event — no correlation window needed.
    Source: Sentinel  (event_type=NETWORK)
    Weight: config.RULE_WEIGHTS[6]
    """
    if event['event_type'] != 'NETWORK':
        return
    if not _actor_matches(event['actor'], event['process_path'], _LOLBIN_SET):
        return

    alert_id = _make_alert_id(6, event['event_id'])
    weight   = config.RULE_WEIGHTS[6]

    # Trusted-path LOLBins (e.g. pwsh from WindowsApps) making network
    # connections are worth recording but don't warrant CRITICAL — that
    # severity is reserved for LOLBin abuse from non-trusted paths.
    if event['trust_level'] == 'TRUSTED':
        severity = 'SUSPICIOUS'
        weight   = weight * 0.5
    else:
        severity = 'CRITICAL'

    db.insert_detection({
        'rule_id':          6,
        'window_type':      'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'lolbin_match':  1.0,
            'base_severity': event['base_severity'],
            'trust_level':   event['trust_level'],
        },
        'confidence':    weight,
        'evidence_refs': [event['event_id']],
    })

    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          6,
        'severity_current': severity,
        'confidence':       weight,
        'status':           'NEW',
        'explanation': (
            f"Rule 6 — LOLBin Network Activity. "
            f"Actor '{event['actor']}' made an outbound network connection "
            f"to {event['destination'] or 'unknown destination'}. "
            f"LOLBins are trusted Windows binaries with documented abuse potential "
            f"for C2, download, and proxy activity (LOLBAS Project). "
            f"Process path: {event['process_path'] or 'not recorded'}. "
            f"Collector severity: {event['base_severity']}. "
            f"Confidence: {weight:.0%}. "
            f"Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_21(event):
    """Rule 21 — Interpreter / BYOI Execution  (HIGH → CRITICAL by path)

    A language interpreter or scripting runtime was spawned.
    BYOI (Bring Your Own Interpreter) is used to bypass application
    whitelisting and execute arbitrary code using trusted runtimes.

    Severity scales with path trust level:
      TRUSTED path   → detection only, no alert  (likely legitimate dev work)
      UNKNOWN path   → SUSPICIOUS alert, 60% confidence
      HIGH_RISK path → CRITICAL alert, full rule weight

    Single-event — no correlation window needed.
    Source: Harbinger  (event_type=PROCESS)
    Weight: config.RULE_WEIGHTS[21]
    """
    if event['event_type'] != 'PROCESS':
        return
    if not _actor_matches(event['actor'], event['process_path'], _INTERPRETER_SET):
        return

    trust  = event['trust_level']
    weight = config.RULE_WEIGHTS[21]

    if trust == 'TRUSTED':
        # Log the detection for Rule 26 integrity / baseline purposes.
        # No alert — spawning an interpreter from a system path is normal
        # for a developer machine. Alert threshold revisit after baseline.
        db.insert_detection({
            'rule_id':          21,
            'window_type':      'single',
            'matched_entities': [event['event_id']],
            'score_factors': {
                'interpreter_match': 1.0,
                'trust_level':       trust,
                'base_severity':     event['base_severity'],
            },
            'confidence':    weight * 0.3,
            'evidence_refs': [event['event_id']],
        })
        return

    # UNKNOWN or HIGH_RISK path — escalate
    if trust == 'HIGH_RISK':
        severity   = 'CRITICAL'
        confidence = weight
    else:                        # UNKNOWN
        severity   = 'SUSPICIOUS'
        confidence = weight * 0.6

    alert_id = _make_alert_id(21, event['event_id'])

    db.insert_detection({
        'rule_id':          21,
        'window_type':      'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'interpreter_match': 1.0,
            'trust_level':       trust,
            'base_severity':     event['base_severity'],
        },
        'confidence':    confidence,
        'evidence_refs': [event['event_id']],
    })

    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          21,
        'severity_current': severity,
        'confidence':       confidence,
        'status':           'NEW',
        'explanation': (
            f"Rule 21 — Interpreter / BYOI Execution. "
            f"Actor '{event['actor']}' was spawned from a {trust.lower()} path. "
            f"Bring Your Own Interpreter attacks use legitimate runtimes to "
            f"execute arbitrary code and bypass application whitelisting. "
            f"Process path: {event['process_path'] or 'not recorded'}. "
            f"Collector severity: {event['base_severity']}. "
            f"Confidence: {confidence:.0%}. "
            f"Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_4(reference_time=None):
    """Rule 4 — After-Hours Intrusion  (CRITICAL)

    A system wake or boot occurred during after-hours (00:00–06:00) AND
    network activity was observed within SHORT_WINDOW (10 minutes).

    Attacker playbook: force or wait for machine wake at night, establish
    C2 before the owner is present to notice unusual activity.

    Power event subtypes that trigger: WAKE, BOOT.
    SLEEP and SHUTDOWN are not suspicious — machine going idle is normal.

    reference_time: optional datetime for testing. Defaults to utcnow().

    Sources: Watchman (event_type=POWER) + Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[4]
    """
    power_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='POWER', reference_time=reference_time
    )
    after_hours_wakes = [
        e for e in power_events
        if e['subtype'] in ('WAKE', 'BOOT') and _is_after_hours(e['observed_at'])
    ]
    if not after_hours_wakes:
        return

    network_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    after_hours_net = [
        e for e in network_events
        if _is_after_hours(e['observed_at'])
    ]
    if not after_hours_net:
        return

    weight = config.RULE_WEIGHTS[4]

    for power_evt in after_hours_wakes:
        power_dt = _parse_dt(power_evt['observed_at'])
        if power_dt is None:
            continue

        # Network events must be within SHORT_WINDOW of the power event
        corroborating = []
        for net_evt in after_hours_net:
            net_dt = _parse_dt(net_evt['observed_at'])
            if net_dt is None:
                continue
            if abs((net_dt - power_dt).total_seconds()) <= config.SHORT_WINDOW:
                corroborating.append(net_evt)

        if not corroborating:
            continue

        # alert_id keyed on power event — one alert per wake event,
        # regardless of how many network connections followed it
        alert_id = _make_alert_id(4, power_evt['event_id'])

        actors       = sorted({n['actor']       for n in corroborating if n['actor']})
        destinations = sorted({n['destination'] for n in corroborating if n['destination']})

        db.insert_detection({
            'rule_id':          4,
            'window_type':      'short',
            'matched_entities': [power_evt['event_id']] + [n['event_id'] for n in corroborating],
            'score_factors': {
                'after_hours':   1.0,
                'power_subtype': power_evt['subtype'],
                'network_count': len(corroborating),
                'base_severity': power_evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [power_evt['event_id']] + [n['event_id'] for n in corroborating],
        })

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          4,
            'severity_current': 'CRITICAL',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 4 — After-Hours Intrusion. "
                f"System {power_evt['subtype']} at {power_evt['observed_at']} "
                f"(after-hours window "
                f"{config.AFTER_HOURS_START:02d}:00\u2013{config.AFTER_HOURS_END:02d}:00). "
                f"{len(corroborating)} network connection(s) within "
                f"{config.SHORT_WINDOW // 60} minutes: "
                f"actors: {_summarise(actors) if actors else 'unknown'}. "
                f"Destinations: {_summarise(destinations) if destinations else 'unknown'}. "
                f"A system that should be idle made network connections shortly "
                f"after waking. Investigate whether this wake was user-initiated. "
                f"Confidence: {weight:.0%}. "
                f"Power event evidence: {power_evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_13(reference_time=None):
    """Rule 13 — Initial Access Suspected  (CRITICAL)

    A process from a HIGH_RISK path (Downloads/Temp/AppData/Public) made
    an outbound network connection within 120 seconds of being spawned.

    Attacker playbook: malicious download executes and immediately calls
    back to a C2 server to retrieve the second-stage payload.  The 120-
    second window was extended from 60 seconds after live adversarial
    testing showed a 75-second delay bypassed the original rule.

    Sources: Harbinger (event_type=PROCESS, trust_level=HIGH_RISK)
             + Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW for candidate retrieval;
             120-second actor-pairing window for process→network delta
    Weight:  config.RULE_WEIGHTS[13]
    """
    PAIRING_WINDOW = 120   # seconds — from red team analysis

    process_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='PROCESS', reference_time=reference_time
    )
    high_risk_procs = [e for e in process_events if e['trust_level'] == 'HIGH_RISK']
    if not high_risk_procs:
        return

    network_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    if not network_events:
        return

    weight = config.RULE_WEIGHTS[13]

    for proc_evt in high_risk_procs:
        proc_dt = _parse_dt(proc_evt['observed_at'])
        if proc_dt is None:
            continue

        # Network event must be from the same actor and arrive AFTER the
        # process starts (delta >= 0) and within the pairing window.
        matching_net = []
        for net_evt in network_events:
            net_dt = _parse_dt(net_evt['observed_at'])
            if net_dt is None:
                continue
            delta = (net_dt - proc_dt).total_seconds()
            if 0 <= delta <= PAIRING_WINDOW and _actors_match(proc_evt['actor'], net_evt['actor']):
                matching_net.append(net_evt)

        if not matching_net:
            continue

        # alert_id keyed on the process event — one alert per suspicious
        # process launch regardless of how many network events followed it
        alert_id     = _make_alert_id(13, proc_evt['event_id'])
        destinations = sorted({n['destination'] for n in matching_net if n['destination']})

        db.insert_detection({
            'rule_id':          13,
            'window_type':      'short',
            'matched_entities': [proc_evt['event_id']] + [n['event_id'] for n in matching_net],
            'score_factors': {
                'high_risk_path': 1.0,
                'trust_level':    proc_evt['trust_level'],
                'network_count':  len(matching_net),
                'base_severity':  proc_evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [proc_evt['event_id']] + [n['event_id'] for n in matching_net],
        })

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          13,
            'severity_current': 'CRITICAL',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 13 — Initial Access Suspected. "
                f"Process '{proc_evt['actor']}' was spawned from a high-risk path "
                f"({proc_evt['process_path'] or 'not recorded'}) "
                f"and made {len(matching_net)} outbound network connection(s) within "
                f"{PAIRING_WINDOW} seconds. "
                f"Destinations: {_summarise(destinations) if destinations else 'unknown'}. "
                f"This pattern matches a malicious download executing and immediately "
                f"calling back to a C2 server to retrieve a second-stage payload. "
                f"Collector severity: {proc_evt['base_severity']}. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {proc_evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_3(reference_time=None):
    """Rule 3 — Persistence + C2 Callback  (CRITICAL)

    A new scheduled task was created in a suspicious (non-trusted) path
    AND an outbound network connection from a non-trusted process occurred
    within SHORT_WINDOW (10 minutes).

    Attacker playbook: install a scheduled task as a persistence mechanism
    while simultaneously calling back to C2, or beacon immediately after
    the task is registered to confirm the implant is active.

    Both events must have trust_level != 'TRUSTED' — a legitimate task
    registered by a system binary co-occurring with a routine browser
    connection should not fire this rule.

    Actor matching: if the task's action binary matches the network actor,
    this is flagged in score_factors as direct evidence of the same binary
    both persisting and beaconing.

    Sources: CityGuard (event_type=SCHEDULED_TASK, subtype='NEW TASK')
             + Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW (10 min) — both events within same window bucket
    Weight:  config.RULE_WEIGHTS[3]
    """
    _SUSPICIOUS_TRUST = {'HIGH_RISK', 'UNKNOWN'}

    task_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='SCHEDULED_TASK', reference_time=reference_time
    )
    new_tasks = [
        e for e in task_events
        if e['subtype'] == 'NEW TASK' and e['trust_level'] in _SUSPICIOUS_TRUST
    ]
    if not new_tasks:
        return

    network_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    suspicious_net = [e for e in network_events if e['trust_level'] in _SUSPICIOUS_TRUST]
    if not suspicious_net:
        return

    weight = config.RULE_WEIGHTS[3]

    for task_evt in new_tasks:
        alert_id = _make_alert_id(3, task_evt['event_id'])

        # Score extra if the task's action binary is also the network actor
        actor_matches = [
            n for n in suspicious_net
            if _actors_match(task_evt['actor'], n['actor'])
            or (task_evt['process_path'] and _actors_match(
                os.path.basename(task_evt['process_path']), n['actor']
            ))
        ]
        direct_match   = len(actor_matches) > 0
        corroborating  = actor_matches if direct_match else suspicious_net
        destinations   = sorted({n['destination'] for n in corroborating if n['destination']})
        actors_net     = sorted({n['actor'] for n in corroborating if n['actor']})

        db.insert_detection({
            'rule_id':          3,
            'window_type':      'short',
            'matched_entities': [task_evt['event_id']] + [n['event_id'] for n in corroborating],
            'score_factors': {
                'task_trust_level': task_evt['trust_level'],
                'network_count':    len(corroborating),
                'actor_match':      direct_match,
                'base_severity':    task_evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [task_evt['event_id']] + [n['event_id'] for n in corroborating],
        })

        match_note = (
            f"The task action binary matches the network actor — "
            f"the same process is both persisting and beaconing. "
            if direct_match else
            f"No direct actor match — task and network events are temporally "
            f"correlated but may involve different binaries. "
        )

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          3,
            'severity_current': 'CRITICAL',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 3 — Persistence + C2 Callback. "
                f"New scheduled task '{task_evt['actor'] or 'unknown'}' "
                f"registered at {task_evt['observed_at']} "
                f"with action path: {task_evt['process_path'] or 'not recorded'}. "
                f"Trust level: {task_evt['trust_level']}. "
                f"{len(corroborating)} outbound network connection(s) from "
                f"non-trusted process(es) within "
                f"{config.SHORT_WINDOW // 60} minutes: "
                f"actors: {_summarise(actors_net) if actors_net else 'unknown'}. "
                f"Destinations: {_summarise(destinations) if destinations else 'unknown'}. "
                f"{match_note}"
                f"Persistence + immediate C2 callback is a hallmark of "
                f"post-exploitation implant deployment. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {task_evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_9(reference_time=None):
    """Rule 9 — WMI Persistence Suspected  (HIGH / SUSPICIOUS)

    A process was spawned by a WMI host (WmiPrvSE.exe) AND a new scheduled
    task was registered within SHORT_WINDOW (10 minutes).

    WMI is a legitimate Windows management interface that attackers abuse to
    spawn processes silently — no visible window, bypasses many process-chain
    detection tools.  WMI execution co-occurring with new scheduled task
    registration suggests the attacker is establishing initial execution via WMI
    while simultaneously installing persistence.

    Parent detection: Harbinger logs the parent process name in the raw line
    ('Parent: WmiPrvSE (PID)') but the normalised schema has no parent field.
    db.get_harbinger_events_by_parent() joins raw_events to retrieve these.

    Sources: Harbinger (parent=WmiPrvSE.exe) + CityGuard (NEW TASK)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[9]
    """
    _WMI_FRAGMENT = 'Parent: WmiPrvSE'   # matches case-insensitively in raw log

    wmi_procs = db.get_harbinger_events_by_parent(
        _WMI_FRAGMENT, config.SHORT_WINDOW, reference_time=reference_time
    )
    if not wmi_procs:
        return

    task_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='SCHEDULED_TASK', reference_time=reference_time
    )
    new_tasks = [e for e in task_events if e['subtype'] == 'NEW TASK']
    if not new_tasks:
        return

    weight = config.RULE_WEIGHTS[9]

    for proc_evt in wmi_procs:
        alert_id    = _make_alert_id(9, proc_evt['event_id'])
        task_actors = sorted({t['actor']        for t in new_tasks if t['actor']})
        task_paths  = sorted({t['process_path'] for t in new_tasks if t['process_path']})

        db.insert_detection({
            'rule_id':          9,
            'window_type':      'short',
            'matched_entities': [proc_evt['event_id']] + [t['event_id'] for t in new_tasks],
            'score_factors': {
                'wmi_parent':    True,
                'task_count':    len(new_tasks),
                'task_paths':    task_paths[:3],
                'base_severity': proc_evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [proc_evt['event_id']] + [t['event_id'] for t in new_tasks],
        })

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          9,
            'severity_current': 'SUSPICIOUS',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 9 — WMI Persistence Suspected. "
                f"Process '{proc_evt['actor'] or 'unknown'}' was spawned by a WMI host "
                f"(WmiPrvSE.exe) at {proc_evt['observed_at']}. "
                f"WMI execution leaves no visible window and bypasses many process-chain "
                f"detection tools that rely on parent-process visibility. "
                f"{len(new_tasks)} new scheduled task(s) were registered within "
                f"{config.SHORT_WINDOW // 60} minutes: "
                f"tasks: {_summarise(task_actors) if task_actors else 'unknown'}. "
                f"WMI-spawned process co-occurring with new persistence is a strong "
                f"indicator of post-exploitation activity. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {proc_evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_7(reference_time=None):
    """Rule 7 — Process Hollowing Suspected  (CRITICAL)

    A well-known Windows system binary name was launched from a path that is NOT
    a trusted system path, AND the same actor made an outbound network connection
    within SHORT_WINDOW (10 minutes).

    Process hollowing: the attacker launches a process using a trusted system
    binary name to evade name-based detection, but the executable is actually
    attacker-controlled code.  The wrong path is the tell — svchost.exe always
    lives in System32; finding it in Temp or AppData is unambiguous masquerade.

    Distinct from Rule 16: Rule 7 = right name, wrong path (fake binary).
    Rule 16 = right name, right path, wrong behaviour (real binary compromised).

    Sources: Harbinger (event_type=PROCESS) + Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[7]
    """
    process_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='PROCESS', reference_time=reference_time
    )
    hollow_procs = [
        e for e in process_events
        if e['trust_level'] != 'TRUSTED'
        and _actor_matches(e['actor'], e['process_path'], _HOLLOWING_SET)
    ]
    if not hollow_procs:
        return

    network_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    if not network_events:
        return

    weight = config.RULE_WEIGHTS[7]

    for proc_evt in hollow_procs:
        matching_net = [
            n for n in network_events
            if _actors_match(proc_evt['actor'], n['actor'])
        ]
        if not matching_net:
            continue

        alert_id     = _make_alert_id(7, proc_evt['event_id'])
        destinations = sorted({n['destination'] for n in matching_net if n['destination']})

        db.insert_detection({
            'rule_id':          7,
            'window_type':      'short',
            'matched_entities': [proc_evt['event_id']] + [n['event_id'] for n in matching_net],
            'score_factors': {
                'hollow_target': proc_evt['actor'],
                'wrong_path':    proc_evt['process_path'],
                'trust_level':   proc_evt['trust_level'],
                'network_count': len(matching_net),
                'base_severity': proc_evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [proc_evt['event_id']] + [n['event_id'] for n in matching_net],
        })

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          7,
            'severity_current': 'CRITICAL',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 7 — Process Hollowing Suspected. "
                f"'{proc_evt['actor']}' has the name of a well-known Windows system binary "
                f"but was launched from a non-system path: "
                f"{proc_evt['process_path'] or 'path not recorded'}. "
                f"Trust level: {proc_evt['trust_level']}. "
                f"The same actor made {len(matching_net)} outbound network connection(s) "
                f"within {config.SHORT_WINDOW // 60} minutes. "
                f"Destinations: {_summarise(destinations) if destinations else 'unknown'}. "
                f"A trusted binary name from the wrong path is unambiguous masquerade — "
                f"the attacker uses a system name to evade name-based detection. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {proc_evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_16(reference_time=None):
    """Rule 16 — Contextual Integrity Violation  (CRITICAL)

    A Windows system process that should never make outbound network connections
    was confirmed running from its legitimate trusted path AND made an outbound
    connection within SHORT_WINDOW (10 minutes).

    Distinct from Rule 7: Rule 7 = right name, wrong path (fake binary).
    Rule 16 = right name, right path, wrong behaviour (real binary compromised).

    Processes like lsass.exe, csrss.exe, wininit.exe have no legitimate reason
    to make outbound network connections under any normal operating condition.
    An outbound connection from these processes indicates the process has been
    compromised via code injection, hollowing-after-load, or is being used as
    cover by a credential-dumping or lateral-movement tool.

    Sources: Harbinger (event_type=PROCESS, trust_level=TRUSTED)
             + Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[16]
    """
    process_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='PROCESS', reference_time=reference_time
    )
    # Right binary, right path — the path IS trusted; the behaviour is not
    suspect_procs = [
        e for e in process_events
        if e['trust_level'] == 'TRUSTED'
        and _actor_matches(e['actor'], e['process_path'], _NEVER_NET_SET)
    ]
    if not suspect_procs:
        return

    network_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    if not network_events:
        return

    weight = config.RULE_WEIGHTS[16]

    for proc_evt in suspect_procs:
        matching_net = [
            n for n in network_events
            if _actors_match(proc_evt['actor'], n['actor'])
        ]
        if not matching_net:
            continue

        alert_id     = _make_alert_id(16, proc_evt['event_id'])
        destinations = sorted({n['destination'] for n in matching_net if n['destination']})

        db.insert_detection({
            'rule_id':          16,
            'window_type':      'short',
            'matched_entities': [proc_evt['event_id']] + [n['event_id'] for n in matching_net],
            'score_factors': {
                'process_name':  proc_evt['actor'],
                'trusted_path':  proc_evt['process_path'],
                'should_net':    False,
                'network_count': len(matching_net),
                'base_severity': proc_evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [proc_evt['event_id']] + [n['event_id'] for n in matching_net],
        })

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          16,
            'severity_current': 'CRITICAL',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 16 — Contextual Integrity Violation. "
                f"Process '{proc_evt['actor']}' was confirmed running from its legitimate "
                f"system path ({proc_evt['process_path'] or 'not recorded'}) "
                f"but made {len(matching_net)} outbound network connection(s) — "
                f"behaviour that is inconsistent with this process's normal function. "
                f"Destinations: {_summarise(destinations) if destinations else 'unknown'}. "
                f"'{proc_evt['actor']}' should never make outbound connections. "
                f"This indicates code injection, hollowing-after-load, or a credential- "
                f"dumping tool operating under this process's cover. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {proc_evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_11(reference_time=None):
    """Rule 11 — Burst Exfiltration Pattern  (SUSPICIOUS)

    The same actor made config.BURST_CONNECTION_THRESHOLD or more outbound
    NETWORK connections within SHORT_WINDOW (10 minutes).

    Rapid repeated connections from a non-trusted process indicate data staging,
    chunked exfiltration to rotating IPs, or C2 beacon behaviour.

    Zero-trust baseline policy:
      HIGH_RISK actor  → SUSPICIOUS alert
      UNKNOWN actor    → SUSPICIOUS alert  (unclassified + burst = suspicious)
      TRUSTED actor    → detection only, no alert
                         (establishes what 'normal' burst looks like for system
                          binaries during the baseline month)

    Note — simplified from full spec:
      Full spec also requires total transfer > 1 MB AND each connection < 10 s.
      Those fields require Sentinel to track connection lifecycle and per-process
      byte counts — neither is logged in current Sentinel output.
      See PHASE7_HANDOFF.md § Nice-to-Have for the enhancement path.

    Source:  Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[11]
    """
    from collections import defaultdict

    net_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    if not net_events:
        return

    # Group by normalised actor name (strip .exe for cross-source consistency)
    by_actor = defaultdict(list)
    for e in net_events:
        key = (e['actor'] or '').lower().rstrip('.exe') if e['actor'] else ''
        key = key.rstrip('.')          # handles names that don't end in .exe
        by_actor[key].append(e)

    weight = config.RULE_WEIGHTS[11]

    for actor_key, events in by_actor.items():
        if len(events) < config.BURST_CONNECTION_THRESHOLD:
            continue

        # Sort by observed_at — anchor on earliest for stable deduplication
        events_sorted = sorted(events, key=lambda e: e['observed_at'] or '')
        anchor        = events_sorted[0]
        alert_id      = _make_alert_id(11, anchor['event_id'])
        destinations  = sorted({e['destination'] for e in events if e['destination']})
        trust         = anchor['trust_level']

        db.insert_detection({
            'rule_id':          11,
            'window_type':      'short',
            'matched_entities': [e['event_id'] for e in events],
            'score_factors': {
                'actor':               actor_key,
                'connection_count':    len(events),
                'unique_destinations': len(destinations),
                'trust_level':         trust,
            },
            'confidence':    weight,
            'evidence_refs': [e['event_id'] for e in events],
        })

        if trust == 'TRUSTED':
            continue    # detection logged; alert suppressed during baseline period

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          11,
            'severity_current': 'SUSPICIOUS',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 11 — Burst Exfiltration Pattern. "
                f"Process '{actor_key}' made {len(events)} outbound network "
                f"connection(s) within {config.SHORT_WINDOW // 60} minutes "
                f"(threshold: {config.BURST_CONNECTION_THRESHOLD}). "
                f"Trust level: {trust}. "
                f"Destinations ({len(destinations)} unique): "
                f"{_summarise(destinations) if destinations else 'unknown'}. "
                f"Rapid repeated outbound connections from a non-trusted process "
                f"indicate data staging, chunked exfiltration, or C2 beacon activity. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {anchor['event_id']}."
            ),
            'linked_case': None,
        })


# ============================================================
# RULE DISPATCH LISTS
# Append new rules here — run_all() picks them up automatically.
# ============================================================

def _rule_2(reference_time=None):
    """Rule 2 — C2 Beacon Suspected  (HIGH → SUSPICIOUS)

    The same process repeatedly connected to the same remote IP across
    multiple discrete sessions within the operational window — a classic
    beacon pattern where malware periodically checks in with a C2 server,
    drops data or receives commands, then closes the connection.

    Detection model:
      Bulwark CONNECTION_END events are session records: each represents
      a completed TCP session.  Seeing the same (actor, destination) pair
      produce >= C2_BEACON_MIN_SESSIONS session records is a frequency
      signal that warrants investigation.
      Cross-confirmation from Sentinel (independent outbound monitor)
      raises confidence.  Trusted-path processes require double the
      threshold — routine update checks are frequent.

    Alert deduplication:
      Keyed on (rule_id, actor, destination, hour-bucket) so one alert
      fires per suspicious pair per hour, not per cycle.

    Severity: SUSPICIOUS (probabilistic — beacon patterns require triage,
      not automatic CRITICAL escalation at this confidence level).

    Note — future enhancement (see PHASE7_HANDOFF.md):
      Store duration_seconds from CONNECTION_END in the events table.
      Long-duration persistent sessions (single session open for hours)
      are a separate TTP (persistent C2 channel vs. periodic beacon)
      but belong in the same rule — add duration arm once schema supports it.

    Sources: Bulwark (CONNECTION_END) + Sentinel (OUTBOUND confirmation)
    Window:  OPERATIONAL_WINDOW (24 hours)
    Weight:  config.RULE_WEIGHTS[2]
    """
    weight = config.RULE_WEIGHTS[2]

    # --- Signal 1: Bulwark session records ---
    bulwark_ends = db.get_events_in_window(
        config.OPERATIONAL_WINDOW,
        collector_name='bulwark',
        event_type='NETWORK',
        reference_time=reference_time,
    )
    session_ends = [e for e in bulwark_ends if e['subtype'] == 'CONNECTION_END']
    if not session_ends:
        return

    # --- Group by (actor, destination) ---
    sessions_by_pair = defaultdict(list)
    for evt in session_ends:
        key = (
            (evt['actor'] or 'unknown').lower(),
            evt['destination'] or 'unknown',
        )
        sessions_by_pair[key].append(evt)

    # --- Signal 2: Sentinel outbound destinations (cross-source confirmation) ---
    sentinel_events = db.get_events_in_window(
        config.OPERATIONAL_WINDOW,
        collector_name='sentinel',
        event_type='NETWORK',
        reference_time=reference_time,
    )
    sentinel_dests = {
        e['destination'] for e in sentinel_events
        if e['destination'] and e['subtype'] == 'OUTBOUND'
    }

    _now        = reference_time or datetime.now()
    hour_bucket = _now.strftime('%Y-%m-%d-%H')

    for (actor, dest), evts in sessions_by_pair.items():
        trust     = evts[-1]['trust_level']
        threshold = (
            config.C2_BEACON_MIN_SESSIONS * 2
            if trust == 'TRUSTED'
            else config.C2_BEACON_MIN_SESSIONS
        )
        if len(evts) < threshold:
            continue

        sentinel_confirmed = dest in sentinel_dests
        confidence         = weight if sentinel_confirmed else weight * 0.65

        evidence = [e['event_id'] for e in evts[:10]]
        alert_id = _make_alert_id(2, actor, dest, hour_bucket)

        db.insert_detection({
            'rule_id':          2,
            'window_type':      'operational',
            'matched_entities': evidence,
            'score_factors': {
                'actor':              actor,
                'destination':        dest,
                'session_count':      len(evts),
                'sentinel_confirmed': sentinel_confirmed,
                'trust_level':        trust,
            },
            'confidence':    confidence,
            'evidence_refs': evidence,
        })

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          2,
            'severity_current': 'SUSPICIOUS',
            'confidence':       confidence,
            'status':           'NEW',
            'explanation': (
                f"Rule 2 — C2 Beacon Suspected. "
                f"Process '{actor}' completed {len(evts)} discrete TCP sessions "
                f"to {dest} within the last "
                f"{config.OPERATIONAL_WINDOW // 3600} hours — "
                f"a frequency pattern consistent with periodic C2 check-in. "
                f"Sentinel confirmation: "
                f"{'YES' if sentinel_confirmed else 'NO (single-source)'}. "
                f"Trust level: {trust}. "
                f"Confidence: {confidence:.0%}. "
                f"Evidence: {', '.join(evidence[:3])}"
                f"{'...' if len(evidence) > 3 else ''}."
            ),
            'linked_case': None,
        })


def _rule_1(reference_time=None):
    """Rule 1 — Data Exfiltration Suspected  (SUSPICIOUS)

    A non-System process produced a resource spike (CPU or RAM) AND made an
    outbound network connection within RESOURCE_EXFIL_WINDOW (5 minutes).

    High CPU during a network transfer indicates active compression, encryption,
    or memory scanning — all consistent with data exfiltration.  High RAM can
    indicate a large in-memory staging buffer before transmission.

    'System' actor is excluded: kernel CPU spikes have no identifiable network
    peer to correlate with.  System + kernel-level events will be covered by a
    future rule when Sysmon.ps1 is built (planned — see PHASE7_HANDOFF.md).

    Pairing: actor must match across RESOURCE and NETWORK events.
    Time delta: |network.observed_at - resource.observed_at| <= RESOURCE_EXFIL_WINDOW.
    Direction is not enforced — network can arrive before or after the spike.

    Zero-trust baseline policy:
      non-TRUSTED network event → SUSPICIOUS alert
      TRUSTED network event     → detection only, no alert

    Sources: Steward (event_type=RESOURCE) + Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW (10 min) for candidate fetch;
             RESOURCE_EXFIL_WINDOW (5 min) for pairing
    Weight:  config.RULE_WEIGHTS[1]
    """
    resource_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='RESOURCE', reference_time=reference_time
    )
    # Exclude System — kernel process has no network peer to pair with
    resource_events = [
        e for e in resource_events
        if e['actor'] and e['actor'].lower() != 'system'
    ]
    if not resource_events:
        return

    network_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    if not network_events:
        return

    weight = config.RULE_WEIGHTS[1]

    for res_evt in resource_events:
        matching_net = []
        res_dt = _parse_dt(res_evt['observed_at'])
        if res_dt is None:
            continue

        for net_evt in network_events:
            if not _actors_match(res_evt['actor'], net_evt['actor']):
                continue
            net_dt = _parse_dt(net_evt['observed_at'])
            if net_dt is None:
                continue
            delta = abs((net_dt - res_dt).total_seconds())
            if delta <= config.RESOURCE_EXFIL_WINDOW:
                matching_net.append(net_evt)

        if not matching_net:
            continue

        alert_id     = _make_alert_id(1, res_evt['event_id'])
        destinations = sorted({n['destination'] for n in matching_net if n['destination']})
        trust        = matching_net[0]['trust_level']

        db.insert_detection({
            'rule_id':          1,
            'window_type':      'short',
            'matched_entities': [res_evt['event_id']] + [n['event_id'] for n in matching_net],
            'score_factors': {
                'resource_actor':  res_evt['actor'],
                'resource_type':   res_evt['subtype'],
                'network_count':   len(matching_net),
                'pairing_window':  config.RESOURCE_EXFIL_WINDOW,
                'base_severity':   res_evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [res_evt['event_id']] + [n['event_id'] for n in matching_net],
        })

        if trust == 'TRUSTED':
            continue    # detection logged; alert suppressed during baseline period

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          1,
            'severity_current': 'SUSPICIOUS',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 1 — Data Exfiltration Suspected. "
                f"Process '{res_evt['actor']}' produced a {res_evt['subtype']} spike "
                f"(severity: {res_evt['base_severity']}) at {res_evt['observed_at']} "
                f"and made {len(matching_net)} outbound network connection(s) within "
                f"{config.RESOURCE_EXFIL_WINDOW // 60} minutes. "
                f"High resource use during active network transfer is consistent with "
                f"on-the-fly compression, encryption, or memory staging before exfiltration. "
                f"Destinations ({len(destinations)} unique): "
                f"{_summarise(destinations) if destinations else 'unknown'}. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {res_evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_5(reference_time=None):
    """Rule 5 — Data Staging Suspected  (SUSPICIOUS)

    An unknown or high-risk process opened a new listening port within
    SHORT_WINDOW.  A fresh listening port from an untrusted process is a
    staging or C2 setup signal — malware commonly opens a port to receive
    staging instructions or to act as a local proxy for data collection
    before exfiltration.

    Zero-trust baseline policy:
      HIGH_RISK actor → SUSPICIOUS alert
      UNKNOWN actor   → SUSPICIOUS alert
      TRUSTED actor   → detection only, no alert

    Note — simplified from full spec:
      Full spec also requires a disk write spike within 5 minutes.
      Steward logs disk I/O to the console only (Write-Host) — never
      written to the log file.  See PHASE7_HANDOFF.md § Nice-to-Have.

    Source:  Bulwark (event_type=PORT, subtype=PORT_OPEN)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[5]
    """
    port_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='PORT', reference_time=reference_time
    )
    open_events = [e for e in port_events if e['subtype'] == 'PORT_OPEN']
    if not open_events:
        return

    weight = config.RULE_WEIGHTS[5]

    for evt in open_events:
        alert_id = _make_alert_id(5, evt['event_id'])
        trust    = evt['trust_level']

        db.insert_detection({
            'rule_id':          5,
            'window_type':      'short',
            'matched_entities': [evt['event_id']],
            'score_factors': {
                'actor':         evt['actor'],
                'port':          evt['destination'],
                'trust_level':   trust,
                'base_severity': evt['base_severity'],
            },
            'confidence':    weight,
            'evidence_refs': [evt['event_id']],
        })

        if trust == 'TRUSTED':
            continue    # detection logged; alert suppressed during baseline period

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          5,
            'severity_current': 'SUSPICIOUS',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 5 — Data Staging Suspected. "
                f"Process '{evt['actor'] or 'unknown'}' opened a new listening port "
                f"{evt['destination'] or 'unknown'} at {evt['observed_at']}. "
                f"Trust level: {trust}. "
                f"A non-trusted process opening a fresh listening port indicates "
                f"C2 channel setup, local staging proxy, or preparation for "
                f"data collection before exfiltration. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_22(reference_time=None):
    """Rule 22 — Cloud API Anomaly  (SUSPICIOUS)

    An outbound NETWORK connection was made after hours by a process that is
    not a known cloud sync client and is not path-classified as TRUSTED.

    The attack scenario: an adversary uses the victim's own cloud API tokens
    to upload data to a hidden folder in their own legitimate cloud storage
    (OneDrive, Google Drive, Dropbox). Traffic goes to microsoft.com / google.com
    and looks identical to legitimate sync — the only tell is the PROCESS making
    the connection is not the expected sync client.

    Distinct from Rule 4: Rule 4 requires a WAKE event (machine was sleeping).
    Rule 22 catches always-on dormant malware making after-hours connections
    on a continuously running machine without a sleep/wake transition.

    Zero-trust baseline policy:
      HIGH_RISK actor → SUSPICIOUS alert
      UNKNOWN actor   → SUSPICIOUS alert
      TRUSTED actor   → detection only, no alert

    Note — simplified from full spec:
      Full spec also requires:
        1. Destination identified as a cloud storage provider IP range
        2. Transfer volume > 100 MB
      Neither is available in current Sentinel output (IPs only, no domain
      names; no per-connection byte counts). See PHASE7_HANDOFF.md § Nice-to-Have.

    Source:  Sentinel (event_type=NETWORK)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[22]
    """
    _sync_set = {s.lower().rstrip('.exe') for s in config.KNOWN_SYNC_CLIENTS}

    net_events = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='NETWORK', reference_time=reference_time
    )
    if not net_events:
        return

    weight = config.RULE_WEIGHTS[22]

    for evt in net_events:
        if not _is_after_hours(evt['observed_at']):
            continue

        # Strip .exe for comparison against the sync whitelist
        actor_key = (evt['actor'] or '').lower().rstrip('.exe').rstrip('.')
        if actor_key in _sync_set:
            continue    # known legitimate sync client — skip

        alert_id = _make_alert_id(22, evt['event_id'])
        trust    = evt['trust_level']

        db.insert_detection({
            'rule_id':          22,
            'window_type':      'short',
            'matched_entities': [evt['event_id']],
            'score_factors': {
                'actor':       evt['actor'],
                'destination': evt['destination'],
                'trust_level': trust,
                'after_hours': True,
            },
            'confidence':    weight,
            'evidence_refs': [evt['event_id']],
        })

        if trust == 'TRUSTED':
            continue    # detection logged; alert suppressed during baseline period

        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          22,
            'severity_current': 'SUSPICIOUS',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"Rule 22 — Cloud API Anomaly. "
                f"Process '{evt['actor'] or 'unknown'}' made an outbound network "
                f"connection after hours at {evt['observed_at']} "
                f"(after-hours window: {config.AFTER_HOURS_START:02d}:00–"
                f"{config.AFTER_HOURS_END:02d}:00). "
                f"This process is not in the known sync client whitelist. "
                f"Destination: {evt['destination'] or 'unknown'}. "
                f"Trust level: {trust}. "
                f"An unrecognised process making after-hours cloud connections "
                f"may be using stolen API tokens to exfiltrate data through "
                f"a legitimate cloud storage provider. "
                f"Confidence: {weight:.0%}. "
                f"Evidence: {evt['event_id']}."
            ),
            'linked_case': None,
        })


def _rule_18(reference_time=None):
    """Rule 18 — Correlation Engine Health  [MEDIUM / SUSPICIOUS]

    Two independent checks run each cycle:

    Part A — Collector silence:
      Any collector not seen within COLLECTOR_SILENCE_THRESHOLD seconds fires a
      SUSPICIOUS alert.  Alert_id is keyed per collector per hour bucket so at
      most one alert is raised per collector per hour regardless of cycle frequency.
      'Signal in silence' — a missing heartbeat is a HIGH-priority detection signal,
      not a reliability nuisance.

    Part B — Alert flood detection:
      If >= ENGINE_FLOOD_THRESHOLD alerts were created in the last 60 seconds,
      log ENGINE_FLOOD_DETECTED.  Alert_id is keyed per minute bucket.
      Rationale: an adversary with code execution can flood the engine with
      synthetic LOLBin events, causing CPU exhaustion and event-dropping, then
      execute the real attack in the blind window.  The flood signal itself is
      the detection — even a degraded engine must write this entry.

    Part C — Integrity chain verification (Rule 26 / Visit Integrity):
      For every raw_events row that has been normalized, recompute
      SHA256(collector_name + ":" + raw_event_hash)[:32] and compare it to
      the stored normalized_event_id.  A mismatch means a row was modified
      after normalization — evidence of log injection or SQLite tampering.
      Alert_id is keyed on raw_event_hash — one alert per tampered row, ever.

    Sources: Python Core (self-monitoring — reads collector_health, alerts,
             and raw_events tables).
    """
    _now = reference_time or datetime.now()

    # --- Part A: Collector silence (three-state) ---
    # QUIET  — heartbeat current, log silent → alive with nothing to report → no alert
    # DOWN   — heartbeat stale + log silent  → process dead                 → CRITICAL
    # SILENT — no heartbeat data (legacy)    → original SUSPICIOUS fallback
    silence_cutoff   = _now - timedelta(seconds=config.COLLECTOR_SILENCE_THRESHOLD)
    heartbeat_cutoff = _now - timedelta(seconds=config.HEARTBEAT_SILENCE_THRESHOLD)
    hour_bucket      = _now.strftime('%Y-%m-%d-%H')

    for row in db.get_all_collector_health():
        last_seen_dt = _parse_dt(row.get('last_seen'))
        if last_seen_dt is None:
            continue
        if last_seen_dt >= silence_cutoff:
            continue  # log events are current — no silence

        collector = row['collector_name']
        hb        = health_db.get_collector_status(collector)
        hb_ts     = _parse_dt(hb.get('last_heartbeat')) if hb else None

        # QUIET — heartbeat is current, log is just quiet (nothing anomalous to report)
        if hb_ts is not None and hb_ts >= heartbeat_cutoff:
            continue

        if hb is not None and hb.get('status') == 'DOWN':
            # DOWN — both log and heartbeat stale → process is dead
            severity = 'CRITICAL'
            subtype  = 'COLLECTOR_DOWN'
            explanation = (
                f"[Rule 18] COLLECTOR_DOWN: '{collector}' heartbeat has gone silent. "
                f"Last log event: {row.get('last_seen')}. "
                f"Last heartbeat: {hb.get('last_heartbeat')}. "
                f"Both log stream and in-process heartbeat are stale — collector process "
                f"is dead or was killed. A running collector writes a heartbeat every 5 "
                f"seconds independent of scan results. Silence here means process "
                f"termination, not a quiet collection period. "
                f"Signal in silence — active suppression cannot be ruled out. "
                f"Confidence: {config.RULE_WEIGHTS[18]:.0%}."
            )
        else:
            # SILENT — no heartbeat data, legacy fallback
            severity = 'SUSPICIOUS'
            subtype  = 'COLLECTOR_SILENT'
            explanation = (
                f"[Rule 18] Collector silence detected: '{collector}' last seen "
                f"{row.get('last_seen')}. "
                f"No new events for >{config.COLLECTOR_SILENCE_THRESHOLD // 60} minutes. "
                f"No heartbeat data available for cross-reference. "
                f"Signal in silence — collector may be down, log file missing, "
                f"or actively suppressed by an adversary. "
                f"Confidence: {config.RULE_WEIGHTS[18]:.0%}."
            )

        weight   = config.RULE_WEIGHTS[18]
        alert_id = _make_alert_id(18, f"{subtype.lower()}:{collector}:{hour_bucket}")

        db.insert_detection({
            'rule_id':          18,
            'window_type':      'operational',
            'matched_entities': [collector],
            'score_factors': {
                'collector':           collector,
                'last_seen':           row.get('last_seen'),
                'last_heartbeat':      hb.get('last_heartbeat') if hb else None,
                'heartbeat_status':    hb.get('status') if hb else None,
                'status':              row.get('status'),
                'silence_threshold_s': config.COLLECTOR_SILENCE_THRESHOLD,
                'subtype':             subtype,
            },
            'confidence':    weight,
            'evidence_refs': [],
        })
        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          18,
            'severity_current': severity,
            'confidence':       weight,
            'status':           'NEW',
            'explanation':      explanation,
            'linked_case':      None,
        })

    # --- Part B: Alert flood ---
    recent_count = db.count_recent_alerts(60, reference_time=_now)
    if recent_count >= config.ENGINE_FLOOD_THRESHOLD:
        minute_bucket = _now.strftime('%Y-%m-%d-%H-%M')
        weight        = config.RULE_WEIGHTS[18]
        alert_id      = _make_alert_id(18, f"flood:{minute_bucket}")

        db.insert_detection({
            'rule_id':          18,
            'window_type':      'short',
            'matched_entities': [],
            'score_factors': {
                'alert_rate_per_minute': recent_count,
                'threshold':             config.ENGINE_FLOOD_THRESHOLD,
            },
            'confidence':    weight,
            'evidence_refs': [],
        })
        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          18,
            'severity_current': 'SUSPICIOUS',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"[Rule 18] ENGINE_FLOOD_DETECTED: {recent_count} alerts generated "
                f"in the last 60 seconds "
                f"(threshold: {config.ENGINE_FLOOD_THRESHOLD}). "
                f"Possible adversarial alert flooding to blind the correlation engine. "
                f"Confidence: {weight:.0%}."
            ),
            'linked_case': None,
        })

    # --- Part C: Integrity chain verification ---
    for row in db.get_raw_events_for_integrity_check():
        expected = hashlib.sha256(
            (row['collector_name'] + ':' + row['raw_event_hash']).encode('utf-8')
        ).hexdigest()[:32]
        if row['normalized_event_id'] == expected:
            continue

        weight   = config.RULE_WEIGHTS[18]
        alert_id = _make_alert_id(18, f"tamper:{row['raw_event_hash']}")

        db.insert_detection({
            'rule_id':          18,
            'window_type':      'operational',
            'matched_entities': [row['collector_name']],
            'score_factors': {
                'collector':     row['collector_name'],
                'raw_hash':      row['raw_event_hash'],
                'stored_neid':   row['normalized_event_id'],
                'expected_neid': expected,
            },
            'confidence':    weight,
            'evidence_refs': [],
        })
        db.insert_alert({
            'alert_id':         alert_id,
            'rule_id':          18,
            'severity_current': 'SUSPICIOUS',
            'confidence':       weight,
            'status':           'NEW',
            'explanation': (
                f"[Rule 18] INTEGRITY_CHAIN_BROKEN: normalized_event_id mismatch "
                f"in raw_events for collector '{row['collector_name']}'. "
                f"Stored:   {row['normalized_event_id'][:16]}... "
                f"Expected: {expected[:16]}... "
                f"The raw_events table may have been modified after normalization "
                f"— possible log injection or SQLite tampering. "
                f"Confidence: {weight:.0%}."
            ),
            'linked_case': None,
            'created_at': _now.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': _now.strftime('%Y-%m-%d %H:%M:%S'),
        })


def _rule_8(event):
    """Rule 8 — DoH Evasion Suspected  (CRITICAL)

    A process made a connection to a known DNS-over-HTTPS resolver IP on port 443.
    DoH bypasses the standard DNS stack — Bloodhound monitors normal DNS queries
    but cannot see DoH traffic.  An adversary uses DoH to hide C2 beacon domain
    lookups from DNS-based detection.

    Single-event — any DoH connection is immediately actionable.
    Severity derived from collector: CRITICAL if process not in DoH whitelist,
    SUSPICIOUS if whitelisted (zero-trust during baseline).
    Source: DoH_Detector  (event_type=NETWORK, subtype=DOH_CONNECTION)
    Weight: config.RULE_WEIGHTS[8]
    """
    if event['event_type'] != 'NETWORK':
        return
    if event['subtype'] != 'DOH_CONNECTION':
        return

    weight   = config.RULE_WEIGHTS[8]
    alert_id = _make_alert_id(8, event['event_id'])

    # Collector marks non-whitelisted processes CRITICAL, whitelisted UNKNOWN.
    # Zero-trust: UNKNOWN → SUSPICIOUS alert (still actionable during baseline).
    severity = 'CRITICAL' if event['base_severity'] == 'CRITICAL' else 'SUSPICIOUS'

    db.insert_detection({
        'rule_id':          8,
        'window_type':      'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'actor':         event['actor'],
            'resolver':      event['destination'],
            'trust_level':   event['trust_level'],
            'base_severity': event['base_severity'],
        },
        'confidence':    weight,
        'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          8,
        'severity_current': severity,
        'confidence':       weight,
        'status':           'NEW',
        'explanation': (
            f"[Rule 8] DoH Evasion Suspected. "
            f"Process '{event['actor'] or 'unknown'}' connected to a known "
            f"DNS-over-HTTPS resolver at {event['destination'] or 'unknown'}. "
            f"DoH bypasses the standard DNS stack — Bloodhound cannot see these "
            f"queries. Adversaries use DoH to hide C2 beacon domain lookups. "
            f"Process path: {event['process_path'] or 'not recorded'}. "
            f"Trust level: {event['trust_level']}. "
            f"Confidence: {weight:.0%}. "
            f"Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_19(event):
    """Rule 19 — Self-Protection / Script FIM  (CRITICAL)

    The Warden collector has detected tampering with the SOC infrastructure:
    a monitored script's hash has changed (FIM_VIOLATION), or a log file has
    been deleted or truncated (LOG_TAMPER).  Both subtypes demand immediate
    triage — they indicate an adversary or rogue process actively attacking
    the detection capability itself.

    COLLECTOR_DOWN and MANIFEST_MISSING normalize into INTEGRITY events but
    are handled by Rule 18 (Engine Health) via ingest-rate monitoring, not
    here.  They produce no Rule 19 alert.

    Single-event — any FIM_VIOLATION or LOG_TAMPER event is immediately
    actionable regardless of trust level or process path.
    Source: Warden  (event_type=INTEGRITY, subtype=FIM_VIOLATION|LOG_TAMPER)
    Weight: config.RULE_WEIGHTS[19]
    """
    if event['event_type'] != 'INTEGRITY':
        return
    if event['subtype'] not in ('FIM_VIOLATION', 'LOG_TAMPER'):
        return

    weight   = config.RULE_WEIGHTS[19]
    alert_id = _make_alert_id(19, event['event_id'])

    subtype_label = (
        'Script hash mismatch (FIM violation)'
        if event['subtype'] == 'FIM_VIOLATION'
        else 'Log file tampered or deleted'
    )

    db.insert_detection({
        'rule_id':          19,
        'window_type':      'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'subtype':       event['subtype'],
            'actor':         event['actor'],
            'base_severity': event['base_severity'],
        },
        'confidence':    weight,
        'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          19,
        'severity_current': 'CRITICAL',
        'confidence':       weight,
        'status':           'NEW',
        'explanation': (
            f"[Rule 19] SOC Self-Protection Violation. "
            f"{subtype_label}: '{event['actor'] or 'unknown target'}'. "
            f"Warden detected a change to monitored SOC infrastructure. "
            f"This may indicate an adversary suppressing detection capability "
            f"before or after an intrusion. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_10(event):
    """Rule 10 — Account Manipulation  (CRITICAL/SUSPICIOUS)

    SecEventLog detected a change to a local account or security group.
    Any account manipulation on a home machine is anomalous — legitimate
    software never creates, deletes, or modifies local accounts without
    explicit user intent.

    Severity is passed through from the collector — SecEventLog.ps1 already
    assigns CRITICAL for account creation/deletion/group membership changes
    and SUSPICIOUS for enables, password resets, and account modifications.

    Single-event — every account manipulation event is immediately actionable.
    Source: SecEventLog  (event_type=ACCOUNT)
    Weight: config.RULE_WEIGHTS[10]
    """
    if event['event_type'] != 'ACCOUNT':
        return

    weight   = config.RULE_WEIGHTS[10]
    alert_id = _make_alert_id(10, event['event_id'])
    severity = event['base_severity'] if event['base_severity'] in ('CRITICAL', 'SUSPICIOUS') else 'SUSPICIOUS'

    db.insert_detection({
        'rule_id':          10,
        'window_type':      'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'subtype':       event['subtype'],
            'actor':         event['actor'],
            'base_severity': event['base_severity'],
        },
        'confidence':    weight,
        'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          10,
        'severity_current': severity,
        'confidence':       weight,
        'status':           'NEW',
        'explanation': (
            f"[Rule 10] Account Manipulation Detected. "
            f"Event: {event['subtype']}. "
            f"Account: '{event['actor'] or 'unknown'}'. "
            f"On a home machine, account changes without explicit user action "
            f"indicate credential manipulation or persistence. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_17(reference_time=None):
    """Rule 17 — Identity / RID Hijack  (CRITICAL)

    Correlates an account creation or enable event (SecEventLog) with a
    registry modification (Registry_Warden) in the same short window.
    RID hijacking requires both: creating a low-privilege account AND
    modifying the SAM registry hive to clone a privileged account's RID.

    Registry_Warden does not yet monitor SAM hive keys directly — this rule
    will become more precise when SAM key monitoring is added.  In the
    interim, any registry change coinciding with account creation is a
    credible signal on a home machine where both are normally absent.

    Sources: SecEventLog (event_type=ACCOUNT, subtype=ACCOUNT_CREATED|ACCOUNT_ENABLED)
             Registry_Warden (event_type=REGISTRY)
    Window:  SHORT_WINDOW (10 min)
    Weight:  config.RULE_WEIGHTS[17]
    """
    all_acct = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='ACCOUNT', reference_time=reference_time
    )
    account_events = [
        e for e in all_acct
        if e['subtype'] in ('ACCOUNT_CREATED', 'ACCOUNT_ENABLED')
        and e['collector_name'].lower() == 'seceventlog'
    ]

    all_reg = db.get_events_in_window(
        config.SHORT_WINDOW, event_type='REGISTRY', reference_time=reference_time
    )
    registry_events = [
        e for e in all_reg
        if e['collector_name'].lower() == 'registry_warden'
    ]

    if not account_events or not registry_events:
        return

    evidence   = [e['event_id'] for e in account_events + registry_events]
    alert_id   = _make_alert_id(17, *evidence)
    weight     = config.RULE_WEIGHTS[17]
    acct_names = [e['actor'] or 'unknown' for e in account_events]
    reg_keys   = [e['actor'] or 'unknown' for e in registry_events]

    db.insert_detection({
        'rule_id':          17,
        'window_type':      'short',
        'matched_entities': evidence,
        'score_factors': {
            'account_events':  [e['subtype'] for e in account_events],
            'account_actors':  acct_names,
            'registry_events': [e['subtype'] for e in registry_events],
            'registry_keys':   reg_keys,
        },
        'confidence':    weight,
        'evidence_refs': evidence,
    })
    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          17,
        'severity_current': 'CRITICAL',
        'confidence':       weight,
        'status':           'NEW',
        'explanation': (
            f"[Rule 17] Identity / RID Hijack Suspected. "
            f"Account manipulation ({', '.join(set(e['subtype'] for e in account_events))}) "
            f"for '{_summarise(acct_names)}' coincided with "
            f"{len(registry_events)} registry modification(s) "
            f"({_summarise(reg_keys)}) in the same {config.SHORT_WINDOW // 60}-minute window. "
            f"RID hijacking requires both account creation and SAM registry modification. "
            f"Confidence: {weight:.0%}. Evidence: {', '.join(evidence[:3])}."
        ),
        'linked_case': None,
    })


# ============================================================
# SYSMON RULES (Phase 7A) — Rules 28–39
# All single-event / Tier 1.
# Source: SysmonWatcher (Microsoft-Windows-Sysmon/Operational)
# ============================================================

def _rule_28(event):
    """Rule 28 — Browser Debugger Attachment  (CRITICAL)
    An unknown process opened a handle to a browser process with write/inject
    capability (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION).
    Legitimate software never debugs production browsers — this pattern is
    characteristic of credential-harvesting tools that hook browser memory to
    extract session tokens, saved passwords, and form data.
    Source: SysmonWatcher (event_type=PROCESS_ACCESS, subtype=BROWSER_DEBUGGER)
    """
    if event['event_type'] != 'PROCESS_ACCESS':
        return
    if event['subtype'] != 'BROWSER_DEBUGGER':
        return
    weight   = config.RULE_WEIGHTS[28]
    alert_id = _make_alert_id(28, event['event_id'])
    db.insert_detection({
        'rule_id': 28, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'source': event['actor'], 'target': event['destination'],
            'source_path': event['process_path'], 'base_severity': event['base_severity'],
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 28,
        'severity_current': 'CRITICAL', 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 28] Browser Debugger Attachment. "
            f"Process '{event['actor'] or 'unknown'}' opened a handle to "
            f"'{event['destination'] or 'browser process'}' with write/inject capability. "
            f"Legitimate software never debugs production browsers. This is characteristic of "
            f"credential-harvesting tools that read browser memory for session tokens and passwords. "
            f"Source path: {event['process_path'] or 'not recorded'}. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_29(event):
    """Rule 29 — High-Risk Path Launch  (CRITICAL → SUSPICIOUS)
    A process launched from a staging path (Downloads, Temp, AppData\\Roaming,
    Public, ProgramData, Windows\\Temp) or used encoded/obfuscated command-line
    arguments. These are primary initial-access and persistence indicators.
    TrustedHighRiskProcesses (Defender, Claude Code) are downgraded to SUSPICIOUS
    at the collector level — severity passed through here.
    Source: SysmonWatcher (event_type=PROCESS, subtype=HIGH_RISK_LAUNCH|ENCODED_CMDLINE)
    """
    if event['event_type'] != 'PROCESS':
        return
    if event['subtype'] not in ('HIGH_RISK_LAUNCH', 'ENCODED_CMDLINE'):
        return
    if event['base_severity'] not in ('CRITICAL', 'SUSPICIOUS'):
        return
    weight   = config.RULE_WEIGHTS[29]
    severity = event['base_severity']
    alert_id = _make_alert_id(29, event['event_id'])
    db.insert_detection({
        'rule_id': 29, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'subtype': event['subtype'], 'actor': event['actor'],
            'process_path': event['process_path'], 'base_severity': severity,
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 29,
        'severity_current': severity, 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 29] High-Risk Path Launch. "
            f"Process '{event['actor'] or 'unknown'}' launched from a staging path "
            f"({event['process_path'] or 'path not recorded'}). "
            f"{'Encoded or obfuscated command-line arguments detected. ' if event['subtype'] == 'ENCODED_CMDLINE' else ''}"
            f"High-risk paths (Downloads, Temp, AppData\\Roaming, Public, ProgramData) "
            f"are primary attacker staging areas. Cross-reference with Rule 38 (downloaded file) "
            f"and Rule 13 (initial access) for the same actor. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_30(event):
    """Rule 30 — AMSI Provider Tampered  (CRITICAL)
    A registry key controlling AMSI (Anti-Malware Scan Interface) providers was
    modified. AMSI connects PowerShell, VBScript, and scripting runtimes to AV
    engines at the scan interface. Removing or replacing an AMSI provider blinds
    real-time protection to malicious script content — a prerequisite for
    script-based evasion attacks.
    Source: SysmonWatcher (event_type=REGISTRY, subtype=AMSI_TAMPER)
    """
    if event['event_type'] != 'REGISTRY':
        return
    if event['subtype'] != 'AMSI_TAMPER':
        return
    weight   = config.RULE_WEIGHTS[30]
    alert_id = _make_alert_id(30, event['event_id'])
    db.insert_detection({
        'rule_id': 30, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'actor': event['actor'], 'key': event['destination'],
            'base_severity': event['base_severity'],
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 30,
        'severity_current': 'CRITICAL', 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 30] AMSI Provider Tampered. "
            f"Process '{event['actor'] or 'unknown'}' modified the AMSI provider registry key "
            f"({event['destination'] or 'key not recorded'}). "
            f"AMSI connects scripting runtimes to AV engines — modifying this key blinds "
            f"real-time protection to malicious script content. This is a prerequisite "
            f"step for script-based evasion. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_31(event):
    """Rule 31 — Unmanaged PS Host / DLL Hijack  (CRITICAL → SUSPICIOUS)
    Three DLL-load anomalies from Sysmon EID 7:
      DLL_HIJACK     — DLL loaded from non-standard path (classic hijack vector)
      UNMANAGED_PWSH — Unmanaged host loaded PS runtime DLL (C2 framework indicator:
                       Cobalt Strike / Covenant execute PS without launching powershell.exe)
      DLL_USERPATH   — DLL loaded from user-writable path (supply chain / sideload risk)
    Severity follows collector assessment.
    Source: SysmonWatcher (event_type=DLL)
    """
    if event['event_type'] != 'DLL':
        return
    if event['subtype'] not in ('DLL_HIJACK', 'UNMANAGED_PWSH', 'DLL_USERPATH'):
        return
    if event['base_severity'] not in ('CRITICAL', 'SUSPICIOUS'):
        return
    weight   = config.RULE_WEIGHTS[31]
    severity = event['base_severity']
    alert_id = _make_alert_id(31, event['event_id'])
    subtype_desc = {
        'DLL_HIJACK':     'DLL loaded from unexpected path — possible DLL hijack',
        'UNMANAGED_PWSH': 'unmanaged host loaded PowerShell runtime DLL — C2 framework indicator',
        'DLL_USERPATH':   'DLL loaded from user-writable path — supply chain / sideload risk',
    }.get(event['subtype'], event['subtype'])
    db.insert_detection({
        'rule_id': 31, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'subtype': event['subtype'], 'actor': event['actor'],
            'dll_path': event['process_path'], 'base_severity': severity,
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 31,
        'severity_current': severity, 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 31] DLL Load Anomaly — {event['subtype']}. "
            f"Process '{event['actor'] or 'unknown'}': {subtype_desc}. "
            f"DLL path: {event['process_path'] or 'not recorded'}. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_32(event):
    """Rule 32 — WMI Persistence Binding  (CRITICAL)
    WMI subscription infrastructure modified: Filter (EID 19), Consumer (EID 20),
    or FilterToConsumerBinding (EID 21) created/modified. WMI subscriptions are a
    primary fileless persistence mechanism — survive reboots without disk files and
    are invisible to Scheduled Task monitoring (CityGuard). A complete persistence
    triplet requires Filter + Consumer + Binding.
    Source: SysmonWatcher (event_type=WMI)
    """
    if event['event_type'] != 'WMI':
        return
    if event['subtype'] not in ('WMI_FILTER', 'WMI_CONSUMER', 'WMI_BINDING'):
        return
    if event['base_severity'] not in ('CRITICAL', 'SUSPICIOUS'):
        return
    weight   = config.RULE_WEIGHTS[32]
    alert_id = _make_alert_id(32, event['event_id'])
    wmi_component = {
        'WMI_FILTER':   'event filter (trigger condition)',
        'WMI_CONSUMER': 'event consumer (payload/action)',
        'WMI_BINDING':  'filter-to-consumer binding (activation link)',
    }.get(event['subtype'], event['subtype'])
    db.insert_detection({
        'rule_id': 32, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'subtype': event['subtype'], 'actor': event['actor'],
            'base_severity': event['base_severity'],
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 32,
        'severity_current': 'CRITICAL', 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 32] WMI Persistence Binding. "
            f"WMI subscription {wmi_component} created by '{event['actor'] or 'unknown'}'. "
            f"WMI subscriptions survive reboots without disk files and are invisible to "
            f"Scheduled Task monitoring. A complete persistence triplet requires all three: "
            f"Filter + Consumer + Binding. Cross-reference EID 19/20/21 events. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_33(event):
    """Rule 33 — Remote Thread Injection  (CRITICAL)
    A process created a remote thread in another process (Sysmon EID 8).
    CreateRemoteThread is the primary mechanism for process injection — DLL injection,
    shellcode injection, Metasploit, Cobalt Strike. Legitimate software almost never
    creates threads in other processes outside of debuggers (excluded by sysmonconfig).
    Source: SysmonWatcher (event_type=INJECTION, subtype=REMOTE_THREAD)
    """
    if event['event_type'] != 'INJECTION':
        return
    if event['subtype'] != 'REMOTE_THREAD':
        return
    weight   = config.RULE_WEIGHTS[33]
    alert_id = _make_alert_id(33, event['event_id'])
    db.insert_detection({
        'rule_id': 33, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'source': event['actor'], 'target': event['destination'],
            'base_severity': event['base_severity'],
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 33,
        'severity_current': 'CRITICAL', 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 33] Remote Thread Injection. "
            f"Process '{event['actor'] or 'unknown'}' created a remote thread in "
            f"'{event['destination'] or 'unknown target'}'. "
            f"CreateRemoteThread is the primary code injection mechanism used by C2 frameworks, "
            f"DLL injection, and shellcode execution. Legitimate software almost never "
            f"creates threads in other processes. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_34(event):
    """Rule 34 — LSASS Process Access  (CRITICAL)
    A process opened a handle to lsass.exe. LSASS stores Windows credentials,
    Kerberos tickets, and NTLM hashes in memory. Any process accessing LSASS
    memory is a credential-dumping indicator (Mimikatz, ProcDump, custom tools).
    Known monitoring processes are whitelisted at the collector level — events
    reaching here are already assessed CRITICAL or SUSPICIOUS.
    Source: SysmonWatcher (event_type=PROCESS_ACCESS, subtype=LSASS_ACCESS)
    """
    if event['event_type'] != 'PROCESS_ACCESS':
        return
    if event['subtype'] != 'LSASS_ACCESS':
        return
    if event['base_severity'] not in ('CRITICAL', 'SUSPICIOUS'):
        return
    weight   = config.RULE_WEIGHTS[34]
    alert_id = _make_alert_id(34, event['event_id'])
    db.insert_detection({
        'rule_id': 34, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'source': event['actor'], 'source_path': event['process_path'],
            'base_severity': event['base_severity'],
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 34,
        'severity_current': 'CRITICAL', 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 34] LSASS Process Access. "
            f"Process '{event['actor'] or 'unknown'}' opened a handle to lsass.exe. "
            f"LSASS stores Windows credentials, Kerberos tickets, and NTLM hashes in memory. "
            f"This is characteristic of credential-dumping tools (Mimikatz, ProcDump). "
            f"Source path: {event['process_path'] or 'not recorded'}. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_35(event):
    """Rule 35 — Raw Disk Read  (CRITICAL → SUSPICIOUS)
    A process opened a raw disk device handle (\\Device\\HarddiskVolumeX), bypassing
    the file system. Used for offline SAM/NTDS.dit extraction, volume shadow copy
    abuse, and forensic evasion. Known-good processes (search indexer, AV, defrag,
    backup) are excluded at the collector whitelist level.
    Source: SysmonWatcher (event_type=DISK, subtype=RAW_DISK_READ)
    """
    if event['event_type'] != 'DISK':
        return
    if event['subtype'] != 'RAW_DISK_READ':
        return
    if event['base_severity'] not in ('CRITICAL', 'SUSPICIOUS'):
        return
    weight   = config.RULE_WEIGHTS[35]
    severity = event['base_severity']
    alert_id = _make_alert_id(35, event['event_id'])
    db.insert_detection({
        'rule_id': 35, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'actor': event['actor'], 'device': event['destination'],
            'process_path': event['process_path'], 'base_severity': severity,
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 35,
        'severity_current': severity, 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 35] Raw Disk Read. "
            f"Process '{event['actor'] or 'unknown'}' opened a raw disk handle to "
            f"'{event['destination'] or 'unknown device'}'. "
            f"Raw disk reads bypass the file system and are used for offline SAM/NTDS.dit "
            f"extraction, volume shadow copy abuse, and forensic evasion. "
            f"Process path: {event['process_path'] or 'not recorded'}. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_36(event):
    """Rule 36 — Unsigned Driver Loaded  (CRITICAL)
    An unsigned or untrusted driver was loaded (Sysmon EID 6). On modern Windows
    with Secure Boot and KMCS enforced, unsigned drivers should never load in
    normal operation. Used for kernel rootkits, BYOD (Bring Your Own Driver)
    attacks, and hardware-level access below OS visibility.
    Source: SysmonWatcher (event_type=DRIVER, subtype=UNSIGNED_DRIVER)
    """
    if event['event_type'] != 'DRIVER':
        return
    if event['subtype'] != 'UNSIGNED_DRIVER':
        return
    weight   = config.RULE_WEIGHTS[36]
    alert_id = _make_alert_id(36, event['event_id'])
    db.insert_detection({
        'rule_id': 36, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'driver': event['actor'], 'driver_path': event['process_path'],
            'base_severity': event['base_severity'],
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 36,
        'severity_current': 'CRITICAL', 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 36] Unsigned Driver Loaded. "
            f"Driver '{event['actor'] or 'unknown'}' loaded without a valid digital signature. "
            f"Driver path: {event['process_path'] or 'not recorded'}. "
            f"Unsigned drivers on modern Windows indicate a kernel rootkit, BYOD attack, "
            f"or disabled driver signature enforcement. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_37(event):
    """Rule 37 — C2 Named Pipe  (CRITICAL → SUSPICIOUS)
    A process created or connected to a named pipe matching C2 framework patterns
    (Sysmon EID 17/18). Named pipes are the primary IPC channel used by C2
    frameworks post-exploitation: Cobalt Strike uses named pipe MSSE-<id>-server,
    Metasploit/Meterpreter uses its own patterns. The sysmonconfig filter targets
    known-bad patterns — events here are already assessed by the collector.
    Source: SysmonWatcher (event_type=PIPE, subtype=PIPE_CREATED|PIPE_CONNECTED)
    """
    if event['event_type'] != 'PIPE':
        return
    if event['subtype'] not in ('PIPE_CREATED', 'PIPE_CONNECTED'):
        return
    if event['base_severity'] not in ('CRITICAL', 'SUSPICIOUS'):
        return
    weight      = config.RULE_WEIGHTS[37]
    severity    = event['base_severity']
    alert_id    = _make_alert_id(37, event['event_id'])
    pipe_action = 'created' if event['subtype'] == 'PIPE_CREATED' else 'connected to'
    db.insert_detection({
        'rule_id': 37, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'actor': event['actor'], 'pipe_name': event['destination'],
            'action': pipe_action, 'base_severity': severity,
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 37,
        'severity_current': severity, 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 37] C2 Named Pipe. "
            f"Process '{event['actor'] or 'unknown'}' {pipe_action} suspicious named pipe "
            f"'{event['destination'] or 'pipe name not recorded'}'. "
            f"C2 frameworks (Cobalt Strike, Metasploit/Meterpreter) use named pipes for "
            f"inter-process communication between implant and operator tooling. "
            f"Process path: {event['process_path'] or 'not recorded'}. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_38(event):
    """Rule 38 — Downloaded Executable  (CRITICAL → SUSPICIOUS)
    EID 11 (EXECUTABLE_CREATED): executable dropped in a user-writable staging
    path — payload drop indicator.
    EID 15 (ZONE_IDENTIFIER): file with Zone.Identifier ADS (Mark of the Web,
    ZoneId=3) detected — file was downloaded from the internet and has not yet
    been executed (MOTW is cleared by many droppers on execution).
    Cross-reference with Rule 29 if the same file later launches as a process.
    Source: SysmonWatcher (event_type=FILE)
    """
    if event['event_type'] != 'FILE':
        return
    if event['subtype'] not in ('EXECUTABLE_CREATED', 'ZONE_IDENTIFIER'):
        return
    if event['base_severity'] not in ('CRITICAL', 'SUSPICIOUS'):
        return
    weight   = config.RULE_WEIGHTS[38]
    severity = event['base_severity']
    alert_id = _make_alert_id(38, event['event_id'])
    subtype_desc = (
        'executable dropped in high-risk staging path'
        if event['subtype'] == 'EXECUTABLE_CREATED'
        else 'internet-origin file (Zone.Identifier / Mark of the Web) detected'
    )
    db.insert_detection({
        'rule_id': 38, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'subtype': event['subtype'], 'actor': event['actor'],
            'file_path': event['process_path'], 'base_severity': severity,
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 38,
        'severity_current': severity, 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 38] Downloaded Executable — {event['subtype']}. "
            f"Process '{event['actor'] or 'unknown'}': {subtype_desc}. "
            f"File: {event['process_path'] or 'not recorded'}. "
            f"{'Zone.Identifier present — file not yet executed. ' if event['subtype'] == 'ZONE_IDENTIFIER' else ''}"
            f"Cross-reference with Rule 29 if the same file later launches as a process. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


def _rule_39(event):
    """Rule 39 — Process Hollowing Confirmed  (CRITICAL)
    Sysmon EID 25 (ProcessTampering) detected process image tampering — the running
    process memory no longer matches the binary on disk. This is the kernel-level
    confirmation of process hollowing: a legitimate binary is started, its memory
    image is unmapped and replaced with a malicious payload. The process appears
    legitimate in task managers but executes attacker code.
    Requires Sysmon 13+. One of the highest-confidence injection detections
    available without a kernel driver.
    Source: SysmonWatcher (event_type=PROCESS, subtype=PROCESS_TAMPER)
    """
    if event['event_type'] != 'PROCESS':
        return
    if event['subtype'] != 'PROCESS_TAMPER':
        return
    weight   = config.RULE_WEIGHTS[39]
    alert_id = _make_alert_id(39, event['event_id'])
    db.insert_detection({
        'rule_id': 39, 'window_type': 'single',
        'matched_entities': [event['event_id']],
        'score_factors': {
            'actor': event['actor'], 'process_path': event['process_path'],
            'base_severity': event['base_severity'],
        },
        'confidence': weight, 'evidence_refs': [event['event_id']],
    })
    db.insert_alert({
        'alert_id': alert_id, 'rule_id': 39,
        'severity_current': 'CRITICAL', 'confidence': weight, 'status': 'NEW',
        'explanation': (
            f"[Rule 39] Process Hollowing Confirmed. "
            f"Sysmon EID 25 detected process image tampering for "
            f"'{event['actor'] or 'unknown'}' ({event['process_path'] or 'path not recorded'}). "
            f"Running process memory no longer matches the binary on disk — kernel-level "
            f"signature of process hollowing. A legitimate binary is started and its memory "
            f"replaced with a malicious payload. Immediate triage required. "
            f"Confidence: {weight:.0%}. Evidence: {event['event_id']}."
        ),
        'linked_case': None,
    })


# ============================================================
# RULE 41 — Blind Window Exploitation
# RULE 42 — Coordinated Collector Suppression
# ============================================================

def _emit_blind_alert(rule_id, subtype, down_collector, down_row,
                       concurrent_events, hour_bucket, severity, explanation, _now):
    """Shared emit helper for Rule 41 pattern branches."""
    weight   = config.RULE_WEIGHTS.get(rule_id, 1.0)
    alert_id = _make_alert_id(rule_id, f"{subtype.lower()}:{down_collector}:{hour_bucket}")

    db.insert_detection({
        'rule_id':          rule_id,
        'window_type':      'short',
        'matched_entities': ([down_collector]
                             + list({e['collector_name'] for e in concurrent_events})),
        'score_factors': {
            'down_collector':    down_collector,
            'last_heartbeat':    down_row.get('last_heartbeat'),
            'concurrent_events': len(concurrent_events),
            'subtype':           subtype,
        },
        'confidence':    weight,
        'evidence_refs': [e['event_id'] for e in concurrent_events],
    })
    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          rule_id,
        'severity_current': severity,
        'confidence':       weight,
        'status':           'NEW',
        'explanation':      f"{explanation}Confidence: {weight:.0%}.",
        'linked_case':      None,
    })


def _rule_41(reference_time=None):
    """Rule 41 — Blind Window Exploitation  [CRITICAL]

    A DOWN collector creates a visibility gap. This rule asks: what happened
    during that gap? If other collectors report suspicious or critical activity
    in the SHORT_WINDOW while one collector is silenced, an adversary may be
    exploiting the blind spot they created.

    Patterns (all checked independently per downed collector):
      NETWORK_BLIND_PROCESS   — Sentinel/Bulwark DOWN + Harbinger process activity
      PROCESS_UNDER_BLIND     — Any DOWN + Harbinger CRITICAL process creation
      PERSISTENCE_UNDER_BLIND — Any DOWN + CityGuard suspicious/critical task event
      AUTH_COLLECTOR_BLIND    — SecEventLog DOWN + any concurrent suspicious/critical events
      ACTIVITY_UNDER_BLIND    — Any DOWN + >=2 CRITICAL events from other collectors

    Alert dedup: keyed per rule + subtype + down_collector + hour_bucket.
    Source: health_db (collector status) + events (concurrent activity).
    """
    _now = reference_time or datetime.now()

    down_collectors = [
        row for row in health_db.get_all_collector_status()
        if row.get('status') == 'DOWN'
    ]
    if not down_collectors:
        return

    hour_bucket   = _now.strftime('%Y-%m-%d-%H')
    window_events = db.get_events_in_window(config.SHORT_WINDOW, reference_time=_now)

    for down_row in down_collectors:
        down_collector = down_row['collector_name']

        other_events = [
            e for e in window_events
            if e['collector_name'] != down_collector
        ]
        if not other_events:
            continue

        susp_crit = [
            e for e in other_events
            if e['base_severity'] in ('SUSPICIOUS', 'CRITICAL')
        ]

        # --- NETWORK_BLIND_PROCESS ---
        # Network monitor killed + Harbinger sees process activity in the gap
        if down_collector in ('sentinel', 'bulwark'):
            harbinger_procs = [
                e for e in susp_crit
                if e['collector_name'] == 'harbinger'
                and e['event_type'] == 'PROCESS'
            ]
            if harbinger_procs:
                actors = ', '.join({e['actor'] for e in harbinger_procs if e['actor']})
                _emit_blind_alert(
                    rule_id=41, subtype='NETWORK_BLIND_PROCESS',
                    down_collector=down_collector, down_row=down_row,
                    concurrent_events=harbinger_procs,
                    hour_bucket=hour_bucket, severity='CRITICAL',
                    explanation=(
                        f"[Rule 41] NETWORK_BLIND_PROCESS: '{down_collector}' "
                        f"(network monitor) is DOWN. "
                        f"{len(harbinger_procs)} suspicious process event(s) seen by "
                        f"Harbinger during the blind window. "
                        f"Pattern: kill the network monitor, run the payload — "
                        f"C2 callbacks and exfiltration will be invisible to the "
                        f"downed collector. Processes: {actors}. "
                    ),
                    _now=_now,
                )

        # --- PROCESS_UNDER_BLIND ---
        # Any collector down + Harbinger sees a CRITICAL (high-risk path) process
        crit_procs = [
            e for e in other_events
            if e['collector_name'] == 'harbinger'
            and e['event_type'] == 'PROCESS'
            and e['base_severity'] == 'CRITICAL'
        ]
        if crit_procs:
            actors = ', '.join({e['actor'] for e in crit_procs if e['actor']})
            _emit_blind_alert(
                rule_id=41, subtype='PROCESS_UNDER_BLIND',
                down_collector=down_collector, down_row=down_row,
                concurrent_events=crit_procs,
                hour_bucket=hour_bucket, severity='CRITICAL',
                explanation=(
                    f"[Rule 41] PROCESS_UNDER_BLIND: '{down_collector}' is DOWN. "
                    f"{len(crit_procs)} CRITICAL process event(s) seen by Harbinger "
                    f"during the blind window. "
                    f"A high-risk process launched while a collector was silenced. "
                    f"Processes: {actors}. "
                ),
                _now=_now,
            )

        # --- PERSISTENCE_UNDER_BLIND ---
        # Any collector down + CityGuard sees a suspicious/critical scheduled task
        persistence_events = [
            e for e in susp_crit
            if e['collector_name'] == 'cityguard'
            and e['event_type'] == 'TASK'
        ]
        if persistence_events:
            actors = ', '.join({e['actor'] for e in persistence_events if e['actor']})
            _emit_blind_alert(
                rule_id=41, subtype='PERSISTENCE_UNDER_BLIND',
                down_collector=down_collector, down_row=down_row,
                concurrent_events=persistence_events,
                hour_bucket=hour_bucket, severity='CRITICAL',
                explanation=(
                    f"[Rule 41] PERSISTENCE_UNDER_BLIND: '{down_collector}' is DOWN. "
                    f"{len(persistence_events)} suspicious scheduled task event(s) "
                    f"seen by CityGuard during the blind window. "
                    f"Collector silenced before persistence was installed. "
                    f"Tasks: {actors}. "
                ),
                _now=_now,
            )

        # --- AUTH_COLLECTOR_BLIND ---
        # SecEventLog killed + any concurrent suspicious/critical activity
        if down_collector == 'seceventlog' and susp_crit:
            sources = ', '.join({e['collector_name'] for e in susp_crit})
            _emit_blind_alert(
                rule_id=41, subtype='AUTH_COLLECTOR_BLIND',
                down_collector=down_collector, down_row=down_row,
                concurrent_events=susp_crit,
                hour_bucket=hour_bucket, severity='CRITICAL',
                explanation=(
                    f"[Rule 41] AUTH_COLLECTOR_BLIND: 'seceventlog' "
                    f"(authentication monitor) is DOWN. "
                    f"{len(susp_crit)} suspicious/critical event(s) seen by other "
                    f"collectors during the blind window. "
                    f"Account creation, privilege escalation, and logon events are "
                    f"currently invisible. Active collectors: {sources}. "
                ),
                _now=_now,
            )

        # --- ACTIVITY_UNDER_BLIND ---
        # Any collector down + >= 2 CRITICAL events from other collectors
        crit_any = [
            e for e in other_events
            if e['base_severity'] == 'CRITICAL'
        ]
        if len(crit_any) >= 2:
            sources = ', '.join({e['collector_name'] for e in crit_any})
            _emit_blind_alert(
                rule_id=41, subtype='ACTIVITY_UNDER_BLIND',
                down_collector=down_collector, down_row=down_row,
                concurrent_events=crit_any,
                hour_bucket=hour_bucket, severity='CRITICAL',
                explanation=(
                    f"[Rule 41] ACTIVITY_UNDER_BLIND: '{down_collector}' is DOWN. "
                    f"{len(crit_any)} CRITICAL event(s) from other collectors "
                    f"during the blind window. "
                    f"High-confidence adversarial activity while a collector was silenced. "
                    f"Reporting collectors: {sources}. "
                ),
                _now=_now,
            )


def _rule_42(reference_time=None):
    """Rule 42 — Coordinated Collector Suppression  [CRITICAL]

    Two or more collectors simultaneously in DOWN state. Simultaneous multi-kill
    is nearly impossible through coincidental failure — this is coordinated
    suppression. No event correlation needed; the concurrent dead state is the
    signal.

    Alert dedup: keyed per hour bucket. Fires once per hour regardless of
    how many cycles observe the concurrent DOWN state.
    Source: health_db only.
    """
    _now = reference_time or datetime.now()

    down_collectors = [
        row['collector_name']
        for row in health_db.get_all_collector_status()
        if row.get('status') == 'DOWN'
    ]
    if len(down_collectors) < 2:
        return

    hour_bucket = _now.strftime('%Y-%m-%d-%H')
    weight      = config.RULE_WEIGHTS[42]
    alert_id    = _make_alert_id(42, f"coordinated_suppression:{hour_bucket}")
    names       = ', '.join(sorted(down_collectors))

    db.insert_detection({
        'rule_id':          42,
        'window_type':      'short',
        'matched_entities': down_collectors,
        'score_factors': {
            'down_collectors': down_collectors,
            'count':           len(down_collectors),
        },
        'confidence':    weight,
        'evidence_refs': [],
    })
    db.insert_alert({
        'alert_id':         alert_id,
        'rule_id':          42,
        'severity_current': 'CRITICAL',
        'confidence':       weight,
        'status':           'NEW',
        'explanation': (
            f"[Rule 42] COORDINATED_SUPPRESSION: {len(down_collectors)} collectors "
            f"simultaneously in DOWN state: {names}. "
            f"Simultaneous multi-collector failure is statistically improbable without "
            f"adversarial coordination. Each collector runs an independent in-process "
            f"heartbeat — concurrent death means concurrent kill. "
            f"Confidence: {weight:.0%}."
        ),
        'linked_case': None,
    })


_TIER_1_RULES = [_rule_6, _rule_21, _rule_8, _rule_19, _rule_10,
                 _rule_28, _rule_29, _rule_30, _rule_31, _rule_32,
                 _rule_33, _rule_34, _rule_35, _rule_36, _rule_37,
                 _rule_38, _rule_39]
_TIER_2_RULES = [_rule_3, _rule_4, _rule_13, _rule_9, _rule_7, _rule_16,
                 _rule_2, _rule_11, _rule_1, _rule_5, _rule_22, _rule_18, _rule_17,
                 _rule_41, _rule_42]

# _TIER_3_RULES = []   # Operational   — populated after baseline month
# _TIER_4_RULES = []   # Campaign      — populated after baseline month


# ============================================================
# MAIN ENTRY POINT — called by engine.py each cycle
# ============================================================

def run_all():
    """Run all implemented correlation rules.

    Returns a summary dict for engine logging:
        events_processed  — Tier 1 events evaluated this cycle
        new_detections    — detections created this cycle
        new_alerts        — alerts created this cycle
    """
    det_before   = db.count_detections()
    alert_before = db.count_alerts()

    # --- Tier 1: single-event rules ---
    # Only uncorrelated events — each event is evaluated exactly once.
    # Correlated_at stamps are batched into one UPDATE at the end of the loop.
    pending = db.get_uncorrelated_events()
    for event in pending:
        for rule_fn in _TIER_1_RULES:
            rule_fn(event)
    db.mark_events_correlated_batch([e['event_id'] for e in pending])

    # --- Tier 2: short-window rules ---
    # reference_time is fixed once per cycle so all rules share the same clock.
    reference_time = datetime.now()
    for rule_fn in _TIER_2_RULES:
        rule_fn(reference_time=reference_time)

    return {
        'events_processed': len(pending),
        'new_detections':   db.count_detections() - det_before,
        'new_alerts':       db.count_alerts()     - alert_before,
    }
