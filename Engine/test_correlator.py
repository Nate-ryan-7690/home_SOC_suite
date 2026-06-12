import os, sqlite3, hashlib
from datetime import datetime
import db, health_db, normalizer, correlator, config

# Fresh databases
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
if os.path.exists('hocsoc_health.db'):
    os.remove('hocsoc_health.db')
db.initialize()
health_db.initialize()

print('=== correlator.py TESTS ===')
print()


# -------------------------------------------------------
# Helper: insert a pre-built normalized event directly
# -------------------------------------------------------
def _insert_event(event_id, event_type, subtype, actor, process_path,
                  destination, base_severity, trust_level,
                  collector='harbinger', confidence=1.0,
                  observed_at='2026-03-20 10:00:00'):
    db.insert_event({
        'event_id':          event_id,
        'schema_version':    '1.0',
        'collector_name':    collector,
        'source_host':       'TEST-HOST',
        'observed_at':       observed_at,
        'ingested_at':       '2026-03-20 10:00:00',
        'event_type':        event_type,
        'subtype':           subtype,
        'actor':             actor,
        'process_path':      process_path,
        'destination':       destination,
        'base_severity':     base_severity,
        'trust_level':       trust_level,
        'parser_confidence': confidence,
        'ingest_status':     'OK',
    })


# -------------------------------------------------------
# Test 1: Rule 6 fires on LOLBin NETWORK event
# -------------------------------------------------------
print('Test 1: Rule 6 fires on LOLBin NETWORK event...')
_insert_event(
    event_id='ev_r6_lolbin',
    event_type='NETWORK', subtype='OUTBOUND',
    actor='powershell',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    destination='5.6.7.8',
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='sentinel',
)
correlator.run_all()
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det = conn.execute("SELECT * FROM detections WHERE rule_id=6").fetchall()
alt = conn.execute("SELECT * FROM alerts WHERE rule_id=6").fetchall()
conn.close()
assert len(det) == 1, f'Expected 1 detection, got {len(det)}'
assert len(alt) == 1, f'Expected 1 alert, got {len(alt)}'
assert alt[0]['severity_current'] == 'SUSPICIOUS'   # TRUSTED path → SUSPICIOUS (not CRITICAL)
assert '5.6.7.8' in alt[0]['explanation']
assert 'LOLBin' in alt[0]['explanation']
print('  detection created, alert=SUSPICIOUS (trusted path), explanation contains destination  PASS')


# -------------------------------------------------------
# Test 2: Rule 6 fires when actor logged without .exe suffix
# -------------------------------------------------------
print('Test 2: Rule 6 matches actor without .exe suffix...')
_insert_event(
    event_id='ev_r6_no_ext',
    event_type='NETWORK', subtype='OUTBOUND',
    actor='certutil',          # no .exe — Sentinel logs it this way
    process_path=r'C:\Windows\System32\certutil.exe',
    destination='evil.com',
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='sentinel',
)
correlator.run_all()
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det2 = conn.execute("SELECT * FROM detections WHERE rule_id=6 AND matched_entities LIKE '%ev_r6_no_ext%'").fetchall()
conn.close()
assert len(det2) == 1, f'Expected 1 detection for no-ext actor, got {len(det2)}'
print('  certutil (no .exe) matched certutil.exe in LOLBIN_LIST  PASS')


# -------------------------------------------------------
# Test 3: Rule 6 does NOT fire on non-LOLBin NETWORK event
# -------------------------------------------------------
print('Test 3: Rule 6 ignores non-LOLBin NETWORK event...')
before = db.count_detections()
_insert_event(
    event_id='ev_r6_chrome',
    event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome',
    process_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    destination='8.8.8.8',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel',
)
correlator.run_all()
after = db.count_detections()
assert after == before, f'Expected no new detection for chrome, got {after - before}'
print('  chrome.exe not in LOLBIN_LIST, no detection  PASS')


# -------------------------------------------------------
# Test 4: Rule 6 does NOT fire on LOLBin PROCESS event (wrong type)
# Use cmd.exe — in LOLBIN_LIST but NOT in INTERPRETER_LIST,
# so neither Rule 6 nor Rule 21 should fire on this PROCESS event.
# -------------------------------------------------------
print('Test 4: Rule 6 ignores PROCESS events (only fires on NETWORK)...')
before = db.count_detections()
_insert_event(
    event_id='ev_r6_process',
    event_type='PROCESS', subtype='NEW PROCESS',
    actor='cmd.exe',
    process_path=r'C:\Windows\system32\cmd.exe',
    destination=None,
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='harbinger',
)
correlator.run_all()
after = db.count_detections()
assert after == before, f'Rule 6 should not fire on PROCESS events, got {after - before} new detections'
print('  LOLBin PROCESS event correctly ignored by Rule 6  PASS')


# -------------------------------------------------------
# Test 5: Rule 21 fires CRITICAL on interpreter from HIGH_RISK path
# -------------------------------------------------------
print('Test 5: Rule 21 CRITICAL on interpreter from HIGH_RISK path...')
appdata_temp = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp')
_insert_event(
    event_id='ev_r21_highrisk',
    event_type='PROCESS', subtype='NEW PROCESS',
    actor='python.exe',
    process_path=os.path.join(appdata_temp, 'python.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger',
)
correlator.run_all()
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt21 = conn.execute(
    "SELECT * FROM alerts WHERE rule_id=21 AND alert_id=?",
    (correlator._make_alert_id(21, 'ev_r21_highrisk'),)
).fetchone()
conn.close()
assert alt21 is not None,                          'No alert for HIGH_RISK interpreter'
assert alt21['severity_current'] == 'CRITICAL',    f"severity={alt21['severity_current']}"
assert alt21['confidence'] == config.RULE_WEIGHTS[21], f"confidence={alt21['confidence']}"
assert 'HIGH_RISK' in alt21['explanation'].upper() or 'high_risk' in alt21['explanation']
print(f'  alert=CRITICAL, confidence={alt21["confidence"]:.0%}  PASS')


# -------------------------------------------------------
# Test 6: Rule 21 fires SUSPICIOUS on interpreter from UNKNOWN path
# -------------------------------------------------------
print('Test 6: Rule 21 SUSPICIOUS on interpreter from UNKNOWN path...')
_insert_event(
    event_id='ev_r21_unknown',
    event_type='PROCESS', subtype='NEW PROCESS',
    actor='node.exe',
    process_path=r'C:\SomeRandomFolder\node.exe',
    destination=None,
    base_severity='UNKNOWN', trust_level='UNKNOWN',
    collector='harbinger',
)
correlator.run_all()
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt21u = conn.execute(
    "SELECT * FROM alerts WHERE rule_id=21 AND alert_id=?",
    (correlator._make_alert_id(21, 'ev_r21_unknown'),)
).fetchone()
conn.close()
assert alt21u is not None,                            'No alert for UNKNOWN path interpreter'
assert alt21u['severity_current'] == 'SUSPICIOUS',    f"severity={alt21u['severity_current']}"
expected_conf = round(config.RULE_WEIGHTS[21] * 0.6, 10)
assert round(alt21u['confidence'], 10) == expected_conf, f"confidence={alt21u['confidence']}"
print(f'  alert=SUSPICIOUS, confidence={alt21u["confidence"]:.0%}  PASS')


# -------------------------------------------------------
# Test 7: Rule 21 creates detection only (no alert) on TRUSTED path
# -------------------------------------------------------
print('Test 7: Rule 21 detection-only on interpreter from TRUSTED path...')
alerts_before = db.count_alerts()
_insert_event(
    event_id='ev_r21_trusted',
    event_type='PROCESS', subtype='NEW PROCESS',
    actor='python.exe',
    process_path=r'C:\Program Files\Python312\python.exe',
    destination=None,
    base_severity='UNKNOWN', trust_level='TRUSTED',
    collector='harbinger',
)
correlator.run_all()
alerts_after = db.count_alerts()
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det_trusted = conn.execute(
    "SELECT * FROM detections WHERE rule_id=21 AND matched_entities LIKE '%ev_r21_trusted%'"
).fetchall()
conn.close()
assert alerts_after == alerts_before, f'Expected no new alert for TRUSTED path, got {alerts_after - alerts_before} new'
assert len(det_trusted) == 1,         f'Expected 1 detection, got {len(det_trusted)}'
print('  detection logged, no alert generated for TRUSTED path  PASS')


# -------------------------------------------------------
# Test 8: Rule 21 does NOT fire on non-interpreter PROCESS event
# -------------------------------------------------------
print('Test 8: Rule 21 ignores non-interpreter PROCESS event...')
before = db.count_detections()
_insert_event(
    event_id='ev_r21_notepad',
    event_type='PROCESS', subtype='NEW PROCESS',
    actor='notepad.exe',
    process_path=r'C:\Windows\system32\notepad.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger',
)
correlator.run_all()
after = db.count_detections()
assert after == before, f'notepad.exe should not trigger Rule 21'
print('  notepad.exe not in INTERPRETER_LIST, no detection  PASS')


# -------------------------------------------------------
# Test 9: Alert deduplication — same event does not create a second alert
# -------------------------------------------------------
print('Test 9: Alert deduplication...')
# Insert a duplicate event_id that produces the same alert_id
# We do this by directly calling the rule function twice on the same event
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
ev = conn.execute("SELECT * FROM events WHERE event_id='ev_r6_lolbin'").fetchone()
conn.close()

alert_count_before = db.count_alerts()
correlator._rule_6(ev)   # fire the rule manually a second time
alert_count_after  = db.count_alerts()
assert alert_count_after == alert_count_before, \
    f'Duplicate alert inserted: {alert_count_after - alert_count_before} new alerts'
print('  duplicate rule fire produced 0 new alerts (INSERT OR IGNORE)  PASS')


# -------------------------------------------------------
# Test 10: run_all() marks events correlated — second call processes 0
# -------------------------------------------------------
print('Test 10: Events marked correlated after run_all()...')
# All events inserted above have been processed — pending should be 0
pending = db.get_uncorrelated_events()
assert len(pending) == 0, f'Expected 0 uncorrelated events, got {len(pending)}'

# Insert a fresh event and confirm it gets picked up then cleared
_insert_event(
    event_id='ev_fresh',
    event_type='PROCESS', subtype='STARTUP',
    actor='svchost.exe',
    process_path=r'C:\Windows\system32\svchost.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger',
)
result1 = correlator.run_all()
assert result1['events_processed'] == 1, f"Expected 1, got {result1['events_processed']}"
result2 = correlator.run_all()
assert result2['events_processed'] == 0, f"Expected 0 on second call, got {result2['events_processed']}"
print('  first call processed 1, second call processed 0  PASS')


# -------------------------------------------------------
# Test 11: run_all() return dict is accurate
# -------------------------------------------------------
print('Test 11: run_all() return dict accuracy...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='ev_summary_lolbin',
    event_type='NETWORK', subtype='OUTBOUND',
    actor='mshta',
    process_path=r'C:\Windows\system32\mshta.exe',
    destination='1.2.3.4',
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='sentinel',
)
_insert_event(
    event_id='ev_summary_interp',
    event_type='PROCESS', subtype='NEW PROCESS',
    actor='ruby.exe',
    process_path=os.path.join(appdata_temp, 'ruby.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger',
)
result = correlator.run_all()
assert result['events_processed'] == 2, f"events_processed={result['events_processed']}"
assert result['new_detections']   == 2, f"new_detections={result['new_detections']}"
assert result['new_alerts']       == 2, f"new_alerts={result['new_alerts']}"
print(f'  events_processed=2, new_detections=2, new_alerts=2  PASS')


# ============================================================
# Rule 4 tests — fresh DB for each to prevent window leakage
# reference_time controls the window; observed_at places events inside it.
#
# Strategy: reference_time = 03:10, window = 10 min → cutoff = 03:00
#   Power event at 03:00 → inside window, after-hours ✓
#   Network event at 03:02 → inside window, after-hours ✓
# ============================================================

from datetime import datetime as _dt

_REF_AFTER  = _dt(2026, 3, 20,  3, 10, 0)   # 03:10 — after-hours reference
_REF_DAY    = _dt(2026, 3, 20, 11, 10, 0)   # 11:10 — daytime reference
_WAKE_TIME  = '2026-03-20 03:00:00'          # inside after-hours window
_NET_TIME   = '2026-03-20 03:02:00'          # 2 min after wake — within SHORT_WINDOW
_DAY_WAKE   = '2026-03-20 11:00:00'          # daytime wake
_DAY_NET    = '2026-03-20 11:02:00'          # daytime network


# -------------------------------------------------------
# Test 12: Rule 4 fires — after-hours WAKE + NETWORK in window
# -------------------------------------------------------
print('Test 12: Rule 4 fires on after-hours WAKE + NETWORK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r4_wake', event_type='POWER', subtype='WAKE',
    actor=None, process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='watchman', observed_at=_WAKE_TIME,
)
_insert_event(
    event_id='r4_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome', process_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    destination='185.199.110.133',
    base_severity='UNKNOWN', trust_level='TRUSTED',
    collector='sentinel', observed_at=_NET_TIME,
)
correlator._rule_4(reference_time=_REF_AFTER)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det4  = conn.execute("SELECT * FROM detections WHERE rule_id=4").fetchall()
alt4  = conn.execute("SELECT * FROM alerts    WHERE rule_id=4").fetchall()
conn.close()
assert len(det4) == 1, f'Expected 1 detection, got {len(det4)}'
assert len(alt4) == 1, f'Expected 1 alert, got {len(alt4)}'
assert alt4[0]['severity_current'] == 'CRITICAL', f"severity={alt4[0]['severity_current']}"
assert '03:00' in alt4[0]['explanation'] or 'WAKE' in alt4[0]['explanation']
assert '185.199.110.133' in alt4[0]['explanation']
print('  CRITICAL alert generated, wake time and destination in explanation  PASS')


# -------------------------------------------------------
# Test 13: Rule 4 does NOT fire — wake is daytime (not after-hours)
# -------------------------------------------------------
print('Test 13: Rule 4 ignores daytime wake + network...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r4_day_wake', event_type='POWER', subtype='WAKE',
    actor=None, process_path=None, destination=None,
    base_severity='OK', trust_level='UNKNOWN',
    collector='watchman', observed_at=_DAY_WAKE,
)
_insert_event(
    event_id='r4_day_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome', process_path=None, destination='8.8.8.8',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at=_DAY_NET,
)
correlator._rule_4(reference_time=_REF_DAY)
assert db.count_alerts() == 0, f'Expected no alert for daytime wake, got {db.count_alerts()}'
print('  no alert for 11:00 wake (outside 00:00-06:00 window)  PASS')


# -------------------------------------------------------
# Test 14: Rule 4 does NOT fire — after-hours wake but no network in window
# -------------------------------------------------------
print('Test 14: Rule 4 ignores after-hours wake with no network activity...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r4_lonely_wake', event_type='POWER', subtype='WAKE',
    actor=None, process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='watchman', observed_at=_WAKE_TIME,
)
# No NETWORK event inserted
correlator._rule_4(reference_time=_REF_AFTER)
assert db.count_alerts() == 0, f'Expected no alert (no network), got {db.count_alerts()}'
print('  no alert when wake has no corroborating network event  PASS')


# -------------------------------------------------------
# Test 15: Rule 4 does NOT fire — power event is SLEEP, not WAKE/BOOT
# -------------------------------------------------------
print('Test 15: Rule 4 ignores SLEEP power subtype...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r4_sleep', event_type='POWER', subtype='SLEEP',
    actor=None, process_path=None, destination=None,
    base_severity='OK', trust_level='UNKNOWN',
    collector='watchman', observed_at=_WAKE_TIME,
)
_insert_event(
    event_id='r4_sleep_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome', process_path=None, destination='8.8.8.8',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at=_NET_TIME,
)
correlator._rule_4(reference_time=_REF_AFTER)
assert db.count_alerts() == 0, f'Expected no alert for SLEEP event, got {db.count_alerts()}'
print('  SLEEP subtype correctly excluded (only WAKE/BOOT trigger Rule 4)  PASS')


# -------------------------------------------------------
# Test 16: Rule 4 deduplication — calling rule twice produces 1 alert
# -------------------------------------------------------
print('Test 16: Rule 4 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r4_dup_wake', event_type='POWER', subtype='WAKE',
    actor=None, process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='watchman', observed_at=_WAKE_TIME,
)
_insert_event(
    event_id='r4_dup_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome', process_path=None, destination='8.8.8.8',
    base_severity='UNKNOWN', trust_level='TRUSTED',
    collector='sentinel', observed_at=_NET_TIME,
)
correlator._rule_4(reference_time=_REF_AFTER)
correlator._rule_4(reference_time=_REF_AFTER)   # second call — same data
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')


# ============================================================
# Rule 13 tests — Initial Access Suspected
# Fresh DB for each test. reference_time controls the window.
#
# Strategy: reference_time = T+11min, SHORT_WINDOW = 10min
#   Process at T=0     → inside window ✓
#   Network at T+90s   → inside window, within 120s PAIRING_WINDOW ✓
# ============================================================

_R13_PROC_TIME = '2026-03-20 04:03:00'   # 04:03:00 — after-hours, inside window
_R13_NET_90    = '2026-03-20 04:04:30'   # 04:04:30 — 90s after process (within 120s)
_R13_NET_121   = '2026-03-20 04:05:01'   # 04:05:01 — 121s after process (outside 120s)
_R13_NET_PREV  = '2026-03-20 04:02:55'   # 04:02:55 — 5s BEFORE process (negative delta)
_R13_REF       = _dt(2026, 3, 20, 4, 13, 0)   # reference: 04:13 → cutoff 04:03 → all inside


# -------------------------------------------------------
# Test 17: Rule 13 fires — HIGH_RISK process + same actor NETWORK within 120s
# -------------------------------------------------------
print('Test 17: Rule 13 fires on HIGH_RISK process + NETWORK same actor...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

appdata_temp = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp')
_insert_event(
    event_id='r13_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R13_PROC_TIME,
)
_insert_event(
    event_id='r13_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',                  # Sentinel logs without .exe
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination='192.0.2.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R13_NET_90,
)
correlator._rule_13(reference_time=_R13_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det13 = conn.execute("SELECT * FROM detections WHERE rule_id=13").fetchall()
alt13 = conn.execute("SELECT * FROM alerts    WHERE rule_id=13").fetchall()
conn.close()
assert len(det13) == 1, f'Expected 1 detection, got {len(det13)}'
assert len(alt13) == 1, f'Expected 1 alert, got {len(alt13)}'
assert alt13[0]['severity_current'] == 'CRITICAL'
assert '192.0.2.1'   in alt13[0]['explanation']
assert 'Initial Access' in alt13[0]['explanation']
print('  CRITICAL alert, actor matched across .exe suffix, destination in explanation  PASS')


# -------------------------------------------------------
# Test 18: Rule 13 no-fire — process is TRUSTED path (not HIGH_RISK)
# -------------------------------------------------------
print('Test 18: Rule 13 ignores TRUSTED path process...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r13_trusted_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='chrome.exe',
    process_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger', observed_at=_R13_PROC_TIME,
)
_insert_event(
    event_id='r13_trusted_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome',
    process_path=None, destination='8.8.8.8',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at=_R13_NET_90,
)
correlator._rule_13(reference_time=_R13_REF)
assert db.count_alerts() == 0, f'Expected no alert for TRUSTED process, got {db.count_alerts()}'
print('  TRUSTED path process correctly ignored  PASS')


# -------------------------------------------------------
# Test 19: Rule 13 no-fire — HIGH_RISK process but different actor on network
# -------------------------------------------------------
print('Test 19: Rule 13 ignores HIGH_RISK process when network actor differs...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r13_wrong_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R13_PROC_TIME,
)
_insert_event(
    event_id='r13_wrong_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome',               # different binary — should not pair
    process_path=None, destination='8.8.8.8',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at=_R13_NET_90,
)
correlator._rule_13(reference_time=_R13_REF)
assert db.count_alerts() == 0, f'Expected no alert (actor mismatch), got {db.count_alerts()}'
print('  actor mismatch (evil.exe vs chrome) correctly prevented alert  PASS')


# -------------------------------------------------------
# Test 20: Rule 13 no-fire — network event arrives 121 seconds after process
# -------------------------------------------------------
print('Test 20: Rule 13 ignores network event outside 120s pairing window...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r13_late_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R13_PROC_TIME,
)
_insert_event(
    event_id='r13_late_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',
    process_path=None, destination='192.0.2.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R13_NET_121,   # 121s — just over limit
)
correlator._rule_13(reference_time=_R13_REF)
assert db.count_alerts() == 0, f'Expected no alert (121s > 120s window), got {db.count_alerts()}'
print('  network at +121s outside pairing window, no alert  PASS')


# -------------------------------------------------------
# Test 21: Rule 13 no-fire — network event is BEFORE the process
# -------------------------------------------------------
print('Test 21: Rule 13 ignores network event that precedes process...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r13_early_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R13_PROC_TIME,
)
_insert_event(
    event_id='r13_early_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',
    process_path=None, destination='192.0.2.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R13_NET_PREV,   # 5s BEFORE process
)
correlator._rule_13(reference_time=_R13_REF)
assert db.count_alerts() == 0, f'Expected no alert (network precedes process), got {db.count_alerts()}'
print('  network before process (negative delta) correctly excluded  PASS')


# -------------------------------------------------------
# Test 22: Rule 13 deduplication — same data, two calls → 1 alert
# -------------------------------------------------------
print('Test 22: Rule 13 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r13_dup_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R13_PROC_TIME,
)
_insert_event(
    event_id='r13_dup_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',
    process_path=None, destination='192.0.2.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R13_NET_90,
)
correlator._rule_13(reference_time=_R13_REF)
correlator._rule_13(reference_time=_R13_REF)   # second call — same data
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')


# ============================================================
# Rule 3 tests — Persistence + C2 Callback
# Fresh DB for each test.
# Both events must be within SHORT_WINDOW (10 min) of reference_time.
# ============================================================

_R3_TASK_TIME = '2026-03-20 05:05:00'   # inside window from 05:14 ref
_R3_NET_TIME  = '2026-03-20 05:08:00'   # 3 min after task — also inside window
_R3_REF       = _dt(2026, 3, 20, 5, 14, 0)   # cutoff = 05:04 → both events inside


# -------------------------------------------------------
# Test 23: Rule 3 fires — HIGH_RISK task + UNKNOWN network in window
# -------------------------------------------------------
print('Test 23: Rule 3 fires on HIGH_RISK NEW TASK + UNKNOWN network...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r3_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R3_TASK_TIME,
)
_insert_event(
    event_id='r3_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination='198.51.100.1',
    base_severity='UNKNOWN', trust_level='UNKNOWN',
    collector='sentinel', observed_at=_R3_NET_TIME,
)
correlator._rule_3(reference_time=_R3_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det3 = conn.execute("SELECT * FROM detections WHERE rule_id=3").fetchall()
alt3 = conn.execute("SELECT * FROM alerts    WHERE rule_id=3").fetchall()
conn.close()
assert len(det3) == 1, f'Expected 1 detection, got {len(det3)}'
assert len(alt3) == 1, f'Expected 1 alert, got {len(alt3)}'
assert alt3[0]['severity_current'] == 'CRITICAL'
assert '198.51.100.1' in alt3[0]['explanation']
assert 'Persistence' in alt3[0]['explanation']
print('  CRITICAL alert, destination and Persistence in explanation  PASS')


# -------------------------------------------------------
# Test 24: Rule 3 no-fire — task is TRUSTED path (system binary)
# -------------------------------------------------------
print('Test 24: Rule 3 ignores TRUSTED path scheduled task...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r3_trusted_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker',
    process_path=r'C:\Windows\System32\usoclient.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='cityguard', observed_at=_R3_TASK_TIME,
)
_insert_event(
    event_id='r3_trusted_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',
    process_path=None, destination='198.51.100.1',
    base_severity='UNKNOWN', trust_level='UNKNOWN',
    collector='sentinel', observed_at=_R3_NET_TIME,
)
correlator._rule_3(reference_time=_R3_REF)
assert db.count_alerts() == 0, f'Expected no alert for TRUSTED task, got {db.count_alerts()}'
print('  TRUSTED task path correctly excluded  PASS')


# -------------------------------------------------------
# Test 25: Rule 3 no-fire — suspicious task but no network in window
# -------------------------------------------------------
print('Test 25: Rule 3 ignores suspicious task with no network activity...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r3_no_net_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R3_TASK_TIME,
)
# No NETWORK event inserted
correlator._rule_3(reference_time=_R3_REF)
assert db.count_alerts() == 0, f'Expected no alert (no network), got {db.count_alerts()}'
print('  no alert when task has no corroborating network event  PASS')


# -------------------------------------------------------
# Test 26: Rule 3 no-fire — network is TRUSTED (system process, not suspicious)
# -------------------------------------------------------
print('Test 26: Rule 3 ignores TRUSTED network alongside suspicious task...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r3_tnet_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R3_TASK_TIME,
)
_insert_event(
    event_id='r3_tnet_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='svchost',
    process_path=r'C:\Windows\system32\svchost.exe',
    destination='13.107.4.50',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at=_R3_NET_TIME,
)
correlator._rule_3(reference_time=_R3_REF)
assert db.count_alerts() == 0, f'Expected no alert (TRUSTED network), got {db.count_alerts()}'
print('  TRUSTED network correctly excluded — routine svchost traffic not flagged  PASS')


# -------------------------------------------------------
# Test 27: Rule 3 actor match — task action binary matches network actor
# -------------------------------------------------------
print('Test 27: Rule 3 actor match noted in detection score_factors...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r3_match_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\beacon.exe',
    process_path=os.path.join(appdata_temp, 'beacon.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R3_TASK_TIME,
)
_insert_event(
    event_id='r3_match_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='beacon',           # same binary, no .exe — Sentinel format
    process_path=None, destination='203.0.113.42',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R3_NET_TIME,
)
correlator._rule_3(reference_time=_R3_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
import json
det_match = conn.execute("SELECT * FROM detections WHERE rule_id=3").fetchone()
conn.close()
assert det_match is not None, 'Expected detection for actor match'
factors = json.loads(det_match['score_factors'])
assert factors['actor_match'] is True, f"actor_match={factors['actor_match']}"
print('  actor_match=True in score_factors, same binary persisting and beaconing  PASS')


# -------------------------------------------------------
# Test 28: Rule 3 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 28: Rule 3 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r3_dup_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\evil.exe',
    process_path=os.path.join(appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R3_TASK_TIME,
)
_insert_event(
    event_id='r3_dup_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',
    process_path=None, destination='198.51.100.1',
    base_severity='UNKNOWN', trust_level='UNKNOWN',
    collector='sentinel', observed_at=_R3_NET_TIME,
)
correlator._rule_3(reference_time=_R3_REF)
correlator._rule_3(reference_time=_R3_REF)
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 9 tests — WMI Persistence Suspected
# Fresh DB for each test.
# Requires a helper that inserts BOTH a normalized event AND
# the corresponding raw_events row (with normalized_event_id)
# so that db.get_harbinger_events_by_parent() JOIN resolves.
# ============================================================

_R9_PROC_TIME = '2026-03-20 06:02:00'
_R9_TASK_TIME = '2026-03-20 06:05:00'
_R9_REF       = _dt(2026, 3, 20, 6, 11, 0)   # cutoff 06:01 → both events inside


def _insert_wmi_process(event_id, actor, process_path, trust_level, base_severity,
                         parent_name='WmiPrvSE', observed_at=_R9_PROC_TIME):
    """Insert a normalized PROCESS event AND the raw_events row that the
    get_harbinger_events_by_parent() JOIN needs to resolve the parent."""
    _insert_event(
        event_id=event_id, event_type='PROCESS', subtype='NEW PROCESS',
        actor=actor, process_path=process_path, destination=None,
        base_severity=base_severity, trust_level=trust_level,
        collector='harbinger', observed_at=observed_at,
    )
    raw_line = (
        f'[{observed_at}] [{base_severity}] NEW PROCESS: {actor} | PID: 1234 | '
        f'Parent: {parent_name} (555) | Path: {process_path or ""} | CMD: '
    )
    conn = sqlite3.connect('hocsoc.db')
    conn.execute("""
        INSERT OR IGNORE INTO raw_events
            (collector_name, raw_payload, observed_at, recorded_at,
             source_host, raw_event_hash, normalized_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, ('harbinger', raw_line, observed_at, observed_at,
          'TEST-HOST', f'rawhash_{event_id}', event_id))
    conn.commit()
    conn.close()


# -------------------------------------------------------
# Test 29: Rule 9 fires — WmiPrvSE parent + NEW TASK in window
# -------------------------------------------------------
print('Test 29: Rule 9 fires on WmiPrvSE parent + NEW TASK in window...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_wmi_process('r9_proc', actor='payload.exe',
                    process_path=r'C:\Windows\Temp\payload.exe',
                    trust_level='HIGH_RISK', base_severity='CRITICAL')
_insert_event(
    event_id='r9_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\payload.exe',
    process_path=r'C:\Windows\Temp\payload.exe', destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R9_TASK_TIME,
)
correlator._rule_9(reference_time=_R9_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det9 = conn.execute("SELECT * FROM detections WHERE rule_id=9").fetchall()
alt9 = conn.execute("SELECT * FROM alerts    WHERE rule_id=9").fetchall()
conn.close()
assert len(det9) == 1, f'Expected 1 detection, got {len(det9)}'
assert len(alt9) == 1, f'Expected 1 alert, got {len(alt9)}'
assert alt9[0]['severity_current'] == 'SUSPICIOUS'
assert 'WMI' in alt9[0]['explanation']
assert 'WmiPrvSE' in alt9[0]['explanation']
print('  SUSPICIOUS alert, WMI and WmiPrvSE in explanation  PASS')


# -------------------------------------------------------
# Test 30: Rule 9 no-fire — WmiPrvSE process but no NEW TASK in window
# -------------------------------------------------------
print('Test 30: Rule 9 ignores WmiPrvSE process with no NEW TASK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_wmi_process('r9_no_task_proc', actor='payload.exe',
                    process_path=r'C:\Windows\Temp\payload.exe',
                    trust_level='HIGH_RISK', base_severity='CRITICAL')
# No SCHEDULED_TASK event inserted
correlator._rule_9(reference_time=_R9_REF)
assert db.count_alerts() == 0, f'Expected no alert (no NEW TASK), got {db.count_alerts()}'
print('  no alert when WMI process has no corroborating NEW TASK  PASS')


# -------------------------------------------------------
# Test 31: Rule 9 no-fire — NEW TASK in window but parent is NOT WmiPrvSE
# -------------------------------------------------------
print('Test 31: Rule 9 ignores non-WmiPrvSE parent even if NEW TASK exists...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_wmi_process('r9_normal_parent', actor='payload.exe',
                    process_path=r'C:\Windows\Temp\payload.exe',
                    trust_level='HIGH_RISK', base_severity='CRITICAL',
                    parent_name='explorer')   # NOT WmiPrvSE
_insert_event(
    event_id='r9_task_only', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\payload.exe',
    process_path=r'C:\Windows\Temp\payload.exe', destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R9_TASK_TIME,
)
correlator._rule_9(reference_time=_R9_REF)
assert db.count_alerts() == 0, f'Expected no alert (parent is explorer, not WmiPrvSE), got {db.count_alerts()}'
print('  non-WmiPrvSE parent correctly excluded  PASS')


# -------------------------------------------------------
# Test 32: Rule 9 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 32: Rule 9 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_wmi_process('r9_dup_proc', actor='beacon.exe',
                    process_path=r'C:\Windows\Temp\beacon.exe',
                    trust_level='HIGH_RISK', base_severity='CRITICAL')
_insert_event(
    event_id='r9_dup_task', event_type='SCHEDULED_TASK', subtype='NEW TASK',
    actor=r'\Temp\beacon.exe',
    process_path=r'C:\Windows\Temp\beacon.exe', destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='cityguard', observed_at=_R9_TASK_TIME,
)
correlator._rule_9(reference_time=_R9_REF)
correlator._rule_9(reference_time=_R9_REF)   # second call — same data
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')


# ============================================================
# Rule 7 tests — Process Hollowing Suspected
# Fresh DB for each test.
# Condition: HOLLOWING_TARGET from non-TRUSTED path + NETWORK from same actor.
# ============================================================

_R7_PROC_TIME = '2026-03-20 07:00:00'
_R7_NET_TIME  = '2026-03-20 07:03:00'
_R7_REF       = _dt(2026, 3, 20, 7, 9, 0)   # cutoff 06:59 → both events inside

_appdata_temp = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp')


# -------------------------------------------------------
# Test 33: Rule 7 fires — HOLLOWING_TARGET from HIGH_RISK path + network
# -------------------------------------------------------
print('Test 33: Rule 7 fires on HOLLOWING_TARGET from HIGH_RISK path + NETWORK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r7_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='svchost.exe',
    process_path=os.path.join(_appdata_temp, 'svchost.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R7_PROC_TIME,
)
_insert_event(
    event_id='r7_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='svchost',                        # Sentinel drops .exe
    process_path=os.path.join(_appdata_temp, 'svchost.exe'),
    destination='185.220.101.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R7_NET_TIME,
)
correlator._rule_7(reference_time=_R7_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det7 = conn.execute("SELECT * FROM detections WHERE rule_id=7").fetchall()
alt7 = conn.execute("SELECT * FROM alerts    WHERE rule_id=7").fetchall()
conn.close()
assert len(det7) == 1, f'Expected 1 detection, got {len(det7)}'
assert len(alt7) == 1, f'Expected 1 alert, got {len(alt7)}'
assert alt7[0]['severity_current'] == 'CRITICAL'
assert 'Hollowing' in alt7[0]['explanation'] or 'hollowing' in alt7[0]['explanation'].lower()
assert '185.220.101.1' in alt7[0]['explanation']
print('  CRITICAL alert, Hollowing and destination in explanation  PASS')


# -------------------------------------------------------
# Test 34: Rule 7 no-fire — HOLLOWING_TARGET from TRUSTED path (legitimate)
# -------------------------------------------------------
print('Test 34: Rule 7 ignores HOLLOWING_TARGET from TRUSTED path...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r7_trusted_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='svchost.exe',
    process_path=r'C:\Windows\System32\svchost.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger', observed_at=_R7_PROC_TIME,
)
_insert_event(
    event_id='r7_trusted_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='svchost',
    process_path=r'C:\Windows\System32\svchost.exe',
    destination='20.60.246.1',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at=_R7_NET_TIME,
)
correlator._rule_7(reference_time=_R7_REF)
assert db.count_alerts() == 0, f'Expected no alert for TRUSTED svchost.exe, got {db.count_alerts()}'
print('  TRUSTED svchost.exe from System32 correctly excluded  PASS')


# -------------------------------------------------------
# Test 35: Rule 7 no-fire — HOLLOWING_TARGET from wrong path but no NETWORK
# -------------------------------------------------------
print('Test 35: Rule 7 ignores HOLLOWING_TARGET with no corroborating NETWORK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r7_no_net_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='explorer.exe',
    process_path=os.path.join(_appdata_temp, 'explorer.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R7_PROC_TIME,
)
# No NETWORK event inserted
correlator._rule_7(reference_time=_R7_REF)
assert db.count_alerts() == 0, f'Expected no alert (no network), got {db.count_alerts()}'
print('  no alert when hollow process has no corroborating network event  PASS')


# -------------------------------------------------------
# Test 36: Rule 7 no-fire — non-HOLLOWING_TARGET binary from wrong path + network
# -------------------------------------------------------
print('Test 36: Rule 7 ignores non-HOLLOWING_TARGET binary from wrong path + NETWORK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r7_nolist_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='evil.exe',                       # NOT in HOLLOWING_TARGETS
    process_path=os.path.join(_appdata_temp, 'evil.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R7_PROC_TIME,
)
_insert_event(
    event_id='r7_nolist_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='evil',
    process_path=os.path.join(_appdata_temp, 'evil.exe'),
    destination='1.2.3.4',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R7_NET_TIME,
)
correlator._rule_7(reference_time=_R7_REF)
assert db.count_alerts() == 0, f'Expected no Rule 7 alert (evil.exe not in HOLLOWING_TARGETS), got {db.count_alerts()}'
print('  evil.exe not in HOLLOWING_TARGETS — Rule 7 correctly silent  PASS')


# -------------------------------------------------------
# Test 37: Rule 7 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 37: Rule 7 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r7_dup_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='lsass.exe',
    process_path=os.path.join(_appdata_temp, 'lsass.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R7_PROC_TIME,
)
_insert_event(
    event_id='r7_dup_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='lsass',
    process_path=os.path.join(_appdata_temp, 'lsass.exe'),
    destination='77.88.55.66',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R7_NET_TIME,
)
correlator._rule_7(reference_time=_R7_REF)
correlator._rule_7(reference_time=_R7_REF)   # second call — same data
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')


# ============================================================
# Rule 16 tests — Contextual Integrity Violation
# Fresh DB for each test.
# Condition: NEVER_NET binary from TRUSTED path + NETWORK from same actor.
# NEVER_NET_BINARIES = lsass, csrss, wininit, smss, lsm
# Distinct from Rule 7: trust_level MUST be TRUSTED here.
# ============================================================

_R16_PROC_TIME = '2026-03-20 08:00:00'
_R16_NET_TIME  = '2026-03-20 08:04:00'
_R16_REF       = _dt(2026, 3, 20, 8, 9, 0)   # cutoff 07:59 → both events inside


# -------------------------------------------------------
# Test 38: Rule 16 fires — NEVER_NET binary from TRUSTED path + NETWORK
# -------------------------------------------------------
print('Test 38: Rule 16 fires on NEVER_NET binary from TRUSTED path + NETWORK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r16_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='lsass.exe',
    process_path=r'C:\Windows\System32\lsass.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger', observed_at=_R16_PROC_TIME,
)
_insert_event(
    event_id='r16_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='lsass',
    process_path=r'C:\Windows\System32\lsass.exe',
    destination='10.0.0.99',
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='sentinel', observed_at=_R16_NET_TIME,
)
correlator._rule_16(reference_time=_R16_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det16 = conn.execute("SELECT * FROM detections WHERE rule_id=16").fetchall()
alt16 = conn.execute("SELECT * FROM alerts    WHERE rule_id=16").fetchall()
conn.close()
assert len(det16) == 1, f'Expected 1 detection, got {len(det16)}'
assert len(alt16) == 1, f'Expected 1 alert, got {len(alt16)}'
assert alt16[0]['severity_current'] == 'CRITICAL'
assert 'Integrity' in alt16[0]['explanation'] or 'integrity' in alt16[0]['explanation'].lower()
assert '10.0.0.99' in alt16[0]['explanation']
print('  CRITICAL alert, Integrity and destination in explanation  PASS')


# -------------------------------------------------------
# Test 39: Rule 16 no-fire — NEVER_NET from TRUSTED path but no NETWORK
# -------------------------------------------------------
print('Test 39: Rule 16 ignores NEVER_NET binary with no NETWORK event...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r16_no_net_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='csrss.exe',
    process_path=r'C:\Windows\System32\csrss.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger', observed_at=_R16_PROC_TIME,
)
# No NETWORK event inserted
correlator._rule_16(reference_time=_R16_REF)
assert db.count_alerts() == 0, f'Expected no alert (no network), got {db.count_alerts()}'
print('  no alert when NEVER_NET binary has no corroborating NETWORK  PASS')


# -------------------------------------------------------
# Test 40: Rule 16 no-fire — NEVER_NET from HIGH_RISK path + NETWORK (Rule 7 territory)
# -------------------------------------------------------
print('Test 40: Rule 16 ignores NEVER_NET binary from HIGH_RISK path (Rule 7 fires instead)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r16_hr_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='lsass.exe',
    process_path=os.path.join(_appdata_temp, 'lsass.exe'),
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',   # NOT TRUSTED
    collector='harbinger', observed_at=_R16_PROC_TIME,
)
_insert_event(
    event_id='r16_hr_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='lsass',
    process_path=os.path.join(_appdata_temp, 'lsass.exe'),
    destination='1.2.3.4',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R16_NET_TIME,
)
correlator._rule_16(reference_time=_R16_REF)
assert db.count_alerts() == 0, f'Expected no Rule 16 alert (trust_level=HIGH_RISK, not TRUSTED), got {db.count_alerts()}'
print('  HIGH_RISK lsass.exe correctly excluded from Rule 16 (Rule 7 handles this case)  PASS')


# -------------------------------------------------------
# Test 41: Rule 16 no-fire — TRUSTED binary NOT in NEVER_NET_BINARIES + NETWORK
# -------------------------------------------------------
print('Test 41: Rule 16 ignores TRUSTED binary not in NEVER_NET_BINARIES...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r16_nolist_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='svchost.exe',                    # in HOLLOWING_TARGETS but NOT in NEVER_NET_BINARIES
    process_path=r'C:\Windows\System32\svchost.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger', observed_at=_R16_PROC_TIME,
)
_insert_event(
    event_id='r16_nolist_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='svchost',
    process_path=r'C:\Windows\System32\svchost.exe',
    destination='13.107.4.50',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at=_R16_NET_TIME,
)
correlator._rule_16(reference_time=_R16_REF)
assert db.count_alerts() == 0, f'Expected no Rule 16 alert (svchost not in NEVER_NET_BINARIES), got {db.count_alerts()}'
print('  svchost.exe not in NEVER_NET_BINARIES — Rule 16 correctly silent  PASS')


# -------------------------------------------------------
# Test 42: Rule 16 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 42: Rule 16 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r16_dup_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='wininit.exe',
    process_path=r'C:\Windows\System32\wininit.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='harbinger', observed_at=_R16_PROC_TIME,
)
_insert_event(
    event_id='r16_dup_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='wininit',
    process_path=r'C:\Windows\System32\wininit.exe',
    destination='198.51.100.77',
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='sentinel', observed_at=_R16_NET_TIME,
)
correlator._rule_16(reference_time=_R16_REF)
correlator._rule_16(reference_time=_R16_REF)   # second call — same data
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 11 tests — Burst Exfiltration Pattern
# Fresh DB for each test.
# Condition: same actor, >= BURST_CONNECTION_THRESHOLD NETWORK events
#            in SHORT_WINDOW.
# Zero-trust policy: HIGH_RISK + UNKNOWN → SUSPICIOUS alert;
#                    TRUSTED → detection only.
# ============================================================

_R11_REF = _dt(2026, 3, 20, 9, 9, 0)   # reference time; cutoff 08:59

def _net(event_id, actor, process_path, trust_level, base_severity,
         destination, observed_at):
    _insert_event(
        event_id=event_id, event_type='NETWORK', subtype='OUTBOUND',
        actor=actor, process_path=process_path, destination=destination,
        base_severity=base_severity, trust_level=trust_level,
        collector='sentinel', observed_at=observed_at,
    )


# -------------------------------------------------------
# Test 43: Rule 11 fires — HIGH_RISK actor, BURST_CONNECTION_THRESHOLD connections → SUSPICIOUS alert
# -------------------------------------------------------
print(f'Test 43: Rule 11 fires on HIGH_RISK actor with {config.BURST_CONNECTION_THRESHOLD} connections...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_appdata_temp = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp')
for i in range(config.BURST_CONNECTION_THRESHOLD):
    _net(f'r11_hr_{i}', actor='stager.exe',
         process_path=os.path.join(_appdata_temp, 'stager.exe'),
         trust_level='HIGH_RISK', base_severity='CRITICAL',
         destination=f'1.2.3.{i + 1}', observed_at=f'2026-03-20 09:0{i}:00')

correlator._rule_11(reference_time=_R11_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det11 = conn.execute("SELECT * FROM detections WHERE rule_id=11").fetchall()
alt11 = conn.execute("SELECT * FROM alerts    WHERE rule_id=11").fetchall()
conn.close()
assert len(det11) == 1, f'Expected 1 detection, got {len(det11)}'
assert len(alt11) == 1, f'Expected 1 alert, got {len(alt11)}'
assert alt11[0]['severity_current'] == 'SUSPICIOUS'
assert 'stager' in alt11[0]['explanation']
assert str(config.BURST_CONNECTION_THRESHOLD) in alt11[0]['explanation']
print('  SUSPICIOUS alert, actor and count in explanation  PASS')


# -------------------------------------------------------
# Test 43b: Rule 11 no-fire — one below threshold
# -------------------------------------------------------
print(f'Test 43b: Rule 11 no-fire with {config.BURST_CONNECTION_THRESHOLD - 1} connections (threshold - 1)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.BURST_CONNECTION_THRESHOLD - 1):
    _net(f'r11_below_{i}', actor='stager.exe',
         process_path=os.path.join(_appdata_temp, 'stager.exe'),
         trust_level='HIGH_RISK', base_severity='CRITICAL',
         destination=f'2.2.2.{i + 1}', observed_at=f'2026-03-20 09:0{i}:00')

correlator._rule_11(reference_time=_R11_REF)
assert db.count_alerts() == 0, f'Expected 0 alerts at threshold-1, got {db.count_alerts()}'
print('  no alert at threshold - 1  PASS')


# -------------------------------------------------------
# Test 44: Rule 11 fires — UNKNOWN actor, BURST_CONNECTION_THRESHOLD connections → SUSPICIOUS alert
# -------------------------------------------------------
print(f'Test 44: Rule 11 fires on UNKNOWN actor with {config.BURST_CONNECTION_THRESHOLD} connections...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.BURST_CONNECTION_THRESHOLD):
    _net(f'r11_unk_{i}', actor='mystery.exe',
         process_path=r'C:\SomeUnknownFolder\mystery.exe',
         trust_level='UNKNOWN', base_severity='UNKNOWN',
         destination=f'10.0.0.{i + 1}', observed_at=f'2026-03-20 09:0{i}:00')

correlator._rule_11(reference_time=_R11_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt11u = conn.execute("SELECT * FROM alerts WHERE rule_id=11").fetchall()
conn.close()
assert len(alt11u) == 1, f'Expected 1 alert for UNKNOWN actor, got {len(alt11u)}'
assert alt11u[0]['severity_current'] == 'SUSPICIOUS'
print('  UNKNOWN actor with burst also fires SUSPICIOUS alert (zero-trust)  PASS')


# -------------------------------------------------------
# Test 45: Rule 11 — TRUSTED actor, BURST_CONNECTION_THRESHOLD connections → detection only, no alert
# -------------------------------------------------------
print('Test 45: Rule 11 detection-only for TRUSTED actor burst...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.BURST_CONNECTION_THRESHOLD):
    _net(f'r11_tr_{i}', actor='svchost.exe',
         process_path=r'C:\Windows\System32\svchost.exe',
         trust_level='TRUSTED', base_severity='OK',
         destination=f'20.0.0.{i + 1}', observed_at=f'2026-03-20 09:0{i}:00')

alerts_before = db.count_alerts()
correlator._rule_11(reference_time=_R11_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det11t = conn.execute("SELECT * FROM detections WHERE rule_id=11").fetchall()
conn.close()
assert db.count_alerts() == alerts_before, \
    f'Expected no alert for TRUSTED burst, got {db.count_alerts() - alerts_before} new'
assert len(det11t) == 1, f'Expected 1 detection, got {len(det11t)}'
print('  detection logged, no alert for TRUSTED actor (baseline period)  PASS')


# -------------------------------------------------------
# Test 46: Rule 11 no-fire — only 2 connections (below threshold)
# -------------------------------------------------------
print('Test 46: Rule 11 ignores burst below threshold (2 connections)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i, dest in enumerate(['30.0.0.1', '30.0.0.2']):
    _net(f'r11_low_{i}', actor='loader.exe',
         process_path=os.path.join(_appdata_temp, 'loader.exe'),
         trust_level='HIGH_RISK', base_severity='CRITICAL',
         destination=dest, observed_at=f'2026-03-20 09:0{i}:00')

correlator._rule_11(reference_time=_R11_REF)
assert db.count_detections() == 0, \
    f'Expected no detection for 2 connections (below threshold={config.BURST_CONNECTION_THRESHOLD})'
print(f'  2 connections below threshold of {config.BURST_CONNECTION_THRESHOLD} — no detection  PASS')


# -------------------------------------------------------
# Test 47: Rule 11 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 47: Rule 11 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.BURST_CONNECTION_THRESHOLD):
    _net(f'r11_dup_{i}', actor='beacon.exe',
         process_path=os.path.join(_appdata_temp, 'beacon.exe'),
         trust_level='HIGH_RISK', base_severity='CRITICAL',
         destination=f'40.0.0.{i + 1}', observed_at=f'2026-03-20 09:0{i}:00')

correlator._rule_11(reference_time=_R11_REF)
correlator._rule_11(reference_time=_R11_REF)   # second call — same data
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 1 tests — Data Exfiltration Suspected
# Fresh DB for each test.
# Condition: non-System RESOURCE event + NETWORK from same actor
#            within RESOURCE_EXFIL_WINDOW (5 min / 300s).
# ============================================================

_R1_RES_TIME  = '2026-03-20 10:00:00'
_R1_NET_NEAR  = '2026-03-20 10:04:00'   # 4 min after — inside 5 min window
_R1_NET_FAR   = '2026-03-20 10:06:01'   # 6 min after — outside 5 min window
_R1_REF       = _dt(2026, 3, 20, 10, 9, 0)   # cutoff 09:59 → all inside SHORT_WINDOW


def _res(event_id, actor, trust_level, base_severity, subtype='CPU',
         observed_at=_R1_RES_TIME):
    _insert_event(
        event_id=event_id, event_type='RESOURCE', subtype=subtype,
        actor=actor, process_path=None, destination=None,
        base_severity=base_severity, trust_level=trust_level,
        collector='steward', observed_at=observed_at,
    )


# -------------------------------------------------------
# Test 48: Rule 1 fires — per-process CPU spike + same actor non-TRUSTED NETWORK
# -------------------------------------------------------
print('Test 48: Rule 1 fires on CPU spike + same actor non-TRUSTED NETWORK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_res('r1_res', actor='stager.exe', trust_level='UNKNOWN', base_severity='CRITICAL')
_net('r1_net', actor='stager',
     process_path=r'C:\SomeFolder\stager.exe',
     trust_level='UNKNOWN', base_severity='UNKNOWN',
     destination='198.51.100.1', observed_at=_R1_NET_NEAR)

correlator._rule_1(reference_time=_R1_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det1 = conn.execute("SELECT * FROM detections WHERE rule_id=1").fetchall()
alt1 = conn.execute("SELECT * FROM alerts    WHERE rule_id=1").fetchall()
conn.close()
assert len(det1) == 1, f'Expected 1 detection, got {len(det1)}'
assert len(alt1) == 1, f'Expected 1 alert, got {len(alt1)}'
assert alt1[0]['severity_current'] == 'SUSPICIOUS'
assert 'stager' in alt1[0]['explanation']
assert '198.51.100.1' in alt1[0]['explanation']
print('  SUSPICIOUS alert, actor and destination in explanation  PASS')


# -------------------------------------------------------
# Test 49: Rule 1 no-fire — System actor excluded
# -------------------------------------------------------
print('Test 49: Rule 1 ignores System CPU spike (kernel process excluded)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_res('r1_sys_res', actor='System', trust_level='UNKNOWN', base_severity='CRITICAL')
_net('r1_sys_net', actor='svchost',
     process_path=r'C:\Windows\System32\svchost.exe',
     trust_level='TRUSTED', base_severity='OK',
     destination='13.107.4.50', observed_at=_R1_NET_NEAR)

correlator._rule_1(reference_time=_R1_REF)
assert db.count_detections() == 0, \
    f'Expected no detection for System actor, got {db.count_detections()}'
print('  System actor correctly excluded — no detection  PASS')


# -------------------------------------------------------
# Test 50: Rule 1 — TRUSTED network → detection only, no alert
# -------------------------------------------------------
print('Test 50: Rule 1 detection-only when network event is TRUSTED...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_res('r1_tr_res', actor='chrome', trust_level='UNKNOWN', base_severity='SUSPICIOUS')
_net('r1_tr_net', actor='chrome',
     process_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
     trust_level='TRUSTED', base_severity='OK',
     destination='142.250.185.46', observed_at=_R1_NET_NEAR)

alerts_before = db.count_alerts()
correlator._rule_1(reference_time=_R1_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det1t = conn.execute("SELECT * FROM detections WHERE rule_id=1").fetchall()
conn.close()
assert db.count_alerts() == alerts_before, \
    f'Expected no alert for TRUSTED network, got {db.count_alerts() - alerts_before} new'
assert len(det1t) == 1, f'Expected 1 detection, got {len(det1t)}'
print('  detection logged, no alert for TRUSTED network (baseline period)  PASS')


# -------------------------------------------------------
# Test 51: Rule 1 no-fire — actor mismatch between resource and network
# -------------------------------------------------------
print('Test 51: Rule 1 ignores resource + network when actors differ...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_res('r1_mis_res', actor='python.exe', trust_level='UNKNOWN', base_severity='CRITICAL')
_net('r1_mis_net', actor='chrome',
     process_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
     trust_level='TRUSTED', base_severity='OK',
     destination='142.250.185.46', observed_at=_R1_NET_NEAR)

correlator._rule_1(reference_time=_R1_REF)
assert db.count_detections() == 0, \
    f'Expected no detection (actor mismatch), got {db.count_detections()}'
print('  actor mismatch (python.exe vs chrome) correctly excluded  PASS')


# -------------------------------------------------------
# Test 52: Rule 1 no-fire — network event outside 5 min pairing window
# -------------------------------------------------------
print('Test 52: Rule 1 ignores network event outside 5-min pairing window...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_res('r1_far_res', actor='stager.exe', trust_level='UNKNOWN', base_severity='CRITICAL')
_net('r1_far_net', actor='stager',
     process_path=r'C:\SomeFolder\stager.exe',
     trust_level='UNKNOWN', base_severity='UNKNOWN',
     destination='198.51.100.1', observed_at=_R1_NET_FAR)   # 6 min — over limit

correlator._rule_1(reference_time=_R1_REF)
assert db.count_detections() == 0, \
    f'Expected no detection (6 min > 5 min window), got {db.count_detections()}'
print(f'  network at +6 min outside {config.RESOURCE_EXFIL_WINDOW//60}-min pairing window — no detection  PASS')


# -------------------------------------------------------
# Test 53: Rule 1 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 53: Rule 1 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_res('r1_dup_res', actor='exfil.exe', trust_level='HIGH_RISK', base_severity='CRITICAL')
_net('r1_dup_net', actor='exfil',
     process_path=os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp', 'exfil.exe'),
     trust_level='HIGH_RISK', base_severity='CRITICAL',
     destination='203.0.113.5', observed_at=_R1_NET_NEAR)

correlator._rule_1(reference_time=_R1_REF)
correlator._rule_1(reference_time=_R1_REF)
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 5 tests — Data Staging Suspected
# Fresh DB for each test.
# Condition: PORT_OPEN event from non-TRUSTED process in SHORT_WINDOW.
# Zero-trust policy: HIGH_RISK + UNKNOWN → SUSPICIOUS alert;
#                    TRUSTED → detection only.
# ============================================================

_R5_REF = _dt(2026, 3, 20, 11, 9, 0)   # cutoff 10:59


def _port_open(event_id, actor, process_path, trust_level, base_severity,
               port='52518', observed_at='2026-03-20 11:00:00'):
    _insert_event(
        event_id=event_id, event_type='PORT', subtype='PORT_OPEN',
        actor=actor, process_path=process_path, destination=port,
        base_severity=base_severity, trust_level=trust_level,
        collector='bulwark', observed_at=observed_at,
    )


# -------------------------------------------------------
# Test 54: Rule 5 fires — HIGH_RISK process opens port → SUSPICIOUS alert
# -------------------------------------------------------
print('Test 54: Rule 5 fires on HIGH_RISK process opening a port...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_port_open('r5_hr', actor='Agent',
           process_path=r'C:\ProgramData\Evil\Agent.exe',
           trust_level='HIGH_RISK', base_severity='SUSPICIOUS')

correlator._rule_5(reference_time=_R5_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det5 = conn.execute("SELECT * FROM detections WHERE rule_id=5").fetchall()
alt5 = conn.execute("SELECT * FROM alerts    WHERE rule_id=5").fetchall()
conn.close()
assert len(det5) == 1, f'Expected 1 detection, got {len(det5)}'
assert len(alt5) == 1, f'Expected 1 alert, got {len(alt5)}'
assert alt5[0]['severity_current'] == 'SUSPICIOUS'
assert 'Agent' in alt5[0]['explanation']
assert '52518' in alt5[0]['explanation']
print('  SUSPICIOUS alert, actor and port in explanation  PASS')


# -------------------------------------------------------
# Test 55: Rule 5 fires — UNKNOWN process opens port → SUSPICIOUS alert
# -------------------------------------------------------
print('Test 55: Rule 5 fires on UNKNOWN process opening a port...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_port_open('r5_unk', actor='mystery',
           process_path=None,
           trust_level='UNKNOWN', base_severity='UNKNOWN', port='44444')

correlator._rule_5(reference_time=_R5_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt5u = conn.execute("SELECT * FROM alerts WHERE rule_id=5").fetchall()
conn.close()
assert len(alt5u) == 1, f'Expected 1 alert for UNKNOWN, got {len(alt5u)}'
assert alt5u[0]['severity_current'] == 'SUSPICIOUS'
print('  UNKNOWN process opening port fires SUSPICIOUS alert (zero-trust)  PASS')


# -------------------------------------------------------
# Test 56: Rule 5 — TRUSTED process opens port → detection only, no alert
# -------------------------------------------------------
print('Test 56: Rule 5 detection-only for TRUSTED process port open...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_port_open('r5_tr', actor='svchost',
           process_path=r'C:\Windows\System32\svchost.exe',
           trust_level='TRUSTED', base_severity='OK', port='7680')

alerts_before = db.count_alerts()
correlator._rule_5(reference_time=_R5_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det5t = conn.execute("SELECT * FROM detections WHERE rule_id=5").fetchall()
conn.close()
assert db.count_alerts() == alerts_before, \
    f'Expected no alert for TRUSTED process, got {db.count_alerts() - alerts_before} new'
assert len(det5t) == 1, f'Expected 1 detection, got {len(det5t)}'
print('  detection logged, no alert for TRUSTED process (baseline period)  PASS')


# -------------------------------------------------------
# Test 57: Rule 5 no-fire — PORT_CLOSE event (not PORT_OPEN)
# -------------------------------------------------------
print('Test 57: Rule 5 ignores PORT_CLOSE events...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r5_close', event_type='PORT', subtype='PORT_CLOSE',
    actor='Agent', process_path=r'C:\ProgramData\Evil\Agent.exe',
    destination='52518', base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
    collector='bulwark', observed_at='2026-03-20 11:00:00',
)
correlator._rule_5(reference_time=_R5_REF)
assert db.count_detections() == 0, \
    f'Expected no detection for PORT_CLOSE, got {db.count_detections()}'
print('  PORT_CLOSE event correctly ignored (only PORT_OPEN triggers Rule 5)  PASS')


# -------------------------------------------------------
# Test 58: Rule 5 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 58: Rule 5 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_port_open('r5_dup', actor='stager',
           process_path=r'C:\Users\Public\stager.exe',
           trust_level='HIGH_RISK', base_severity='CRITICAL', port='9999')

correlator._rule_5(reference_time=_R5_REF)
correlator._rule_5(reference_time=_R5_REF)
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 22 tests — Cloud API Anomaly
# Fresh DB for each test.
# Condition: NETWORK event + after-hours + actor NOT in KNOWN_SYNC_CLIENTS
#            + non-TRUSTED trust level.
# After-hours window: AFTER_HOURS_START (00:00) to AFTER_HOURS_END (06:00).
# ============================================================

_R22_AFTER  = '2026-03-20 02:30:00'   # 02:30 — inside after-hours window
_R22_DAY    = '2026-03-20 14:00:00'   # 14:00 — daytime
_R22_REF_A  = _dt(2026, 3, 20,  2, 39, 0)   # cutoff 02:29 → after-hours event inside
_R22_REF_D  = _dt(2026, 3, 20, 14,  9, 0)   # cutoff 13:59 → daytime event inside


# -------------------------------------------------------
# Test 59: Rule 22 fires — after-hours, HIGH_RISK, not in sync whitelist
# -------------------------------------------------------
print('Test 59: Rule 22 fires on after-hours HIGH_RISK non-sync-client...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r22_hr', event_type='NETWORK', subtype='OUTBOUND',
    actor='malware.exe',
    process_path=os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'malware.exe'),
    destination='40.82.116.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R22_AFTER,
)
correlator._rule_22(reference_time=_R22_REF_A)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
det22 = conn.execute("SELECT * FROM detections WHERE rule_id=22").fetchall()
alt22 = conn.execute("SELECT * FROM alerts    WHERE rule_id=22").fetchall()
conn.close()
assert len(det22) == 1, f'Expected 1 detection, got {len(det22)}'
assert len(alt22) == 1, f'Expected 1 alert, got {len(alt22)}'
assert alt22[0]['severity_current'] == 'SUSPICIOUS'
assert 'malware' in alt22[0]['explanation']
assert '02:30' in alt22[0]['explanation'] or '02:' in alt22[0]['explanation']
print('  SUSPICIOUS alert, actor and after-hours time in explanation  PASS')


# -------------------------------------------------------
# Test 60: Rule 22 fires — after-hours, UNKNOWN actor, not in sync whitelist
# -------------------------------------------------------
print('Test 60: Rule 22 fires on after-hours UNKNOWN non-sync-client...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r22_unk', event_type='NETWORK', subtype='OUTBOUND',
    actor='mystery',
    process_path=r'C:\SomeFolder\mystery.exe',
    destination='52.96.1.1',
    base_severity='UNKNOWN', trust_level='UNKNOWN',
    collector='sentinel', observed_at=_R22_AFTER,
)
correlator._rule_22(reference_time=_R22_REF_A)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt22u = conn.execute("SELECT * FROM alerts WHERE rule_id=22").fetchall()
conn.close()
assert len(alt22u) == 1, f'Expected 1 alert for UNKNOWN, got {len(alt22u)}'
assert alt22u[0]['severity_current'] == 'SUSPICIOUS'
print('  UNKNOWN after-hours non-sync-client fires SUSPICIOUS alert (zero-trust)  PASS')


# -------------------------------------------------------
# Test 61: Rule 22 no-fire — actor is in KNOWN_SYNC_CLIENTS whitelist
# -------------------------------------------------------
print('Test 61: Rule 22 ignores known sync client (onedrive)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r22_sync', event_type='NETWORK', subtype='OUTBOUND',
    actor='onedrive',
    process_path=r'C:\Users\Schüler\AppData\Local\Microsoft\OneDrive\OneDrive.exe',
    destination='13.107.42.14',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R22_AFTER,
)
correlator._rule_22(reference_time=_R22_REF_A)
assert db.count_detections() == 0, \
    f'Expected no detection for known sync client, got {db.count_detections()}'
print('  onedrive in KNOWN_SYNC_CLIENTS — correctly excluded  PASS')


# -------------------------------------------------------
# Test 62: Rule 22 no-fire — daytime connection (not after-hours)
# -------------------------------------------------------
print('Test 62: Rule 22 ignores daytime connections...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r22_day', event_type='NETWORK', subtype='OUTBOUND',
    actor='malware.exe',
    process_path=os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'malware.exe'),
    destination='40.82.116.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R22_DAY,
)
correlator._rule_22(reference_time=_R22_REF_D)
assert db.count_detections() == 0, \
    f'Expected no detection for daytime connection, got {db.count_detections()}'
print('  14:00 connection outside after-hours window correctly excluded  PASS')


# -------------------------------------------------------
# Test 63: Rule 22 deduplication — two calls produce 1 alert
# -------------------------------------------------------
print('Test 63: Rule 22 deduplication — repeated evaluation produces 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r22_dup', event_type='NETWORK', subtype='OUTBOUND',
    actor='exfiltool',
    process_path=os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'exfiltool.exe'),
    destination='20.150.1.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_R22_AFTER,
)
correlator._rule_22(reference_time=_R22_REF_A)
correlator._rule_22(reference_time=_R22_REF_A)
assert db.count_alerts() == 1, f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 18 tests — Correlation Engine Health
# Fresh DB for each test.
#
# Part A — Collector silence:
#   collector_health row with last_seen > COLLECTOR_SILENCE_THRESHOLD ago → alert.
# Part B — Alert flood:
#   >= ENGINE_FLOOD_THRESHOLD alerts in last 60s → ENGINE_FLOOD_DETECTED.
# ============================================================

_R18_NOW   = _dt(2026, 3, 20, 14, 0, 0)    # reference time for all Rule 18 tests
_R18_STALE = '2026-03-20 13:00:00'          # 60 min ago — beyond 30-min threshold
_R18_FRESH = '2026-03-20 13:45:00'          # 15 min ago — within 30-min threshold
_R18_FLOOD_TS = '2026-03-20 13:59:30'       # 30s before reference — inside 60s window


def _insert_collector_health(collector_name, last_seen, status='ACTIVE'):
    conn = sqlite3.connect('hocsoc.db')
    conn.execute("""
        INSERT OR REPLACE INTO collector_health
            (collector_name, last_seen, last_file_offset, last_event_count, status)
        VALUES (?, ?, 0, 0, ?)
    """, (collector_name, last_seen, status))
    conn.commit()
    conn.close()


def _insert_raw_alert(alert_id, created_at, rule_id=99):
    """Insert a minimal alert row directly for flood testing."""
    conn = sqlite3.connect('hocsoc.db')
    conn.execute("""
        INSERT OR IGNORE INTO alerts
            (alert_id, rule_id, severity_current, confidence, status,
             explanation, created_at, updated_at)
        VALUES (?, ?, 'SUSPICIOUS', 0.5, 'NEW', 'test flood alert', ?, ?)
    """, (alert_id, rule_id, created_at, created_at))
    conn.commit()
    conn.close()


# -------------------------------------------------------
# Test 64: Rule 18 Part A fires — collector silent > threshold
# -------------------------------------------------------
print('Test 64: Rule 18 fires on collector silent beyond threshold...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_collector_health('sentinel', _R18_STALE)
correlator._rule_18(reference_time=_R18_NOW)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt18a = conn.execute("SELECT * FROM alerts WHERE rule_id=18").fetchall()
conn.close()
assert len(alt18a) == 1, f'Expected 1 alert, got {len(alt18a)}'
assert alt18a[0]['severity_current'] == 'SUSPICIOUS'
assert 'sentinel' in alt18a[0]['explanation']
assert 'silence' in alt18a[0]['explanation'].lower() or 'silent' in alt18a[0]['explanation'].lower()
print('  SUSPICIOUS alert fired, collector name and silence in explanation  PASS')


# -------------------------------------------------------
# Test 65: Rule 18 Part A no-fire — collector seen recently
# -------------------------------------------------------
print('Test 65: Rule 18 ignores collector seen within threshold...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_collector_health('sentinel', _R18_FRESH)
correlator._rule_18(reference_time=_R18_NOW)
assert db.count_alerts() == 0, \
    f'Expected no alert for fresh collector, got {db.count_alerts()}'
print('  collector seen 15 min ago (< 30 min threshold) — correctly silent  PASS')


# -------------------------------------------------------
# Test 66: Rule 18 no-fire — collector_health table is empty
# -------------------------------------------------------
print('Test 66: Rule 18 ignores empty collector_health table...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

correlator._rule_18(reference_time=_R18_NOW)
assert db.count_alerts() == 0, \
    f'Expected no alert with empty collector_health, got {db.count_alerts()}'
print('  empty collector_health table — no alert  PASS')


# -------------------------------------------------------
# Test 67: Rule 18 Part A deduplication — same collector, same hour → 1 alert
# -------------------------------------------------------
print('Test 67: Rule 18 silence deduplication - same collector same hour -> 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_collector_health('bulwark', _R18_STALE)
correlator._rule_18(reference_time=_R18_NOW)
correlator._rule_18(reference_time=_R18_NOW)
assert db.count_alerts() == 1, \
    f'Expected 1 alert after 2 calls (same hour bucket), got {db.count_alerts()}'
print('  1 alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')


# -------------------------------------------------------
# Test 68: Rule 18 Part B fires — N alerts in last 60s → ENGINE_FLOOD_DETECTED
# -------------------------------------------------------
print('Test 68: Rule 18 fires ENGINE_FLOOD_DETECTED on alert burst >= threshold...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.ENGINE_FLOOD_THRESHOLD):
    _insert_raw_alert(f'flood_alert_{i:04d}', _R18_FLOOD_TS)

correlator._rule_18(reference_time=_R18_NOW)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt18f = conn.execute("SELECT * FROM alerts WHERE rule_id=18").fetchall()
conn.close()
assert len(alt18f) == 1, f'Expected 1 ENGINE_FLOOD alert, got {len(alt18f)}'
assert 'FLOOD' in alt18f[0]['explanation'] or 'flood' in alt18f[0]['explanation'].lower()
assert str(config.ENGINE_FLOOD_THRESHOLD) in alt18f[0]['explanation']
print('  ENGINE_FLOOD_DETECTED alert fired, threshold in explanation  PASS')


# -------------------------------------------------------
# Test 69: Rule 18 Part B no-fire — N-1 alerts (below threshold)
# -------------------------------------------------------
print('Test 69: Rule 18 ignores alert burst below threshold...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.ENGINE_FLOOD_THRESHOLD - 1):
    _insert_raw_alert(f'sub_flood_{i:04d}', _R18_FLOOD_TS)

correlator._rule_18(reference_time=_R18_NOW)
conn = sqlite3.connect('hocsoc.db')
r18_flood_count = conn.execute(
    "SELECT COUNT(*) FROM alerts WHERE rule_id=18").fetchone()[0]
conn.close()
assert r18_flood_count == 0, \
    f'Expected no Rule 18 flood alert for {config.ENGINE_FLOOD_THRESHOLD - 1} alerts (< threshold {config.ENGINE_FLOOD_THRESHOLD}), got {r18_flood_count}'
print(f'  {config.ENGINE_FLOOD_THRESHOLD - 1} alerts below threshold {config.ENGINE_FLOOD_THRESHOLD} — no flood alert  PASS')


# -------------------------------------------------------
# Test 70: Rule 18 Part B deduplication — same minute bucket → 1 flood alert
# -------------------------------------------------------
print('Test 70: Rule 18 flood deduplication - same minute bucket -> 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.ENGINE_FLOOD_THRESHOLD):
    _insert_raw_alert(f'dup_flood_{i:04d}', _R18_FLOOD_TS)

correlator._rule_18(reference_time=_R18_NOW)
correlator._rule_18(reference_time=_R18_NOW)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
flood_alerts = conn.execute("SELECT * FROM alerts WHERE rule_id=18").fetchall()
conn.close()
assert len(flood_alerts) == 1, \
    f'Expected 1 flood alert after 2 calls (same minute), got {len(flood_alerts)}'
print('  1 flood alert after 2 rule evaluations on same data (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 18 Part C tests — Integrity chain verification
# Fresh DB for each test.
#
# Condition: normalized_event_id in raw_events != recomputed
#            SHA256(collector_name + ":" + raw_event_hash)[:32]
# ============================================================

def _insert_raw_event_chain(raw_event_hash, collector_name, normalized_event_id):
    """Insert a raw_events row with an explicit normalized_event_id for
    integrity chain testing."""
    conn = sqlite3.connect('hocsoc.db')
    conn.execute("""
        INSERT OR IGNORE INTO raw_events
            (collector_name, raw_payload, observed_at, recorded_at,
             source_host, raw_event_hash, normalized_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (collector_name, 'test raw payload', '2026-03-20 10:00:00',
          '2026-03-20 10:00:00', 'TEST-HOST', raw_event_hash, normalized_event_id))
    conn.commit()
    conn.close()


# Pre-compute a correct normalized_event_id for test use
_CHAIN_COLLECTOR  = 'sentinel'
_CHAIN_RAW_HASH   = 'a' * 64   # synthetic SHA256 hex
import hashlib as _hl
_CHAIN_CORRECT_NEID = _hl.sha256(
    (_CHAIN_COLLECTOR + ':' + _CHAIN_RAW_HASH).encode()
).hexdigest()[:32]
_CHAIN_TAMPERED_NEID = 'deadbeef' * 8   # deliberately wrong (32 chars)


# -------------------------------------------------------
# Test 71: Rule 18 Part C no-fire — correct chain passes
# -------------------------------------------------------
print('Test 71: Rule 18 integrity chain passes for correct normalized_event_id...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_raw_event_chain(_CHAIN_RAW_HASH, _CHAIN_COLLECTOR, _CHAIN_CORRECT_NEID)
correlator._rule_18(reference_time=_R18_NOW)
conn = sqlite3.connect('hocsoc.db')
chain_alerts = conn.execute(
    "SELECT * FROM alerts WHERE rule_id=18").fetchall()
conn.close()
assert len(chain_alerts) == 0, \
    f'Expected no alert for correct chain, got {len(chain_alerts)}'
print('  correct normalized_event_id — chain intact, no alert  PASS')


# -------------------------------------------------------
# Test 72: Rule 18 Part C fires — tampered normalized_event_id
# -------------------------------------------------------
print('Test 72: Rule 18 fires INTEGRITY_CHAIN_BROKEN on tampered normalized_event_id...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_raw_event_chain(_CHAIN_RAW_HASH, _CHAIN_COLLECTOR, _CHAIN_TAMPERED_NEID)
correlator._rule_18(reference_time=_R18_NOW)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
tamper_alerts = conn.execute(
    "SELECT * FROM alerts WHERE rule_id=18").fetchall()
conn.close()
assert len(tamper_alerts) == 1, \
    f'Expected 1 tamper alert, got {len(tamper_alerts)}'
assert tamper_alerts[0]['severity_current'] == 'SUSPICIOUS'
assert 'INTEGRITY' in tamper_alerts[0]['explanation'] or \
       'integrity' in tamper_alerts[0]['explanation'].lower()
assert _CHAIN_COLLECTOR in tamper_alerts[0]['explanation']
print('  SUSPICIOUS alert fired, INTEGRITY_CHAIN_BROKEN and collector in explanation  PASS')


# -------------------------------------------------------
# Test 73: Rule 18 Part C deduplication — same row, two calls → 1 alert
# -------------------------------------------------------
print('Test 73: Rule 18 integrity deduplication - same tampered row -> 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_raw_event_chain(_CHAIN_RAW_HASH, _CHAIN_COLLECTOR, _CHAIN_TAMPERED_NEID)
correlator._rule_18(reference_time=_R18_NOW)
correlator._rule_18(reference_time=_R18_NOW)
conn = sqlite3.connect('hocsoc.db')
dup_count = conn.execute(
    "SELECT COUNT(*) FROM alerts WHERE rule_id=18").fetchone()[0]
conn.close()
assert dup_count == 1, \
    f'Expected 1 alert after 2 calls (INSERT OR IGNORE), got {dup_count}'
print('  1 alert after 2 rule evaluations on same tampered row (INSERT OR IGNORE)  PASS')



# ============================================================
# Rule 8 tests — DoH Evasion Suspected
# Fresh DB for each test.
#
# Condition: event_type=NETWORK, subtype=DOH_CONNECTION
# base_severity=CRITICAL (not in whitelist) -> CRITICAL alert
# base_severity=UNKNOWN  (whitelisted proc) -> SUSPICIOUS alert
# ============================================================

# -------------------------------------------------------
# Test 74: Rule 8 fires CRITICAL on non-whitelisted DOH_CONNECTION
# -------------------------------------------------------
print('Test 74: Rule 8 fires CRITICAL on non-whitelisted DOH_CONNECTION...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r8_crit', event_type='NETWORK', subtype='DOH_CONNECTION',
    actor='malware',
    process_path=os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'malware.exe'),
    destination='8.8.8.8',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='doh_detector', observed_at='2026-03-20 10:00:00',
)
correlator.run_all()
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt8c = conn.execute("SELECT * FROM alerts WHERE rule_id=8").fetchall()
conn.close()
assert len(alt8c) == 1, f'Expected 1 alert, got {len(alt8c)}'
assert alt8c[0]['severity_current'] == 'CRITICAL'
assert 'DoH' in alt8c[0]['explanation'] or 'doh' in alt8c[0]['explanation'].lower()
assert '8.8.8.8' in alt8c[0]['explanation']
print('  CRITICAL alert, DoH and resolver in explanation  PASS')


# -------------------------------------------------------
# Test 75: Rule 8 fires SUSPICIOUS on whitelisted DOH_CONNECTION (UNKNOWN severity)
# -------------------------------------------------------
print('Test 75: Rule 8 fires SUSPICIOUS on whitelisted process DOH_CONNECTION...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r8_unk', event_type='NETWORK', subtype='DOH_CONNECTION',
    actor='chrome',
    process_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    destination='8.8.4.4',
    base_severity='UNKNOWN', trust_level='TRUSTED',
    collector='doh_detector', observed_at='2026-03-20 10:00:00',
)
correlator.run_all()
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
alt8u = conn.execute("SELECT * FROM alerts WHERE rule_id=8").fetchall()
conn.close()
assert len(alt8u) == 1, f'Expected 1 SUSPICIOUS alert, got {len(alt8u)}'
assert alt8u[0]['severity_current'] == 'SUSPICIOUS'
print('  SUSPICIOUS alert for whitelisted process (zero-trust baseline)  PASS')


# -------------------------------------------------------
# Test 76: Rule 8 no-fire — NETWORK event with wrong subtype
# -------------------------------------------------------
print('Test 76: Rule 8 ignores NETWORK event with subtype OUTBOUND...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r8_wrong_sub', event_type='NETWORK', subtype='OUTBOUND',
    actor='chrome',
    process_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    destination='8.8.8.8',
    base_severity='OK', trust_level='TRUSTED',
    collector='sentinel', observed_at='2026-03-20 10:00:00',
)
correlator.run_all()
_conn76 = sqlite3.connect('hocsoc.db')
r8_count = _conn76.execute(
    "SELECT COUNT(*) FROM alerts WHERE rule_id=8").fetchone()[0]
_conn76.close()
assert r8_count == 0, f'Expected no Rule 8 alert for OUTBOUND subtype, got {r8_count}'
print('  OUTBOUND subtype correctly ignored by Rule 8  PASS')


# -------------------------------------------------------
# Test 77: Rule 8 deduplication — same event, two run_all() calls -> 1 alert
# -------------------------------------------------------
print('Test 77: Rule 8 deduplication - same DOH event -> 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r8_dup', event_type='NETWORK', subtype='DOH_CONNECTION',
    actor='evil',
    process_path=os.path.join(os.path.expanduser('~'), 'Downloads', 'evil.exe'),
    destination='1.1.1.1',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='doh_detector', observed_at='2026-03-20 10:00:00',
)
correlator.run_all()
correlator.run_all()
assert db.count_alerts() == 1, \
    f'Expected 1 alert after 2 run_all() calls, got {db.count_alerts()}'
print('  1 alert after 2 run_all() calls (INSERT OR IGNORE)  PASS')



# -------------------------------------------------------
# Test 78: Rule 19 fires CRITICAL on FIM_VIOLATION
# -------------------------------------------------------
print('Test 78: Rule 19 fires CRITICAL on FIM_VIOLATION...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r19_fim', event_type='INTEGRITY', subtype='FIM_VIOLATION',
    actor='Sentinel.ps1 [Collectors] | Hash mismatch',
    process_path=None, destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='warden', observed_at='2026-03-24 09:00:01',
)
correlator.run_all()
_conn78 = sqlite3.connect('hocsoc.db')
_conn78.row_factory = sqlite3.Row
alts78 = _conn78.execute("SELECT * FROM alerts WHERE rule_id=19").fetchall()
_conn78.close()
assert len(alts78) == 1, f'Expected 1 Rule 19 alert, got {len(alts78)}'
assert alts78[0]['severity_current'] == 'CRITICAL'
assert '[Rule 19]' in alts78[0]['explanation']
assert 'FIM' in alts78[0]['explanation'] or 'hash' in alts78[0]['explanation'].lower()
print('  Rule 19 CRITICAL fired for FIM_VIOLATION  PASS')


# -------------------------------------------------------
# Test 79: Rule 19 fires CRITICAL on LOG_TAMPER
# -------------------------------------------------------
print('Test 79: Rule 19 fires CRITICAL on LOG_TAMPER...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r19_log', event_type='INTEGRITY', subtype='LOG_TAMPER',
    actor='Network_Watchdog_Log.txt | Was: 102400 bytes | Now: 512 bytes | Lost: 101888 bytes',
    process_path=None, destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='warden', observed_at='2026-03-24 09:01:05',
)
correlator.run_all()
_conn79 = sqlite3.connect('hocsoc.db')
_conn79.row_factory = sqlite3.Row
alts79 = _conn79.execute("SELECT * FROM alerts WHERE rule_id=19").fetchall()
_conn79.close()
assert len(alts79) == 1, f'Expected 1 Rule 19 alert, got {len(alts79)}'
assert alts79[0]['severity_current'] == 'CRITICAL'
assert 'tampered' in alts79[0]['explanation'].lower() or 'deleted' in alts79[0]['explanation'].lower()
print('  Rule 19 CRITICAL fired for LOG_TAMPER  PASS')


# -------------------------------------------------------
# Test 80: Rule 19 no-fire on COLLECTOR_DOWN and MANIFEST_MISSING
# (those subtypes are handled by Rule 18, not Rule 19)
# -------------------------------------------------------
print('Test 80: Rule 19 ignores COLLECTOR_DOWN and MANIFEST_MISSING...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r19_cd', event_type='INTEGRITY', subtype='COLLECTOR_DOWN',
    actor='Sentinel.ps1', process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='warden', observed_at='2026-03-24 09:02:10',
)
_insert_event(
    event_id='r19_mm', event_type='INTEGRITY', subtype='MANIFEST_MISSING',
    actor=None, process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='warden', observed_at='2026-03-24 09:03:00',
)
correlator.run_all()
_conn80 = sqlite3.connect('hocsoc.db')
_conn80.row_factory = sqlite3.Row
r19_count = _conn80.execute("SELECT COUNT(*) FROM alerts WHERE rule_id=19").fetchone()[0]
_conn80.close()
assert r19_count == 0, f'Expected no Rule 19 alert for COLLECTOR_DOWN/MANIFEST_MISSING, got {r19_count}'
print('  COLLECTOR_DOWN and MANIFEST_MISSING correctly ignored by Rule 19  PASS')


# -------------------------------------------------------
# Test 81: Rule 19 deduplication — same FIM event, two run_all() -> 1 alert
# -------------------------------------------------------
print('Test 81: Rule 19 deduplication - same FIM event -> 1 alert...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r19_dup', event_type='INTEGRITY', subtype='FIM_VIOLATION',
    actor='Warden.ps1 [self] | Hash mismatch',
    process_path=None, destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='warden', observed_at='2026-03-24 09:04:00',
)
correlator.run_all()
correlator.run_all()
assert db.count_alerts() == 1, \
    f'Expected 1 alert after 2 run_all() calls, got {db.count_alerts()}'
print('  1 alert after 2 run_all() calls (INSERT OR IGNORE)  PASS')



# -------------------------------------------------------
# Test 82: Rule 10 fires CRITICAL on ACCOUNT_CREATED
# -------------------------------------------------------
print('Test 82: Rule 10 fires CRITICAL on ACCOUNT_CREATED...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r10_created', event_type='ACCOUNT', subtype='ACCOUNT_CREATED',
    actor='backdoor', process_path=None, destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='seceventlog', observed_at='2026-03-24 10:00:00',
)
correlator.run_all()
_conn82 = sqlite3.connect('hocsoc.db')
_conn82.row_factory = sqlite3.Row
alts82 = _conn82.execute("SELECT * FROM alerts WHERE rule_id=10").fetchall()
_conn82.close()
assert len(alts82) == 1,                              f'Expected 1 alert, got {len(alts82)}'
assert alts82[0]['severity_current'] == 'CRITICAL',   f"severity={alts82[0]['severity_current']}"
assert '[Rule 10]' in alts82[0]['explanation']
assert 'backdoor' in alts82[0]['explanation']
print('  Rule 10 CRITICAL for ACCOUNT_CREATED  PASS')


# -------------------------------------------------------
# Test 83: Rule 10 fires SUSPICIOUS on ACCOUNT_ENABLED
# -------------------------------------------------------
print('Test 83: Rule 10 fires SUSPICIOUS on ACCOUNT_ENABLED...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r10_enabled', event_type='ACCOUNT', subtype='ACCOUNT_ENABLED',
    actor='Guest', process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='seceventlog', observed_at='2026-03-24 10:01:00',
)
correlator.run_all()
_conn83 = sqlite3.connect('hocsoc.db')
_conn83.row_factory = sqlite3.Row
alts83 = _conn83.execute("SELECT * FROM alerts WHERE rule_id=10").fetchall()
_conn83.close()
assert len(alts83) == 1,                                f'Expected 1 alert, got {len(alts83)}'
assert alts83[0]['severity_current'] == 'SUSPICIOUS',   f"severity={alts83[0]['severity_current']}"
print('  Rule 10 SUSPICIOUS for ACCOUNT_ENABLED  PASS')


# -------------------------------------------------------
# Test 84: Rule 10 no-fire on AUTH event (wrong event_type)
# -------------------------------------------------------
print('Test 84: Rule 10 ignores AUTH events...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r10_auth', event_type='AUTH', subtype='LOGON_SUCCESS',
    actor='johndoe', process_path=None, destination=None,
    base_severity='OK', trust_level='UNKNOWN',
    collector='seceventlog', observed_at='2026-03-24 10:02:00',
)
correlator.run_all()
_conn84 = sqlite3.connect('hocsoc.db')
r10_count = _conn84.execute(
    "SELECT COUNT(*) FROM alerts WHERE rule_id=10").fetchone()[0]
_conn84.close()
assert r10_count == 0, f'Expected no alert for AUTH event, got {r10_count}'
print('  AUTH events correctly ignored by Rule 10  PASS')


# -------------------------------------------------------
# Test 85: Rule 10 deduplication — same ACCOUNT event, two run_all() -> 1 alert
# -------------------------------------------------------
print('Test 85: Rule 10 deduplication...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r10_dup', event_type='ACCOUNT', subtype='ACCOUNT_DELETED',
    actor='victim', process_path=None, destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='seceventlog', observed_at='2026-03-24 10:03:00',
)
correlator.run_all()
correlator.run_all()
assert db.count_alerts() == 1, \
    f'Expected 1 alert after 2 run_all() calls, got {db.count_alerts()}'
print('  1 alert after 2 run_all() calls (INSERT OR IGNORE)  PASS')


# -------------------------------------------------------
# Test 86: Rule 17 fires CRITICAL on ACCOUNT_CREATED + REGISTRY in window
# reference_time = event_time + 1 min so events fall inside the 10-min window.
# -------------------------------------------------------
print('Test 86: Rule 17 fires on ACCOUNT_CREATED + REGISTRY in same window...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

from datetime import datetime as _dt17, timedelta as _td17
_r17_evt_time = '2026-03-24 10:00:00'
_r17_ref      = _dt17(2026, 3, 24, 10, 1, 0)   # 1 min after events → window covers 09:51-10:01

_insert_event(
    event_id='r17_acct', event_type='ACCOUNT', subtype='ACCOUNT_CREATED',
    actor='backdoor', process_path=None, destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='seceventlog', observed_at=_r17_evt_time,
)
_insert_event(
    event_id='r17_reg', event_type='REGISTRY', subtype='NEW VALUE',
    actor=r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts',
    process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='registry_warden', observed_at=_r17_evt_time,
)
correlator._rule_17(reference_time=_r17_ref)
_conn86 = sqlite3.connect('hocsoc.db')
_conn86.row_factory = sqlite3.Row
alts86 = _conn86.execute("SELECT * FROM alerts WHERE rule_id=17").fetchall()
_conn86.close()
assert len(alts86) == 1,                              f'Expected 1 Rule 17 alert, got {len(alts86)}'
assert alts86[0]['severity_current'] == 'CRITICAL',   f"severity={alts86[0]['severity_current']}"
assert '[Rule 17]' in alts86[0]['explanation']
print('  Rule 17 CRITICAL: ACCOUNT_CREATED + REGISTRY in window  PASS')


# -------------------------------------------------------
# Test 87: Rule 17 no-fire — ACCOUNT_CREATED alone (no Registry event)
# -------------------------------------------------------
print('Test 87: Rule 17 no-fire when REGISTRY event absent...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r17_solo', event_type='ACCOUNT', subtype='ACCOUNT_CREATED',
    actor='backdoor', process_path=None, destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='seceventlog', observed_at='2026-03-24 10:00:00',
)
correlator._rule_17(reference_time=_r17_ref)
_conn87 = sqlite3.connect('hocsoc.db')
r17_count = _conn87.execute(
    "SELECT COUNT(*) FROM alerts WHERE rule_id=17").fetchone()[0]
_conn87.close()
assert r17_count == 0, f'Expected no Rule 17 alert without Registry event, got {r17_count}'
print('  No Rule 17 alert when Registry event is absent  PASS')


# -------------------------------------------------------
# Test 88: Rule 17 no-fire — REGISTRY alone (no ACCOUNT_CREATED/ENABLED)
# -------------------------------------------------------
print('Test 88: Rule 17 no-fire when ACCOUNT event absent...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r17_regonly', event_type='REGISTRY', subtype='MODIFIED VALUE',
    actor=r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Update',
    process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='registry_warden', observed_at='2026-03-24 10:00:00',
)
correlator._rule_17(reference_time=_r17_ref)
_conn88 = sqlite3.connect('hocsoc.db')
r17_count2 = _conn88.execute(
    "SELECT COUNT(*) FROM alerts WHERE rule_id=17").fetchone()[0]
_conn88.close()
assert r17_count2 == 0, f'Expected no Rule 17 alert without ACCOUNT event, got {r17_count2}'
print('  No Rule 17 alert when ACCOUNT event is absent  PASS')


# -------------------------------------------------------
# Test 89: Rule 17 deduplication — same pair, two calls -> 1 alert
# -------------------------------------------------------
print('Test 89: Rule 17 deduplication...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r17_dup_a', event_type='ACCOUNT', subtype='ACCOUNT_ENABLED',
    actor='Guest', process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='seceventlog', observed_at='2026-03-24 10:00:00',
)
_insert_event(
    event_id='r17_dup_r', event_type='REGISTRY', subtype='NEW VALUE',
    actor=r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil',
    process_path=None, destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='registry_warden', observed_at='2026-03-24 10:00:00',
)
correlator._rule_17(reference_time=_r17_ref)
correlator._rule_17(reference_time=_r17_ref)
assert db.count_alerts() == 1, \
    f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 calls (INSERT OR IGNORE)  PASS')


_r2_event_time = '2026-03-25 10:00:00'
_r2_ref        = datetime(2026, 3, 25, 11, 0, 0)   # 1 hour after events — within OPERATIONAL_WINDOW


# -------------------------------------------------------
# Test 90: Rule 2 fires with >= C2_BEACON_MIN_SESSIONS CONNECTION_END sessions
# -------------------------------------------------------
print(f'Test 90: Rule 2 — beacon fires with {config.C2_BEACON_MIN_SESSIONS} sessions...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.C2_BEACON_MIN_SESSIONS):
    _insert_event(
        event_id=f'r2_sess_{i}', event_type='NETWORK', subtype='CONNECTION_END',
        actor='malware.exe', process_path=r'C:\Users\Public\malware.exe',
        destination='10.10.10.10',
        base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
        collector='bulwark', observed_at=_r2_event_time,
    )

correlator._rule_2(reference_time=_r2_ref)
_conn90 = sqlite3.connect('hocsoc.db')
_conn90.row_factory = sqlite3.Row
_r2_alerts = _conn90.execute("SELECT * FROM alerts WHERE rule_id=2").fetchall()
_conn90.close()
assert len(_r2_alerts) == 1, f'Expected 1 alert, got {len(_r2_alerts)}'
assert _r2_alerts[0]['severity_current'] == 'SUSPICIOUS'
assert 'C2 Beacon' in _r2_alerts[0]['explanation']
assert '10.10.10.10' in _r2_alerts[0]['explanation']
print('  1 SUSPICIOUS alert, explanation contains destination  PASS')


# -------------------------------------------------------
# Test 91: Rule 2 no-fire below threshold (C2_BEACON_MIN_SESSIONS - 1 sessions)
# -------------------------------------------------------
print(f'Test 91: Rule 2 — no alert below threshold ({config.C2_BEACON_MIN_SESSIONS - 1} sessions)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.C2_BEACON_MIN_SESSIONS - 1):
    _insert_event(
        event_id=f'r2_low_{i}', event_type='NETWORK', subtype='CONNECTION_END',
        actor='malware.exe', process_path=r'C:\Users\Public\malware.exe',
        destination='10.10.10.10',
        base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
        collector='bulwark', observed_at=_r2_event_time,
    )

correlator._rule_2(reference_time=_r2_ref)
assert db.count_alerts() == 0, f'Expected 0 alerts below threshold, got {db.count_alerts()}'
print(f'  0 alerts with {config.C2_BEACON_MIN_SESSIONS - 1} sessions (below threshold of {config.C2_BEACON_MIN_SESSIONS})  PASS')


# -------------------------------------------------------
# Test 92: Rule 2 Sentinel confirmation raises confidence
# -------------------------------------------------------
print('Test 92: Rule 2 — Sentinel confirmation boosts confidence...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.C2_BEACON_MIN_SESSIONS):
    _insert_event(
        event_id=f'r2_conf_{i}', event_type='NETWORK', subtype='CONNECTION_END',
        actor='malware.exe', process_path=r'C:\Users\Public\malware.exe',
        destination='10.10.10.10',
        base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
        collector='bulwark', observed_at=_r2_event_time,
    )

# Sentinel confirms same destination
_insert_event(
    event_id='r2_sentinel', event_type='NETWORK', subtype='OUTBOUND',
    actor='malware.exe', process_path=r'C:\Users\Public\malware.exe',
    destination='10.10.10.10',
    base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
    collector='sentinel', observed_at=_r2_event_time,
)

correlator._rule_2(reference_time=_r2_ref)
_conn92 = sqlite3.connect('hocsoc.db')
_conn92.row_factory = sqlite3.Row
_r2_conf_alerts = _conn92.execute("SELECT confidence FROM alerts WHERE rule_id=2").fetchall()
_conn92.close()
assert len(_r2_conf_alerts) == 1
_expected_conf = round(config.RULE_WEIGHTS[2], 10)
assert round(_r2_conf_alerts[0]['confidence'], 10) == _expected_conf, \
    f"Expected full weight {_expected_conf}, got {_r2_conf_alerts[0]['confidence']}"
print(f'  Sentinel confirmed — confidence={_r2_conf_alerts[0]["confidence"]:.0%} (full weight)  PASS')


# -------------------------------------------------------
# Test 93: Rule 2 deduplication — same pair, two calls -> 1 alert
# -------------------------------------------------------
print('Test 93: Rule 2 deduplication...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

for i in range(config.C2_BEACON_MIN_SESSIONS):
    _insert_event(
        event_id=f'r2_dup_{i}', event_type='NETWORK', subtype='CONNECTION_END',
        actor='malware.exe', process_path=r'C:\Users\Public\malware.exe',
        destination='10.10.10.10',
        base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
        collector='bulwark', observed_at=_r2_event_time,
    )

correlator._rule_2(reference_time=_r2_ref)
correlator._rule_2(reference_time=_r2_ref)
assert db.count_alerts() == 1, \
    f'Expected 1 alert after 2 calls, got {db.count_alerts()}'
print('  1 alert after 2 calls (INSERT OR IGNORE)  PASS')




# ============================================================
# SYSMON RULES 28–39  (Tests 94–117)
# ============================================================

# -------------------------------------------------------
# Test 94: Rule 28 — fires on BROWSER_DEBUGGER
# -------------------------------------------------------
print('Test 94: Rule 28 fires on PROCESS_ACCESS/BROWSER_DEBUGGER...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r28_fire', event_type='PROCESS_ACCESS', subtype='BROWSER_DEBUGGER',
    actor='unknown_tool.exe', process_path=r'C:\Users\Public\unknown_tool.exe',
    destination='chrome.exe',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c94 = sqlite3.connect('hocsoc.db')
_c94.row_factory = sqlite3.Row
_d94 = _c94.execute("SELECT * FROM detections WHERE rule_id=28").fetchall()
_a94 = _c94.execute("SELECT * FROM alerts WHERE rule_id=28").fetchall()
_c94.close()
assert len(_d94) == 1, f'Expected 1 detection, got {len(_d94)}'
assert len(_a94) == 1, f'Expected 1 alert, got {len(_a94)}'
assert _a94[0]['severity_current'] == 'CRITICAL'
assert 'chrome.exe' in _a94[0]['explanation']
print('  detection + CRITICAL alert, explanation contains target  PASS')


# -------------------------------------------------------
# Test 95: Rule 28 — no-fire on BROWSER_MONITOR (OK severity, different subtype)
# -------------------------------------------------------
print('Test 95: Rule 28 no-fire on BROWSER_MONITOR...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r28_nofire', event_type='PROCESS_ACCESS', subtype='BROWSER_MONITOR',
    actor='svchost.exe', process_path=r'C:\Windows\System32\svchost.exe',
    destination='chrome.exe',
    base_severity='OK', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for BROWSER_MONITOR (system monitoring, OK severity)  PASS')


# -------------------------------------------------------
# Test 96: Rule 29 — fires on HIGH_RISK_LAUNCH
# -------------------------------------------------------
print('Test 96: Rule 29 fires on PROCESS/HIGH_RISK_LAUNCH...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r29_fire', event_type='PROCESS', subtype='HIGH_RISK_LAUNCH',
    actor='payload.exe', process_path=r'C:\Users\Schüler\Downloads\payload.exe',
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c96 = sqlite3.connect('hocsoc.db')
_c96.row_factory = sqlite3.Row
_a96 = _c96.execute("SELECT * FROM alerts WHERE rule_id=29").fetchall()
_c96.close()
assert len(_a96) == 1, f'Expected 1 alert, got {len(_a96)}'
assert _a96[0]['severity_current'] == 'CRITICAL'
assert 'Downloads' in _a96[0]['explanation']
print('  CRITICAL alert, explanation contains path  PASS')


# -------------------------------------------------------
# Test 97: Rule 29 — no-fire on OK severity (whitelisted/baselined process)
# -------------------------------------------------------
print('Test 97: Rule 29 no-fire on PROCESS/HIGH_RISK_LAUNCH with OK severity...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r29_nofire', event_type='PROCESS', subtype='HIGH_RISK_LAUNCH',
    actor='installer.exe', process_path=r'C:\Users\Schüler\Downloads\installer.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for OK severity high-risk path  PASS')


# -------------------------------------------------------
# Test 98: Rule 30 — fires on AMSI_TAMPER
# -------------------------------------------------------
print('Test 98: Rule 30 fires on REGISTRY/AMSI_TAMPER...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r30_fire', event_type='REGISTRY', subtype='AMSI_TAMPER',
    actor='malware.exe', process_path=r'C:\Users\Public\malware.exe',
    destination=r'HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c98 = sqlite3.connect('hocsoc.db')
_c98.row_factory = sqlite3.Row
_a98 = _c98.execute("SELECT * FROM alerts WHERE rule_id=30").fetchall()
_c98.close()
assert len(_a98) == 1, f'Expected 1 alert, got {len(_a98)}'
assert _a98[0]['severity_current'] == 'CRITICAL'
assert 'AMSI' in _a98[0]['explanation']
print('  CRITICAL alert, AMSI in explanation  PASS')


# -------------------------------------------------------
# Test 99: Rule 30 — no-fire on unrelated REGISTRY subtype
# -------------------------------------------------------
print('Test 99: Rule 30 no-fire on REGISTRY/KEY_MODIFIED...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r30_nofire', event_type='REGISTRY', subtype='KEY_MODIFIED',
    actor='svchost.exe', process_path=r'C:\Windows\System32\svchost.exe',
    destination=r'HKLM\SOFTWARE\SomeKey',
    base_severity='SUSPICIOUS', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for non-AMSI registry event  PASS')


# -------------------------------------------------------
# Test 100: Rule 31 — fires on DLL_HIJACK (CRITICAL)
# -------------------------------------------------------
print('Test 100: Rule 31 fires on DLL/DLL_HIJACK...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r31_hijack', event_type='DLL', subtype='DLL_HIJACK',
    actor='victim.exe', process_path=r'C:\Users\Public\version.dll',
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c100 = sqlite3.connect('hocsoc.db')
_c100.row_factory = sqlite3.Row
_a100 = _c100.execute("SELECT * FROM alerts WHERE rule_id=31").fetchall()
_c100.close()
assert len(_a100) == 1, f'Expected 1 alert, got {len(_a100)}'
assert _a100[0]['severity_current'] == 'CRITICAL'
assert 'DLL_HIJACK' in _a100[0]['explanation']
print('  CRITICAL alert for DLL_HIJACK  PASS')


# -------------------------------------------------------
# Test 101: Rule 31 — fires on DLL_USERPATH at SUSPICIOUS
# -------------------------------------------------------
print('Test 101: Rule 31 fires on DLL/DLL_USERPATH at SUSPICIOUS...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r31_userpath', event_type='DLL', subtype='DLL_USERPATH',
    actor='someapp.exe', process_path=r'C:\Users\Schüler\AppData\Roaming\someapp\helper.dll',
    destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='sysmonwatcher',
)
correlator.run_all()
_c101 = sqlite3.connect('hocsoc.db')
_c101.row_factory = sqlite3.Row
_a101 = _c101.execute("SELECT * FROM alerts WHERE rule_id=31").fetchall()
_c101.close()
assert len(_a101) == 1, f'Expected 1 alert, got {len(_a101)}'
assert _a101[0]['severity_current'] == 'SUSPICIOUS'
print('  SUSPICIOUS alert for DLL_USERPATH (severity passes through)  PASS')


# -------------------------------------------------------
# Test 102: Rule 32 — fires on WMI_BINDING (CRITICAL)
# -------------------------------------------------------
print('Test 102: Rule 32 fires on WMI/WMI_BINDING...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r32_binding', event_type='WMI', subtype='WMI_BINDING',
    actor='NBDA0665\\Schüler', process_path=None,
    destination=None,
    base_severity='CRITICAL', trust_level='UNKNOWN',
    collector='sysmonwatcher',
)
correlator.run_all()
_c102 = sqlite3.connect('hocsoc.db')
_c102.row_factory = sqlite3.Row
_a102 = _c102.execute("SELECT * FROM alerts WHERE rule_id=32").fetchall()
_c102.close()
assert len(_a102) == 1, f'Expected 1 alert, got {len(_a102)}'
assert _a102[0]['severity_current'] == 'CRITICAL'
assert 'binding' in _a102[0]['explanation']
print('  CRITICAL alert for WMI_BINDING, binding in explanation  PASS')


# -------------------------------------------------------
# Test 103: Rule 32 — no-fire on WMI event with OK severity
# -------------------------------------------------------
print('Test 103: Rule 32 no-fire on WMI/WMI_FILTER with OK severity...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r32_nofire', event_type='WMI', subtype='WMI_FILTER',
    actor='SYSTEM', process_path=None,
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for OK severity WMI event  PASS')


# -------------------------------------------------------
# Test 104: Rule 33 — fires on INJECTION/REMOTE_THREAD
# -------------------------------------------------------
print('Test 104: Rule 33 fires on INJECTION/REMOTE_THREAD...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r33_fire', event_type='INJECTION', subtype='REMOTE_THREAD',
    actor='injector.exe', process_path=r'C:\Users\Public\injector.exe',
    destination='svchost.exe',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c104 = sqlite3.connect('hocsoc.db')
_c104.row_factory = sqlite3.Row
_a104 = _c104.execute("SELECT * FROM alerts WHERE rule_id=33").fetchall()
_c104.close()
assert len(_a104) == 1, f'Expected 1 alert, got {len(_a104)}'
assert _a104[0]['severity_current'] == 'CRITICAL'
assert 'svchost.exe' in _a104[0]['explanation']
print('  CRITICAL alert, target in explanation  PASS')


# -------------------------------------------------------
# Test 105: Rule 33 — no-fire on wrong event_type
# -------------------------------------------------------
print('Test 105: Rule 33 no-fire on PROCESS/REMOTE_THREAD (wrong event_type)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r33_nofire', event_type='PROCESS', subtype='REMOTE_THREAD',
    actor='test.exe', process_path=r'C:\Windows\System32\test.exe',
    destination=None,
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for wrong event_type  PASS')


# -------------------------------------------------------
# Test 106: Rule 34 — fires on PROCESS_ACCESS/LSASS_ACCESS
# -------------------------------------------------------
print('Test 106: Rule 34 fires on PROCESS_ACCESS/LSASS_ACCESS...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r34_fire', event_type='PROCESS_ACCESS', subtype='LSASS_ACCESS',
    actor='mimikatz.exe', process_path=r'C:\Users\Public\mimikatz.exe',
    destination='lsass.exe',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c106 = sqlite3.connect('hocsoc.db')
_c106.row_factory = sqlite3.Row
_a106 = _c106.execute("SELECT * FROM alerts WHERE rule_id=34").fetchall()
_c106.close()
assert len(_a106) == 1, f'Expected 1 alert, got {len(_a106)}'
assert _a106[0]['severity_current'] == 'CRITICAL'
assert 'lsass' in _a106[0]['explanation']
print('  CRITICAL alert, lsass in explanation  PASS')


# -------------------------------------------------------
# Test 107: Rule 34 — no-fire on OK severity (whitelisted monitor)
# -------------------------------------------------------
print('Test 107: Rule 34 no-fire on LSASS_ACCESS with OK severity...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r34_nofire', event_type='PROCESS_ACCESS', subtype='LSASS_ACCESS',
    actor='svchost.exe', process_path=r'C:\Windows\System32\svchost.exe',
    destination='lsass.exe',
    base_severity='OK', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for OK severity LSASS access (whitelisted monitor)  PASS')


# -------------------------------------------------------
# Test 108: Rule 35 — fires on DISK/RAW_DISK_READ CRITICAL
# -------------------------------------------------------
print('Test 108: Rule 35 fires on DISK/RAW_DISK_READ (CRITICAL)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r35_crit', event_type='DISK', subtype='RAW_DISK_READ',
    actor='unknown.exe', process_path=r'C:\Users\Public\unknown.exe',
    destination=r'\Device\HarddiskVolume3',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c108 = sqlite3.connect('hocsoc.db')
_c108.row_factory = sqlite3.Row
_a108 = _c108.execute("SELECT * FROM alerts WHERE rule_id=35").fetchall()
_c108.close()
assert len(_a108) == 1, f'Expected 1 alert, got {len(_a108)}'
assert _a108[0]['severity_current'] == 'CRITICAL'
assert 'HarddiskVolume' in _a108[0]['explanation']
print('  CRITICAL alert, device in explanation  PASS')


# -------------------------------------------------------
# Test 109: Rule 35 — SUSPICIOUS passes through
# -------------------------------------------------------
print('Test 109: Rule 35 SUSPICIOUS severity passes through...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r35_susp', event_type='DISK', subtype='RAW_DISK_READ',
    actor='borderline.exe', process_path=r'C:\Program Files\borderline.exe',
    destination=r'\Device\HarddiskVolume3',
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='sysmonwatcher',
)
correlator.run_all()
_c109 = sqlite3.connect('hocsoc.db')
_c109.row_factory = sqlite3.Row
_a109 = _c109.execute("SELECT * FROM alerts WHERE rule_id=35").fetchall()
_c109.close()
assert len(_a109) == 1, f'Expected 1 alert, got {len(_a109)}'
assert _a109[0]['severity_current'] == 'SUSPICIOUS'
print('  SUSPICIOUS severity passes through correctly  PASS')


# -------------------------------------------------------
# Test 110: Rule 36 — fires on DRIVER/UNSIGNED_DRIVER
# -------------------------------------------------------
print('Test 110: Rule 36 fires on DRIVER/UNSIGNED_DRIVER...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r36_fire', event_type='DRIVER', subtype='UNSIGNED_DRIVER',
    actor='rootkit.sys', process_path=r'C:\Users\Public\rootkit.sys',
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c110 = sqlite3.connect('hocsoc.db')
_c110.row_factory = sqlite3.Row
_a110 = _c110.execute("SELECT * FROM alerts WHERE rule_id=36").fetchall()
_c110.close()
assert len(_a110) == 1, f'Expected 1 alert, got {len(_a110)}'
assert _a110[0]['severity_current'] == 'CRITICAL'
assert 'rootkit.sys' in _a110[0]['explanation']
print('  CRITICAL alert, driver name in explanation  PASS')


# -------------------------------------------------------
# Test 111: Rule 36 — no-fire on DRIVER with different subtype
# -------------------------------------------------------
print('Test 111: Rule 36 no-fire on DRIVER/SIGNED_DRIVER...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r36_nofire', event_type='DRIVER', subtype='SIGNED_DRIVER',
    actor='legit.sys', process_path=r'C:\Windows\System32\drivers\legit.sys',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for signed driver  PASS')


# -------------------------------------------------------
# Test 112: Rule 37 — fires on PIPE/PIPE_CREATED (CRITICAL)
# -------------------------------------------------------
print('Test 112: Rule 37 fires on PIPE/PIPE_CREATED...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r37_created', event_type='PIPE', subtype='PIPE_CREATED',
    actor='beacon.exe', process_path=r'C:\Users\Public\beacon.exe',
    destination=r'\\.\pipe\MSSE-1234-server',
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c112 = sqlite3.connect('hocsoc.db')
_c112.row_factory = sqlite3.Row
_a112 = _c112.execute("SELECT * FROM alerts WHERE rule_id=37").fetchall()
_c112.close()
assert len(_a112) == 1, f'Expected 1 alert, got {len(_a112)}'
assert _a112[0]['severity_current'] == 'CRITICAL'
assert 'created' in _a112[0]['explanation']
print('  CRITICAL alert, pipe action in explanation  PASS')


# -------------------------------------------------------
# Test 113: Rule 37 — SUSPICIOUS passes through on PIPE_CONNECTED
# -------------------------------------------------------
print('Test 113: Rule 37 SUSPICIOUS passes through on PIPE_CONNECTED...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r37_connected', event_type='PIPE', subtype='PIPE_CONNECTED',
    actor='implant.exe', process_path=r'C:\Users\Public\implant.exe',
    destination=r'\\.\pipe\meterpreter',
    base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c113 = sqlite3.connect('hocsoc.db')
_c113.row_factory = sqlite3.Row
_a113 = _c113.execute("SELECT * FROM alerts WHERE rule_id=37").fetchall()
_c113.close()
assert len(_a113) == 1, f'Expected 1 alert, got {len(_a113)}'
assert _a113[0]['severity_current'] == 'SUSPICIOUS'
assert 'connected to' in _a113[0]['explanation']
print('  SUSPICIOUS alert, connected to in explanation  PASS')


# -------------------------------------------------------
# Test 114: Rule 38 — fires on FILE/FILE_HOTPATH (CRITICAL)
# -------------------------------------------------------
print('Test 114: Rule 38 fires on FILE/FILE_HOTPATH...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r38_exec', event_type='FILE', subtype='FILE_HOTPATH',
    actor='chrome.exe', process_path=r'C:\Users\Schüler\Downloads\evil.exe',
    destination=None,
    base_severity='CRITICAL', trust_level='HIGH_RISK',
    collector='sysmonwatcher',
)
correlator.run_all()
_c114 = sqlite3.connect('hocsoc.db')
_c114.row_factory = sqlite3.Row
_a114 = _c114.execute("SELECT * FROM alerts WHERE rule_id=38").fetchall()
_c114.close()
assert len(_a114) == 1, f'Expected 1 alert, got {len(_a114)}'
assert _a114[0]['severity_current'] == 'CRITICAL'
assert 'staging path' in _a114[0]['explanation']
print('  CRITICAL alert for dropped executable  PASS')


# -------------------------------------------------------
# Test 115: Rule 38 — SUSPICIOUS for DOWNLOADED_FILE
# -------------------------------------------------------
print('Test 115: Rule 38 fires on FILE/DOWNLOADED_FILE (SUSPICIOUS)...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r38_zone', event_type='FILE', subtype='DOWNLOADED_FILE',
    actor='browser.exe', process_path=r'C:\Users\Schüler\Downloads\setup.exe',
    destination=None,
    base_severity='SUSPICIOUS', trust_level='UNKNOWN',
    collector='sysmonwatcher',
)
correlator.run_all()
_c115 = sqlite3.connect('hocsoc.db')
_c115.row_factory = sqlite3.Row
_a115 = _c115.execute("SELECT * FROM alerts WHERE rule_id=38").fetchall()
_c115.close()
assert len(_a115) == 1, f'Expected 1 alert, got {len(_a115)}'
assert _a115[0]['severity_current'] == 'SUSPICIOUS'
assert 'Zone.Identifier' in _a115[0]['explanation']
print('  SUSPICIOUS alert, Zone.Identifier in explanation  PASS')


# -------------------------------------------------------
# Test 116: Rule 39 — fires on PROCESS/PROCESS_TAMPER
# -------------------------------------------------------
print('Test 116: Rule 39 fires on PROCESS/PROCESS_TAMPER...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r39_fire', event_type='PROCESS', subtype='PROCESS_TAMPER',
    actor='svchost.exe', process_path=r'C:\Windows\System32\svchost.exe',
    destination=None,
    base_severity='CRITICAL', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
_c116 = sqlite3.connect('hocsoc.db')
_c116.row_factory = sqlite3.Row
_a116 = _c116.execute("SELECT * FROM alerts WHERE rule_id=39").fetchall()
_c116.close()
assert len(_a116) == 1, f'Expected 1 alert, got {len(_a116)}'
assert _a116[0]['severity_current'] == 'CRITICAL'
assert 'hollowing' in _a116[0]['explanation']
print('  CRITICAL alert, hollowing in explanation  PASS')


# -------------------------------------------------------
# Test 117: Rule 39 — no-fire on PROCESS/PROCESS_TERMINATED (wrong subtype)
# -------------------------------------------------------
print('Test 117: Rule 39 no-fire on PROCESS/PROCESS_TERMINATED...')
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

_insert_event(
    event_id='r39_nofire', event_type='PROCESS', subtype='PROCESS_TERMINATED',
    actor='notepad.exe', process_path=r'C:\Windows\System32\notepad.exe',
    destination=None,
    base_severity='OK', trust_level='TRUSTED',
    collector='sysmonwatcher',
)
correlator.run_all()
assert db.count_alerts() == 0, f'Expected 0 alerts, got {db.count_alerts()}'
print('  no alert for PROCESS_TERMINATED (wrong subtype)  PASS')



# ============================================================
# TESTS 118–121: Rules 41 and 42 — Blind Window & Coordinated Suppression
# ============================================================

_R41_EVT = '2026-03-21 08:00:00'
_R41_REF = _dt(2026, 3, 21, 8, 5, 0)   # 5 min after → inside SHORT_WINDOW
_R42_REF = _dt(2026, 3, 21, 9, 0, 0)


def _reset_dbs():
    """Drop and re-initialise both operational and health databases."""
    if os.path.exists('hocsoc.db'):
        os.remove('hocsoc.db')
    if os.path.exists('hocsoc_health.db'):
        os.remove('hocsoc_health.db')
    db.initialize()
    health_db.initialize()


# -------------------------------------------------------
# Test 118: Rule 41 fires — NETWORK_BLIND_PROCESS
#   Sentinel DOWN + Harbinger reports a SUSPICIOUS process in the gap
# -------------------------------------------------------
print('Test 118: Rule 41 CRITICAL on Sentinel DOWN + Harbinger SUSPICIOUS process...')
_reset_dbs()

health_db.upsert_collector_status(
    collector_name='sentinel', heartbeat_ts=None,
    last_recorded=_R41_REF, cycle=1, uptime=0, status='DOWN',
)
_insert_event(
    event_id='r41_proc', event_type='PROCESS', subtype='NEW PROCESS',
    actor='payload.exe',
    process_path=r'C:\Windows\Temp\payload.exe',
    destination=None,
    base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R41_EVT,
)
correlator._rule_41(reference_time=_R41_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a118 = conn.execute("SELECT * FROM alerts WHERE rule_id=41").fetchall()
conn.close()
assert len(_a118) == 1, f'Expected 1 alert (NETWORK_BLIND_PROCESS), got {len(_a118)}'
assert _a118[0]['severity_current'] == 'CRITICAL'
assert 'NETWORK_BLIND_PROCESS' in _a118[0]['explanation']
print('  CRITICAL NETWORK_BLIND_PROCESS alert  PASS')


# -------------------------------------------------------
# Test 119: Rule 41 no-fire — no collectors are DOWN
# -------------------------------------------------------
print('Test 119: Rule 41 no-fire when no collectors are DOWN...')
_reset_dbs()

_insert_event(
    event_id='r41_no_down', event_type='PROCESS', subtype='NEW PROCESS',
    actor='payload.exe', process_path=r'C:\Windows\Temp\payload.exe',
    destination=None, base_severity='SUSPICIOUS', trust_level='HIGH_RISK',
    collector='harbinger', observed_at=_R41_EVT,
)
# health_db is empty → no DOWN collectors recorded
correlator._rule_41(reference_time=_R41_REF)
assert db.count_alerts() == 0, f'Expected 0 alerts (no DOWN collectors), got {db.count_alerts()}'
print('  no alert — no DOWN collectors  PASS')


# -------------------------------------------------------
# Test 120: Rule 42 fires — 2 collectors simultaneously DOWN
# -------------------------------------------------------
print('Test 120: Rule 42 CRITICAL on 2 collectors simultaneously DOWN...')
_reset_dbs()

for _cname in ('sentinel', 'bulwark'):
    health_db.upsert_collector_status(
        collector_name=_cname, heartbeat_ts=None,
        last_recorded=_R42_REF, cycle=1, uptime=0, status='DOWN',
    )
correlator._rule_42(reference_time=_R42_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a120 = conn.execute("SELECT * FROM alerts WHERE rule_id=42").fetchall()
conn.close()
assert len(_a120) == 1, f'Expected 1 alert, got {len(_a120)}'
assert _a120[0]['severity_current'] == 'CRITICAL'
assert 'COORDINATED_SUPPRESSION' in _a120[0]['explanation']
print('  CRITICAL COORDINATED_SUPPRESSION alert  PASS')


# -------------------------------------------------------
# Test 121: Rule 42 no-fire — only 1 collector DOWN
# -------------------------------------------------------
print('Test 121: Rule 42 no-fire when only 1 collector is DOWN...')
_reset_dbs()

health_db.upsert_collector_status(
    collector_name='sentinel', heartbeat_ts=None,
    last_recorded=_R42_REF, cycle=1, uptime=0, status='DOWN',
)
correlator._rule_42(reference_time=_R42_REF)
assert db.count_alerts() == 0, f'Expected 0 alerts (only 1 DOWN), got {db.count_alerts()}'
print('  no alert — only 1 collector DOWN  PASS')


# ============================================================
# TESTS 122–135: Rules 43–48 — Supply-Chain Spawn Detection
# ============================================================

_R43_EVT = '2026-03-22 09:00:00'
_R43_REF = _dt(2026, 3, 22, 9, 5, 0)   # 5 min after → inside SHORT_WINDOW


def _insert_harbinger_spawn(event_id, actor, process_path, trust_level,
                             base_severity, parent_name, cmd='',
                             observed_at=_R43_EVT):
    """Insert a Harbinger PROCESS event plus the raw_events row needed for
    parent/CMD matching via the JOIN used by Rules 43–48."""
    _insert_event(
        event_id=event_id, event_type='PROCESS', subtype='NEW PROCESS',
        actor=actor, process_path=process_path, destination=None,
        base_severity=base_severity, trust_level=trust_level,
        collector='harbinger', observed_at=observed_at,
    )
    raw_line = (
        f'[{observed_at}] [{base_severity}] NEW PROCESS: {actor} | PID: 9999 | '
        f'Parent: {parent_name} (1234) | Path: {process_path or ""} | CMD: {cmd}'
    )
    conn = sqlite3.connect('hocsoc.db')
    conn.execute("""
        INSERT OR IGNORE INTO raw_events
            (collector_name, raw_payload, observed_at, recorded_at,
             source_host, raw_event_hash, normalized_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, ('harbinger', raw_line, observed_at, observed_at,
          'TEST-HOST', f'rawhash_{event_id}', event_id))
    conn.commit()
    conn.close()


# -------------------------------------------------------
# Test 122: Rule 43 fires — chrome spawns powershell (SUSPICIOUS)
# -------------------------------------------------------
print('Test 122: Rule 43 SUSPICIOUS on chrome spawning powershell...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r43_fire',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',
    base_severity='SUSPICIOUS',
    parent_name='chrome',
)
correlator._rule_43(reference_time=_R43_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a122 = conn.execute("SELECT * FROM alerts WHERE rule_id=43").fetchall()
conn.close()
assert len(_a122) == 1, f'Expected 1 alert, got {len(_a122)}'
assert _a122[0]['severity_current'] == 'SUSPICIOUS'
assert 'scripting engine' in _a122[0]['explanation']
print('  SUSPICIOUS alert, scripting engine in explanation  PASS')


# -------------------------------------------------------
# Test 123: Rule 43 no-fire — suite launcher CMD fragment excluded
#   node IS in KNOWN_BAD_PARENTS, but CMD contains the suite launcher path
# -------------------------------------------------------
print('Test 123: Rule 43 no-fire when CMD contains suite launcher fragment...')
_reset_dbs()

_launcher_cmd = (
    r'pwsh.exe -ExecutionPolicy Bypass -WindowStyle Hidden '
    r'-File "C:\Users\Schuler\Desktop\SOC\Scripts\\Collectors\Sentinel.ps1"'
)
_insert_harbinger_spawn(
    event_id='r43_launcher',
    actor='pwsh.exe',
    process_path=r'C:\Program Files\PowerShell\7\pwsh.exe',
    trust_level='TRUSTED',
    base_severity='OK',
    parent_name='node',          # node IS in KNOWN_BAD_PARENTS
    cmd=_launcher_cmd,
)
correlator._rule_43(reference_time=_R43_REF)
assert db.count_alerts() == 0, (
    f'Expected 0 alerts (suite launcher excluded), got {db.count_alerts()}'
)
print('  no alert — suite launcher CMD fragment excluded  PASS')


# -------------------------------------------------------
# Test 124: Rule 43 no-fire — non-bad parent (explorer is not in KNOWN_BAD_PARENTS)
# -------------------------------------------------------
print('Test 124: Rule 43 no-fire when parent is not in KNOWN_BAD_PARENTS...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r43_nofire_parent',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',
    base_severity='OK',
    parent_name='explorer',      # explorer NOT in KNOWN_BAD_PARENTS
)
correlator._rule_43(reference_time=_R43_REF)
assert db.count_alerts() == 0, (
    f'Expected 0 alerts (explorer not a bad parent), got {db.count_alerts()}'
)
print('  no alert — explorer not in KNOWN_BAD_PARENTS  PASS')


# -------------------------------------------------------
# Test 125: Rule 44 fires — node spawns python from HIGH_RISK path (HIGH)
# -------------------------------------------------------
print('Test 125: Rule 44 HIGH on node spawning python from HIGH_RISK path...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r44_fire',
    actor='python.exe',
    process_path=os.path.join(appdata_temp, 'python.exe'),
    trust_level='HIGH_RISK',
    base_severity='CRITICAL',
    parent_name='node',
)
correlator._rule_44(reference_time=_R43_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a125 = conn.execute("SELECT * FROM alerts WHERE rule_id=44").fetchall()
conn.close()
assert len(_a125) == 1, f'Expected 1 alert, got {len(_a125)}'
assert _a125[0]['severity_current'] == 'HIGH'
assert 'high-risk path' in _a125[0]['explanation']
print('  HIGH alert, high-risk path in explanation  PASS')


# -------------------------------------------------------
# Test 126: Rule 44 no-fire — spawn from trusted path (trust_level not HIGH_RISK)
# -------------------------------------------------------
print('Test 126: Rule 44 no-fire when spawn path is trusted...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r44_nofire_trusted',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',       # NOT HIGH_RISK → Rule 44 should not fire
    base_severity='SUSPICIOUS',
    parent_name='chrome',
)
correlator._rule_44(reference_time=_R43_REF)
assert db.count_alerts() == 0, (
    f'Expected 0 alerts (trust_level TRUSTED, not HIGH_RISK), got {db.count_alerts()}'
)
print('  no rule-44 alert — trust_level TRUSTED is not HIGH_RISK  PASS')


# -------------------------------------------------------
# Test 127: Rule 45 fires — chrome→powershell + powershell outbound callback (CRITICAL)
# -------------------------------------------------------
print('Test 127: Rule 45 CRITICAL on bad-parent spawn + matching outbound network...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r45_proc',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',
    base_severity='SUSPICIOUS',
    parent_name='chrome',
)
_insert_event(
    event_id='r45_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='powershell',          # Sentinel logs process names without .exe
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    destination='142.11.206.73',
    base_severity='CRITICAL', trust_level='UNTRUSTED',
    collector='sentinel', observed_at=_R43_EVT,
)
correlator._rule_45(reference_time=_R43_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a127 = conn.execute("SELECT * FROM alerts WHERE rule_id=45").fetchall()
conn.close()
assert len(_a127) == 1, f'Expected 1 alert, got {len(_a127)}'
assert _a127[0]['severity_current'] == 'CRITICAL'
assert 'callback' in _a127[0]['explanation']
print('  CRITICAL alert, callback in explanation  PASS')


# -------------------------------------------------------
# Test 128: Rule 45 no-fire — spawn present but no outbound network callback
# -------------------------------------------------------
print('Test 128: Rule 45 no-fire when no outbound network connection follows spawn...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r45_no_net_proc',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',
    base_severity='SUSPICIOUS',
    parent_name='chrome',
)
# No network event inserted
correlator._rule_45(reference_time=_R43_REF)
assert db.count_alerts() == 0, f'Expected 0 alerts (no network event), got {db.count_alerts()}'
print('  no alert — no outbound connection  PASS')


# -------------------------------------------------------
# Test 129: Rule 46 fires — full chain: bad parent → HIGH_RISK path → outbound (CRITICAL)
# -------------------------------------------------------
print('Test 129: Rule 46 CRITICAL on full supply-chain execution chain...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r46_proc',
    actor='python.exe',
    process_path=os.path.join(appdata_temp, 'python.exe'),
    trust_level='HIGH_RISK',
    base_severity='CRITICAL',
    parent_name='chrome',
)
_insert_event(
    event_id='r46_net', event_type='NETWORK', subtype='OUTBOUND',
    actor='python',
    process_path=os.path.join(appdata_temp, 'python.exe'),
    destination='142.11.206.73',
    base_severity='CRITICAL', trust_level='UNTRUSTED',
    collector='sentinel', observed_at=_R43_EVT,
)
correlator._rule_46(reference_time=_R43_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a129 = conn.execute("SELECT * FROM alerts WHERE rule_id=46").fetchall()
conn.close()
assert len(_a129) == 1, f'Expected 1 alert, got {len(_a129)}'
assert _a129[0]['severity_current'] == 'CRITICAL'
assert 'supply-chain' in _a129[0]['explanation']
print('  CRITICAL alert, supply-chain in explanation  PASS')


# -------------------------------------------------------
# Test 130: Rule 46 no-fire — HIGH_RISK spawn without outbound network
# -------------------------------------------------------
print('Test 130: Rule 46 no-fire when HIGH_RISK spawn has no network connection...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r46_no_net',
    actor='python.exe',
    process_path=os.path.join(appdata_temp, 'python.exe'),
    trust_level='HIGH_RISK',
    base_severity='CRITICAL',
    parent_name='chrome',
)
correlator._rule_46(reference_time=_R43_REF)
assert db.count_alerts() == 0, f'Expected 0 alerts (no network event), got {db.count_alerts()}'
print('  no alert — no outbound connection  PASS')


# -------------------------------------------------------
# Test 131: Rule 47 fires — -EncodedCommand flag present (HIGH)
# -------------------------------------------------------
print('Test 131: Rule 47 HIGH on -EncodedCommand flag...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r47_enc',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',
    base_severity='SUSPICIOUS',
    parent_name='explorer',      # parent irrelevant — Rule 47 checks CMD only
    cmd='powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=',
)
correlator._rule_47(reference_time=_R43_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a131 = conn.execute("SELECT * FROM alerts WHERE rule_id=47").fetchall()
conn.close()
assert len(_a131) == 1, f'Expected 1 alert, got {len(_a131)}'
assert _a131[0]['severity_current'] == 'HIGH'
assert 'Obfuscated' in _a131[0]['explanation']
print('  HIGH alert, Obfuscated in explanation  PASS')


# -------------------------------------------------------
# Test 132: Rule 47 no-fire — -ExecutionPolicy Bypass alone is not sufficient
# -------------------------------------------------------
print('Test 132: Rule 47 no-fire on -ExecutionPolicy Bypass alone...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r47_bypass_only',
    actor='pwsh.exe',
    process_path=r'C:\Program Files\PowerShell\7\pwsh.exe',
    trust_level='TRUSTED',
    base_severity='OK',
    parent_name='explorer',
    cmd='pwsh.exe -ExecutionPolicy Bypass -File "C:\\tools\\myscript.ps1"',
)
correlator._rule_47(reference_time=_R43_REF)
assert db.count_alerts() == 0, (
    f'Expected 0 alerts (-ExecutionPolicy Bypass alone not sufficient), '
    f'got {db.count_alerts()}'
)
print('  no alert — -ExecutionPolicy Bypass alone does not trigger Rule 47  PASS')


# -------------------------------------------------------
# Test 133: Rule 47 no-fire — suite launcher CMD fragment excluded
#   -WindowStyle Hidden + -ExecutionPolicy Bypass IS present, but the CMD
#   also contains the suite launcher path fragment → excluded
# -------------------------------------------------------
print('Test 133: Rule 47 no-fire when CMD contains suite launcher fragment...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r47_launcher',
    actor='pwsh.exe',
    process_path=r'C:\Program Files\PowerShell\7\pwsh.exe',
    trust_level='TRUSTED',
    base_severity='OK',
    parent_name='python',
    cmd=(
        r'pwsh.exe -WindowStyle Hidden -ExecutionPolicy Bypass '
        r'-File "C:\Users\Schuler\Desktop\SOC\Scripts\\Collectors\Harbinger.ps1"'
    ),
)
correlator._rule_47(reference_time=_R43_REF)
assert db.count_alerts() == 0, (
    f'Expected 0 alerts (suite launcher excluded), got {db.count_alerts()}'
)
print('  no alert — suite launcher CMD fragment excluded  PASS')


# -------------------------------------------------------
# Test 134: Rule 48 fires — chrome spawns powershell (CRITICAL)
# -------------------------------------------------------
print('Test 134: Rule 48 CRITICAL on chrome spawning powershell...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r48_fire',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',
    base_severity='SUSPICIOUS',
    parent_name='chrome',
)
correlator._rule_48(reference_time=_R43_REF)
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
_a134 = conn.execute("SELECT * FROM alerts WHERE rule_id=48").fetchall()
conn.close()
assert len(_a134) == 1, f'Expected 1 alert, got {len(_a134)}'
assert _a134[0]['severity_current'] == 'CRITICAL'
assert 'chrome' in _a134[0]['explanation']
print('  CRITICAL alert, chrome in explanation  PASS')


# -------------------------------------------------------
# Test 135: Rule 48 no-fire — non-bad pair (explorer→powershell not in KNOWN_BAD_PAIRS)
# -------------------------------------------------------
print('Test 135: Rule 48 no-fire on pair not in KNOWN_BAD_PAIRS...')
_reset_dbs()

_insert_harbinger_spawn(
    event_id='r48_nofire',
    actor='powershell.exe',
    process_path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    trust_level='TRUSTED',
    base_severity='OK',
    parent_name='explorer',      # explorer not in KNOWN_BAD_PAIRS
)
correlator._rule_48(reference_time=_R43_REF)
assert db.count_alerts() == 0, (
    f'Expected 0 alerts (explorer not in KNOWN_BAD_PAIRS), got {db.count_alerts()}'
)
print('  no alert — explorer not in KNOWN_BAD_PAIRS  PASS')


print()
print('correlator.py PASS - all 135 tests')
