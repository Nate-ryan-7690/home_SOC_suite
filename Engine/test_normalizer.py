import os, sqlite3, hashlib
import db, log_parser, normalizer, config

# Fresh database
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

print('=== normalizer.py TESTS ===')
print()


# -------------------------------------------------------
# Helper: insert a fake raw_event directly and return its row
# -------------------------------------------------------
def _insert_raw(collector, raw_payload, observed_at='2026-03-20 10:00:00'):
    raw_hash = hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()
    db.insert_raw_event(
        collector_name=collector,
        raw_payload=raw_payload,
        observed_at=observed_at,
        source_host='TEST-HOST',
        raw_event_hash=raw_hash,
    )
    conn = sqlite3.connect('hocsoc.db')
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        'SELECT * FROM raw_events WHERE raw_event_hash = ?', (raw_hash,)
    ).fetchone()
    conn.close()
    return row


# -------------------------------------------------------
# Test 1: Harbinger — STARTUP event
# -------------------------------------------------------
print('Test 1: Harbinger STARTUP normalization...')
raw = _insert_raw(
    'harbinger',
    r'[2026-03-20 10:00:00] [UNKNOWN] STARTUP: svchost.exe | PID: 1700 | Parent: services.exe (1492) | Path: C:\Windows\system32\svchost.exe'
)
result = normalizer.normalize_raw_event(raw)
assert result['event_type']        == 'PROCESS',              f"event_type={result['event_type']}"
assert result['subtype']           == 'STARTUP',              f"subtype={result['subtype']}"
assert result['actor']             == 'svchost.exe',          f"actor={result['actor']}"
assert result['process_path']      == r'C:\Windows\system32\svchost.exe', f"path={result['process_path']}"
assert result['base_severity']     == 'UNKNOWN',              f"severity={result['base_severity']}"
assert result['trust_level']       == 'TRUSTED',              f"trust={result['trust_level']}"
assert result['parser_confidence'] == 1.0,                    f"confidence={result['parser_confidence']}"
print('  event_type=PROCESS, subtype=STARTUP, trust=TRUSTED  PASS')


# -------------------------------------------------------
# Test 2: Harbinger — CRITICAL process from high-risk path
# -------------------------------------------------------
print('Test 2: Harbinger HIGH_RISK path detection...')
appdata_temp = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp')
raw2_payload = f'[2026-03-20 10:01:00] [CRITICAL] NEW PROCESS: evil.exe | PID: 9999 | Parent: cmd.exe (888) | Path: {appdata_temp}\\evil.exe'
raw2 = _insert_raw('harbinger', raw2_payload, '2026-03-20 10:01:00')
result2 = normalizer.normalize_raw_event(raw2)
assert result2['trust_level']  == 'HIGH_RISK', f"trust={result2['trust_level']}"
assert result2['base_severity'] == 'CRITICAL',  f"severity={result2['base_severity']}"
print(f'  trust=HIGH_RISK, severity=CRITICAL  PASS')


# -------------------------------------------------------
# Test 3: Sentinel — outbound network event
# -------------------------------------------------------
print('Test 3: Sentinel outbound network normalization...')
raw3 = _insert_raw(
    'sentinel',
    r'[10:00:00] [CRITICAL] NEW: powershell -> 5.6.7.8 (Moscow, RU) | PATH: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
)
result3 = normalizer.normalize_raw_event(raw3)
assert result3['event_type']   == 'NETWORK',    f"event_type={result3['event_type']}"
assert result3['subtype']      == 'OUTBOUND',   f"subtype={result3['subtype']}"
assert result3['actor']        == 'powershell', f"actor={result3['actor']}"
assert result3['destination']  == '5.6.7.8',   f"dest={result3['destination']}"
assert result3['trust_level']  == 'TRUSTED',    f"trust={result3['trust_level']}"
print('  event_type=NETWORK, subtype=OUTBOUND, destination=5.6.7.8  PASS')


# -------------------------------------------------------
# Test 4: CityGuard — scheduled task with action path
# -------------------------------------------------------
print('Test 4: CityGuard NEW TASK normalization...')
raw4 = _insert_raw(
    'cityguard',
    r'[2026-03-20 12:05:00] [CRITICAL] NEW TASK: \Temp\evil.exe | Action: C:\Temp\evil.exe'
)
result4 = normalizer.normalize_raw_event(raw4)
assert result4['event_type']   == 'SCHEDULED_TASK', f"event_type={result4['event_type']}"
assert result4['subtype']      == 'NEW TASK',        f"subtype={result4['subtype']}"
assert result4['process_path'] == r'C:\Temp\evil.exe', f"path={result4['process_path']}"
print('  event_type=SCHEDULED_TASK, subtype=NEW TASK  PASS')


# -------------------------------------------------------
# Test 5: Watchman — power event subtype mapping
# -------------------------------------------------------
print('Test 5: Watchman power event subtype mapping...')
power_cases = [
    ('1',    'WAKE'),
    ('42',   'SLEEP'),
    ('41',   'UNEXPECTED_SHUTDOWN'),
    ('6005', 'BOOT'),
    ('6006', 'SHUTDOWN'),
    ('1074', 'CLEAN_SHUTDOWN'),
]
for event_id, expected_subtype in power_cases:
    payload = f'[2026-03-20 10:00:00] [OK] EventID {event_id} | test description | Time: 2026-03-20 10:00:00'
    raw_w = _insert_raw('watchman', payload, f'2026-03-20 10:00:0{event_id[-1:]}')
    result_w = normalizer.normalize_raw_event(raw_w)
    assert result_w['event_type'] == 'POWER',           f"event_type={result_w['event_type']}"
    assert result_w['subtype']    == expected_subtype,  f"EventID {event_id}: expected {expected_subtype}, got {result_w['subtype']}"
print('  all 6 EventID subtypes mapped correctly  PASS')


# -------------------------------------------------------
# Test 6: Unknown collector — confidence 0.4
# -------------------------------------------------------
print('Test 6: Unknown collector fallback...')
raw6 = _insert_raw(
    'unknown_collector',
    '[2026-03-20 10:00:00] [OK] some message'
)
result6 = normalizer.normalize_raw_event(raw6)
assert result6['event_type']        == 'UNKNOWN', f"event_type={result6['event_type']}"
assert result6['parser_confidence'] == 0.4,       f"confidence={result6['parser_confidence']}"
print('  event_type=UNKNOWN, confidence=0.4  PASS')


# -------------------------------------------------------
# Test 7: Known collector, regex no-match — confidence 0.5
# -------------------------------------------------------
print('Test 7: Known collector, unparseable message — confidence 0.5...')
raw7 = _insert_raw(
    'harbinger',
    '[2026-03-20 10:00:00] [OK] This line does not match any harbinger pattern'
)
result7 = normalizer.normalize_raw_event(raw7)
assert result7['event_type']        == 'UNKNOWN', f"event_type={result7['event_type']}"
assert result7['parser_confidence'] == 0.5,       f"confidence={result7['parser_confidence']}"
print('  event_type=UNKNOWN, confidence=0.5  PASS')


# -------------------------------------------------------
# Test 8: Deterministic event_id
# -------------------------------------------------------
print('Test 8: Deterministic event_id...')
raw8 = _insert_raw(
    'harbinger',
    r'[2026-03-20 11:00:00] [OK] STARTUP: calc.exe | PID: 100 | Parent: explorer.exe (500) | Path: C:\Windows\system32\calc.exe',
    '2026-03-20 11:00:00'
)
r1 = normalizer.normalize_raw_event(raw8)
r2 = normalizer.normalize_raw_event(raw8)
assert r1['event_id'] == r2['event_id'], 'event_id not deterministic'
# Verify the formula manually
expected_id = hashlib.sha256(
    f"harbinger:{raw8['raw_event_hash']}".encode('utf-8')
).hexdigest()[:32]
assert r1['event_id'] == expected_id, f"event_id mismatch: {r1['event_id']} != {expected_id}"
print(f'  event_id={r1["event_id"]}  PASS')


# -------------------------------------------------------
# Test 9: normalize_pending() — end-to-end pipeline
# -------------------------------------------------------
print('Test 9: normalize_pending() pipeline...')

# Fresh db for clean count
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

# Ingest 2 known-format events via log_parser
import tempfile, shutil
tmp = tempfile.mkdtemp()
log_path = os.path.join(tmp, 'Harbinger_Log.txt')
with open(log_path, 'w', encoding='utf-8') as f:
    f.write('[2026-03-20 10:00:00] [UNKNOWN] STARTUP: svchost.exe | PID: 1700 | Parent: services.exe (1492) | Path: C:\\Windows\\system32\\svchost.exe\n')
    f.write('[2026-03-20 10:01:00] [CRITICAL] NEW PROCESS: powershell.exe | PID: 9999 | Parent: cmd.exe (888) | Path: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n')

config.LOG_FILES['harbinger'] = log_path
log_parser.ingest_collector('harbinger')

# Before normalization — pending count should be 2
pending_before = db.get_pending_raw_events()
assert len(pending_before) == 2, f'Expected 2 pending, got {len(pending_before)}'

# Run normalizer
count = normalizer.normalize_pending()
assert count == 2, f'Expected 2 normalized, got {count}'

# After normalization — no pending remain
pending_after = db.get_pending_raw_events()
assert len(pending_after) == 0, f'Expected 0 pending after, got {len(pending_after)}'

# raw_events rows should have normalized_event_id stamped
conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
rows = conn.execute('SELECT normalized_event_id FROM raw_events').fetchall()
assert all(r['normalized_event_id'] is not None for r in rows), \
    'Some raw_events not stamped with normalized_event_id'

# events table should have 2 rows
events = conn.execute('SELECT * FROM events').fetchall()
assert len(events) == 2, f'Expected 2 events, got {len(events)}'
conn.close()

shutil.rmtree(tmp)
print('  2 raw events ingested, normalized, stamped, events table populated  PASS')


# -------------------------------------------------------
# Test 10: normalize_pending() idempotent — second call inserts nothing
# -------------------------------------------------------
print('Test 10: normalize_pending() idempotent...')
count2 = normalizer.normalize_pending()
assert count2 == 0, f'Expected 0 on second run, got {count2}'
print('  second call returned 0 (no double-normalization)  PASS')


# -------------------------------------------------------
# Test 11: Harbinger — empty path (kernel process), CMD field stripped
# -------------------------------------------------------
print('Test 11: Harbinger empty path + CMD field handled...')
raw11 = _insert_raw(
    'harbinger',
    '[2026-03-20 10:00:00] [UNKNOWN] STARTUP: smss.exe | PID: 664 | Parent: System (4) | Path:  | CMD: '
)
result11 = normalizer.normalize_raw_event(raw11)
assert result11['event_type']        == 'PROCESS',  f"event_type={result11['event_type']}"
assert result11['process_path']      is None,        f"path should be None, got '{result11['process_path']}'"
assert result11['trust_level']       == 'UNKNOWN',   f"trust={result11['trust_level']}"
assert result11['parser_confidence'] == 1.0,         f"confidence={result11['parser_confidence']}"
print('  empty path -> None, CMD stripped, confidence=1.0  PASS')


# -------------------------------------------------------
# Test 12: Harbinger — path present, CMD field stripped cleanly
# -------------------------------------------------------
print('Test 12: Harbinger path present, CMD field stripped...')
raw12 = _insert_raw(
    'harbinger',
    r'[2026-03-20 10:00:00] [UNKNOWN] STARTUP: svchost.exe | PID: 1696 | Parent: services.exe (1500) | Path: C:\WINDOWS\system32\svchost.exe | CMD: C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p'
)
result12 = normalizer.normalize_raw_event(raw12)
assert result12['process_path'] == r'C:\WINDOWS\system32\svchost.exe', \
    f"CMD leaked into path: '{result12['process_path']}'"
assert result12['trust_level']  == 'TRUSTED', f"trust={result12['trust_level']}"
print('  path clean, CMD not included in process_path  PASS')


# -------------------------------------------------------
# Test 13: Bulwark — CONNECTION_START (session tracker format)
# Old GEO_ANOMALY format removed — replaced by session tracking in Bulwark.ps1
# -------------------------------------------------------
print('Test 13: Bulwark CONNECTION_START (session tracker) normalization...')
raw13 = _insert_raw(
    'bulwark',
    r'[2026-03-21 07:18:33] [UNKNOWN] CONNECTION_START: Process=officeclicktorun | Remote=52.96.153.146:443 | Location=Nairobi, KE | Path: C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe'
)
result13 = normalizer.normalize_raw_event(raw13)
assert result13['event_type']        == 'NETWORK',           f"event_type={result13['event_type']}"
assert result13['subtype']           == 'CONNECTION_START',  f"subtype={result13['subtype']}"
assert result13['actor']             == 'officeclicktorun',  f"actor={result13['actor']}"
assert result13['destination']       == '52.96.153.146',     f"dest={result13['destination']}"
assert result13['process_path']      == r'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe', \
    f"path={result13['process_path']}"
assert result13['parser_confidence'] == 1.0,                 f"confidence={result13['parser_confidence']}"
print('  CONNECTION_START -> event_type=NETWORK, actor/dest/path correct  PASS')



# -------------------------------------------------------
# Test 14: Steward — per-process HIGH CPU with RAM
# "HIGH CPU: chrome at 72% | RAM: 145 MB"
# -------------------------------------------------------
print('Test 14: Steward per-process HIGH CPU normalization...')
raw14 = _insert_raw(
    'steward',
    '[2026-03-21 09:15:00] [CRITICAL] HIGH CPU: chrome at 72% | RAM: 145 MB'
)
result14 = normalizer.normalize_raw_event(raw14)
assert result14['event_type']        == 'RESOURCE',   f"event_type={result14['event_type']}"
assert result14['subtype']           == 'CPU',         f"subtype={result14['subtype']}"
assert result14['actor']             == 'chrome',      f"actor={result14['actor']}"
assert result14['process_path']      is None,          f"process_path should be None, got {result14['process_path']}"
assert result14['parser_confidence'] == 1.0,           f"confidence={result14['parser_confidence']}"
print('  event_type=RESOURCE, subtype=CPU, actor=chrome, path=None  PASS')


# -------------------------------------------------------
# Test 15: Steward — system-level HIGH CPU (no RAM field)
# "HIGH CPU: System at 99%"
# -------------------------------------------------------
print('Test 15: Steward system-level HIGH CPU normalization...')
raw15 = _insert_raw(
    'steward',
    '[2026-03-21 19:59:04] [CRITICAL] HIGH CPU: System at 99%'
)
result15 = normalizer.normalize_raw_event(raw15)
assert result15['event_type']        == 'RESOURCE',   f"event_type={result15['event_type']}"
assert result15['subtype']           == 'CPU',         f"subtype={result15['subtype']}"
assert result15['actor']             == 'System',      f"actor={result15['actor']}"
assert result15['process_path']      is None,          f"process_path should be None"
assert result15['parser_confidence'] == 1.0,           f"confidence={result15['parser_confidence']}"
print('  event_type=RESOURCE, subtype=CPU, actor=System, path=None  PASS')


# -------------------------------------------------------
# Test 16: Steward — system-level HIGH RAM
# "HIGH RAM: System at 95%"
# -------------------------------------------------------
print('Test 16: Steward system-level HIGH RAM normalization...')
raw16 = _insert_raw(
    'steward',
    '[2026-03-21 19:59:10] [CRITICAL] HIGH RAM: System at 95%'
)
result16 = normalizer.normalize_raw_event(raw16)
assert result16['event_type']        == 'RESOURCE',   f"event_type={result16['event_type']}"
assert result16['subtype']           == 'RAM',         f"subtype={result16['subtype']}"
assert result16['actor']             == 'System',      f"actor={result16['actor']}"
assert result16['process_path']      is None,          f"process_path should be None"
assert result16['parser_confidence'] == 1.0,           f"confidence={result16['parser_confidence']}"
print('  event_type=RESOURCE, subtype=RAM, actor=System, path=None  PASS')



# -------------------------------------------------------
# Test 17: Bulwark — PORT OPEN with path
# "[PORT OPEN] PORT OPENED: 52518 | Process: Agent | Path: C:\ProgramData\..."
# -------------------------------------------------------
print('Test 17: Bulwark PORT OPEN with path normalization...')
raw17 = _insert_raw(
    'bulwark',
    r'[2026-03-21 19:58:43] [PORT OPEN] PORT OPENED: 52518 | Process: Agent | Path: C:\ProgramData\Battle.net\Agent\Agent.9390\Agent.exe'
)
result17 = normalizer.normalize_raw_event(raw17)
assert result17['event_type']        == 'PORT',         f"event_type={result17['event_type']}"
assert result17['subtype']           == 'PORT_OPEN',    f"subtype={result17['subtype']}"
assert result17['actor']             == 'Agent',        f"actor={result17['actor']}"
assert result17['destination']       == '52518',        f"destination={result17['destination']}"
assert result17['process_path']      == r'C:\ProgramData\Battle.net\Agent\Agent.9390\Agent.exe', \
    f"path={result17['process_path']}"
assert result17['trust_level']       == 'HIGH_RISK',    f"trust={result17['trust_level']}"
assert result17['parser_confidence'] == 1.0,            f"confidence={result17['parser_confidence']}"
print('  event_type=PORT, subtype=PORT_OPEN, actor=Agent, trust=HIGH_RISK  PASS')


# -------------------------------------------------------
# Test 18: Bulwark — PORT CLOSE with empty path
# "[PORT CLOSE] PORT CLOSED: 2869 | Process: System | Path: "
# -------------------------------------------------------
print('Test 18: Bulwark PORT CLOSE with empty path normalization...')
raw18 = _insert_raw(
    'bulwark',
    '[2026-03-21 18:39:42] [PORT CLOSE] PORT CLOSED: 2869 | Process: System | Path: '
)
result18 = normalizer.normalize_raw_event(raw18)
assert result18['event_type']        == 'PORT',         f"event_type={result18['event_type']}"
assert result18['subtype']           == 'PORT_CLOSE',   f"subtype={result18['subtype']}"
assert result18['actor']             == 'System',       f"actor={result18['actor']}"
assert result18['destination']       == '2869',         f"destination={result18['destination']}"
assert result18['process_path']      is None,           f"empty path should be None"
assert result18['trust_level']       == 'UNKNOWN',      f"trust={result18['trust_level']}"
assert result18['parser_confidence'] == 1.0,            f"confidence={result18['parser_confidence']}"
print('  event_type=PORT, subtype=PORT_CLOSE, empty path -> None, trust=UNKNOWN  PASS')



# -------------------------------------------------------
# Test 19: DoH_Detector — DOH_CONN_NEW (CRITICAL, non-whitelisted)
# "[2026-03-24 08:43:01] [CRITICAL] DOH_CONN_NEW: Process=chrome | Path=C:\...\chrome.exe | PID=1234 | Resolver=8.8.8.8 | LocalPort=52000"
# -------------------------------------------------------
print('Test 19: DoH_Detector DOH_CONN_NEW normalization...')
raw19 = _insert_raw(
    'doh_detector',
    r'[2026-03-24 08:43:01] [CRITICAL] DOH_CONN_NEW: Process=chrome | Path=C:\Program Files\Google\Chrome\Application\chrome.exe | PID=1234 | Resolver=8.8.8.8 | LocalPort=52000'
)
result19 = normalizer.normalize_raw_event(raw19)
assert result19['event_type']        == 'NETWORK',           f"event_type={result19['event_type']}"
assert result19['subtype']           == 'DOH_CONNECTION',    f"subtype={result19['subtype']}"
assert result19['actor']             == 'chrome',            f"actor={result19['actor']}"
assert result19['destination']       == '8.8.8.8',           f"destination={result19['destination']}"
assert result19['process_path']      == r'C:\Program Files\Google\Chrome\Application\chrome.exe', \
    f"path={result19['process_path']}"
assert result19['base_severity']     == 'CRITICAL',          f"severity={result19['base_severity']}"
assert result19['trust_level']       == 'TRUSTED',           f"trust={result19['trust_level']}"
assert result19['parser_confidence'] == 1.0,                 f"confidence={result19['parser_confidence']}"
print('  event_type=NETWORK, subtype=DOH_CONNECTION, resolver=8.8.8.8, trust=TRUSTED  PASS')


# -------------------------------------------------------
# Test 20: DoH_Detector — DOH_CONN_ENDED skipped (returns confidence=0.5, UNKNOWN)
# "[2026-03-24 08:43:15] [OK] DOH_CONN_ENDED: Process=chrome | PID=1234 | Resolver=8.8.8.8 | Duration=14s"
# -------------------------------------------------------
print('Test 20: DoH_Detector DOH_CONN_ENDED does not parse as actionable event...')
raw20 = _insert_raw(
    'doh_detector',
    '[2026-03-24 08:43:15] [OK] DOH_CONN_ENDED: Process=chrome | PID=1234 | Resolver=8.8.8.8 | Duration=14s'
)
result20 = normalizer.normalize_raw_event(raw20)
assert result20['event_type']        == 'UNKNOWN',   f"expected UNKNOWN for ENDED line, got {result20['event_type']}"
assert result20['parser_confidence'] == 0.5,         f"expected 0.5 for unmatched line, got {result20['parser_confidence']}"
print('  DOH_CONN_ENDED -> event_type=UNKNOWN, confidence=0.5 (informational, not actionable)  PASS')



# -------------------------------------------------------
# Test 21: Warden — INTEGRITY_VIOLATION (FIM_VIOLATION)
# "INTEGRITY_VIOLATION: Sentinel.ps1 [Collectors] | Hash mismatch"
# -------------------------------------------------------
print('Test 21: Warden INTEGRITY_VIOLATION (FIM_VIOLATION)...')
raw21 = _insert_raw(
    'warden',
    '[2026-03-24 09:00:01] [CRITICAL] INTEGRITY_VIOLATION: Sentinel.ps1 [Collectors] | Hash mismatch'
)
result21 = normalizer.normalize_raw_event(raw21)
assert result21['event_type']        == 'INTEGRITY',      f"event_type={result21['event_type']}"
assert result21['subtype']           == 'FIM_VIOLATION',  f"subtype={result21['subtype']}"
assert result21['actor']             == 'Sentinel.ps1 [Collectors] | Hash mismatch', \
    f"actor={result21['actor']}"
assert result21['base_severity']     == 'CRITICAL',       f"severity={result21['base_severity']}"
assert result21['parser_confidence'] == 1.0,              f"confidence={result21['parser_confidence']}"
print('  INTEGRITY_VIOLATION -> event_type=INTEGRITY, subtype=FIM_VIOLATION, CRITICAL  PASS')


# -------------------------------------------------------
# Test 22: Warden — LOG_TRUNCATED (LOG_TAMPER)
# "LOG_TRUNCATED: Network_Watchdog_Log.txt | Was: 102400 bytes | Now: 512 bytes | Lost: 101888 bytes"
# -------------------------------------------------------
print('Test 22: Warden LOG_TRUNCATED (LOG_TAMPER)...')
raw22 = _insert_raw(
    'warden',
    '[2026-03-24 09:01:05] [CRITICAL] LOG_TRUNCATED: Network_Watchdog_Log.txt | Was: 102400 bytes | Now: 512 bytes | Lost: 101888 bytes'
)
result22 = normalizer.normalize_raw_event(raw22)
assert result22['event_type']        == 'INTEGRITY',   f"event_type={result22['event_type']}"
assert result22['subtype']           == 'LOG_TAMPER',  f"subtype={result22['subtype']}"
assert 'Network_Watchdog_Log.txt' in result22['actor'], f"actor={result22['actor']}"
assert result22['base_severity']     == 'CRITICAL',    f"severity={result22['base_severity']}"
assert result22['parser_confidence'] == 1.0,           f"confidence={result22['parser_confidence']}"
print('  LOG_TRUNCATED -> event_type=INTEGRITY, subtype=LOG_TAMPER, CRITICAL  PASS')


# -------------------------------------------------------
# Test 23: Warden — COLLECTOR_DOWN
# "COLLECTOR_DOWN: Sentinel.ps1 not found in running processes"
# -------------------------------------------------------
print('Test 23: Warden COLLECTOR_DOWN normalization...')
raw23 = _insert_raw(
    'warden',
    '[2026-03-24 09:02:10] [SUSPICIOUS] COLLECTOR_DOWN: Sentinel.ps1 not found in running processes'
)
result23 = normalizer.normalize_raw_event(raw23)
assert result23['event_type']        == 'INTEGRITY',       f"event_type={result23['event_type']}"
assert result23['subtype']           == 'COLLECTOR_DOWN',  f"subtype={result23['subtype']}"
assert result23['actor']             == 'Sentinel.ps1',    f"actor={result23['actor']}"
assert result23['base_severity']     == 'SUSPICIOUS',      f"severity={result23['base_severity']}"
assert result23['parser_confidence'] == 1.0,               f"confidence={result23['parser_confidence']}"
print('  COLLECTOR_DOWN -> event_type=INTEGRITY, subtype=COLLECTOR_DOWN, actor=Sentinel.ps1  PASS')


# -------------------------------------------------------
# Test 24: Warden — MANIFEST_MISSING
# "MANIFEST_MISSING: No manifest file found — FIM cannot run until baseline is created"
# -------------------------------------------------------
print('Test 24: Warden MANIFEST_MISSING normalization...')
raw24 = _insert_raw(
    'warden',
    '[2026-03-24 09:03:00] [SUSPICIOUS] MANIFEST_MISSING: No manifest file found -- FIM cannot run until baseline is created'
)
result24 = normalizer.normalize_raw_event(raw24)
assert result24['event_type']        == 'INTEGRITY',        f"event_type={result24['event_type']}"
assert result24['subtype']           == 'MANIFEST_MISSING', f"subtype={result24['subtype']}"
assert result24['actor']             is None,               f"actor should be None, got {result24['actor']}"
assert result24['parser_confidence'] == 1.0,               f"confidence={result24['parser_confidence']}"
print('  MANIFEST_MISSING -> event_type=INTEGRITY, subtype=MANIFEST_MISSING, actor=None  PASS')



# -------------------------------------------------------
# Test 25: SecEventLog — ACCOUNT_CREATED (event_type=ACCOUNT, actor=NewUser)
# "ACCOUNT_CREATED: NewUser=backdoor | CreatedBy=SYSTEM"
# -------------------------------------------------------
print('Test 25: SecEventLog ACCOUNT_CREATED normalization...')
raw25 = _insert_raw(
    'seceventlog',
    '[2026-03-24 10:00:00] [CRITICAL] ACCOUNT_CREATED: NewUser=backdoor | CreatedBy=SYSTEM'
)
result25 = normalizer.normalize_raw_event(raw25)
assert result25['event_type']        == 'ACCOUNT',          f"event_type={result25['event_type']}"
assert result25['subtype']           == 'ACCOUNT_CREATED',  f"subtype={result25['subtype']}"
assert result25['actor']             == 'backdoor',         f"actor={result25['actor']}"
assert result25['base_severity']     == 'CRITICAL',         f"severity={result25['base_severity']}"
assert result25['parser_confidence'] == 1.0,                f"confidence={result25['parser_confidence']}"
print('  ACCOUNT_CREATED -> event_type=ACCOUNT, actor=NewUser, CRITICAL  PASS')


# -------------------------------------------------------
# Test 26: SecEventLog — GROUP_MEMBER_ADDED (actor=Member)
# "GROUP_MEMBER_ADDED: Member=CN=evil,DC=local | Group=Administrators (LocalGroup) | AddedBy=johndoe"
# -------------------------------------------------------
print('Test 26: SecEventLog GROUP_MEMBER_ADDED normalization...')
raw26 = _insert_raw(
    'seceventlog',
    '[2026-03-24 10:01:00] [CRITICAL] GROUP_MEMBER_ADDED: Member=CN=evil,DC=local | Group=Administrators (LocalGroup) | AddedBy=johndoe'
)
result26 = normalizer.normalize_raw_event(raw26)
assert result26['event_type']        == 'ACCOUNT',              f"event_type={result26['event_type']}"
assert result26['subtype']           == 'GROUP_MEMBER_ADDED',   f"subtype={result26['subtype']}"
assert result26['actor']             == 'CN=evil,DC=local',     f"actor={result26['actor']}"
assert result26['parser_confidence'] == 1.0,                    f"confidence={result26['parser_confidence']}"
print('  GROUP_MEMBER_ADDED -> event_type=ACCOUNT, actor=Member field  PASS')


# -------------------------------------------------------
# Test 27: SecEventLog — LOGON_SUCCESS (event_type=AUTH, destination=IP)
# "LOGON_SUCCESS: User=johndoe | Type=Interactive | Workstation=MYPC | Source=192.168.1.5 (LOCAL)"
# -------------------------------------------------------
print('Test 27: SecEventLog LOGON_SUCCESS normalization...')
raw27 = _insert_raw(
    'seceventlog',
    '[2026-03-24 10:02:00] [OK] LOGON_SUCCESS: User=johndoe | Type=Interactive | Workstation=MYPC | Source=192.168.1.5 (LOCAL)'
)
result27 = normalizer.normalize_raw_event(raw27)
assert result27['event_type']        == 'AUTH',            f"event_type={result27['event_type']}"
assert result27['subtype']           == 'LOGON_SUCCESS',   f"subtype={result27['subtype']}"
assert result27['actor']             == 'johndoe',         f"actor={result27['actor']}"
assert result27['destination']       == '192.168.1.5',     f"destination={result27['destination']}"
assert result27['parser_confidence'] == 1.0,               f"confidence={result27['parser_confidence']}"
print('  LOGON_SUCCESS -> event_type=AUTH, actor=User, destination=IP  PASS')


# -------------------------------------------------------
# Test 28: SecEventLog — SERVICE_INSTALLED (event_type=SYSTEM)
# "SERVICE_INSTALLED: Name=evilsvc | Path=C:\Temp\evil.exe | StartType=2 | Account=LocalSystem | InstalledBy=johndoe"
# -------------------------------------------------------
print('Test 28: SecEventLog SERVICE_INSTALLED normalization...')
raw28 = _insert_raw(
    'seceventlog',
    r'[2026-03-24 10:03:00] [CRITICAL] SERVICE_INSTALLED: Name=evilsvc | Path=C:\Temp\evil.exe | StartType=2 | Account=LocalSystem | InstalledBy=johndoe'
)
result28 = normalizer.normalize_raw_event(raw28)
assert result28['event_type']        == 'SYSTEM',             f"event_type={result28['event_type']}"
assert result28['subtype']           == 'SERVICE_INSTALLED',  f"subtype={result28['subtype']}"
assert result28['base_severity']     == 'CRITICAL',           f"severity={result28['base_severity']}"
assert result28['parser_confidence'] == 1.0,                  f"confidence={result28['parser_confidence']}"
print('  SERVICE_INSTALLED -> event_type=SYSTEM, CRITICAL  PASS')


# -------------------------------------------------------
# Test 29: Bulwark — CONNECTION_START (replaces old GEO_ANOMALY)
# -------------------------------------------------------
print('Test 29: Bulwark CONNECTION_START normalization...')
raw29 = _insert_raw(
    'bulwark',
    r'[2026-03-25 21:00:00] [UNKNOWN] CONNECTION_START: Process=msedge | Remote=142.250.185.78:443 | Location=Mountain View, US | Path: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
)
result29 = normalizer.normalize_raw_event(raw29)
assert result29['event_type']        == 'NETWORK',           f"event_type={result29['event_type']}"
assert result29['subtype']           == 'CONNECTION_START',  f"subtype={result29['subtype']}"
assert result29['actor']             == 'msedge',            f"actor={result29['actor']}"
assert result29['destination']       == '142.250.185.78',    f"destination={result29['destination']}"
assert result29['parser_confidence'] == 1.0,                 f"confidence={result29['parser_confidence']}"
print('  CONNECTION_START -> event_type=NETWORK, actor=msedge, destination=IP  PASS')


# -------------------------------------------------------
# Test 30: Bulwark — CONNECTION_END with session metadata
# -------------------------------------------------------
print('Test 30: Bulwark CONNECTION_END normalization...')
raw30 = _insert_raw(
    'bulwark',
    r'[2026-03-25 21:47:30] [OK] CONNECTION_END: Process=msedge | Remote=142.250.185.78:443 | Location=Mountain View, US | Cycles=570 | Duration=47m30s | Started=2026-03-25 21:00:00 | Path: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
)
result30 = normalizer.normalize_raw_event(raw30)
assert result30['event_type']        == 'NETWORK',          f"event_type={result30['event_type']}"
assert result30['subtype']           == 'CONNECTION_END',   f"subtype={result30['subtype']}"
assert result30['actor']             == 'msedge',           f"actor={result30['actor']}"
assert result30['destination']       == '142.250.185.78',   f"destination={result30['destination']}"
assert result30['parser_confidence'] == 1.0,                f"confidence={result30['parser_confidence']}"
print('  CONNECTION_END -> event_type=NETWORK, actor=msedge, destination=IP  PASS')


# -------------------------------------------------------
# Test 31: Bulwark — CONNECTION_START with IPv6 remote
# -------------------------------------------------------
print('Test 31: Bulwark CONNECTION_START IPv6 remote...')
raw31 = _insert_raw(
    'bulwark',
    '[2026-03-25 21:00:00] [UNKNOWN] CONNECTION_START: Process=chrome | Remote=2001:4860:4860::8888:443 | Location=Mountain View, US | Path: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
)
result31 = normalizer.normalize_raw_event(raw31)
assert result31['event_type']        == 'NETWORK',          f"event_type={result31['event_type']}"
assert result31['subtype']           == 'CONNECTION_START', f"subtype={result31['subtype']}"
assert result31['actor']             == 'chrome',           f"actor={result31['actor']}"
assert result31['destination']       == '2001:4860:4860::8888', f"destination={result31['destination']}"
assert result31['parser_confidence'] == 1.0,                f"confidence={result31['parser_confidence']}"
print('  CONNECTION_START IPv6 -> destination strips port correctly  PASS')


# -------------------------------------------------------
# Test 32: Bulwark — PORT_OPEN still works (unchanged format)
# -------------------------------------------------------
print('Test 32: Bulwark PORT_OPEN still normalizes correctly...')
raw32 = _insert_raw(
    'bulwark',
    r'[2026-03-25 21:00:00] [PORT OPEN] PORT OPENED: 52518 | Process: Agent | Path: C:\Program Files\Agent\agent.exe'
)
result32 = normalizer.normalize_raw_event(raw32)
assert result32['event_type']        == 'PORT',      f"event_type={result32['event_type']}"
assert result32['subtype']           == 'PORT_OPEN', f"subtype={result32['subtype']}"
assert result32['actor']             == 'Agent',     f"actor={result32['actor']}"
assert result32['destination']       == '52518',     f"destination={result32['destination']}"
assert result32['parser_confidence'] == 1.0,         f"confidence={result32['parser_confidence']}"
print('  PORT_OPEN -> event_type=PORT, subtype=PORT_OPEN  PASS')


print()
print('normalizer.py PASS - all 32 tests')
