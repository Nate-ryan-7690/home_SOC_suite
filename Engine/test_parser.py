import os, tempfile, shutil, sqlite3
import db, log_parser, config

# Fresh database
if os.path.exists('hocsoc.db'):
    os.remove('hocsoc.db')
db.initialize()

tmp = tempfile.mkdtemp()
print('=== log_parser.py TESTS ===')
print()

# -------------------------------------------------------
# Test 1: Standard format (harbinger)
# -------------------------------------------------------
print('Test 1: Standard format parse (harbinger)...')
log1 = os.path.join(tmp, 'Harbinger_Log.txt')
with open(log1, 'w', encoding='utf-8') as f:
    f.write('--- HARBINGER LOG STARTED: 03/20/2026 10:23:00 ---\n')
    f.write('--- MONITORING: Process Creation ---\n')
    f.write('\n')
    f.write('[2026-03-20 10:23:01] [UNKNOWN] STARTUP: svchost.exe | PID: 1700 | Parent: services.exe (1492) | Path: C:\\Windows\\system32\\svchost.exe\n')
    f.write('[2026-03-20 10:25:00] [CRITICAL] NEW PROCESS: powershell.exe | PID: 9999 | Parent: cmd.exe (888) | Path: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n')

config.LOG_FILES['harbinger'] = log1
count = log_parser.ingest_collector('harbinger')
assert count == 2, f'Expected 2, got {count}'
print(f'  inserted {count} events  PASS')

# -------------------------------------------------------
# Test 2: Structural lines skipped (cityguard)
# -------------------------------------------------------
print('Test 2: Structural lines skipped...')
log2 = os.path.join(tmp, 'CityGuard_Log.txt')
with open(log2, 'w', encoding='utf-8') as f:
    f.write('--- CITYGUARD LOG STARTED: 03/20/2026 12:00:00 ---\n')
    f.write('--- SESSION SNAPSHOT ---\n')
    f.write('SNAPSHOT: \\Adobe Acrobat Update Task | State: Ready | Action: C:\\Program Files\\Adobe\\ARM\\AdobeARM.exe\n')
    f.write('[2026-03-20 12:05:00] [CRITICAL] NEW TASK: \\Temp\\evil.exe | Action: C:\\Temp\\evil.exe\n')

config.LOG_FILES['cityguard'] = log2
count2 = log_parser.ingest_collector('cityguard')
assert count2 == 1, f'Expected 1, got {count2}'
print(f'  1 event inserted, structural lines skipped  PASS')

# -------------------------------------------------------
# Test 3: Sentinel date reconstruction
# -------------------------------------------------------
print('Test 3: Sentinel date reconstruction...')
log3 = os.path.join(tmp, 'Sentinel_Log.txt')
with open(log3, 'w', encoding='utf-8') as f:
    f.write('--- Network Security Log Started: 03/20/2026 15:00:00 ---\n')
    f.write('--- [BOOT AUDIT] ---\n')
    f.write('Format: [Time] APP -> REMOTE_IP (LOCATION) | PATH\n')
    f.write('------------------------------------------------\n')
    f.write('\n')
    f.write('[15:00:01] [UNKNOWN] NEW: chrome -> 1.2.3.4 (Berlin, DE) | PATH: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n')
    f.write('[15:00:02] [CRITICAL] NEW: powershell -> 5.6.7.8 (Moscow, RU) | PATH: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n')

config.LOG_FILES['sentinel'] = log3
count3 = log_parser.ingest_collector('sentinel')
assert count3 == 2, f'Expected 2, got {count3}'

session = db.get_session_context('sentinel')
assert session == '2026-03-20', f'Expected 2026-03-20, got {session}'

conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT * FROM raw_events WHERE collector_name='sentinel' ORDER BY observed_at").fetchall()
assert len(rows) == 2
assert rows[0]['observed_at'] == '2026-03-20 15:00:01', f"Got {rows[0]['observed_at']}"
assert rows[1]['observed_at'] == '2026-03-20 15:00:02'
conn.close()
print(f'  session_date=2026-03-20, observed_at correctly reconstructed  PASS')

# -------------------------------------------------------
# Test 4: Watchman — Time: field as observed_at
# -------------------------------------------------------
print('Test 4: Watchman dual timestamp...')
log4 = os.path.join(tmp, 'Watchman_Log.txt')
with open(log4, 'w', encoding='utf-8') as f:
    f.write('--- WATCHMAN LOG STARTED: 03/20/2026 10:00:00 ---\n')
    f.write('\n')
    f.write('[2026-03-20 10:00:01] [SUSPICIOUS] EventID 1 | System woke from sleep | Time: 2026-03-20 01:34:14\n')
    f.write('[2026-03-20 10:00:01] [OK] EventID 6005 | System boot | Time: 2026-03-20 08:30:00\n')

config.LOG_FILES['watchman'] = log4
count4 = log_parser.ingest_collector('watchman')
assert count4 == 2

conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT * FROM raw_events WHERE collector_name='watchman' ORDER BY observed_at").fetchall()
assert rows[0]['observed_at'] == '2026-03-20 01:34:14', f"Got {rows[0]['observed_at']}"
assert rows[1]['observed_at'] == '2026-03-20 08:30:00'
conn.close()
print(f'  observed_at = Time: field, not outer timestamp  PASS')

# -------------------------------------------------------
# Test 5: Deduplication
# -------------------------------------------------------
print('Test 5: Deduplication...')
log5 = os.path.join(tmp, 'dedup_test.txt')
with open(log5, 'w', encoding='utf-8') as f:
    f.write('[2026-03-20 11:00:00] [OK] EventID 1 | System woke from sleep | Time: 2026-03-20 11:00:00\n')

config.LOG_FILES['watchman'] = log5
c1 = log_parser.ingest_collector('watchman')
db.update_collector_health('watchman', offset=0, event_count=0, status='ACTIVE')
c2 = log_parser.ingest_collector('watchman')
assert c1 == 1 and c2 == 0, f'c1={c1} c2={c2}'
print(f'  first pass={c1}, second pass={c2} (duplicate rejected)  PASS')

# -------------------------------------------------------
# Test 6: Log rotation detection
# -------------------------------------------------------
print('Test 6: Log rotation detection...')
log6 = os.path.join(tmp, 'rotation_test.txt')
with open(log6, 'w', encoding='utf-8') as f:
    f.write('[2026-03-20 12:00:00] [OK] EventID 1 | System woke from sleep | Time: 2026-03-20 12:00:00\n')

config.LOG_FILES['watchman'] = log6
log_parser.ingest_collector('watchman')

# Simulate rotation: set stored offset higher than file size
db.update_collector_health('watchman', offset=99999, event_count=0, status='ACTIVE')

# Write new content (post-rotation)
with open(log6, 'w', encoding='utf-8') as f:
    f.write('[2026-03-21 08:00:00] [OK] EventID 6005 | System boot | Time: 2026-03-21 08:00:00\n')

count6 = log_parser.ingest_collector('watchman')
assert count6 == 1, f'Expected 1 after rotation, got {count6}'
print(f'  offset reset on rotation, new file read from start  PASS')

# -------------------------------------------------------
# Test 7: Missing log file -> SILENT
# -------------------------------------------------------
print('Test 7: Missing log file -> SILENT status...')
config.LOG_FILES['bloodhound'] = os.path.join(tmp, 'nonexistent.txt')
count7 = log_parser.ingest_collector('bloodhound')
assert count7 == 0

conn = sqlite3.connect('hocsoc.db')
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT status FROM collector_health WHERE collector_name='bloodhound'").fetchone()
assert row['status'] == 'SILENT', f"Got {row['status']}"
conn.close()
print(f'  count=0, status=SILENT  PASS')

# Cleanup
shutil.rmtree(tmp)
print()
print('log_parser.py PASS - all 7 tests')
