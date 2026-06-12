# test_db_alert_management.py
# Run from SOC_dev\Engine\ directory: python test_db_alert_management.py
#
# Overrides config.DB_PATH before importing db so this test never
# touches the dev or live database regardless of ROOT_PATH.

import os
from datetime import datetime

import config
_TEST_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_alert_mgmt.db")
if os.path.exists(_TEST_DB):
    os.remove(_TEST_DB)
config.DB_PATH = _TEST_DB

import db

print("=== db.py alert-management TESTS ===")
print()

db.initialize()

# -------------------------------------------------------
# Helper: insert a minimal alert row
# -------------------------------------------------------
_COUNTER = [0]

def _make_alert(status="NEW", comment=None, reviewed_at=None):
    _COUNTER[0] += 1
    aid = f"test-alert-{_COUNTER[0]:03d}"
    now = datetime.now().isoformat()
    with db.get_connection() as conn:
        conn.execute(
            """INSERT INTO alerts
               (alert_id, rule_id, severity_current, confidence,
                status, explanation, linked_case, created_at, updated_at,
                analyst_comment, reviewed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (aid, 99, "CRITICAL", 0.9, status,
             "Test alert explanation.", None, now, now,
             comment, reviewed_at)
        )
    return aid


# -------------------------------------------------------
# Test 1: get_alert_by_id -- found
# -------------------------------------------------------
print("Test 1: get_alert_by_id returns correct row when alert exists...")
aid1 = _make_alert()
row = db.get_alert_by_id(aid1)
assert row is not None, "Expected row, got None"
assert row["alert_id"] == aid1, f"Wrong alert_id: {row['alert_id']}"
assert row["rule_id"] == 99
assert row["severity_current"] == "CRITICAL"
print("  row returned with correct fields  PASS")


# -------------------------------------------------------
# Test 2: get_alert_by_id -- not found returns None
# -------------------------------------------------------
print("Test 2: get_alert_by_id returns None for unknown ID...")
row = db.get_alert_by_id("does-not-exist")
assert row is None, f"Expected None, got {row}"
print("  None returned  PASS")


# -------------------------------------------------------
# Test 3: update_alert_classify -- RESOLVED, no comment
# -------------------------------------------------------
print("Test 3: classify as RESOLVED (no comment)...")
aid3 = _make_alert()
db.update_alert_classify(aid3, "RESOLVED")
row = db.get_alert_by_id(aid3)
assert row["status"] == "RESOLVED", f"Expected RESOLVED, got {row['status']}"
assert row["reviewed_at"] is not None, "reviewed_at should be set"
assert row["analyst_comment"] is None, "comment should remain None"
print("  status=RESOLVED, reviewed_at set, comment stays None  PASS")


# -------------------------------------------------------
# Test 4: update_alert_classify -- FALSE_POSITIVE with comment
# -------------------------------------------------------
print("Test 4: classify as FALSE_POSITIVE with comment...")
aid4 = _make_alert()
db.update_alert_classify(aid4, "FALSE_POSITIVE", "Legit sync client, whitelisted.")
row = db.get_alert_by_id(aid4)
assert row["status"] == "FALSE_POSITIVE", f"Expected FALSE_POSITIVE, got {row['status']}"
assert row["analyst_comment"] == "Legit sync client, whitelisted.", f"Wrong comment: {row['analyst_comment']}"
assert row["reviewed_at"] is not None
print("  status=FALSE_POSITIVE, comment saved  PASS")


# -------------------------------------------------------
# Test 5: update_alert_classify -- MONITOR with comment
# -------------------------------------------------------
print("Test 5: classify as MONITOR with comment...")
aid5 = _make_alert()
db.update_alert_classify(aid5, "MONITOR", "Watching for recurrence.")
row = db.get_alert_by_id(aid5)
assert row["status"] == "MONITOR", f"Expected MONITOR, got {row['status']}"
assert row["analyst_comment"] == "Watching for recurrence."
print("  status=MONITOR, comment saved  PASS")


# -------------------------------------------------------
# Test 6: COALESCE -- None does not overwrite existing comment
# -------------------------------------------------------
print("Test 6: re-classify with None comment does not wipe existing comment...")
aid6 = _make_alert()
db.update_alert_classify(aid6, "MONITOR", "Original note.")
db.update_alert_classify(aid6, "RESOLVED", None)
row = db.get_alert_by_id(aid6)
assert row["status"] == "RESOLVED"
assert row["analyst_comment"] == "Original note.", \
    f"Comment was wiped, got: {row['analyst_comment']}"
print("  existing comment preserved when None passed  PASS")


# -------------------------------------------------------
# Test 7: _migrate() is idempotent -- initialize() twice is safe
# -------------------------------------------------------
print("Test 7: calling initialize() twice does not raise...")
try:
    db.initialize()
    db.initialize()
    print("  no exception on double initialize  PASS")
except Exception as e:
    assert False, f"initialize() raised on second call: {e}"


# -------------------------------------------------------
# Test 8: existing data survives a migration re-run
# -------------------------------------------------------
print("Test 8: alert data survives a migration re-run...")
aid8 = _make_alert(comment="Pre-existing note.")
db.initialize()
row = db.get_alert_by_id(aid8)
assert row is not None, "Alert disappeared after migration re-run"
assert row["analyst_comment"] == "Pre-existing note.", \
    f"Comment lost after migration: {row['analyst_comment']}"
print("  alert and comment intact after migration re-run  PASS")


# -------------------------------------------------------
# Cleanup
# -------------------------------------------------------
if os.path.exists(_TEST_DB):
    os.remove(_TEST_DB)

print()
print("All tests passed.")
