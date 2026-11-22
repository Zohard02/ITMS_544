import datetime as dt
import pytest
from tests.unit.conftest import HDR, load_service

TODAY = dt.date.today(); PAST = (TODAY - dt.timedelta(days=1)).isoformat(); FUT = (TODAY + dt.timedelta(days=5)).isoformat()
ST_OK = dict(iam_exists=True, mfa=True, console=True, groups=["TechTeam"], active_keys=0)

@pytest.mark.parametrize("reg,st,label,tone", [
    (None, dict(iam_exists=True), "UNTRACKED", "bad"),
    ({"status": "failed"}, dict(iam_exists=True), "FAILED", "bad"),
    ({"status": "provisioning"}, dict(iam_exists=False), "FAILED", "bad"),
    ({"status": "active", "mfa_deadline": FUT}, dict(iam_exists=False), "MISSING", "bad"),
    ({"status": "active", "mfa_deadline": FUT}, {**ST_OK, "mfa": False}, "MFA PENDING", "warn"),
    ({"status": "active", "mfa_deadline": PAST}, {**ST_OK, "mfa": False}, "MFA OVERDUE", "bad"),
    ({"status": "active", "mfa_deadline": PAST}, ST_OK, "OK", "ok"),
    ({"status": "offboarded"}, dict(iam_exists=True, console=False, groups=[], active_keys=0), "CLOSED", "muted"),
    ({"status": "offboarded"}, dict(iam_exists=True, console=False, groups=[], active_keys=1), "DRIFT", "bad"),
    ({"status": "offboarded"}, dict(iam_exists=True, console=True, groups=[], active_keys=0), "DRIFT", "bad"),
    ({"status": "offboarded"}, dict(iam_exists=True, console=False, groups=["TechTeam"], active_keys=0), "DRIFT", "bad"),
    ({"status": "offboarded"}, dict(iam_exists=False), "CLOSED", "muted"),
])
def test_health_table(aws, reg, st, label, tone):
    assert load_service("dashboard").health(reg, st) == (label, tone)

def test_api_requires_token(dashboard):
    assert dashboard.get("/api/employees").status_code == 401

def test_empty_org(dashboard):
    d = dashboard.get("/api/employees", headers=HDR).get_json()
    assert d["employees"] == [] and d["summary"]["total"] == 0

def test_summary_counts_and_cache(aws, dashboard):
    on = load_service("onboarding").app.test_client(); off = load_service("offboarding").app.test_client()
    for n, p in (("ann", "developer"), ("bob", "finance"), ("cat", "hr")):
        on.post("/onboard", json={"username": n, "full_name": n, "email": "x@y.z", "persona": p}, headers=HDR)
    off.post("/offboard", json={"username": "cat"}, headers=HDR)
    d = dashboard.get("/api/employees?refresh=1", headers=HDR).get_json()
    s = d["summary"]; assert (s["total"], s["active"], s["offboarded"], s["no_mfa"]) == (3, 2, 1, 2)
    on.post("/onboard", json={"username": "dan", "full_name": "d", "email": "x@y.z", "persona": "hr"}, headers=HDR)
    assert dashboard.get("/api/employees", headers=HDR).get_json()["summary"]["total"] == 3         # cached
    assert dashboard.get("/api/employees?refresh=1", headers=HDR).get_json()["summary"]["total"] == 4

def test_mfa_enrolled_user_becomes_ok(aws, dashboard):
    on = load_service("onboarding").app.test_client()
    on.post("/onboard", json={"username": "ann", "full_name": "a", "email": "x@y.z", "persona": "developer"}, headers=HDR)
    rows = lambda: {e["username"]: e for e in dashboard.get("/api/employees?refresh=1", headers=HDR).get_json()["employees"]}
    assert rows()["ann"]["health"] == "MFA PENDING"
    serial = aws["iam"].create_virtual_mfa_device(VirtualMFADeviceName="ann")["VirtualMFADevice"] ["SerialNumber"]
    aws["iam"].enable_mfa_device(UserName="ann", SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321")
    r = rows()["ann"]; assert r["health"] == "OK" and r["iam"]["mfa"] is True

def test_paginates_over_100_users(aws, dashboard):
    for i in range(120):
        aws["iam"].create_user(UserName=f"u{i:03d}", Path="/nimbus/")
    d = dashboard.get("/api/employees?refresh=1", headers=HDR).get_json()
    assert d["summary"]["total"] == 120 and all(e["health"] == "UNTRACKED" for e in d["employees"])

def test_lab_user_outside_path_is_not_listed(aws, dashboard):
    aws["iam"].create_user(UserName="lab-user")                                   # path "/"
    assert dashboard.get("/api/employees?refresh=1", headers=HDR).get_json()["employees"] == []
