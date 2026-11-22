import json, string
import pytest
from tests.unit.conftest import HDR, load_service

GOOD = dict(username="alice", full_name="Alice A", email="a@x.io", persona="developer")

def test_temp_password_is_strong_and_random(aws):
    tp = load_service("onboarding").temp_password
    pws = {tp() for _ in range(50)}
    assert len(pws) == 50
    for p in pws:
        assert len(p) == 20
        assert any(c in string.ascii_lowercase for c in p) and any(c in string.ascii_uppercase for c in p)
        assert any(c in string.digits for c in p) and any(c in "!@#$%^&*()_+-=" for c in p)

@pytest.mark.parametrize("name", ["a", "ab", "1abc", "has space", "x" * 40, "a@b", "", "../etc"])
def test_bad_usernames_rejected(onboarding, name):
    r = onboarding.post("/onboard", json={**GOOD, "username": name}, headers=HDR)
    assert r.status_code == 400

@pytest.mark.parametrize("field,val", [("persona", "wizard"), ("email", "no-at-sign"), ("full_name", "")])
def test_other_validation(onboarding, field, val):
    assert onboarding.post("/onboard", json={**GOOD, field: val}, headers=HDR).status_code == 400

def test_requires_token(onboarding):
    assert onboarding.post("/onboard", json=GOOD).status_code == 401

def test_creates_user_with_guard_group_tags(onboarding, aws):
    r = onboarding.post("/onboard", json=GOOD, headers=HDR); assert r.status_code == 201
    iam = aws["iam"]
    assert iam.get_user(UserName="alice")["User"]["Path"] == "/nimbus/"
    assert [g["GroupName"] for g in iam.list_groups_for_user(UserName="alice")["Groups"]] == ["TechTeam"]
    assert [p["PolicyName"] for p in iam.list_attached_user_policies(UserName="alice")["AttachedPolicies"]] == ["Nimbus-RequireMFA"]
    tags = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName="alice")["Tags"]}
    assert tags["persona"] == "developer" and tags["status"] == "active" and tags["managed-by"] == "lab02"

def test_password_returned_once_never_stored(onboarding, aws):
    body = onboarding.post("/onboard", json=GOOD, headers=HDR).get_json()
    pw = body["temp_password"]; assert pw
    for o in aws["s3"].list_objects_v2(Bucket="nimbus-test")["Contents"]:
        assert pw not in aws["s3"].get_object(Bucket="nimbus-test", Key=o["Key"])["Body"].read().decode()

def test_console_access_can_be_disabled(onboarding, aws):
    body = onboarding.post("/onboard", json={**GOOD, "console_access": False}, headers=HDR).get_json()
    assert body["temp_password"] is None
    with pytest.raises(Exception): aws["iam"].get_login_profile(UserName="alice")

def test_duplicate_is_409(onboarding):
    onboarding.post("/onboard", json=GOOD, headers=HDR)
    assert onboarding.post("/onboard", json=GOOD, headers=HDR).status_code == 409

def test_registry_status_active_and_deadline(onboarding, aws):
    onboarding.post("/onboard", json=GOOD, headers=HDR)
    rec = aws["nimbus"].get_employee("alice")
    assert rec["status"] == "active" and rec["group"] == "TechTeam" and rec["mfa_deadline"] > rec["onboarded_at"][:10]

def test_failed_run_is_recorded_and_can_resume(onboarding, aws):
    aws["iam"].delete_group(GroupName="TechTeam")                       # make step 3 fail
    r = onboarding.post("/onboard", json=GOOD, headers=HDR)
    assert r.status_code == 502 and "create-user" in r.get_json()["steps"]
    assert aws["nimbus"].get_employee("alice")["status"] == "failed"
    aws["iam"].create_group(GroupName="TechTeam", Path="/nimbus/")
    assert onboarding.post("/onboard", json=GOOD, headers=HDR).status_code == 201   # resumes
    assert aws["nimbus"].get_employee("alice")["status"] == "active"

def test_username_is_normalised_to_lowercase(onboarding, aws):
    assert onboarding.post("/onboard", json={**GOOD, "username": "  Alice "}, headers=HDR).get_json() ["username"] == "alice"
