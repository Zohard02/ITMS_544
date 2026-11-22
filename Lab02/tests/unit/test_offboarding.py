from tests.unit.conftest import HDR
import pytest, boto3
from botocore.exceptions import ClientError

def mk(c, name="carol", persona="finance"):
    assert c.post("/onboard", json={"username": name, "full_name": "C", "email": "c@x.io", "persona": persona}, headers=HDR).status_code == 201

@pytest.fixture
def both(aws):
    from tests.unit.conftest import load_service
    return load_service("onboarding").app.test_client(), load_service("offboarding").app.test_client()

def test_unknown_user_404_and_token_required(both):
    on, off = both
    assert off.post("/offboard", json={"username": "ghost"}, headers=HDR).status_code == 404
    assert off.post("/offboard", json={"username": "ghost"}).status_code == 401

def test_offboard_removes_every_access_path(both, aws):
    on, off = both; mk(on); iam = aws["iam"]
    iam.create_access_key(UserName="carol"); iam.create_access_key(UserName="carol")
    r = off.post("/offboard", json={"username": "carol", "reason": "left"}, headers=HDR); assert r.status_code == 200
    assert iam.list_groups_for_user(UserName="carol")["Groups"] == []
    assert all(k["Status"] == "Inactive" for k in iam.list_access_keys(UserName="carol")["AccessKeyMetadata"])
    with pytest.raises(ClientError): iam.get_login_profile(UserName="carol")
    names = [p["PolicyName"] for p in iam.list_attached_user_policies(UserName="carol")["AttachedPolicies"]]
    assert "Nimbus-DenyAll" in names
    tags = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName="carol")["Tags"]}
    assert tags["status"] == "offboarded" and "offboarded" in tags

def test_user_is_kept_for_audit_not_deleted(both, aws):
    on, off = both; mk(on); off.post("/offboard", json={"username": "carol"}, headers=HDR)
    assert aws["iam"].get_user(UserName="carol")["User"]["UserName"] == "carol"

def test_registry_and_audit_updated(both, aws):
    on, off = both; mk(on); off.post("/offboard", json={"username": "carol", "reason": "r", "actor": "admin"}, headers=HDR)
    rec = aws["nimbus"].get_employee("carol")
    assert rec["status"] == "offboarded" and rec["offboard_reason"] == "r" and rec["offboarded_by"] == "admin"
    keys = [o["Key"] for o in aws["s3"].list_objects_v2(Bucket="nimbus-test", Prefix="audit/")["Contents"]]
    assert any("-offboard-carol" in k for k in keys)

def test_second_offboard_is_409(both):
    on, off = both; mk(on)
    off.post("/offboard", json={"username": "carol"}, headers=HDR)
    assert off.post("/offboard", json={"username": "carol"}, headers=HDR).status_code == 409

def test_user_without_console_or_keys_is_fine(both, aws):
    on, off = both
    on.post("/onboard", json={"username": "dave", "full_name": "D", "email": "d@x.io", "persona": "devops", "console_access": False}, headers=HDR)
    assert off.post("/offboard", json={"username": "dave"}, headers=HDR).status_code == 200
