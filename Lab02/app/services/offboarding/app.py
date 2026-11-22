"""Offboarding microservice - the same pipeline in reverse (deck Module 4.4, step 4)."""
from botocore.exceptions import ClientError
from flask import Flask, jsonify, request
from common import nimbus
from common.config import IAM_PATH

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", service="offboarding")


def _paged(fn, key, **kw):
    for page in nimbus.client("iam").get_paginator(fn).paginate(**kw):
        yield from page[key]

@app.post("/offboard")
@nimbus.require_internal_token
def offboard():
    b = request.get_json(force=True, silent=True) or {}
    username = str(b.get("username", "")).strip().lower()
    actor = str(b.get("actor", "unknown"))[:40]
    reason = str(b.get("reason", ""))[:200]
    rec = nimbus.get_employee(username)
    if not rec:
        return jsonify(error="unknown employee (not in registry)"), 404
    if rec.get("status") == "offboarded":
        return jsonify(error="already offboarded"), 409

    iam = nimbus.client("iam")
    deny_all = f"arn:aws:iam::{nimbus.account_id()}:policy{IAM_PATH}Nimbus-DenyAll"
    steps = []
    try:
        # 1. Kill switch first: an explicit Deny beats every Allow (deck 2.4).
        iam.attach_user_policy(UserName=username, PolicyArn=deny_all); steps.append("attach-DenyAll")
        # 2. Programmatic credentials -> Inactive (kept for forensics, unusable).
        for k in _paged("list_access_keys", "AccessKeyMetadata", UserName=username):
            if k["Status"] == "Active":
                iam.update_access_key(UserName=username, AccessKeyId=k["AccessKeyId"], Status="Inactive")
                steps.append(f"deactivate-key:{k['AccessKeyId'][-4:]}")
        # 3. Console password.
        try:
            iam.delete_login_profile(UserName=username); steps.append("delete-login-profile")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        # 4. Group membership (removes the Allow side).
        for g in _paged("list_groups_for_user", "Groups", UserName=username):
            iam.remove_user_from_group(GroupName=g["GroupName"], UserName=username)
            steps.append(f"remove-from-group:{g['GroupName']}")
        # 5. Tag + registry + audit.
        iam.tag_user(UserName=username, Tags=[{"Key": "status", "Value": "offboarded"},
                                              {"Key": "offboarded", "Value": str(nimbus.now().date())}])
        rec.update(status="offboarded", offboarded_at=nimbus.now().isoformat(),
                   offboarded_by=actor, offboard_reason=reason)
        nimbus.put_employee(rec)
        nimbus.audit("offboard", username, actor, {"reason": reason, "steps": steps})
        nimbus.log_event("offboarded", username=username, actor=actor, steps=len(steps))
    except ClientError as e:
        nimbus.audit("offboard-failed", username, actor, {"error": str(e), "steps": steps})
        nimbus.log_event("offboard_failed", username=username, actor=actor, error=e.response["Error"]["Code"])
        return jsonify(error=e.response["Error"]["Message"], code=e.response["Error"]["Code"], steps=steps), 502
    return jsonify(username=username, steps=steps), 200
