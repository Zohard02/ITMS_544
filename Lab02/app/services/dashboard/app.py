"""Dashboard microservice - read-only view that RECONCILES the registry (what we
think exists) with live IAM (what really exists). Differences = security findings."""
import threading, time, datetime as dt
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError
from flask import Flask, jsonify, request
from common import nimbus
from common.config import IAM_PATH

app = Flask(__name__)
_cache = {"t": 0, "data": None}
_lock = threading.Lock()
TTL = 15  # seconds - protects the IAM API rate limits as the org grows to 100+


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", service="dashboard")


def _list(fn, key, **kw):
    out = []
    for page in nimbus.client("iam").get_paginator(fn).paginate(**kw):
        out += page[key]
    return out


def iam_state(username):
    iam = nimbus.client("iam")
    try:
        iam.get_user(UserName=username)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return {"iam_exists": False}
        raise
    try:
        iam.get_login_profile(UserName=username); console = True
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        console = False
    keys = _list("list_access_keys", "AccessKeyMetadata", UserName=username)
    return {"iam_exists": True, "console": console,
            "groups": [g["GroupName"] for g in _list("list_groups_for_user", "Groups", UserName=username)],
            "mfa": len(_list("list_mfa_devices", "MFADevices", UserName=username)) > 0,
            "active_keys": sum(k["Status"] == "Active" for k in keys),
            "policies": [p["PolicyName"] for p in
                         _list("list_attached_user_policies", "AttachedPolicies", UserName=username)]}


def health(reg, st):
    today = dt.date.today().isoformat()
    if reg is None:
        return "UNTRACKED", "bad"     # IAM user exists under /nimbus/ but nobody onboarded it
    s = reg["status"]
    if s in ("failed", "provisioning"):
        return "FAILED", "bad"
    if s == "offboarded":
        if st.get("iam_exists") and (st.get("active_keys") or st.get("console") or st.get("groups")):
            return "DRIFT", "bad"     # offboarded but access still alive
        return "CLOSED", "muted"
    if not st.get("iam_exists"):
        return "MISSING", "bad"
    if not st["mfa"]:
        return ("MFA OVERDUE", "bad") if reg.get("mfa_deadline", "9999") < today else ("MFA PENDING", "warn")
    return "OK", "ok"


def build():
    registry = {r["username"]: r for r in nimbus.list_employees()}
    iam_users = {u["UserName"] for u in _list("list_users", "Users", PathPrefix=IAM_PATH)}
    names = sorted(set(registry) | iam_users)
    with ThreadPoolExecutor(8) as ex:
        states = dict(zip(names, ex.map(iam_state, names)))
    rows = []
    for n in names:
        reg, st = registry.get(n), states[n]
        label, tone = health(reg, st)
        rows.append({"username": n, "full_name": (reg or {}).get("full_name", "-"),
                     "persona": (reg or {}).get("persona", "-"),
                     "status": (reg or {}).get("status", "untracked"),
                     "onboarded_at": (reg or {}).get("onboarded_at", ""),
                     "offboarded_at": (reg or {}).get("offboarded_at", ""),
                     "mfa_deadline": (reg or {}).get("mfa_deadline", ""),
                     "iam": st, "health": label, "tone": tone})
    summary = {"total": len(rows),
               "active": sum(r["status"] == "active" for r in rows),
               "offboarded": sum(r["status"] == "offboarded" for r in rows),
               "attention": sum(r["tone"] in ("bad", "warn") for r in rows),
               "no_mfa": sum(r["status"] == "active" and r["iam"].get("iam_exists") and not r["iam"]["mfa"] for r in rows)}
    return {"summary": summary, "employees": rows, "generated_at": nimbus.now().isoformat()}


@app.get("/api/employees")
@nimbus.require_internal_token
def employees():
    with _lock:
        if request.args.get("refresh") or not _cache["data"] or time.time() - _cache["t"] > TTL:
            _cache.update(t=time.time(), data=build())
        return jsonify(_cache["data"])
