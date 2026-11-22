"""Onboarding microservice - creates the IAM identity (deck Module 4.4 / script 03)."""
import re, secrets, string, datetime as dt
from botocore.exceptions import ClientError
from flask import Flask, jsonify, request
from common import nimbus
from common.config import IAM_PATH, MFA_DEADLINE_DAYS, PERSONAS, SERVICE_TAG

app = Flask(__name__)
USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")


def temp_password(n=20):
    sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()_+-="]
    chars = [secrets.choice(s) for s in sets] + [secrets.choice("".join(sets)) for _ in range(n - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", service="onboarding")


@app.post("/onboard")
@nimbus.require_internal_token
def onboard():
    b = request.get_json(force=True, silent=True) or {}
    username = str(b.get("username", "")).strip().lower()
    persona = str(b.get("persona", "")).strip().lower()
    full_name = str(b.get("full_name", "")).strip()[:80]
    email = str(b.get("email", "")).strip()[:120]
    actor = str(b.get("actor", "unknown"))[:40]
    console = bool(b.get("console_access", True))

    if not USERNAME_RE.match(username):
        return jsonify(error="username must be 3-32 chars: a-z 0-9 . _ - (start with a letter)"), 400
    if persona not in PERSONAS:
        return jsonify(error=f"persona must be one of {sorted(PERSONAS)}"), 400
    if not full_name or "@" not in email:
        return jsonify(error="full_name and a valid email are required"), 400
    group = PERSONAS[persona]

    existing = nimbus.get_employee(username)
    if existing and existing.get("status") in ("active", "offboarded"):
        return jsonify(error=f"{username} already exists with status '{existing['status']}'"), 409

    today = nimbus.now().date()
    deadline = (today + dt.timedelta(days=MFA_DEADLINE_DAYS)).isoformat()
    rec = {"username": username, "full_name": full_name, "email": email, "persona": persona,
           "group": group, "status": "provisioning", "onboarded_at": nimbus.now().isoformat(),
           "onboarded_by": actor, "mfa_deadline": deadline, "console_access": console}
    nimbus.put_employee(rec)           # intent is recorded BEFORE we touch IAM

    iam = nimbus.client("iam")
    acct = nimbus.account_id()
    mfa_policy = f"arn:aws:iam::{acct}:policy{IAM_PATH}Nimbus-RequireMFA"
    steps, password = [], None
    try:
        try:
            iam.create_user(UserName=username, Path=IAM_PATH, Tags=[
                {"Key": "persona", "Value": persona}, {"Key": "status", "Value": "active"},
                {"Key": "onboarded", "Value": str(today)}, {"Key": "mfa-deadline", "Value": deadline},
                {"Key": "managed-by", "Value": SERVICE_TAG}])
            steps.append("create-user")
        except ClientError as e:       # resume a previously failed attempt
            if e.response["Error"]["Code"] != "EntityAlreadyExists" or not existing:
                raise
            steps.append("create-user (already existed - resumed)")
        # Order matters (deck 5.4): MFA guard BEFORE any credential or permission exists.
        iam.attach_user_policy(UserName=username, PolicyArn=mfa_policy)
        steps.append("attach-RequireMFA")
        iam.add_user_to_group(GroupName=group, UserName=username)
        steps.append(f"add-to-group:{group}")
        if console:
            password = temp_password()
            try:
                iam.create_login_profile(UserName=username, Password=password, PasswordResetRequired=True)
                steps.append("create-login-profile (reset required)")
            except ClientError as e:
                if e.response["Error"]["Code"] != "EntityAlreadyExists":
                    raise
                password = None
                steps.append("login-profile already existed")
        rec["status"] = "active"
        nimbus.put_employee(rec)
        nimbus.audit("onboard", username, actor, {"group": group, "persona": persona, "steps": steps})
        nimbus.log_event("onboarded", username=username, group=group, actor=actor, console_access=console)
    except ClientError as e:
        rec.update(status="failed", error=e.response["Error"]["Code"], failed_after=steps)
        nimbus.put_employee(rec)
        nimbus.audit("onboard-failed", username, actor, {"error": str(e), "steps": steps})
        nimbus.log_event("onboard_failed", username=username, actor=actor, error=e.response["Error"]["Code"])
        return jsonify(error=e.response["Error"]["Message"], code=e.response["Error"]["Code"], steps=steps), 502
    # The password is returned ONCE to the caller and never stored or logged.
    return jsonify(username=username, group=group, steps=steps, temp_password=password,
                   mfa_deadline=deadline), 201
