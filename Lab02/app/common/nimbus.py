"""Helpers shared by all four services.

* aws_session()  - every service runs on its OWN EC2 instance, and that instance has its
                   OWN IAM role (instance profile). boto3 finds the role by itself through
                   the instance metadata service (IMDSv2). No keys, no AssumeRole.
* get_secret()   - reads from SSM Parameter Store (SecureString). Nothing secret in the code.
* registry/audit - JSON documents in S3 (the "database" of this lab).
* require_internal_token - service-to-service authentication (on top of mutual TLS).
* cognito_auth.verify_jwt - the signed in admin (JWT), checked by every service when Cognito is configured.
* internal_tls_kwargs()  - the client certificate settings the web service uses to call the others.
"""
import functools, hmac, json, os, sys, threading, time, datetime as dt
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from flask import jsonify, request

REGION = os.environ.get("AWS_REGION", "us-east-2")
BUCKET = os.environ.get("NIMBUS_BUCKET", "")
PARAM_PREFIX = os.environ.get("NIMBUS_PARAM_PREFIX", "/nimbus").rstrip("/")
_CFG = Config(region_name=REGION, retries={"max_attempts": 5, "mode": "standard"})

_lock = threading.Lock()
_session = None
_account = None


def aws_session():
    """boto3 session that uses the credentials of THIS instance's role (refreshed automatically)."""
    global _session
    with _lock:
        if _session is None:
            _session = boto3.Session(region_name=REGION)
        return _session


def client(name):
    return aws_session().client(name, config=_CFG)


def account_id():
    global _account
    if _account is None:
        _account = client("sts").get_caller_identity()["Account"]
    return _account


def whoami():
    return client("sts").get_caller_identity()["Arn"]


# ---------- structured logging (written to /var/log/nimbus/app.log and shipped to CloudWatch Logs by the CloudWatch agent) ----------
SERVICE = os.environ.get("SERVICE_NAME", "app")
SENSITIVE = ("password", "token", "secret", "key")

def log_event(event, **fields):
    """One JSON line on stdout. Never pass secrets: values of sensitive-looking keys are masked."""
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "service": SERVICE, "event": event}
    for k, v in fields.items():
        rec[k] = "***" if any(s in k.lower() for s in SENSITIVE) else v
    print(json.dumps(rec, default=str), file=sys.stdout, flush=True)


# ---------- SSM Parameter Store (SecureString, default AWS managed key: free) ----------
_secret_cache = {}
SECRET_TTL = 60          # seconds: short, so a rotated secret is picked up quickly
TOKEN_CURRENT = "internal-token/current"
TOKEN_PREVIOUS = "internal-token/previous"


def get_secret(name, ttl=SECRET_TTL):
    """name is relative to the parameter prefix, for example 'web-login' -> /nimbus/web-login."""
    hit = _secret_cache.get(name)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    raw = client("ssm").get_parameter(Name=f"{PARAM_PREFIX}/{name}", WithDecryption=True)["Parameter"] ["Value"]
    try:
        val = json.loads(raw)
    except ValueError:
        val = raw
    _secret_cache[name] = (time.time(), val)
    return val


def internal_token():
    return str(get_secret(TOKEN_CURRENT))


def _accepted_tokens(refresh=False):
    ttl = 0 if refresh else SECRET_TTL
    toks = [str(get_secret(TOKEN_CURRENT, ttl=ttl))]
    try:                                         # the previous token stays valid during a rotation
        toks.append(str(get_secret(TOKEN_PREVIOUS, ttl=ttl)))
    except ClientError:
        pass
    return toks


def internal_tls_kwargs():
    """requests keyword arguments for calling another service over mutual TLS.
    Empty (plain http, for local development) unless INTERNAL_CA is set."""
    ca = os.environ.get("INTERNAL_CA")
    if not ca:
        return {}
    return {"verify": ca, "cert": (os.environ["INTERNAL_CLIENT_CERT"], os.environ["INTERNAL_CLIENT_KEY"])}


_last_refresh = [0.0]


def require_internal_token(fn):
    """Service-to-service auth. Accepts the current AND previous token version so that
    rotating the secret never causes an outage; unknown tokens are logged and rejected."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        supplied = request.headers.get("X-Internal-Token", "").encode()
        ok = any(hmac.compare_digest(supplied, t.encode()) for t in _accepted_tokens())
        if not ok and time.time() - _last_refresh[0] > 5:       # maybe our cache is stale: refresh once
            _last_refresh[0] = time.time()
            ok = any(hmac.compare_digest(supplied, t.encode()) for t in _accepted_tokens(refresh=True))
            if ok:
                log_event("internal_token_refreshed")
        if not ok:
            log_event("internal_auth_rejected", path=request.path, remote=request.remote_addr)
            return jsonify(error="unauthorized"), 401
        # Second check: the signed in ADMIN. Both must pass: the service token proves the CALLER is our web
        # service, the JWT proves a real admin is behind the request.
        from common import cognito_auth
        if cognito_auth.enabled():
            bearer = request.headers.get("Authorization", "")
            try:
                claims = cognito_auth.verify_jwt(bearer[7:] if bearer.startswith("Bearer ") else "")
            except cognito_auth.AuthError as e:
                log_event("jwt_rejected", path=request.path, reason=str(e), remote=request.remote_addr)
                return jsonify(error="unauthorized"), 401
            request.environ["nimbus.jwt_user"] = claims.get("username", "")
        return fn(*a, **k)
    return wrapper


# ---------- S3 registry + audit log ----------
def now():
    return dt.datetime.now(dt.timezone.utc)


def _key(username):
    return f"registry/{username}.json"


def put_json(key, obj):
    client("s3").put_object(Bucket=BUCKET, Key=key, ContentType="application/json",
                            Body=json.dumps(obj, indent=2, default=str).encode())


def get_json(key):
    try:
        body = client("s3").get_object(Bucket=BUCKET, Key=key)["Body"].read()
        return json.loads(body)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


def get_employee(username):
    return get_json(_key(username))


def put_employee(rec):
    put_json(_key(rec["username"]), rec)


def list_employees():
    s3 = client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix="registry/"):
        keys += [o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".json")]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(8) as ex:
        return [r for r in ex.map(get_json, keys) if r]


def audit(action, username, actor, detail=None):
    ts = now().strftime("%Y%m%dT%H%M%S%fZ")
    put_json(f"audit/{ts}-{action}-{username}.json",
             {"time": now().isoformat(), "action": action, "username": username,
              "actor": actor, "service_identity": whoami(), "detail": detail or {}})
