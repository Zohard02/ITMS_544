"""Web UI microservice - three pages (Onboard, Offboard, Dashboard). It runs in the PUBLIC subnet and
holds NO Cognito permissions and NO admin password. Administrators sign in with Amazon Cognito (password plus an authenticator app code) and receive a signed JWT. Every request is checked against that JWT, and the JWT is forwarded to the private services, which verify it again. The private services also demand mutual TLS and the internal token."""
import hmac, os, secrets, time
import requests
from flask import Flask, flash, redirect, render_template, request, session, url_for, abort
from common import cognito_auth, nimbus
from common.config import PERSONAS

app = Flask(__name__)
URLS = {"onboarding": os.environ.get("ONBOARD_URL", "http://127.0.0.1:5001"),
        "offboarding": os.environ.get("OFFBOARD_URL", "http://127.0.0.1:5002"),
        "dashboard": os.environ.get("DASHBOARD_URL", "http://127.0.0.1:5003")}
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",   # set on the server, where TLS is on
                  PERMANENT_SESSION_LIFETIME=1800)
MAX_FAILS, LOCK_SECONDS = 5, 300
_fails = {}                                    # remote address -> (count, first failure time); per worker process

@app.after_request
def security_headers(resp):
    """Browser-side defences (a small 'edge' layer, deck Module 5 and 6)."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"                      # pages can contain one-time passwords
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=86400"
    return resp


def _login():
    return nimbus.get_secret("web-login")   # only the cookie signing key is stored here now


def _load_key(tries=10):
    for i in range(tries):                      # roles/secrets may still be propagating at boot
        try:
            return _login()["flask_secret_key"]  # session-signing key lives in Parameter Store
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(3)


app.secret_key = _load_key()


@app.before_request
def guard():
    if request.endpoint in ("login", "mfa", "static", "healthz"):
        return
    try:                                           # EVERY request must carry a valid, unexpired admin JWT
        session["user"] = cognito_auth.verify_jwt(session.get("jwt", ""))["username"]
    except cognito_auth.AuthError as e:
        if session.get("jwt"):
            nimbus.log_event("session_jwt_rejected", reason=str(e), remote=request.remote_addr)
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400, "bad CSRF token")


@app.context_processor
def inject():
    session.setdefault("csrf", secrets.token_urlsafe(16))
    return {"csrf": session["csrf"], "user": session.get("user"), "personas": PERSONAS}


def call(svc, method, path, **kw):
    try:
        r = requests.request(method, URLS[svc] + path, timeout=20,
                             headers={"X-Internal-Token": nimbus.internal_token(),
                                      "Authorization": "Bearer " + session.get("jwt", "")},
                             **nimbus.internal_tls_kwargs(), **kw)
        return r.status_code, r.json()
    except (requests.RequestException, ValueError) as e:
        return 503, {"error": f"{svc} service unavailable: {e.__class__.__name__}"}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "web"}


def _locked(ip):
    n, first = _fails.get(ip, (0, 0))
    return n >= MAX_FAILS and time.time() - first < LOCK_SECONDS


def _failed(ip, what):
    n, first = _fails.get(ip, (0, 0))
    _fails[ip] = (n + 1, first if n and time.time() - first < LOCK_SECONDS else time.time())
    nimbus.log_event(what, remote=ip, attempt=_fails[ip][0])
    flash("Invalid credentials", "bad")           # one message for every failure: never say which part was wrong


def _next(result, ip):
    """Move the browser to the right step of the sign in, or finish it."""
    if result["state"] == "tokens":
        _fails.pop(ip, None)
        claims = cognito_auth.verify_jwt(result["access_token"])      # also proves the user is in the admins group
        nimbus.log_event("login_success", remote=ip, user=claims["username"])
        session.clear(); session.permanent = True
        session["jwt"] = result["access_token"]; session["user"] = claims["username"]
        return redirect(url_for("dashboard"))
    session.clear()
    session["pending"] = result                   # a short lived Cognito challenge, useless without the code
    return redirect(url_for("mfa"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if _locked(ip):
            nimbus.log_event("login_locked_out", remote=ip)
            flash("Too many failed attempts. Try again in a few minutes.", "bad")
            return render_template("login.html"), 429
        try:
            return _next(cognito_auth.start_login(request.form.get("username", ""), request.form.get("password", "")), ip)
        except cognito_auth.AuthError:
            _failed(ip, "login_failed")
    return render_template("login.html")


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    pending = session.get("pending")
    if not pending:
        return redirect(url_for("login"))
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if _locked(ip):
            flash("Too many failed attempts. Try again in a few minutes.", "bad")
            return render_template("login.html"), 429
        code = request.form.get("code", "").strip()
        try:
            step = cognito_auth.finish_setup if pending["state"] == "setup" else cognito_auth.answer_totp
            return _next(step(pending, code), ip)
        except cognito_auth.AuthError:
            _failed(ip, "mfa_failed")
            session["pending"] = pending
    uri = ""
    if pending["state"] == "setup":
        uri = f"otpauth://totp/Nimbus:{pending['username']}?secret={pending['secret']}&issuer=Nimbus"
    return render_template("mfa.html", setup=pending["state"] == "setup", secret=pending.get("secret"), uri=uri)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/onboard", methods=["GET", "POST"])
def onboard():
    result = None
    if request.method == "POST":
        f = request.form
        code, body = call("onboarding", "POST", "/onboard", json={
            "username": f.get("username"), "full_name": f.get("full_name"), "email": f.get("email"),
            "persona": f.get("persona"), "console_access": f.get("console_access") == "on",
            "actor": session["user"]})
        if code == 201:
            result = body                       # contains the one-time password
        else:
            flash(body.get("error", "Onboarding failed"), "bad")
    return render_template("onboard.html", result=result)


@app.route("/offboard", methods=["GET", "POST"])
def offboard():
    if request.method == "POST":
        code, body = call("offboarding", "POST", "/offboard", json={
            "username": request.form.get("username"), "reason": request.form.get("reason", ""),
            "actor": session["user"]})
        if code == 200:
            flash(f"Offboarded {body['username']}: " + ", ".join(body["steps"]), "ok")
        else:
            flash(body.get("error", "Offboarding failed"), "bad")
        return redirect(url_for("offboard"))
    code, data = call("dashboard", "GET", "/api/employees", params={"refresh": 1})
    active = [e for e in data.get("employees", []) if e["status"] == "active"] if code == 200 else []
    if code != 200:
        flash(data.get("error", "Could not load employees"), "bad")
    return render_template("offboard.html", active=active)


@app.get("/dashboard")
def dashboard():
    code, data = call("dashboard", "GET", "/api/employees",
                      params={"refresh": 1} if request.args.get("refresh") else {})
    if code != 200:
        flash(data.get("error", "Dashboard service error"), "bad")
        data = {"summary": {}, "employees": [], "generated_at": ""}
    return render_template("dashboard.html", d=data)
