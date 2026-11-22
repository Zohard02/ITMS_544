import re
from unittest import mock
import pytest
from tests.unit.conftest import load_service

def login(c, pw="pw", code="123456"):
    """Both steps of the Cognito sign in: password, then the authenticator code."""
    r = c.post("/login", data={"username": "admin", "password": pw})
    if r.status_code == 302 and "/mfa" in r.headers["Location"]:
        return c.post("/mfa", data={"code": code}, follow_redirects=True)
    return c.post("/login", data={"username": "admin", "password": pw}, follow_redirects=True)

def csrf(c, page="/onboard"):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(page).get_data(as_text=True)).group(1)

def test_redirects_when_logged_out(web):
    for p in ("/", "/dashboard", "/onboard", "/offboard"):
        assert web.get(p).status_code == 302 and "/login" in web.get(p).headers["Location"]

def test_healthz_is_open(web):
    assert web.get("/healthz").get_json()["service"] == "web"

def test_wrong_password_rejected(web):
    assert "Invalid credentials" in login(web, "bad").get_data(as_text=True)

def test_login_then_pages_render(web):
    with mock.patch.object(load_service("web"), "call", return_value=(200, {"summary": {}, "employees": [], "generated_at": ""})):
        assert login(web).status_code == 200
        for p in ("/dashboard", "/onboard", "/offboard"):
            assert web.get(p).status_code == 200

def test_post_without_csrf_is_400(web):
    with mock.patch.object(load_service("web"), "call", return_value=(200, {"summary": {}, "employees": []})):
        login(web)
        assert web.post("/onboard", data={"username": "x"}).status_code == 400
        assert web.post("/offboard", data={"username": "x"}).status_code == 400

def test_onboard_shows_one_time_password(web):
    m = load_service("web")
    fake = {"username": "x", "group": "TechTeam", "steps": ["a"], "temp_password": "S3cr3t!pw", "mfa_deadline": "2030-01-01"}
    with mock.patch.object(m, "call", return_value=(200, {"summary": {}, "employees": []})):
        login(web); tok = csrf(web)
    with mock.patch.object(m, "call", return_value=(201, fake)):
        html = web.post("/onboard", data={"csrf": tok, "username": "x", "full_name": "X", "email": "a@b.c", "persona": "developer"}).get_data(as_text=True)
    assert "S3cr3t!pw" in html and "One-time console password" in html

def test_backend_error_is_flashed(web):
    m = load_service("web")
    with mock.patch.object(m, "call", return_value=(200, {"summary": {}, "employees": []})):
        login(web); tok = csrf(web)
    with mock.patch.object(m, "call", return_value=(409, {"error": "already exists"})):
        assert "already exists" in web.post("/onboard", data={"csrf": tok, "username": "x"}).get_data(as_text=True)

def test_logout_clears_session(web):
    with mock.patch.object(load_service("web"), "call", return_value=(200, {"summary": {}, "employees": [], "generated_at": ""})):
        login(web); tok = csrf(web)
        web.post("/logout", data={"csrf": tok})
        assert web.get("/dashboard").status_code == 302

def test_service_down_shows_error_not_500(web):
    with mock.patch.object(load_service("web"), "call", return_value=(503, {"error": "dashboard service unavailable"})):
        login(web)
        r = web.get("/dashboard"); assert r.status_code == 200 and "unavailable" in r.get_data(as_text=True)


def test_security_headers_present(web):
    r = web.get("/login")
    h = r.headers
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"] and h["Cache-Control"] == "no-store"
    assert h["Referrer-Policy"] == "no-referrer"

def test_session_cookie_flags(web):
    m = load_service("web"); assert m.app.config["SESSION_COOKIE_HTTPONLY"] and m.app.config["SESSION_COOKIE_SAMESITE"] == "Strict"

def test_hsts_and_secure_cookie_only_when_tls_enabled(web):
    m = load_service("web")
    assert "Strict-Transport-Security" not in web.get("/login").headers
    m.app.config["SESSION_COOKIE_SECURE"] = True
    try: assert "Strict-Transport-Security" in web.get("/login", base_url="https://localhost").headers
    finally: m.app.config["SESSION_COOKIE_SECURE"] = False

def test_lockout_after_five_failures_and_logged(web, capsys):
    m = load_service("web"); m._fails.clear()
    for i in range(5):
        assert "Invalid credentials" in web.post("/login", data={"username": "admin", "password": "bad"}).get_data(as_text=True)
    r = web.post("/login", data={"username": "admin", "password": "pw"})       # even the right password is refused now
    assert r.status_code == 429
    out = capsys.readouterr().out
    assert out.count('"event": "login_failed"') == 5 and "login_locked_out" in out
    m._fails.clear()

def test_successful_login_resets_counter_and_is_logged(web, capsys):
    m = load_service("web"); m._fails.clear()
    web.post("/login", data={"username": "admin", "password": "bad"})
    assert web.post("/login", data={"username": "admin", "password": "pw"}).status_code == 302
    assert web.post("/mfa", data={"code": "123456"}).status_code == 302
    assert "login_success" in capsys.readouterr().out and not m._fails


# ---- Cognito / JWT specific behaviour of the console ----
def test_password_alone_is_not_enough(web):
    r = web.post("/login", data={"username": "admin", "password": "pw"})
    assert r.status_code == 302 and "/mfa" in r.headers["Location"]
    assert web.get("/dashboard").status_code == 302 and "/login" in web.get("/dashboard").headers["Location"]

def test_wrong_authenticator_code_is_rejected(web):
    web.post("/login", data={"username": "admin", "password": "pw"})
    assert "Invalid credentials" in web.post("/mfa", data={"code": "000000"}).get_data(as_text=True)
    assert web.get("/dashboard").status_code == 302

def test_first_sign_in_shows_secret_for_authenticator_app(web, idp):
    idp.enrolled = False
    web.post("/login", data={"username": "admin", "password": "pw"})
    html = web.get("/mfa").get_data(as_text=True)
    assert "ABCDEFSECRET" in html and "otpauth://totp/" in html
    assert web.post("/mfa", data={"code": "123456"}).status_code == 302

def test_mfa_page_without_a_started_login_goes_back_to_login(web):
    assert "/login" in web.get("/mfa").headers["Location"]

def test_expired_jwt_ends_the_session(web, cog):
    m = load_service("web")
    with mock.patch.object(m, "call", return_value=(200, {"summary": {}, "employees": [], "generated_at": ""})):
        login(web)
        with web.session_transaction() as s:
            s["jwt"] = cog.make(exp=1700000000, iat=1690000000)      # long expired
        assert web.get("/dashboard").status_code == 302

def test_session_with_a_token_from_another_key_is_refused(web, cog):
    with web.session_transaction() as s:
        s["jwt"] = cog.make(signing_key=cog.other_key); s["user"] = "admin"
    assert web.get("/dashboard").status_code == 302

def test_jwt_is_forwarded_to_the_backends(web, cog):
    m = load_service("web")
    seen = {}
    def fake_request(method, url, **kw):
        seen.update(kw["headers"])
        return mock.Mock(status_code=200, json=lambda: {"summary": {}, "employees": [], "generated_at": ""})
    login(web)
    with mock.patch.object(m.requests, "request", fake_request):
        web.get("/dashboard")
    assert seen["Authorization"].startswith("Bearer ey") and seen["X-Internal-Token"]
