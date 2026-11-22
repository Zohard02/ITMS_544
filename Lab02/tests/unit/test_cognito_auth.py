"""JWT verification rules, and the second check made by every private service."""
import pytest
import jwt as pyjwt
from tests.unit.conftest import HDR, load_service

GOOD = {"username": "alice", "full_name": "Alice A", "email": "a@b.co", "persona": "developer", "actor": "admin"}


def verify(cog, token, **kw):
    return cog.cognito_auth.verify_jwt(token, **kw)


def test_valid_token_is_accepted(cog):
    assert verify(cog, cog.make())["username"] == "admin"

@pytest.mark.parametrize("over", [
    {"exp": 1700000000, "iat": 1690000000},                       # expired
    {"iss": "https://cognito-idp.us-east-2.amazonaws.com/other"},  # another pool
    {"token_use": "id"},                                            # an ID token is not an access token
    {"client_id": "someone-elses-client"},                         # issued to a different app
    {"cognito:groups": ["readers"]},                                # not an admin
    {"cognito:groups": None},                                       # no groups at all
    {"exp": None},                                                  # no expiry claim
])
def test_bad_claims_are_rejected(cog, over):
    with pytest.raises(cog.cognito_auth.AuthError):
        verify(cog, cog.make(**over))

def test_token_signed_with_another_key_is_rejected(cog):
    with pytest.raises(cog.cognito_auth.AuthError):
        verify(cog, cog.make(signing_key=cog.other_key))

def test_alg_none_is_rejected(cog):
    forged = pyjwt.encode({"iss": "x", "sub": "1", "exp": 4102444800, "iat": 1}, key=None, algorithm="none")
    with pytest.raises(cog.cognito_auth.AuthError):
        verify(cog, forged)

def test_hs256_with_the_public_key_trick_is_rejected(cog):
    forged = pyjwt.encode({"iss": "x", "sub": "1", "exp": 4102444800, "iat": 1}, "secret-" * 8, algorithm="HS256")
    with pytest.raises(cog.cognito_auth.AuthError):
        verify(cog, forged)

@pytest.mark.parametrize("junk", ["", "abc", "a.b", "a.b.c.d"])
def test_garbage_is_rejected(cog, junk):
    with pytest.raises(cog.cognito_auth.AuthError):
        verify(cog, junk)

def test_not_configured_fails_closed(monkeypatch):
    from common import cognito_auth
    monkeypatch.delenv("COGNITO_USER_POOL_ID", raising=False)
    assert not cognito_auth.enabled()
    with pytest.raises(cognito_auth.AuthError):
        cognito_auth.verify_jwt("a.b.c")

def test_sign_in_flow_states(cog, idp):
    a = cog.cognito_auth
    assert a.start_login("admin", "pw")["state"] == "totp"
    with pytest.raises(a.AuthError):
        a.start_login("admin", "wrong")
    idp.enrolled = False
    st = a.start_login("admin", "pw")
    assert st["state"] == "setup" and st["secret"] == "ABCDEFSECRET"
    assert a.finish_setup(st, "123456")["state"] == "tokens"
    with pytest.raises(a.AuthError):
        a.finish_setup(st, "999999")

# ---- every private service checks the JWT as well as the internal token ----
def test_service_needs_jwt_when_cognito_is_configured(aws, cog):
    c = load_service("onboarding").app.test_client()
    assert c.post("/onboard", json=GOOD, headers=HDR).status_code == 401                         # token only
    ok = c.post("/onboard", json=GOOD, headers={**HDR, "Authorization": "Bearer " + cog.make()})
    assert ok.status_code == 201

def test_service_refuses_a_good_jwt_without_the_internal_token(aws, cog):
    c = load_service("onboarding").app.test_client()
    assert c.post("/onboard", json=GOOD, headers={"Authorization": "Bearer " + cog.make()}).status_code == 401

def test_service_refuses_a_non_admin_jwt(aws, cog):
    c = load_service("offboarding").app.test_client()
    h = {**HDR, "Authorization": "Bearer " + cog.make(**{"cognito:groups": ["readers"]})}
    assert c.post("/offboard", json={"username": "x", "actor": "a"}, headers=h).status_code == 401

def test_dashboard_refuses_forged_jwt(aws, cog):
    m = load_service("dashboard"); m._cache.update(t=0, data=None)
    h = {**HDR, "Authorization": "Bearer " + cog.make(signing_key=cog.other_key)}
    assert m.app.test_client().get("/api/employees", headers=h).status_code == 401
