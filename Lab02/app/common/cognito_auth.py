"""Administrator sign in with Amazon Cognito and JSON Web Tokens (JWT).

WHY THIS EXISTS. Lab01 kept one admin password in a secret and compared it by hand. Here the web console in the
PUBLIC subnet no longer knows any password at all:

  1. The admin signs in to a Cognito user pool (password plus an authenticator app code, MFA is mandatory).
  2. Cognito answers with signed tokens. The ACCESS token is a JWT: three base64 parts (header.payload.signature),
     signed with Cognito's private key. Anyone can check the signature with the pool's PUBLIC keys (the JWKS).
  3. The web service sends the JWT to the private services. Each one verifies it on its own: signature,
     issuer, expiry, token type, app client and group membership. A stolen password alone is useless without the
     MFA code, and a forged or expired token is refused by every service, not only by the front door.

The sign in calls to Cognito are PUBLIC API operations: they need no AWS credentials, so they are sent unsigned
and the web instance's IAM role does not need a single Cognito permission.
"""
import os, threading
import boto3, jwt
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

ADMIN_GROUP = "admins"
_lock = threading.Lock()
_jwks = None


class AuthError(Exception):
    """Raised for any sign in or token problem. The message is safe to log, never shown in detail to the user."""


def pool_id():
    return os.environ.get("COGNITO_USER_POOL_ID", "")


def client_id():
    return os.environ.get("COGNITO_CLIENT_ID", "")


def region():
    return os.environ.get("AWS_REGION", "us-east-2")


def enabled():
    """True when a pool is configured. Services fail CLOSED when it is not (see the web service)."""
    return bool(pool_id() and client_id())


def issuer():
    return f"https://cognito-idp.{region()}.amazonaws.com/{pool_id()}"


# ---------- verifying a token ----------
def _jwks_client():
    global _jwks
    with _lock:
        if _jwks is None:
            _jwks = jwt.PyJWKClient(issuer() + "/.well-known/jwks.json", cache_keys=True, lifespan=3600, timeout=5)
        return _jwks


def verify_jwt(token, required_group=ADMIN_GROUP):
    """Return the claims of a valid ACCESS token or raise AuthError."""
    if not enabled():
        raise AuthError("cognito is not configured")
    if not token or token.count(".") != 2:
        raise AuthError("malformed token")
    try:
        key = _jwks_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"],               # a fixed list: "alg: none" and HS256 tricks are refused
            issuer=issuer(),                                # must come from OUR pool
            options={"require": ["exp", "iat", "iss", "sub"]})
    except (jwt.PyJWTError, BotoCoreError, OSError) as e:
        raise AuthError(f"token rejected: {e.__class__.__name__}")
    if claims.get("token_use") != "access":                 # an ID token must not be accepted as an access token
        raise AuthError("not an access token")
    if claims.get("client_id") != client_id():              # must have been issued to OUR app client
        raise AuthError("wrong app client")
    if required_group and required_group not in claims.get("cognito:groups", []):
        raise AuthError("not in the required group")
    return claims


# ---------- signing in ----------
def _idp():
    return boto3.client("cognito-idp", region_name=region(),
                        config=Config(signature_version=UNSIGNED, retries={"max_attempts": 3}))


def _result(resp, username):
    """Turn a Cognito reply into one of three states: tokens (done), totp (ask for a code), setup (enrol an app)."""
    if "AuthenticationResult" in resp:
        return {"state": "tokens", "access_token": resp["AuthenticationResult"]["AccessToken"]}
    ch = resp.get("ChallengeName")
    if ch == "SOFTWARE_TOKEN_MFA":
        return {"state": "totp", "session": resp["Session"], "username": username}
    if ch == "MFA_SETUP":
        secret = _idp().associate_software_token(Session=resp["Session"])
        return {"state": "setup", "session": secret["Session"], "secret": secret["SecretCode"], "username": username}
    raise AuthError(f"unexpected challenge {ch}")


def start_login(username, password):
    try:
        resp = _idp().initiate_auth(
            ClientId=client_id(), AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password})
        return _result(resp, username)
    except ClientError as e:
        raise AuthError(e.response["Error"]["Code"])


def answer_totp(pending, code):
    """Second factor for an enrolled admin."""
    try:
        resp = _idp().respond_to_auth_challenge(
            ClientId=client_id(), ChallengeName="SOFTWARE_TOKEN_MFA", Session=pending["session"],
            ChallengeResponses={"USERNAME": pending["username"], "SOFTWARE_TOKEN_MFA_CODE": code})
        return _result(resp, pending["username"])
    except ClientError as e:
        raise AuthError(e.response["Error"]["Code"])


def finish_setup(pending, code):
    """First sign in: prove the authenticator app works by sending one code, then Cognito finishes the login."""
    try:
        v = _idp().verify_software_token(Session=pending["session"], UserCode=code, FriendlyDeviceName="admin-phone")
        if v.get("Status") != "SUCCESS":
            raise AuthError("code not accepted")
        resp = _idp().respond_to_auth_challenge(
            ClientId=client_id(), ChallengeName="MFA_SETUP", Session=v["Session"],
            ChallengeResponses={"USERNAME": pending["username"]})
        return _result(resp, pending["username"])
    except ClientError as e:
        raise AuthError(e.response["Error"]["Code"])
