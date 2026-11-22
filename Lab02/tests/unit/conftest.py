"""Unit-test fixtures: an in-process mock of IAM, S3 and SSM Parameter Store (moto.mock_aws)."""
import importlib.util, json, os, sys, time, types
import boto3, jwt, pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKEN = "unit-token"
HDR = {"X-Internal-Token": TOKEN}
POOL, CLIENT = "us-east-2_TESTPOOL", "test-client-id"


@pytest.fixture
def aws():
    """Fresh fake AWS account with groups, the two guard policies, bucket and secrets."""
    with mock_aws():
        from common import nimbus
        nimbus._session = None; nimbus._account = None; nimbus._secret_cache.clear()
        iam, s3, ssm = boto3.client("iam"), boto3.client("s3"), boto3.client("ssm")
        s3.create_bucket(Bucket="nimbus-test", CreateBucketConfiguration={"LocationConstraint": "us-east-2"})
        for g in ("TechTeam", "BusinessTeam", "SecurityTeam"):
            iam.create_group(GroupName=g, Path="/nimbus/")
        deny = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
        for p in ("Nimbus-RequireMFA", "Nimbus-DenyAll"):
            iam.create_policy(PolicyName=p, Path="/nimbus/", PolicyDocument=deny)
        ssm.put_parameter(Name="/nimbus/internal-token/current", Value=TOKEN, Type="SecureString")
        ssm.put_parameter(Name="/nimbus/web-login", Type="SecureString", Value=json.dumps(
            {"flask_secret_key": "k" * 32, "admin_username": "admin", "admin_password": "pw"}))
        yield {"iam": iam, "s3": s3, "ssm": ssm, "nimbus": nimbus}


def load_service(name):
    """Import services/<name>/app.py under its own module name (must be called inside `aws`)."""
    key = f"unit_svc_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, f"{ROOT}/app/services/{name}/app.py")
    mod = importlib.util.module_from_spec(spec); sys.modules[key] = mod; spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def onboarding(aws):  return load_service("onboarding").app.test_client()
@pytest.fixture
def offboarding(aws): return load_service("offboarding").app.test_client()
@pytest.fixture
def dashboard(aws):
    m = load_service("dashboard"); m._cache.update(t=0, data=None); return m.app.test_client()
@pytest.fixture
def web(aws, cog, idp): return load_service("web").app.test_client()


# ---------- Cognito: a local key pair stands in for the user pool's signing keys, a fake client for its API ----------
@pytest.fixture
def cog(monkeypatch):
    """Configures the Cognito settings and returns make(**overrides) which signs access tokens with a local key."""
    from common import cognito_auth
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setenv("COGNITO_USER_POOL_ID", POOL); monkeypatch.setenv("COGNITO_CLIENT_ID", CLIENT)
    monkeypatch.setenv("AWS_REGION", "us-east-2")
    monkeypatch.setattr(cognito_auth, "_jwks", types.SimpleNamespace(
        get_signing_key_from_jwt=lambda t: types.SimpleNamespace(key=key.public_key())))

    def make(signing_key=None, **over):
        now = int(time.time())
        claims = {"sub": "u-1", "iss": f"https://cognito-idp.us-east-2.amazonaws.com/{POOL}", "client_id": CLIENT,
                  "token_use": "access", "username": "admin", "cognito:groups": ["admins"], "iat": now, "exp": now + 600}
        claims.update(over)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, signing_key or key, algorithm="RS256", headers={"kid": "k1"})
    return types.SimpleNamespace(make=make, other_key=other, cognito_auth=cognito_auth)


class FakeIdp:
    """Just enough of the Cognito API for the sign in flow. Password pw, authenticator code 123456."""
    def __init__(self, cog, enrolled):
        self.cog, self.enrolled = cog, enrolled

    @staticmethod
    def _err(code):
        return ClientError({"Error": {"Code": code, "Message": code}}, "op")

    def initiate_auth(self, ClientId, AuthFlow, AuthParameters):
        assert AuthFlow == "USER_PASSWORD_AUTH" and ClientId == CLIENT
        if AuthParameters["USERNAME"] != "admin" or AuthParameters["PASSWORD"] != "pw":
            raise self._err("NotAuthorizedException")
        return {"ChallengeName": "SOFTWARE_TOKEN_MFA" if self.enrolled else "MFA_SETUP", "Session": "s0"}

    def associate_software_token(self, Session):
        return {"Session": "s1", "SecretCode": "ABCDEFSECRET"}

    def verify_software_token(self, Session, UserCode, FriendlyDeviceName):
        if UserCode != "123456":
            raise self._err("EnableSoftwareTokenMFAException")
        return {"Status": "SUCCESS", "Session": "s2"}

    def respond_to_auth_challenge(self, ClientId, ChallengeName, Session, ChallengeResponses):
        if ChallengeName == "SOFTWARE_TOKEN_MFA" and ChallengeResponses["SOFTWARE_TOKEN_MFA_CODE"] != "123456":
            raise self._err("CodeMismatchException")
        return {"AuthenticationResult": {"AccessToken": self.cog.make()}}


@pytest.fixture
def idp(cog, monkeypatch):
    fake = FakeIdp(cog, enrolled=True)
    monkeypatch.setattr(cog.cognito_auth, "_idp", lambda: fake)
    return fake
