import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))      # `import common` and the services live under app/
# Fixed, fake settings shared by every test (set BEFORE `common.nimbus` is imported).
os.environ.setdefault("AWS_REGION", "us-east-2")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-2")
os.environ.setdefault("NIMBUS_BUCKET", "nimbus-test")
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ.pop("AWS_ENDPOINT_URL", None)
os.environ.pop("AWS_PROFILE", None)
