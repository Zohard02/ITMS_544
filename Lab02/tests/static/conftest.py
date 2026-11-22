"""Helpers for the static tests. They read the Terraform files without running Terraform."""
import glob, os, re
import hcl2, pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TF = os.path.join(ROOT, "terraform")


def tf_files():
    return sorted(glob.glob(f"{TF}/*.tf"))


def all_tf_files():
    return tf_files() + sorted(glob.glob(f"{TF}/modules/*/*.tf"))


def strip(s):
    """Quotes removed from HCL parser output: '"name"' -> 'name'."""
    return s.strip('"') if isinstance(s, str) else s


@pytest.fixture(scope="session")
def parsed():
    out = {}
    for f in all_tf_files():
        with open(f) as fh:
            out[f] = hcl2.load(fh)
    return out


@pytest.fixture(scope="session")
def resources(parsed):
    """{(type, name): body} for the root module only."""
    res = {}
    for f, d in parsed.items():
        if "/modules/" in f:
            continue
        for block in d.get("resource", []):
            for rtype, named in block.items():
                for name, body in named.items():
                    res[(strip(rtype), strip(name))] = body
    return res


@pytest.fixture(scope="session")
def text():
    return {f: open(f).read() for f in all_tf_files()}


def read(path):
    with open(os.path.join(TF, path)) as fh:
        return fh.read()
