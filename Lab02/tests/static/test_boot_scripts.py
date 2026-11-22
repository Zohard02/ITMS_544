"""Render the boot scripts the way Terraform would, then check the shell syntax and the security flags."""
import os, re, subprocess
import pytest
from tests.static.conftest import TF
VARS = dict(service="onboarding", port=5001, region="us-east-2", shutdown_min=180, artifact_bucket="b", artifact_key="app/x.zip",
            artifact_sha="a" * 64, data_bucket="d", param_prefix="/nimbus", log_group="/lab02/app", pool_id="us-east-2_X",
            client_id="c", onboarding_url="https://10.0.11.10:5001", offboarding_url="https://10.0.12.10:5002",
            dashboard_url="https://10.0.11.11:5003", vpc_cidr="10.0.0.0/16")


def render(name, is_web=False, **extra):
    """A tiny stand-in for templatefile(): ${var} substitution and %{ if }/%{ else }/%{ endif } blocks."""
    src = open(os.path.join(TF, "templates", name)).read()
    v = {**VARS, "is_web": is_web, **extra}
    out, stack = [], []
    for line in src.splitlines():
        s = line.strip()
        m = re.match(r"%\{\s*if (\w+)\s*~?\}", s)
        if m:
            stack.append(bool(v[m.group(1)])); continue
        if re.match(r"%\{\s*else\s*~?\}", s):
            stack[-1] = not stack[-1]; continue
        if re.match(r"%\{\s*endif\s*~?\}", s):
            stack.pop(); continue
        if all(stack):
            out.append(re.sub(r"\$\{(\w+)\}", lambda mm: str(v[mm.group(1)]), line))
    assert not stack
    return "\n".join(out) + "\n"


@pytest.mark.parametrize("name,web", [("service.sh.tftpl", False), ("service.sh.tftpl", True), ("nat.sh.tftpl", False)])
def test_shell_syntax(name, web, tmp_path):
    p = tmp_path / "s.sh"; p.write_text(render(name, is_web=web))
    r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_no_unrendered_template_syntax_is_left():
    for name in ("service.sh.tftpl", "nat.sh.tftpl"):
        assert "${" not in render(name) and "%{" not in render(name)


def test_private_services_demand_client_certificates():
    s = render("service.sh.tftpl", is_web=False)
    assert "--cert-reqs 2" in s and "--ca-certs" in s


def test_web_does_not_demand_a_client_certificate_but_presents_one():
    s = render("service.sh.tftpl", is_web=True)
    assert "--cert-reqs" not in s and "browser.pem" in s
    assert "INTERNAL_CLIENT_CERT" in s and "ONBOARD_URL" in s


def test_private_service_env_has_no_web_urls():
    assert "ONBOARD_URL" not in render("service.sh.tftpl", is_web=False)


def test_artifact_hash_is_verified_before_unpacking():
    s = render("service.sh.tftpl")
    assert s.index("sha256sum -c") < s.index("unzip -oq")


def test_no_secret_values_in_user_data():
    s = render("service.sh.tftpl", is_web=True) + render("nat.sh.tftpl")
    for bad in ("password", "BEGIN PRIVATE KEY", "AKIA", "aws_secret"):
        assert bad.lower() not in s.lower().replace("passwords", ""), bad


def test_key_files_are_not_world_readable():
    s = render("service.sh.tftpl")
    assert "chmod 0640 $TLS/*.key" in s and "UMask=0077" in s


def test_systemd_sandboxing_flags():
    s = render("service.sh.tftpl")
    for flag in ("NoNewPrivileges=true", "ProtectSystem=strict", "PrivateTmp=true", "ProtectHome=true",
                 "CapabilityBoundingSet=", "User=nimbus"):
        assert flag in s, flag

def test_nat_forwards_only_https_and_defaults_to_drop():
    s = render("nat.sh.tftpl")
    assert "-P FORWARD DROP" in s and "--dport 443" in s and "MASQUERADE" in s and "ip_forward = 1" in s


def test_both_scripts_set_the_auto_shutdown_timer():
    for n in ("service.sh.tftpl", "nat.sh.tftpl"):
        assert "shutdown -h +180" in render(n)
