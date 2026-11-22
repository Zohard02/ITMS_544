"""The security promises of this lab, written as tests. If someone weakens the code, a test goes red."""
import glob, json, os, re
import pytest
from tests.static.conftest import TF, tf_files, read, strip

FORBIDDEN_TYPES = {  # each of these costs money outside a tiny allowance, so none may appear
    "aws_nat_gateway": "NAT Gateway (about $32 a month)", "aws_eip": "Elastic IP",
    "aws_lb": "load balancer", "aws_alb": "load balancer", "aws_kms_key": "customer managed KMS key ($1 a month)",
    "aws_secretsmanager_secret": "Secrets Manager ($0.40 a secret)", "aws_db_instance": "RDS",
    "aws_waf": "WAF", "aws_wafv2_web_acl": "WAF", "aws_guardduty_detector": "GuardDuty",
    "aws_cognito_user_pool_domain": "hosted UI domain (not needed)",
}


def test_no_billable_resource_types(resources):
    bad = [f"{t} ({FORBIDDEN_TYPES[t]})" for (t, _) in resources if t in FORBIDDEN_TYPES]
    assert not bad, bad


def test_only_gateway_endpoints(resources):
    for (t, n), b in resources.items():
        if t == "aws_vpc_endpoint":
            assert strip(b["vpc_endpoint_type"]) == "Gateway", n


def test_no_ssh_anywhere(text):
    for f, src in text.items():
        assert not re.search(r"(from_port|to_port)\s*=\s*22\b", src), f
        assert "key_name" not in src, f"{f}: instances must have no key pair"


def test_security_group_rules_never_open_ingress_to_the_world(resources):
    for (t, n), b in resources.items():
        if t == "aws_vpc_security_group_ingress_rule":
            assert strip(b.get("cidr_ipv4", "x")) != "0.0.0.0/0", n
            assert "cidr_ipv6" not in b, n


def test_security_groups_have_no_inline_rules(resources):
    for (t, n), b in resources.items():
        if t == "aws_security_group":
            assert "ingress" not in b and "egress" not in b, n


def test_default_security_group_is_emptied(resources):
    assert ("aws_default_security_group", "default") in resources
    b = resources[("aws_default_security_group", "default")]
    assert "ingress" not in b and "egress" not in b


def test_private_route_table_has_no_internet_gateway_route(text):
    src = read("network.tf")
    block = src[src.index('resource "aws_route" "private_via_nat"'):]
    block = block[:block.index("\n}")]
    assert "gateway_id" not in block and "network_interface_id" in block


def test_instances_are_hardened():
    src = read("modules/service_instance/main.tf")
    assert re.search(r'http_tokens\s*=\s*"required"', src)
    assert re.search(r"http_put_response_hop_limit\s*=\s*1\b", src)
    assert re.search(r"encrypted\s*=\s*true", src)
    assert re.search(r'cpu_credits\s*=\s*"standard"', src)
    assert re.search(r'instance_initiated_shutdown_behavior\s*=\s*"terminate"', src)
    assert re.search(r"monitoring\s*=\s*false", src)
    assert "precondition" in src and "free_tier_types" in src


def test_only_free_tier_instance_types_can_be_chosen():
    src = read("variables.tf")
    assert 't3.micro' in src and 't2.micro' in src
    assert not re.search(r"t3\.(small|medium|large)|m5|c5", src)


def test_only_web_and_nat_get_public_addresses():
    src = read("compute.tf")
    assert 'public_ip          = each.key == "web"' in src
    assert "public_ip          = true" in src and src.count("public_ip") == 2


def test_five_instances_only():
    src = read("compute.tf")
    assert src.count('module "nat"') == 1 and src.count('module "service"') == 1
    assert "count" not in re.sub(r"#.*", "", src)


def test_every_instance_has_its_own_role(resources):
    roles = {n for (t, n) in resources if t == "aws_iam_role"}
    assert "instance" in roles
    src = read("iam_services.tf")
    for s in ("web", "onboarding", "offboarding", "dashboard"):
        assert (f'"nimbus-{s}-svc"' in src) or "nimbus-${k}-svc" in src
    assert "nimbus-nat-instance" in src


def policy_files():
    return [p for p in glob.glob(TF + "/policies/*") if "trust" not in p]


def render(p):
    b = open(p).read()
    b = re.sub(r"\$\$\{", "X{", b)
    return json.loads(re.sub(r"\$\{[a-z_]+\}", "x", b))


@pytest.mark.parametrize("p", policy_files(), ids=os.path.basename)
def test_no_policy_allows_everything(p):
    for st in render(p)["Statement"]:
        if st["Effect"] != "Allow":
            continue
        acts = st.get("Action", [])
        acts = [acts] if isinstance(acts, str) else acts
        assert "*" not in acts and not any(a.endswith(":*") for a in acts), (p, st["Sid"])


def test_service_policies_have_no_wildcard_resource_except_listing():
    for s in ("onboarding", "offboarding", "web"):
        for st in render(f"{TF}/policies/svc-{s}.json.tftpl")["Statement"]:
            assert st["Resource"] != "*", (s, st["Sid"])


def test_onboarding_can_attach_only_the_mfa_policy_and_offboarding_only_deny_all():
    on = {st["Sid"]: st for st in render(f"{TF}/policies/svc-onboarding.json.tftpl")["Statement"]}
    off = {st["Sid"]: st for st in render(f"{TF}/policies/svc-offboarding.json.tftpl")["Statement"]}
    assert on["AttachOnlyTheMFAGuardPolicy"]["Condition"]["ArnEquals"]["iam:PolicyARN"].endswith("Nimbus-RequireMFA")
    assert off["AttachOnlyTheDenyAllPolicy"]["Condition"]["ArnEquals"]["iam:PolicyARN"].endswith("Nimbus-DenyAll")
    for doc in (on, off):
        assert all("iam:AttachUserPolicy" not in (st["Action"] if isinstance(st["Action"], list) else [st["Action"]])
                   or "Condition" in st for st in doc.values())


def test_service_instances_can_read_only_their_own_tls_key():
    st = {s["Sid"]: s for s in render(f"{TF}/policies/instance-baseline.json.tftpl")["Statement"]}
    raw = open(f"{TF}/policies/instance-baseline.json.tftpl").read()
    assert "/tls/${service}/*" in raw and "/tls/*" not in raw.replace("/tls/${service}/*", "")


def test_the_web_role_has_no_iam_or_cognito_permissions():
    raw = open(f"{TF}/policies/svc-web.json.tftpl").read()
    assert "iam:" not in raw and "cognito" not in raw and "s3:" not in raw


def test_buckets_come_only_from_the_secure_module(resources, text):
    assert not [k for k in resources if k[0] == "aws_s3_bucket"], "create buckets with modules/secure_bucket"
    src = read("modules/secure_bucket/main.tf")
    for needle in ("aws_s3_bucket_public_access_block", "block_public_acls       = true",
                   "block_public_policy     = true", "ignore_public_acls      = true", "restrict_public_buckets = true",
                   "BucketOwnerEnforced", "AES256", "Enabled", "DenyInsecureTransport", "DenyOldTLS"):
        assert needle in src, needle


def test_data_and_artifact_buckets_are_locked_to_the_vpc_endpoint():
    assert read("storage.tf").count("bucket-vpce-only.json.tftpl") == 2
    p = render(f"{TF}/policies/bucket-vpce-only.json.tftpl")["Statement"][0]
    assert p["Effect"] == "Deny" and "aws:SourceVpce" in p["Condition"]["StringNotEquals"]


def test_s3_endpoint_policy_is_not_a_blanket_allow():
    for st in render(f"{TF}/policies/s3-endpoint-policy.json.tftpl")["Statement"]:
        assert st["Resource"] not in ("*", ["*"])
        assert "s3:DeleteObject" not in st["Action"]


def test_cloudtrail_validates_logs_and_has_no_data_events():
    src = read("detection.tf")
    assert "enable_log_file_validation    = true" in src and "data_resource" not in src


def test_mfa_is_mandatory_and_nobody_can_self_register_in_cognito():
    src = read("cognito.tf")
    assert 'mfa_configuration   = "ON"' in src
    assert "allow_admin_create_user_only = true" in src
    assert "generate_secret = false" in src
    assert "sms" not in src.lower()
    assert 'prevent_user_existence_errors = "ENABLED"' in src


def test_token_lifetimes_are_short():
    src = read("cognito.tf")
    assert int(re.search(r"access_token_validity\s*=\s*(\d+)", src).group(1)) <= 60
    assert int(re.search(r"refresh_token_validity\s*=\s*(\d+)", src).group(1)) <= 1


def test_certificates_are_short_lived_and_bound_to_an_address():
    src = read("pki.tf")
    assert all(int(h) <= 72 for h in re.findall(r"validity_period_hours\s*=\s*(\d+)", src))
    assert "ip_addresses" in src and "is_ca_certificate" in src


def test_secrets_are_secure_strings():
    src = read("parameters.tf") + read("pki.tf")
    for m in re.finditer(r'resource "aws_ssm_parameter" "(\w+)".*?\n}', src, flags=re.S):
        name, body = m.group(1), m.group(0)
        if name in ("ca_cert", "service_cert"):
            assert re.search(r'type\s*=\s*"String"', body), name
        else:
            assert "SecureString" in body, name


def test_admin_cidr_cannot_be_the_whole_internet():
    src = read("variables.tf")
    assert 'var.admin_cidr != "0.0.0.0/0"' in src and '"/32"' in src


def test_state_is_remote_encrypted_and_locked():
    src = read("backend.tf")
    assert 'backend "s3"' in src and "encrypt" in src and "use_lockfile" in src


def test_gitignore_keeps_secrets_out_of_git():
    gi = open(os.path.join(TF, "..", ".gitignore")).read()
    for needle in (".tfstate", "terraform.tfvars", "*.pem", "*.key"):
        assert needle in gi
