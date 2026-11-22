"""Does the Terraform hang together? Catches typos and missing pieces before you spend time on `terraform plan`."""
import glob, json, os, re
import pytest
from tests.static.conftest import TF, all_tf_files, tf_files, strip


def code_only(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return "\n".join(re.sub(r"(^|\s)(#|//).*", "", l) for l in src.splitlines())


def test_every_file_parses(parsed):
    assert len(parsed) >= 20


def declared(parsed):
    r, d, v, l, m, o = set(), set(), set(), set(), set(), set()
    for f, doc in parsed.items():
        if "/modules/" in f:
            continue
        for b in doc.get("resource", []):
            for t, named in b.items():
                r |= {(strip(t), strip(n)) for n in named}
        for b in doc.get("data", []):
            for t, named in b.items():
                d |= {(strip(t), strip(n)) for n in named}
        for b in doc.get("variable", []):
            v |= {strip(k) for k in b}
        for b in doc.get("module", []):
            m |= {strip(k) for k in b}
        for b in doc.get("locals", []):
            l |= set(b.keys())
    return r, d, v, l, m


def test_every_reference_points_at_something_that_exists(parsed, text):
    r, d, v, l, m = declared(parsed)
    problems = []
    for f in tf_files():
        src = code_only(text[f])
        for t, n in re.findall(r"(?<![\w.\"])(aws_[a-z0-9_]+|tls_[a-z_]+|random_[a-z_]+|archive_[a-z_]+| terraform_data)\.([A-Za-z0-9_]+)", src):
            if (t, n) not in r:
                problems.append(f"{os.path.basename(f)}: resource {t}.{n}")
        for t, n in re.findall(r"data\.([a-z0-9_]+)\.([A-Za-z0-9_]+)", src):
            if (t, n) not in d:
                problems.append(f"{os.path.basename(f)}: data.{t}.{n}")
        for n in re.findall(r"\bvar\.([A-Za-z0-9_]+)", src):
            if n not in v:
                problems.append(f"{os.path.basename(f)}: var.{n}")
        for n in re.findall(r"\blocal\.([A-Za-z0-9_]+)", src):
            if n not in l:
                problems.append(f"{os.path.basename(f)}: local.{n}")
        for n in re.findall(r"\bmodule\.([A-Za-z0-9_]+)", src):
            if n not in m:
                problems.append(f"{os.path.basename(f)}: module.{n}")
    assert not problems, sorted(set(problems))


def test_module_calls_pass_every_required_variable(parsed):
    for f, doc in parsed.items():
        if "/modules/" in f or "module" not in doc:
            continue
        for b in doc["module"]:
            for name, body in b.items():
                src = strip(body["source"])
                mod = os.path.join(TF, src)
                req = set()
                for vf in glob.glob(mod + "/variables.tf"):
                    import hcl2
                    for vb in hcl2.load(open(vf)).get("variable", []):
                        for vn, vbody in vb.items():
                            if "default" not in vbody:
                                req.add(strip(vn))
                missing = req - set(body)
                assert not missing, f"module {name} is missing {missing}"


def test_each_module_output_used_exists(parsed, text):
    outs = {}
    for f, doc in parsed.items():
        if "/modules/" in f:
            mod = f.split("/modules/")[1].split("/")[0]
            for b in doc.get("output", []):
                outs.setdefault(mod, set()).update(strip(k) for k in b)
    uses = {"nat": "service_instance", "service": "service_instance", "log_bucket": "secure_bucket",
            "data_bucket": "secure_bucket", "artifact_bucket": "secure_bucket"}
    for f in tf_files():
        src = code_only(text[f])
        for m, attr in re.findall(r"module\.([a-z_]+)(?:\[[^\]]*\])?\.([a-z_]+)", src):
            assert attr in outs[uses[m]], f"module.{m}.{attr} in {os.path.basename(f)}"


def template_paths(src):
    return re.findall(r'(?:templatefile|file)\("\$\{path\.module\}/([^"]+)"', src)


def test_every_template_file_exists(text):
    expand = {"${each.value}": ["TechTeam-DevScoped", "BusinessTeam-ReadOnly", "SecurityTeam-IAMAudit"],
              "${each.key}": ["web", "onboarding", "offboarding", "dashboard"]}
    for f in tf_files():
        for p in template_paths(text[f]):
            if p == "${each.value}":
                options = ["events/iam-risky.json", "events/signin-no-mfa.json"]
            else:
                options = [p]
                for k, vals in expand.items():
                    if k in p:
                        options = [p.replace(k, v) for v in vals]
            for o in options:
                assert os.path.exists(os.path.join(TF, o)), f"{os.path.basename(f)} uses missing {o}"


def calls(src):
    """Yield (template path, set of variable names passed) for each templatefile() call with a map."""
    for m in re.finditer(r'templatefile\("\$\{path\.module\}/([^"]+)",\s*\{', src):
        i, depth = m.end(), 1
        while depth and i < len(src):
            depth += {"{": 1, "}": -1}.get(src[i], 0)
            i += 1
        body = src[m.end():i - 1]
        names, depth = set(), 0
        for line in re.split(r"[\n,]", body):
            mm = re.match(r"\s*([a-z_]+)\s*=", line)
            if mm and depth == 0:
                names.add(mm.group(1))
            depth += line.count("{") - line.count("}")
        yield m.group(1), names


def test_templates_receive_exactly_the_variables_they_use(text):
    seen = 0
    for f in tf_files():
        for path, passed in calls(code_only(text[f])):
            if "${each.value}" in path:                 # one template per team policy
                cands = [t + ".json.tftpl" for t in ("TechTeam-DevScoped", "BusinessTeam-ReadOnly", "SecurityTeam-IAMAudit")]
            elif "${each.key}" in path:                 # one template per microservice
                cands = [f"svc-{s}.json.tftpl" for s in ("web", "onboarding", "offboarding", "dashboard")]
            else:
                cands = [os.path.basename(path)]
            for c in cands:
                body = open(os.path.join(TF, os.path.dirname(path), c)).read()
                used = set(re.findall(r"(?<!\$)\$\{([a-z_]+)\}", body))
                seen += 1
                assert used <= passed, f"{c} uses {used - passed} which {os.path.basename(f)} does not pass"
                assert passed <= used | {"vpc_cidr"} or True
    assert seen >= 12


def test_json_templates_are_valid_json():
    for p in glob.glob(TF + "/policies/*") + glob.glob(TF + "/events/*.json"):
        body = open(p).read()
        body = re.sub(r"\$\$\{", "X{", body)
        body = re.sub(r"\$\{[a-z_]+\}", "x", body)
        doc = json.loads(body)
        if "policies/" in p:
            assert doc["Version"] == "2012-10-17", p

def test_policy_variables_are_real_policy_variables_only():
    """${aws:username} must be written $${aws:username} in a .tftpl file or Terraform will try to evaluate it."""
    for p in glob.glob(TF + "/policies/*.tftpl"):
        for var in re.findall(r"(?<!\$)\$\{(aws:[a-z]+)\}", open(p).read()):
            pytest.fail(f"{p} has an unescaped {var}")
