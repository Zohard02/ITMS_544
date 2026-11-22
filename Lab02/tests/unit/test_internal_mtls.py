"""Mutual TLS between the web service (client) and a private service (server).

Terraform builds a private CA and one certificate per service (terraform/pki.tf). Here we build the same
thing in memory and run a real TLS handshake, so you see what the services enforce:
  * the server only talks to clients that hold a certificate signed by the private CA
  * the client only talks to servers whose certificate is signed by the private CA and names the right IP
"""
import datetime as dt, ipaddress, ssl, threading
import pytest, requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask
from werkzeug.serving import make_server

PEM = serialization.Encoding.PEM
NOPW = serialization.NoEncryption()


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _issue(cn, issuer_key, issuer_name, ca=False, ip=None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(issuer_name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
         .not_valid_after(now + dt.timedelta(hours=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True)
    if ip:
        b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    cert = b.sign(issuer_key or key, hashes.SHA256())
    return key, cert


def _write(tmp, name, key, cert):
    (tmp / f"{name}.crt").write_bytes(cert.public_bytes(PEM))
    if key is not None:
        (tmp / f"{name}.key").write_bytes(key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, NOPW))
    return str(tmp / f"{name}.crt"), str(tmp / f"{name}.key")


@pytest.fixture
def pki(tmp_path):
    ca_key, ca = _issue("lab02-internal-ca", None, _name("lab02-internal-ca"), ca=True)
    other_key, other = _issue("some-other-ca", None, _name("some-other-ca"), ca=True)   # an untrusted CA
    srv = _issue("nimbus-onboarding", ca_key, ca.subject, ip="127.0.0.1")
    cli = _issue("nimbus-web", ca_key, ca.subject, ip="127.0.0.1")
    rogue = _issue("rogue", other_key, other.subject, ip="127.0.0.1")
    p = {"ca": _write(tmp_path, "ca", None, ca)[0], "other_ca": _write(tmp_path, "other", None, other)[0]}
    p["srv"], p["cli"], p["rogue"] = _write(tmp_path, "srv", *srv), _write(tmp_path, "cli", *cli), _write(tmp_path, "rogue", *rogue)
    return p


@pytest.fixture
def server(pki):
    app = Flask("mtls"); app.get("/healthz")(lambda: {"status": "ok"})
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*pki["srv"])                       # like gunicorn --certfile/--keyfile
    ctx.load_verify_locations(pki["ca"])                   # like gunicorn --ca-certs
    ctx.verify_mode = ssl.CERT_REQUIRED                    # like gunicorn --cert-reqs 2
    srv = make_server("127.0.0.1", 0, app, ssl_context=ctx)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    yield f"https://127.0.0.1:{srv.server_port}/healthz"
    srv.shutdown()


def test_client_with_a_cert_from_our_ca_is_accepted(server, pki, monkeypatch):
    from common import nimbus
    monkeypatch.setenv("INTERNAL_CA", pki["ca"]); monkeypatch.setenv("INTERNAL_CLIENT_CERT", pki["cli"][0]); monkeypatch.setenv("INTERNAL_CLIENT_KEY", pki["cli"][1])
    assert requests.get(server, timeout=5, **nimbus.internal_tls_kwargs()).json() == {"status": "ok"}

def test_client_without_a_certificate_is_refused(server, pki):
    with pytest.raises(requests.exceptions.SSLError):
        requests.get(server, timeout=5, verify=pki["ca"])

def test_client_with_a_certificate_from_another_ca_is_refused(server, pki):
    with pytest.raises(requests.exceptions.SSLError):
        requests.get(server, timeout=5, verify=pki["ca"], cert=pki["rogue"])

def test_client_refuses_a_server_it_does_not_trust(server, pki):
    with pytest.raises(requests.exceptions.SSLError):
        requests.get(server, timeout=5, verify=pki["other_ca"], cert=pki["cli"])
