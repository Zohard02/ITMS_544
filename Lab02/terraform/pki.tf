# ---------------------------------------------------------------------------------------------
# A PRIVATE CERTIFICATE AUTHORITY FOR MUTUAL TLS BETWEEN THE SERVICES.
# Network rules decide who can reach a port. Mutual TLS decides who is allowed to TALK once connected:
#   * every service has a certificate signed by this CA, bound to its fixed private address
#   * a service accepts a connection only from a client that shows a certificate signed by this CA
#   * the web service accepts a service only if its certificate is signed by this CA and matches the address
# The private keys are created here, stored in the state, and delivered to each instance through Parameter Store.
# Each instance role may read only ITS OWN key (see policies/instance-baseline.json.tftpl).
# Certificates live 72 hours: far longer than the lab, short enough that a leaked key soon becomes useless.
# ---------------------------------------------------------------------------------------------
resource "tls_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem       = tls_private_key.ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = 72
  allowed_uses          = ["cert_signing", "crl_signing", "digital_signature"]
  subject {
    common_name  = "${local.name}-internal-ca"
    organization = "Nimbus Analytics lab"
  }
}

resource "tls_private_key" "service" {
  for_each    = local.services
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "service" {
  for_each        = local.services
  private_key_pem = tls_private_key.service[each.key].private_key_pem
  ip_addresses    = [local.service_ip[each.key]] # the certificate is valid for this one address
  subject {
    common_name  = "nimbus-${each.key}"
    organization = "Nimbus Analytics lab"
  }
}

resource "tls_locally_signed_cert" "service" {
  for_each              = local.services
  cert_request_pem      = tls_cert_request.service[each.key].cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = 72
  allowed_uses          = ["digital_signature", "server_auth", "client_auth"]
}

resource "aws_ssm_parameter" "ca_cert" {
  name  = "${local.param_prefix}/tls/ca"
  type  = "String" # a CA certificate is public information
  value = tls_self_signed_cert.ca.cert_pem
}

resource "aws_ssm_parameter" "service_cert" {
  for_each = local.services
  name     = "${local.param_prefix}/tls/${each.key}/cert"
  type     = "String"
  value    = tls_locally_signed_cert.service[each.key].cert_pem
}

resource "aws_ssm_parameter" "service_key" {
  for_each = local.services
  name     = "${local.param_prefix}/tls/${each.key}/key"
  type     = "SecureString" # a private key is a secret
  value    = tls_private_key.service[each.key].private_key_pem
}
