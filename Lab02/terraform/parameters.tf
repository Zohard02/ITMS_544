# ---------------------------------------------------------------------------------------------
# SECRETS IN SSM PARAMETER STORE. SecureString parameters are encrypted with the default AWS managed key, and standard
# parameters are free. (Lab01 used Secrets Manager, which costs about $0.40 per secret per month and offers built in
# rotation. Parameter Store is the free alternative; the trade off is that you rotate by script.)
#
# IMPORTANT: Terraform generates these values, so they are ALSO stored in the Terraform state file.
# That is why the state bucket is private, encrypted and versioned, and why state must never go into git.
# ---------------------------------------------------------------------------------------------
resource "random_password" "token_current" {
  length  = 48
  special = false
}

resource "random_password" "token_previous" {
  length  = 48
  special = false
}

resource "random_password" "admin" {
  length           = 20
  special          = true
  override_special = "!@#%^*-_=+"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "random_password" "flask_key" {
  length  = 48
  special = false
}

# The token the services use to prove who they are to each other.
resource "aws_ssm_parameter" "token_current" {
  name  = "${local.param_prefix}/internal-token/current"
  type  = "SecureString"
  value = random_password.token_current.result
  lifecycle { ignore_changes = [value] } # scripts/rotate_token.sh changes the value later. Terraform must not undo it.
}

resource "aws_ssm_parameter" "token_previous" {
  name  = "${local.param_prefix}/internal-token/previous"
  type  = "SecureString"
  value = random_password.token_previous.result
  lifecycle { ignore_changes = [value] }
}

# The key that signs the web console's session cookies. Administrator passwords are NOT stored here any more:
# administrators are users in the Cognito user pool (cognito.tf).
resource "aws_ssm_parameter" "web_login" {
  name  = "${local.param_prefix}/web-login"
  type  = "SecureString"
  value = jsonencode({ flask_secret_key = random_password.flask_key.result })
}
