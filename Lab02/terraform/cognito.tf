# ---------------------------------------------------------------------------------------------
# ADMINISTRATOR IDENTITY: AMAZON COGNITO + JWT, INSTEAD OF A PASSWORD KEPT IN A SECRET.
# Cognito user pools are free for the first 10,000 monthly active users, and TOTP authenticator codes cost nothing
# (text message codes DO cost money, so they are not used). Terraform creates:
#   * a user pool: password policy, mandatory authenticator app MFA, admins only (no self sign up)
#   * an app client for the web console (no client secret, a browser facing app cannot keep one)
#   * a group "admins": the services only accept tokens that carry this group
#   * one admin user. Its password is generated and shown by `terraform output`.
# The default pool tier of a new pool is used on purpose: no Plus tier features, no advanced security (both cost money).
# ---------------------------------------------------------------------------------------------
resource "aws_cognito_user_pool" "admins" {
  name                = "${local.name}-admins"
  mfa_configuration   = "ON"       # no sign in without the second factor
  deletion_protection = "INACTIVE" # lab only: a production pool would be ACTIVE

  software_token_mfa_configuration { enabled = true }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  admin_create_user_config {
    allow_admin_create_user_only = true # nobody can register themselves
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  username_configuration { case_sensitive = false }
}

resource "aws_cognito_user_pool_client" "web" {
  name         = "${local.name}-web-console"
  user_pool_id = aws_cognito_user_pool.admins.id

  generate_secret = false
  # The console sends the password to Cognito once, over TLS. The refresh flow is NOT enabled: when the short
  # token expires, the admin signs in again.
  explicit_auth_flows           = ["ALLOW_USER_PASSWORD_AUTH"]
  prevent_user_existence_errors = "ENABLED" # a wrong user name and a wrong password look identical
  enable_token_revocation       = true

  access_token_validity  = 30
  id_token_validity      = 30
  refresh_token_validity = 1
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}

resource "aws_cognito_user_group" "admins" {
  name         = "admins"
  user_pool_id = aws_cognito_user_pool.admins.id
  description  = "May use the Nimbus console and the private services"
}

resource "aws_cognito_user" "admin" {
  user_pool_id   = aws_cognito_user_pool.admins.id
  username       = "admin"
  password       = random_password.admin.result # a permanent password, so no "change your password" step
  message_action = "SUPPRESS"                   # no invitation email
  attributes = {
    email          = var.alert_email
    email_verified = "true"
  }
}

resource "aws_cognito_user_in_group" "admin" {
  user_pool_id = aws_cognito_user_pool.admins.id
  group_name   = aws_cognito_user_group.admins.name
  username     = aws_cognito_user.admin.username
}
