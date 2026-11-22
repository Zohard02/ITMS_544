# ---------------------------------------------------------------------------------------------
# THE IDENTITY MODEL FROM LAB01, NOW AS CODE: three groups with one managed policy each, and the two guard policies
# that the onboarding and offboarding services attach to individual users.
# The policy documents are JSON template files. templatefile() fills in ${account_id} and writes the result.
# ---------------------------------------------------------------------------------------------
locals {
  group_policies = {
    TechTeam     = "TechTeam-DevScoped"
    BusinessTeam = "BusinessTeam-ReadOnly"
    SecurityTeam = "SecurityTeam-IAMAudit"
  }
}

resource "aws_iam_group" "team" {
  for_each = local.group_policies
  name     = each.key
  path     = "/nimbus/"
}

resource "aws_iam_policy" "team" {
  for_each = local.group_policies
  name     = each.value
  path     = "/nimbus/"
  policy   = templatefile("${path.module}/policies/${each.value}.json.tftpl", { account_id = local.account_id })
}

resource "aws_iam_group_policy_attachment" "team" {
  for_each   = local.group_policies
  group      = aws_iam_group.team[each.key].name
  policy_arn = aws_iam_policy.team[each.key].arn
}

# Attached to EVERY new user by the onboarding service: deny everything until the user has set up MFA.
resource "aws_iam_policy" "require_mfa" {
  name   = "Nimbus-RequireMFA"
  path   = "/nimbus/"
  policy = templatefile("${path.module}/policies/Nimbus-RequireMFA.json.tftpl", { account_id = local.account_id })
}

# Attached by the offboarding service: an explicit deny of everything. The kill switch.
resource "aws_iam_policy" "deny_all" {
  name   = "Nimbus-DenyAll"
  path   = "/nimbus/"
  policy = file("${path.module}/policies/Nimbus-DenyAll.json")
}
