# ---------------------------------------------------------------------------------------------
# ONE IAM ROLE PER INSTANCE. In Lab01 four containers shared one instance role and assumed their service roles.
# Now every microservice has its own EC2 instance, so each instance carries exactly the role it needs and
# nothing more: there is no AssumeRole step and no shared identity.
#   web         reads its login parameter and the token
#   onboarding  creates users and attaches only the MFA guard
#   offboarding attaches only the Deny All kill switch
#   dashboard   read only
#   nat         no AWS permissions at all (only the managed policy that lets you open a Session Manager shell)
# ---------------------------------------------------------------------------------------------
locals {
  instance_roles = merge(
    { for k, v in local.services : k => "nimbus-${k}-svc" },
    { nat = "nimbus-nat-instance" }
  )
}

resource "aws_iam_role" "instance" {
  for_each           = local.instance_roles
  name               = each.value
  path               = "/nimbus/"
  assume_role_policy = file("${path.module}/policies/ec2-trust.json") # only the EC2 service may use these roles
}

resource "aws_iam_instance_profile" "instance" {
  for_each = local.instance_roles
  name     = each.value
  path     = "/nimbus/"
  role     = aws_iam_role.instance[each.key].name
}

# What every service instance needs to boot: its code, its own certificate, a place to write logs.
resource "aws_iam_role_policy" "baseline" {
  for_each = local.services
  name     = "baseline"
  role     = aws_iam_role.instance[each.key].id
  policy = templatefile("${path.module}/policies/instance-baseline.json.tftpl", {
    account_id      = local.account_id
    region          = var.region
    service         = each.key
    artifact_bucket = local.artifact_bucket
    log_group       = local.app_log_group
    param_prefix    = local.param_prefix
  })
}

# What each service is allowed to do: the least privilege policy of that one microservice.
resource "aws_iam_role_policy" "service" {
  for_each = local.services
  name     = "service"
  role     = aws_iam_role.instance[each.key].id
  policy = templatefile("${path.module}/policies/svc-${each.key}.json.tftpl", {
    account_id   = local.account_id
    region       = var.region
    bucket       = local.data_bucket
    param_prefix = local.param_prefix
  })
}

# Session Manager: an audited shell without SSH, without an open port and without a key pair.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  for_each   = local.instance_roles
  role       = aws_iam_role.instance[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
