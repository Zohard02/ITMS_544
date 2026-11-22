# ---------------------------------------------------------------------------------------------
# WHAT TERRAFORM DOES NOT KNOW ABOUT. The onboarding service creates IAM users while the lab runs. Those users are
# not in the Terraform state, so `terraform destroy` could not delete them, and it could not delete the groups and
# policies they belong to. This resource runs scripts/cleanup_app_users.sh at destroy time. Because it depends on
# the groups and policies, Terraform destroys it FIRST, which runs the script before anything it protects goes away.
# It needs the AWS CLI on the machine where you run terraform destroy.
# ---------------------------------------------------------------------------------------------
resource "terraform_data" "app_user_cleanup" {
  input = {
    script = "${path.module}/../scripts/cleanup_app_users.sh"
    region = var.region
  }

  provisioner "local-exec" {
    when        = destroy
    command     = "bash ${self.input.script}"
    environment = { AWS_REGION = self.input.region }
  }

  depends_on = [
    aws_iam_group.team,
    aws_iam_group_policy_attachment.team,
    aws_iam_policy.team,
    aws_iam_policy.require_mfa,
    aws_iam_policy.deny_all,
  ]
}
