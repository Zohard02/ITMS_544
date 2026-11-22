# ---------------------------------------------------------------------------------------------
# FIVE EC2 INSTANCES: one NAT instance and one instance for each of the four microservices.
# The user data scripts are rendered here with templatefile(). They contain NO secrets, only names and addresses:
# every secret is fetched by the instance itself, with its own role, from Parameter Store.
# ---------------------------------------------------------------------------------------------
locals {
  ami_id          = data.aws_ssm_parameter.al2023.value
  free_tier_types = data.aws_ec2_instance_types.free_tier.instance_types
  app_sha         = data.archive_file.app.output_sha256
}

module "nat" {
  source             = "./modules/service_instance"
  name               = "${local.name}-nat"
  subnet_id          = aws_subnet.this["public_a"].id
  private_ip         = local.nat_ip
  security_group_ids = [aws_security_group.nat.id]
  instance_profile   = aws_iam_instance_profile.instance["nat"].name
  ami_id             = local.ami_id
  instance_type      = var.instance_type
  free_tier_types    = local.free_tier_types
  public_ip          = true  # it needs a public address to reach the internet
  source_dest_check  = false # required for forwarding other machines' traffic
  user_data = templatefile("${path.module}/templates/nat.sh.tftpl", {
    vpc_cidr     = var.vpc_cidr
    shutdown_min = local.shutdown_min
  })
}

module "service" {
  source             = "./modules/service_instance"
  for_each           = local.services
  name               = "${local.name}-${each.key}"
  subnet_id          = aws_subnet.this[each.value.subnet].id
  private_ip         = local.service_ip[each.key]
  security_group_ids = [each.key == "web" ? aws_security_group.web.id : aws_security_group.service[each.key].id]
  instance_profile   = aws_iam_instance_profile.instance[each.key].name
  ami_id             = local.ami_id
  instance_type      = var.instance_type
  free_tier_types    = local.free_tier_types
  public_ip          = each.key == "web" # only the web console has a public address

  user_data = templatefile("${path.module}/templates/service.sh.tftpl", {
    service         = each.key
    port            = each.value.port
    is_web          = each.key == "web"
    region          = var.region
    shutdown_min    = local.shutdown_min
    artifact_bucket = local.artifact_bucket
    artifact_key    = aws_s3_object.app.key
    artifact_sha    = local.app_sha
    data_bucket     = local.data_bucket
    param_prefix    = local.param_prefix
    log_group       = local.app_log_group
    pool_id         = aws_cognito_user_pool.admins.id
    client_id       = aws_cognito_user_pool_client.web.id
    onboarding_url  = "https://${local.service_ip["onboarding"]}:${local.services["onboarding"].port}"
    offboarding_url = "https://${local.service_ip["offboarding"]}:${local.services["offboarding"].port}"
    dashboard_url   = "https://${local.service_ip["dashboard"]}:${local.services["dashboard"].port}"
  })

  # Boot order: a service cannot start until the NAT route, the S3 endpoint, its secrets and its code all exist.
  depends_on = [
    aws_route.private_via_nat,
    aws_vpc_endpoint.s3,
    aws_s3_object.app,
    aws_ssm_parameter.token_current,
    aws_ssm_parameter.token_previous,
    aws_ssm_parameter.web_login,
    aws_cognito_user_in_group.admin,
    aws_ssm_parameter.ca_cert,
    aws_ssm_parameter.service_cert,
    aws_ssm_parameter.service_key,
    aws_iam_role_policy.baseline,
    aws_iam_role_policy.service,
    aws_iam_role_policy_attachment.ssm_core,
    module.data_bucket,
    aws_cloudwatch_log_group.app,
    aws_network_acl_rule.public,
    aws_network_acl_rule.private,
  ]
}
