# Locals are named values computed once and reused. Changing a value here changes it everywhere.
locals {
  name       = var.project
  account_id = data.aws_caller_identity.current.account_id
  azs        = slice(data.aws_availability_zones.available.names, 0, 2)

  tags = {
    Project   = var.project
    ManagedBy = "terraform"
    Course    = "cloud-security"
  }
  # Four subnets in two availability zones. Public = has a route to the internet gateway.
  # Private = no route to the internet gateway at all; outbound traffic can only go through the NAT instance.
  subnets = {
    public_a  = { cidr = cidrsubnet(var.vpc_cidr, 8, 1), az = local.azs[0], public = true }
    public_b  = { cidr = cidrsubnet(var.vpc_cidr, 8, 2), az = local.azs[1], public = true }
    private_a = { cidr = cidrsubnet(var.vpc_cidr, 8, 11), az = local.azs[0], public = false }
    private_b = { cidr = cidrsubnet(var.vpc_cidr, 8, 12), az = local.azs[1], public = false }
  }

  # One EC2 instance per microservice. `host` picks a fixed address inside the subnet, so every other
  # resource (certificates, firewall rules, the web service settings) can know it before the instance exists.
  services = {
    web         = { port = 8443, subnet = "public_a", host = 10 }
    onboarding  = { port = 5001, subnet = "private_a", host = 10 }
    offboarding = { port = 5002, subnet = "private_b", host = 10 }
    dashboard   = { port = 5003, subnet = "private_a", host = 11 }
  }
  private_services = { for k, v in local.services : k => v if k != "web" }
  service_ip       = { for k, v in local.services : k => cidrhost(local.subnets[v.subnet].cidr, v.host) }
  nat_ip           = cidrhost(local.subnets.public_a.cidr, 5)

  data_bucket     = "${local.name}-nimbus-${local.account_id}"
  artifact_bucket = "${local.name}-artifacts-${local.account_id}"
  log_bucket      = "${local.name}-logs-${local.account_id}"
  trail_name      = "${local.name}-trail"
  app_log_group   = "/${local.name}/app"
  flow_log_group  = "/${local.name}/flow"
  param_prefix    = "/nimbus"
  shutdown_min    = var.auto_shutdown_hours * 60
}
