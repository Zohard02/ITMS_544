# ---------------------------------------------------------------------------------------------
# NETWORK ACLs: a second firewall layer at the edge of each subnet.
#   * Security groups (security_groups.tf) are STATEFUL and attach to an instance: replies are allowed automatically.
#   * Network ACLs are STATELESS and attach to a subnet: you must allow the request AND the reply, rules are
#     evaluated from the lowest number up, and the first match wins. They can DENY, security groups cannot.
# Replies to outgoing connections come back to a random "ephemeral" port (1024 to 65535), hence rule 120 below.
# ---------------------------------------------------------------------------------------------
locals {
  all = "0.0.0.0/0"

  public_nacl_rules = {
    "in-100"  = { egress = false, number = 100, action = "allow", cidr = var.admin_cidr, from = 8443, to = 8443, note = "admin browser to the web console" }
    "in-105"  = { egress = false, number = 105, action = "deny", cidr = local.all, from = 8443, to = 8443, note = "nobody else may reach the console, even though rule 120 would allow it" }
    "in-110"  = { egress = false, number = 110, action = "allow", cidr = local.subnets.private_a.cidr, from = 443, to = 443, note = "private services to the NAT instance" }
    "in-111"  = { egress = false, number = 111, action = "allow", cidr = local.subnets.private_b.cidr, from = 443, to = 443, note = "private services to the NAT instance" }
    "in-120"  = { egress = false, number = 120, action = "allow", cidr = local.all, from = 1024, to = 65535, note = "replies to connections started from inside" }
    "out-100" = { egress = true, number = 100, action = "allow", cidr = local.all, from = 443, to = 443, note = "HTTPS out: AWS APIs, package index, NAT forwarding" }
    "out-110" = { egress = true, number = 110, action = "allow", cidr = local.subnets.private_a.cidr, from = 5001, to = 5003, note = "web console to the private services" }
    "out-111" = { egress = true, number = 111, action = "allow", cidr = local.subnets.private_b.cidr, from = 5001, to = 5003, note = "web console to the private services" }
    "out-120" = { egress = true, number = 120, action = "allow", cidr = local.all, from = 1024, to = 65535, note = "replies to the admin browser and to the private services" }
  }

  private_nacl_rules = {
    "in-100"  = { egress = false, number = 100, action = "allow", cidr = local.subnets.public_a.cidr, from = 5001, to = 5003, note = "only the web subnet may call the services" }
    "in-105"  = { egress = false, number = 105, action = "deny", cidr = local.all, from = 5001, to = 5003, note = "everyone else is refused, even though rule 120 would allow it" }
    "in-120"  = { egress = false, number = 120, action = "allow", cidr = local.all, from = 1024, to = 65535, note = "replies from the NAT instance and from S3" }
    "out-100" = { egress = true, number = 100, action = "allow", cidr = local.all, from = 443, to = 443, note = "HTTPS out, through the NAT instance or the S3 endpoint" }
    "out-110" = { egress = true, number = 110, action = "allow", cidr = local.subnets.public_a.cidr, from = 1024, to = 65535, note = "replies to the web console" }
  }
}

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [for k, v in local.subnets : aws_subnet.this[k].id if v.public]
  tags       = { Name = "${local.name}-public-nacl" }
}

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [for k, v in local.subnets : aws_subnet.this[k].id if !v.public]
  tags       = { Name = "${local.name}-private-nacl" }
}

resource "aws_network_acl_rule" "public" {
  for_each       = local.public_nacl_rules
  network_acl_id = aws_network_acl.public.id
  egress         = each.value.egress
  rule_number    = each.value.number
  rule_action    = each.value.action
  protocol       = "tcp"
  cidr_block     = each.value.cidr
  from_port      = each.value.from
  to_port        = each.value.to
}

resource "aws_network_acl_rule" "private" {
  for_each       = local.private_nacl_rules
  network_acl_id = aws_network_acl.private.id
  egress         = each.value.egress
  rule_number    = each.value.number
  rule_action    = each.value.action
  protocol       = "tcp"
  cidr_block     = each.value.cidr
  from_port      = each.value.from
  to_port        = each.value.to
}
