# ---------------------------------------------------------------------------------------------
# SECURITY GROUPS: the instance level firewall. Stateful, allow rules only, default is deny.
# Every rule here is a separate resource with a clear purpose. There is NO rule for port 22 anywhere.
# ---------------------------------------------------------------------------------------------

resource "aws_security_group" "web" {
  name        = "${local.name}-web"
  description = "Web console: one port, one address"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.name}-web" }
}

resource "aws_security_group" "service" {
  for_each    = local.private_services # one group per private service, so each can be opened to exactly one caller
  name        = "${local.name}-${each.key}"
  description = "${each.key} service: reachable only from the web security group"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.name}-${each.key}" }
}

resource "aws_security_group" "nat" {
  name        = "${local.name}-nat"
  description = "NAT instance: HTTPS from the private subnets, HTTPS out"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.name}-nat" }
}

# ---- web ----
resource "aws_vpc_security_group_ingress_rule" "web_console" {
  security_group_id = aws_security_group.web.id
  description       = "Admin browser to the console (HTTPS, your address only)"
  cidr_ipv4         = var.admin_cidr
  ip_protocol       = "tcp"
  from_port         = 8443
  to_port           = 8443
}

resource "aws_vpc_security_group_egress_rule" "web_https" {
  security_group_id = aws_security_group.web.id
  description       = "HTTPS to AWS APIs and the package index"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "web_to_service" {
  for_each                     = local.private_services
  security_group_id            = aws_security_group.web.id
  description                  = "Web console to the ${each.key} service"
  referenced_security_group_id = aws_security_group.service[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
}

# ---- private services ----
resource "aws_vpc_security_group_ingress_rule" "service_from_web" {
  for_each                     = local.private_services
  security_group_id            = aws_security_group.service[each.key].id
  description                  = "Only the web security group may call ${each.key}"
  referenced_security_group_id = aws_security_group.web.id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
}

resource "aws_vpc_security_group_egress_rule" "service_https" {
  for_each          = local.private_services
  security_group_id = aws_security_group.service[each.key].id
  description       = "HTTPS to AWS APIs, through the NAT instance or the S3 endpoint"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# ---- NAT instance ----
resource "aws_vpc_security_group_ingress_rule" "nat_from_private" {
  for_each          = { for k, v in local.subnets : k => v if !v.public }
  security_group_id = aws_security_group.nat.id
  description       = "HTTPS from ${each.key} to be forwarded to the internet"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "nat_https" {
  security_group_id = aws_security_group.nat.id
  description       = "HTTPS out to the internet"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}
