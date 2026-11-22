# ---------------------------------------------------------------------------------------------
# LOGS INSIDE THE VPC: application logs from all four instances, and VPC Flow Logs for rejected traffic.
# 7 day retention keeps CloudWatch Logs far below the free 5 GB.
# ---------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "app" {
  name              = local.app_log_group
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = local.flow_log_group
  retention_in_days = 7
}

resource "aws_iam_role" "flowlogs" {
  name               = "${local.name}-flowlogs"
  path               = "/nimbus/"
  assume_role_policy = templatefile("${path.module}/policies/flowlogs-trust.json.tftpl", { account_id = local.account_id })
}

resource "aws_iam_role_policy" "flowlogs" {
  name = "write-one-log-group"
  role = aws_iam_role.flowlogs.id
  policy = templatefile("${path.module}/policies/flowlogs-role.json.tftpl", {
    region = var.region, account_id = local.account_id, log_group = local.flow_log_group
  })
}

# Only REJECTED traffic is recorded: it is the evidence of probes and misconfiguration, and it is tiny.
resource "aws_flow_log" "rejected" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "REJECT"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flowlogs.arn
}
