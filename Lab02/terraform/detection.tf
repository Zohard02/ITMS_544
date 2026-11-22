# ---------------------------------------------------------------------------------------------
# DETECTION: a CloudTrail trail (the record), two EventBridge rules (what matters) and an SNS topic (tell a human).
# The first CloudTrail trail of management events is free. This configuration creates exactly one.
# ---------------------------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = local.trail_name
  s3_bucket_name                = module.log_bucket.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true # digest files prove the logs were not changed afterwards

  event_selector {
    read_write_type           = "All"
    include_management_events = true # management events only: data events (every S3 object) cost money
  }

  depends_on = [module.log_bucket]
}

resource "aws_sns_topic" "alerts" {
  provider = aws.alerts
  name     = "${local.name}-security-alerts"
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "AllowEventBridgePublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  provider = aws.alerts
  arn      = aws_sns_topic.alerts.arn
  policy   = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "email" {
  provider  = aws.alerts
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email # AWS sends a confirmation email: you must click the link
}

locals {
  alert_rules = {
    risky-iam          = "events/iam-risky.json"
    signin-without-mfa = "events/signin-no-mfa.json"
  }
}

resource "aws_cloudwatch_event_rule" "alert" {
  for_each      = local.alert_rules
  provider      = aws.alerts
  name          = "${local.name}-${each.key}"
  description   = "Alert: ${each.key}"
  event_pattern = file("${path.module}/${each.value}")
}

resource "aws_cloudwatch_event_target" "alert" {
  for_each  = local.alert_rules
  provider  = aws.alerts
  rule      = aws_cloudwatch_event_rule.alert[each.key].name
  target_id = "email-the-security-topic"
  arn       = aws_sns_topic.alerts.arn
}
