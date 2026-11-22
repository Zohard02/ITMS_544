output "console_url" {
  description = "Open this in your browser (accept the self signed certificate after checking its fingerprint)"
  value       = "https://${module.service["web"].public_ip}:8443"
}

output "admin_username" {
  value = aws_cognito_user.admin.username
}

output "admin_password" {
  description = "Cognito password of the admin user. Show it with: terraform output -raw admin_password"
  value       = random_password.admin.result
  sensitive   = true
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.admins.id
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.web.id
}

output "instance_ids" {
  value = merge({ nat = module.nat.id }, { for k, m in module.service : k => m.id })
}

output "console_fingerprint_command" {
  description = "Shows the console's certificate fingerprint in the instance's boot log"
  value       = "aws ec2 get-console-output --instance-id ${module.service["web"].id} --latest --output text --region ${var.region} | grep 'BROWSER CERT'"
}

output "data_bucket" {
  value = local.data_bucket
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "free_tier_hours" {
  description = "Instances terminate themselves after this many hours"
  value       = var.auto_shutdown_hours
}
