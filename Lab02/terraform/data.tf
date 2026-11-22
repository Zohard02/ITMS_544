# Data sources READ things that already exist. They create nothing.

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# The newest Amazon Linux 2023 image, looked up through the public AWS parameter (no hard coded image id).
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# Ask AWS which instance types are Free Tier eligible for THIS account. The compute module refuses to launch
# anything else (see the precondition in modules/service_instance/main.tf).
data "aws_ec2_instance_types" "free_tier" {
  filter {
    name   = "free-tier-eligible"
    values = ["true"]
  }
}
