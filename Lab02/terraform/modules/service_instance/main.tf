# One hardened EC2 instance. The same module builds the NAT instance and the four microservices.

resource "aws_instance" "this" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  private_ip                  = var.private_ip
  vpc_security_group_ids      = var.security_group_ids
  iam_instance_profile        = var.instance_profile
  associate_public_ip_address = var.public_ip
  source_dest_check           = var.source_dest_check
  monitoring                  = false # detailed monitoring costs money

  # No key pair, no port 22. Administration is through Session Manager only.

  user_data                   = var.user_data
  user_data_replace_on_change = true # new code or new settings means a new instance

  # Shutting the OS down TERMINATES the instance. The auto shutdown timer therefore ends the billing too.
  instance_initiated_shutdown_behavior = "terminate"

  # t3 instances can borrow CPU and be billed for it ("unlimited" mode). "standard" can never cost extra.
  credit_specification { cpu_credits = "standard" }

  # IMDSv2 only: a stolen request (SSRF) cannot read the instance credentials.
  # Hop limit 1 also keeps the metadata service out of reach of anything running behind the instance.
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8 # 8 GB is the smallest size the image allows. The free tier is 30 GB-MONTHS, so 5 x 8 GB for a few hours is far below it
    encrypted             = true
    delete_on_termination = true
  }

  tags        = { Name = var.name }
  volume_tags = { Name = var.name }

  lifecycle {
    precondition {
      condition     = contains(var.free_tier_types, var.instance_type)
      error_message = "${var.instance_type} is not Free Tier eligible in this account. Use t3.micro or t2.micro."
    }
  }
}
