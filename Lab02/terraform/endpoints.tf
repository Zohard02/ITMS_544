# ---------------------------------------------------------------------------------------------
# S3 GATEWAY ENDPOINT (free). A route in both route tables that sends S3 traffic over the AWS network instead of the
# internet or the NAT instance. The endpoint policy is a firewall rule for that route: only our three buckets
# (and the Amazon Linux package repositories, which are also hosted on S3) can be reached through it.
# Note: there is no endpoint for IAM. That is why the private services need the NAT instance at all.
# ---------------------------------------------------------------------------------------------
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway" # Gateway endpoints are free. Interface endpoints cost money and are NOT used.
  route_table_ids   = [aws_route_table.public.id, aws_route_table.private.id]

  policy = templatefile("${path.module}/policies/s3-endpoint-policy.json.tftpl", {
    data_bucket     = local.data_bucket
    artifact_bucket = local.artifact_bucket
    region          = var.region
  })

  tags = { Name = "${local.name}-s3" }
}
