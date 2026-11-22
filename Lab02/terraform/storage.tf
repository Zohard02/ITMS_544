# ---------------------------------------------------------------------------------------------
# THREE BUCKETS, ALL BUILT BY THE SAME MODULE (modules/secure_bucket). The module applies the data protection
# controls from Lab01 once, so none of the three can be created without them:
#   encryption at rest, Block Public Access, versioning, TLS only, lifecycle expiry.
#   data      the employee registry and the audit trail (the "database" of the lab)
#   artifacts the packaged application code that the instances download at boot
#   logs      CloudTrail files and S3 access logs
# ---------------------------------------------------------------------------------------------
module "log_bucket" {
  source          = "./modules/secure_bucket"
  bucket_name     = local.log_bucket
  noncurrent_days = 7
  expire_days     = 30
  extra_policy_json = templatefile("${path.module}/policies/log-bucket-extra.json.tftpl", {
    log_bucket      = local.log_bucket
    data_bucket     = local.data_bucket
    artifact_bucket = local.artifact_bucket
    region          = var.region
    account_id      = local.account_id
    trail_name      = local.trail_name
  })
}

module "data_bucket" {
  source      = "./modules/secure_bucket"
  bucket_name = local.data_bucket
  log_bucket  = module.log_bucket.id
  log_prefix  = "s3-access/data/"
  # Data perimeter: the service roles may only touch this bucket through OUR VPC endpoint.
  extra_policy_json = templatefile("${path.module}/policies/bucket-vpce-only.json.tftpl", {
    bucket     = local.data_bucket
    vpce_id    = aws_vpc_endpoint.s3.id
    account_id = local.account_id
  })
}

module "artifact_bucket" {
  source      = "./modules/secure_bucket"
  bucket_name = local.artifact_bucket
  log_bucket  = module.log_bucket.id
  log_prefix  = "s3-access/artifacts/"
  extra_policy_json = templatefile("${path.module}/policies/bucket-vpce-only.json.tftpl", {
    bucket     = local.artifact_bucket
    vpce_id    = aws_vpc_endpoint.s3.id
    account_id = local.account_id
  })
}
