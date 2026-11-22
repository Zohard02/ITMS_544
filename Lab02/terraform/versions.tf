# Which Terraform and which providers this configuration was written for.
# A provider is the plug in that knows how to talk to one platform (AWS, TLS certificates, random numbers, zip files).
terraform {
  required_version = ">= 1.10" # 1.10 added native state locking in S3 (use_lockfile)

  required_providers {
    aws     = { source = "hashicorp/aws", version = ">= 5.80, < 6.0" }
    tls     = { source = "hashicorp/tls", version = "~> 4.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

# The main provider: everything lives in the lab region.
provider "aws" {
  region = var.region
  default_tags { tags = local.tags } # every taggable resource gets these tags automatically
}

# A second, named (aliased) provider. IAM and console sign in events are GLOBAL and are delivered to
# us-east-1, so the alert rules and the alert topic must be created in that region (same as Lab01).
provider "aws" {
  alias  = "alerts"
  region = "us-east-1"
  default_tags { tags = local.tags }
}
