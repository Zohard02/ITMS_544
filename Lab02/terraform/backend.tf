# Remote state: the state file lives in the encrypted, versioned S3 bucket you created in Part B.
# The bucket name is not written here (it is different in every account). You pass it at init time:
#   terraform init -backend-config="bucket=<your state bucket>" -backend-config="region=us-east-2"
terraform {
  backend "s3" {
    key          = "lab02/terraform.tfstate"
    encrypt      = true
    use_lockfile = true # a lock object in the same bucket stops two people applying at the same time
  }
}
