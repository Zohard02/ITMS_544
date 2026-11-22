# ---------------------------------------------------------------------------------------------
# THE APPLICATION CODE, PACKAGED AND SHIPPED BY TERRAFORM.
# The app/ folder is zipped, uploaded to the artifact bucket under a name that contains its SHA-256 hash, and every
# instance downloads that exact file and verifies the hash before it unpacks it. No git clone, no GitHub account,
# nothing fetched from the internet to get the code. Change one line of code and the hash, the object name and the
# user data change, so Terraform replaces the instances: that is immutable infrastructure.
# ---------------------------------------------------------------------------------------------
data "archive_file" "app" {
  type        = "zip"
  source_dir  = "${path.module}/../app"
  output_path = "${path.module}/.build/app.zip"
}

resource "aws_s3_object" "app" {
  bucket = module.artifact_bucket.id
  key    = "app/${data.archive_file.app.output_sha256}.zip"
  source = data.archive_file.app.output_path
  etag   = data.archive_file.app.output_md5
}
