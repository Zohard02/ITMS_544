output "id" {
  value       = aws_s3_bucket.this.id
  description = "Bucket name. Resources that use this output wait until the bucket policy exists."
  depends_on  = [aws_s3_bucket_policy.this, aws_s3_bucket_public_access_block.this, aws_s3_bucket_server_side_encryption_configuration.this]
}

output "arn" {
  value = aws_s3_bucket.this.arn
}
