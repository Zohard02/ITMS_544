variable "bucket_name" {
  type        = string
  description = "Globally unique bucket name"
}

variable "log_bucket" {
  type        = string
  default     = null
  description = "Bucket that receives S3 server access logs. null means no access logging."
}

variable "log_prefix" {
  type    = string
  default = ""
}

variable "noncurrent_days" {
  type        = number
  default     = 30
  description = "Old versions of an object are deleted after this many days"
}

variable "expire_days" {
  type        = number
  default     = 0
  description = "Current objects expire after this many days. 0 keeps them."
}

variable "extra_policy_json" {
  type        = string
  default     = ""
  description = "A bucket policy document whose statements are added to the standard ones"
}
