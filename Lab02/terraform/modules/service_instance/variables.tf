variable "name" { type = string }
variable "subnet_id" { type = string }
variable "private_ip" { type = string }
variable "security_group_ids" { type = list(string) }
variable "instance_profile" { type = string }
variable "ami_id" { type = string }
variable "instance_type" { type = string }
variable "free_tier_types" { type = list(string) }
variable "user_data" { type = string }

variable "public_ip" {
  type    = bool
  default = false
}

variable "source_dest_check" {
  type        = bool
  default     = true
  description = "Only the NAT instance sets this to false, because it forwards packets that are not addressed to itself"
}
