variable "region" {
  description = "AWS region for the lab."
  type        = string
  default     = "us-east-2"
}

variable "project" {
  description = "Prefix for every resource name."
  type        = string
  default     = "lab02"
}

variable "vpc_cidr" {
  description = "Address range of the lab network."
  type        = string
  default     = "10.20.0.0/16"
}

variable "admin_cidr" {
  description = "The ONLY address allowed to reach the web console, written as your.ip.address/32."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && endswith(var.admin_cidr, "/32") && var.admin_cidr != "0.0.0.0/0"
    error_message = "admin_cidr must be a single address such as 203.0.113.7/32. Never open the console to the whole internet."
  }
}

variable "alert_email" {
  description = "Where the security alerts are sent. Confirm the subscription email from AWS."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must look like an email address."
  }
}

variable "instance_type" {
  description = "Instance type for all five servers. Must be Free Tier eligible in your account."
  type        = string
  default     = "t3.micro"

  validation {
    condition     = contains(["t3.micro", "t2.micro"], var.instance_type)
    error_message = "Only t3.micro or t2.micro are allowed in this lab (Free Tier)."
  }
}

variable "auto_shutdown_hours" {
  description = "Every server terminates itself after this many hours, in case you forget terraform destroy."
  type        = number
  default     = 5

  validation {
    condition     = var.auto_shutdown_hours >= 1 && var.auto_shutdown_hours <= 12
    error_message = "auto_shutdown_hours must be between 1 and 12."
  }
}
