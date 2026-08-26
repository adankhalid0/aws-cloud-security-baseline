variable "bucket_name" {
  description = "Globally unique name for the S3 bucket."
  type        = string
}

variable "enable_access_logging" {
  description = "Whether a dedicated S3 log bucket should be created for access logs."
  type        = bool
  default     = true
}

variable "noncurrent_version_expiration_days" {
  description = "Number of days before old object versions are automatically deleted."
  type        = number
  default     = 90
}

variable "cloudtrail_bucket_policy" {
  description = "Whether the bucket policy should allow CloudTrail to write logs here."
  type        = bool
  default     = false
}

variable "account_id" {
  description = "AWS account ID (used in the CloudTrail bucket policy condition)."
  type        = string
  default     = ""
}
