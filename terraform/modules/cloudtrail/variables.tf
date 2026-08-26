variable "trail_name" {
  description = "Name of the CloudTrail trail."
  type        = string
  default     = "cloud-sec-baseline-trail"
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket CloudTrail should write logs to (from the s3-secure module)."
  type        = string
}

variable "cloudwatch_retention_days" {
  description = "How long CloudTrail logs are retained in CloudWatch Logs."
  type        = number
  default     = 365
}
