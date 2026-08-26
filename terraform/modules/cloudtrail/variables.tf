variable "trail_name" {
  description = "Navn på CloudTrail-trailen."
  type        = string
  default     = "cloud-sec-baseline-trail"
}

variable "s3_bucket_name" {
  description = "Navn på S3-bucketen CloudTrail skal skrive logger til (fra s3-secure-modulen)."
  type        = string
}

variable "cloudwatch_retention_days" {
  description = "Hvor lenge CloudTrail-logger beholdes i CloudWatch Logs."
  type        = number
  default     = 365
}
