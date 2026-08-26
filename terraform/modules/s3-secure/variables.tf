variable "bucket_name" {
  description = "Globalt unikt navn på S3-bucketen."
  type        = string
}

variable "enable_access_logging" {
  description = "Om det skal opprettes en egen S3-loggbucket for tilgangslogger."
  type        = bool
  default     = true
}

variable "noncurrent_version_expiration_days" {
  description = "Antall dager før gamle objektversjoner slettes automatisk."
  type        = number
  default     = 90
}

variable "cloudtrail_bucket_policy" {
  description = "Om bucket-policyen skal tillate CloudTrail å skrive logger hit."
  type        = bool
  default     = false
}

variable "account_id" {
  description = "AWS-konto-ID (brukes i CloudTrail bucket-policy-condition)."
  type        = string
  default     = ""
}
