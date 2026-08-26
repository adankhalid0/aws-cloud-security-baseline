variable "aws_region" {
  description = "AWS region for the main resources."
  type        = string
  default     = "eu-north-1"
}

variable "logs_bucket_name" {
  description = "Globally unique name for the S3 bucket CloudTrail logs to. MUST be changed before apply."
  type        = string
}

variable "auditor_principal_arns" {
  description = "IAM principal ARNs (e.g. your own user) allowed to assume the auditor role."
  type        = list(string)
}

variable "alarm_notification_email" {
  description = "Email address to subscribe to the CIS security alarms (SNS). Set to \"\" to skip the subscription -- the alarms are created either way."
  type        = string
  default     = ""
}
