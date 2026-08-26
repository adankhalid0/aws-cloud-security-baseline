variable "cloudtrail_log_group_name" {
  description = "Name of the CloudWatch Log Group CloudTrail already writes to (module.cloudtrail's cloudtrail_log_group_name output)."
  type        = string
}

variable "alarm_notification_email" {
  description = "Email address to subscribe to the SNS notifications for the CIS alarms. Set to an empty string (\"\") to create the SNS topic without a subscription (the alarms still exist and can be subscribed to later)."
  type        = string
  default     = ""
}
