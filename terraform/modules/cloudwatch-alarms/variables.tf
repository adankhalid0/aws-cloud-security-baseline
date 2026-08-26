variable "cloudtrail_log_group_name" {
  description = "Navnet på CloudWatch Log Group-en CloudTrail allerede skriver til (module.cloudtrail sitt output cloudtrail_log_group_name)."
  type        = string
}

variable "alarm_notification_email" {
  description = "E-postadresse som skal abonnere på SNS-varslene for CIS-alarmene. Sett til tom streng (\"\") for å opprette SNS-topicet uten abonnement (varslene finnes fortsatt og kan abonneres på senere)."
  type        = string
  default     = ""
}
