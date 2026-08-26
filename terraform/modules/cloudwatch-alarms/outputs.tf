output "sns_topic_arn" {
  description = "ARN of the SNS topic the CIS alarms notify."
  value       = aws_sns_topic.cis_alarms.arn
}

output "alarm_names" {
  description = "Names of all 15 CIS alarms that were created."
  value       = [for a in aws_cloudwatch_metric_alarm.cis : a.alarm_name]
}
