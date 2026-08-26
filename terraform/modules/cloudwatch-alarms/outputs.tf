output "sns_topic_arn" {
  description = "ARN til SNS-topicet CIS-alarmene varsler til."
  value       = aws_sns_topic.cis_alarms.arn
}

output "alarm_names" {
  description = "Navnene på alle 15 CIS-alarmene som ble opprettet."
  value       = [for a in aws_cloudwatch_metric_alarm.cis : a.alarm_name]
}
