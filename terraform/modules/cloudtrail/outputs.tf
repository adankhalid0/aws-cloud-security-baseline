output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group CloudTrail streams to -- used by modules/cloudwatch-alarms for CIS metric filters."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}
