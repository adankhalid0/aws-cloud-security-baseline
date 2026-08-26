output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "cloudwatch_log_group_name" {
  description = "Navnet på CloudWatch Log Group-en CloudTrail streamer til -- brukes av modules/cloudwatch-alarms for CIS metric filters."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}
