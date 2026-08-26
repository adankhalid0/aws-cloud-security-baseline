output "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state (used in the backend block under environments/dev)."
  value       = aws_s3_bucket.tfstate.bucket
}

output "lock_table_name" {
  description = "Name of the DynamoDB table used for state locking."
  value       = aws_dynamodb_table.lock.name
}

output "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt the state."
  value       = aws_kms_key.state.arn
}
