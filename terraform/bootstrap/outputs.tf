output "state_bucket_name" {
  description = "Navn på S3-bucketen for Terraform state (brukes i backend-blokken under environments/dev)."
  value       = aws_s3_bucket.tfstate.bucket
}

output "lock_table_name" {
  description = "Navn på DynamoDB-tabellen for state-låsing."
  value       = aws_dynamodb_table.lock.name
}

output "kms_key_arn" {
  description = "ARN til KMS-nøkkelen brukt for kryptering av state."
  value       = aws_kms_key.state.arn
}
