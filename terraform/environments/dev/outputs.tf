output "logs_bucket_id" {
  value = module.logs_bucket.bucket_id
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "cloudtrail_arn" {
  value = module.cloudtrail.trail_arn
}

output "auditor_role_arn" {
  value = module.iam.auditor_role_arn
}
