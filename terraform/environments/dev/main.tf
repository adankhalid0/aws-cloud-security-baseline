data "aws_caller_identity" "current" {}

# Prowler: s3_account_level_public_access_blocks (HIGH, CIS 2.0 2.1.4)
# Account-wide safety net on top of the per-bucket Public Access Block settings
# already applied in modules/s3-secure -- blocks public access even for buckets
# created outside that module or misconfigured later.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "logs_bucket" {
  source = "../../modules/s3-secure"

  bucket_name              = var.logs_bucket_name
  enable_access_logging    = true
  cloudtrail_bucket_policy = true
  account_id               = data.aws_caller_identity.current.account_id
}

module "vpc" {
  source = "../../modules/vpc"

  name = "cloud-sec-baseline-dev"
}

module "cloudtrail" {
  source = "../../modules/cloudtrail"

  trail_name     = "cloud-sec-baseline-dev-trail"
  s3_bucket_name = module.logs_bucket.bucket_id

  depends_on = [module.logs_bucket]
}

module "iam" {
  source = "../../modules/iam"

  auditor_principal_arns = var.auditor_principal_arns
}

# Prowler: 15x cloudwatch_log_metric_filter_* / cloudwatch_changes_to_*
# (MEDIUM, CIS 2.0 seksjon 4). Kobler metric filters + alarmer til
# CloudTrail-loggruppen som allerede finnes i module.cloudtrail.
module "cloudwatch_alarms" {
  source = "../../modules/cloudwatch-alarms"

  cloudtrail_log_group_name = module.cloudtrail.cloudwatch_log_group_name
  alarm_notification_email  = var.alarm_notification_email

  depends_on = [module.cloudtrail]
}
