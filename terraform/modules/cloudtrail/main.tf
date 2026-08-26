# Multi-region CloudTrail with log file validation + CloudWatch Logs integration.
# This is among the most important CIS/Prowler checks: without CloudTrail you
# have no audit trail of what happens in your account.

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail logs"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.kms.json
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_356: KMS key policy - "Resource=*" here means "this key", not all resources. This is AWS's recommended standard pattern for CloudTrail keys.
  #checkov:skip=CKV_AWS_109: See justification for CKV_AWS_356 above.
  #checkov:skip=CKV_AWS_111: See justification for CKV_AWS_356 above.
  statement {
    sid       = "EnableRootPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudTrailUseOfKey"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsUseOfKey"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudtrail/${var.trail_name}"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = aws_kms_key.cloudtrail.arn
}

data "aws_iam_policy_document" "cwl_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_to_cwl" {
  name               = "${var.trail_name}-cwl-role"
  assume_role_policy = data.aws_iam_policy_document.cwl_assume.json
}

data "aws_iam_policy_document" "cwl_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cwl_permissions" {
  name   = "${var.trail_name}-cwl-policy"
  role   = aws_iam_role.cloudtrail_to_cwl.id
  policy = data.aws_iam_policy_document.cwl_permissions.json
}

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252: Accepting the risk for this portfolio project - no active operations/on-call receiving SNS alerts anyway. The CloudWatch Logs integration still provides full logging and the ability for manual review. See docs/SECURITY_FINDINGS.md section 5.
  name                          = var.trail_name
  s3_bucket_name                = var.s3_bucket_name
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cwl.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  # Prowler: cloudtrail_s3_dataevents_read_enabled / cloudtrail_s3_dataevents_write_enabled.
  # Management events alone do not capture object-level operations (GetObject/
  # PutObject) in S3 -- without data events we have no traceability of who
  # actually read or wrote the CloudTrail logs/tfstate files themselves.
  # "arn:aws:s3" (without a bucket name) covers all buckets in the account,
  # which is what this CIS-related check requires. NB: can add extra
  # CloudTrail cost at high S3 volume -- acceptable for this portfolio project.
  event_selector {
    read_write_type           = "All"
    include_management_events = false

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  depends_on = [aws_iam_role_policy.cwl_permissions]
}
