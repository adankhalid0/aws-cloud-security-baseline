# Reusable module for a "secure by default" S3 bucket:
# - No public access
# - Encryption at rest (KMS)
# - Versioning on
# - Access logging to a dedicated log bucket
# - Lifecycle rule that cleans up old versions
# This is exactly the set of controls Checkov and Prowler check for S3.

data "aws_iam_policy_document" "this_kms" {
  #checkov:skip=CKV_AWS_356: KMS key policy - "Resource=*" here means "this key", not all resources in the account. See justification in modules/cloudtrail/main.tf.
  #checkov:skip=CKV_AWS_109: See justification for CKV_AWS_356 above.
  #checkov:skip=CKV_AWS_111: See justification for CKV_AWS_356 above.
  statement {
    sid       = "EnableRootPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "this" {
  policy                  = data.aws_iam_policy_document.this_kms.json
  description             = "KMS key for ${var.bucket_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV2_AWS_62: No active receiver (SNS/SQS/Lambda) for event notifications in this portfolio project without live operations. See docs/SECURITY_FINDINGS.md section 5.
  bucket = var.bucket_name
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    id = "expire-old-versions"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_expiration_days
    }
    filter {}
  }
}

# --- Dedicated log bucket (receives access logs from the main bucket) ---

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_145: S3 access-logging target buckets do not support SSE-KMS, only AES256/SSE-S3. See comment in aws_s3_bucket_server_side_encryption_configuration.logs.
  #checkov:skip=CKV_AWS_18: This IS the log destination bucket. Logging access to itself is circular and provides no value.
  #checkov:skip=CKV_AWS_21: False positive - aws_s3_bucket_versioning.logs exists and is Enabled. Checkov fails to link the count-indexed bucket (logs[0]) to the resource in the graph.
  #checkov:skip=CKV2_AWS_6: False positive - aws_s3_bucket_public_access_block.logs exists with all 4 flags set to true. Same count-index limitation as above.
  #checkov:skip=CKV2_AWS_61: False positive - aws_s3_bucket_lifecycle_configuration.logs exists. Same count-index limitation as above.
  #checkov:skip=CKV2_AWS_62: No active receiver (SNS/SQS/Lambda) for event notifications in this portfolio project without live operations. See docs/SECURITY_FINDINGS.md section 5.
  count  = var.enable_access_logging ? 1 : 0
  bucket = "${var.bucket_name}-access-logs"
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.enable_access_logging ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # S3 access logging does not support SSE-KMS as a target
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    id = "expire-old-logs"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    status = "Enabled"
    expiration {
      days = 365
    }
    filter {}
  }
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.enable_access_logging ? 1 : 0
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = "access-logs/${var.bucket_name}/"
}

data "aws_iam_policy_document" "log_delivery" {
  count = var.enable_access_logging ? 1 : 0

  statement {
    sid       = "S3ServerAccessLogsPolicy"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs[0].arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.this.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs[0].arn, "${aws_s3_bucket.logs[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  policy = data.aws_iam_policy_document.log_delivery[0].json
}

# --- Optional bucket policy that allows CloudTrail to write here ---

data "aws_iam_policy_document" "cloudtrail" {
  count = var.cloudtrail_bucket_policy ? 1 : 0

  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.this.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/AWSLogs/${var.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.cloudtrail_bucket_policy ? 1 : 0
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.cloudtrail[0].json
}
