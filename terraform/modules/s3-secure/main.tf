# Gjenbrukbar modul for en "sikker som standard" S3-bucket:
# - Ingen offentlig tilgang
# - Kryptering at rest (KMS)
# - Versjonering på
# - Tilgangslogging til egen loggbucket
# - Livssyklusregel som rydder opp gamle versjoner
# Dette er nøyaktig settet med kontroller Checkov og Prowler sjekker for S3.

data "aws_iam_policy_document" "this_kms" {
  #checkov:skip=CKV_AWS_356: KMS nokkelpolicy - "Resource=*" betyr her "denne nokkelen", ikke alle ressurser i kontoen. Se begrunnelse i modules/cloudtrail/main.tf.
  #checkov:skip=CKV_AWS_109: Se begrunnelse for CKV_AWS_356 over.
  #checkov:skip=CKV_AWS_111: Se begrunnelse for CKV_AWS_356 over.
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
  description             = "KMS-nøkkel for ${var.bucket_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV2_AWS_62: Ingen aktiv mottaker (SNS/SQS/Lambda) for hendelsesvarsling i dette portefolje-prosjektet uten drift. Se docs/SECURITY_FINDINGS.md seksjon 5.
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

# --- Egen loggbucket (mottar tilgangslogger fra hovedbucketen) ---

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_145: S3 access-logging-mal-bucketer stotter ikke SSE-KMS, kun AES256/SSE-S3. Se kommentar i aws_s3_bucket_server_side_encryption_configuration.logs.
  #checkov:skip=CKV_AWS_18: Dette ER logg-destinasjonsbucketen. Å logge tilgang til seg selv er sirkulaert og gir ingen verdi.
  #checkov:skip=CKV_AWS_21: Falsk positiv - aws_s3_bucket_versioning.logs finnes og er Enabled. Checkov klarer ikke koble count-indeksert bucket (logs[0]) til ressursen i grafen.
  #checkov:skip=CKV2_AWS_6: Falsk positiv - aws_s3_bucket_public_access_block.logs finnes med alle 4 flagg satt til true. Samme count-indeks-begrensning som over.
  #checkov:skip=CKV2_AWS_61: Falsk positiv - aws_s3_bucket_lifecycle_configuration.logs finnes. Samme count-indeks-begrensning som over.
  #checkov:skip=CKV2_AWS_62: Ingen aktiv mottaker (SNS/SQS/Lambda) for hendelsesvarsling i dette portefolje-prosjektet uten drift. Se docs/SECURITY_FINDINGS.md seksjon 5.
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
      sse_algorithm = "AES256" # S3-tilgangslogging støtter ikke SSE-KMS som mål
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

# --- Valgfri bucket-policy som tillater CloudTrail å skrive hit ---

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
