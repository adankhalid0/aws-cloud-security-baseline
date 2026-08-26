# Bootstrap: oppretter S3-bucket + DynamoDB-tabell for Terraform remote state.
# Kjøres ÉN gang, før resten av prosjektet. Se docs/PLAN.md Fase 2.

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "state_kms" {
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
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "state" {
  policy                  = data.aws_iam_policy_document.state_kms.json
  description             = "KMS-nøkkel for kryptering av Terraform state"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "state" {
  name          = "alias/tfstate-key"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "tfstate" {
  bucket = var.state_bucket_name

  # checkov:skip=CKV_AWS_144: Cross-region replikering er ikke nødvendig for et portefølje-prosjekt.
  #checkov:skip=CKV2_AWS_62: Ingen aktiv mottaker (SNS/SQS/Lambda) for hendelsesvarsling i dette portefolje-prosjektet uten drift. Se docs/SECURITY_FINDINGS.md seksjon 5.
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id = "expire-old-versions"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    filter {}
  }
}

resource "aws_s3_bucket_logging" "tfstate" {
  bucket        = aws_s3_bucket.tfstate.id
  target_bucket = aws_s3_bucket.tfstate.id
  target_prefix = "access-logs/"
}

# Prowler: s3_bucket_secure_transport_policy -- tfstate-bucketen manglet en
# bucket-policy i det hele tatt, sa det var ingenting som hindret ukryptert
# HTTP-tilgang til Terraform state (som kan inneholde sensitive verdier).
data "aws_iam_policy_document" "tfstate" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]

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

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate.json
}

resource "aws_dynamodb_table" "lock" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.state.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}
