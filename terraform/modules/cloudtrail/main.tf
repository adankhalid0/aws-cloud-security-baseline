# Multi-region CloudTrail med log file validation + CloudWatch Logs-integrasjon.
# Dette er blant de aller viktigste CIS/Prowler-sjekkene: uten CloudTrail har du
# ingen revisjonsspor av hva som skjer i kontoen din.

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS-nøkkel for CloudTrail-logger"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.kms.json
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_356: KMS nokkelpolicy - "Resource=*" betyr her "denne nokkelen", ikke alle ressurser. Dette er AWS sitt anbefalte standardmonster for CloudTrail-nokler.
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
  #checkov:skip=CKV_AWS_252: Aksepterer risiko for dette portefolje-prosjektet - ingen aktiv drift/on-call som mottar SNS-varsler uansett. CloudWatch Logs-integrasjonen gir fortsatt full logging og mulighet for manuell gjennomgang. Se docs/SECURITY_FINDINGS.md seksjon 5.
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
  # Management events alene fanger ikke opp objektniva-operasjoner (GetObject/
  # PutObject) i S3 -- uten data events har vi ingen sporbarhet for hvem som
  # faktisk leste eller skrev CloudTrail-loggene/tfstate-filene selv.
  # "arn:aws:s3" (uten bucket-navn) dekker alle bucketer i kontoen, som er det
  # denne CIS-relaterte sjekken krever. NB: kan gi ekstra CloudTrail-kostnad
  # ved hoyt S3-volum -- akseptabelt i dette portefolje-prosjektet.
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
