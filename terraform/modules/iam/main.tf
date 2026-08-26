# IAM module: demonstrates the least-privilege principle.
# 1) A read-only "auditor" role others can assume instead of sharing keys.
# 2) An account-wide password policy that follows the CIS AWS Foundations Benchmark.
#
# NOTE: The actual Terraform deployer (the user/role that runs `terraform apply`)
# is NOT defined here -- it is set up manually with the minimum necessary
# permissions, see docs/PLAN.md Phase 1 (step "Create IAM user for Terraform").

data "aws_iam_policy_document" "auditor_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.auditor_principal_arns
    }

    dynamic "condition" {
      for_each = var.require_mfa_for_auditor_role ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "auditor" {
  name                 = "security-auditor-readonly"
  assume_role_policy   = data.aws_iam_policy_document.auditor_trust.json
  max_session_duration = 3600 # 1 hour -- short, time-limited sessions

  # checkov:skip=CKV_AWS_274: This role is intended for read-only access without a permissions boundary in this portfolio project.
}

resource "aws_iam_role_policy_attachment" "auditor_readonly" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "auditor_security_audit" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Prowler: iam_support_role_created (CIS 2.0 1.20) -- a role dedicated to
# creating/managing AWS Support cases, so that you don't need root or an
# admin user's full permissions just to ask for support help.
# Same principle as the auditor role above: assume-role for known principals,
# MFA-gated, no shared keys.
data "aws_iam_policy_document" "support_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.auditor_principal_arns
    }

    dynamic "condition" {
      for_each = var.require_mfa_for_auditor_role ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "support" {
  name                 = "aws-support-access"
  assume_role_policy   = data.aws_iam_policy_document.support_trust.json
  max_session_duration = 3600 # 1 hour -- short, time-limited sessions

  # checkov:skip=CKV_AWS_274: This role is intended for AWS Support access without a permissions boundary in this portfolio project.
}

resource "aws_iam_role_policy_attachment" "support_access" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

# Account-wide password policy -- one of the most common Prowler/CIS findings in fresh AWS accounts.
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.password_policy_min_length
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
