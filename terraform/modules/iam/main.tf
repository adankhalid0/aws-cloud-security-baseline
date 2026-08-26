# IAM-modul: demonstrerer least-privilege prinsippet.
# 1) En skrivebeskyttet "auditor"-rolle andre kan påta seg (assume) i stedet for å dele nøkler.
# 2) En kontobred passord-policy som følger CIS AWS Foundations Benchmark.
#
# MERK: Selve Terraform-deployeren (brukeren/rollen som kjører `terraform apply`)
# er IKKE definert her -- den settes opp manuelt med minimum nødvendige rettigheter,
# se docs/PLAN.md Fase 1 (steg "Opprett IAM-bruker for Terraform").

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
  max_session_duration = 3600 # 1 time -- korte, tidsbegrensede økter

  # checkov:skip=CKV_AWS_274: Rollen er ment for skrivebeskyttet tilgang uten permissions boundary i dette portefølje-prosjektet.
}

resource "aws_iam_role_policy_attachment" "auditor_readonly" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "auditor_security_audit" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Prowler: iam_support_role_created (CIS 2.0 1.20) -- en rolle dedikert til a
# opprette/handtere saker med AWS Support, slik at man ikke trenger root eller
# en admin-bruker sine fulle rettigheter bare for a be om support-hjelp.
# Samme prinsipp som auditor-rollen over: assume-role for kjente principaler,
# MFA-gated, ingen delte nokler.
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
  max_session_duration = 3600 # 1 time -- korte, tidsbegrensede okter

  # checkov:skip=CKV_AWS_274: Rollen er ment for AWS Support-tilgang uten permissions boundary i dette portefolje-prosjektet.
}

resource "aws_iam_role_policy_attachment" "support_access" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

# Kontobred passordpolicy -- et av de vanligste Prowler/CIS-funnene i ferske AWS-kontoer.
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
