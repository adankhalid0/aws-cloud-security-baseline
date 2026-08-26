variable "auditor_principal_arns" {
  description = "List of IAM principal ARNs allowed to assume the read-only auditor role (e.g. your own IAM user)."
  type        = list(string)
}

variable "require_mfa_for_auditor_role" {
  description = "Require MFA to assume the auditor role."
  type        = bool
  default     = true
}

variable "password_policy_min_length" {
  description = "Minimum password length in the account's IAM password policy."
  type        = number
  default     = 14
}
