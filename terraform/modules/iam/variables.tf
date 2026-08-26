variable "auditor_principal_arns" {
  description = "Liste over IAM-principal-ARNer som skal kunne påta seg den skrivebeskyttede auditor-rollen (f.eks. din egen IAM-bruker)."
  type        = list(string)
}

variable "require_mfa_for_auditor_role" {
  description = "Krev MFA for å påta seg auditor-rollen."
  type        = bool
  default     = true
}

variable "password_policy_min_length" {
  description = "Minste passordlengde i kontoens IAM password policy."
  type        = number
  default     = 14
}
