output "auditor_role_arn" {
  description = "ARN til den skrivebeskyttede auditor-rollen."
  value       = aws_iam_role.auditor.arn
}
