variable "aws_region" {
  description = "AWS-region for hovedressursene."
  type        = string
  default     = "eu-north-1"
}

variable "logs_bucket_name" {
  description = "Globalt unikt navn på S3-bucketen CloudTrail logger til. MÅ endres før apply."
  type        = string
}

variable "auditor_principal_arns" {
  description = "IAM-principal-ARNer (f.eks. din egen bruker) som kan påta seg auditor-rollen."
  type        = list(string)
}

variable "alarm_notification_email" {
  description = "E-postadresse som skal abonnere på CIS-sikkerhetsalarmene (SNS). Sett til \"\" for å hoppe over abonnement -- alarmene opprettes uansett."
  type        = string
  default     = ""
}
