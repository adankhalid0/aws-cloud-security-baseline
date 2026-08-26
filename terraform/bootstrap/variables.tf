variable "aws_region" {
  description = "AWS-region hvor state-ressursene opprettes."
  type        = string
  default     = "eu-north-1" # Stockholm - nærmest Norge
}

variable "state_bucket_name" {
  description = "Globalt unikt navn på S3-bucketen som skal lagre Terraform state. MÅ endres før apply."
  type        = string
  # Eksempel: "tfstate-cloud-sec-baseline-<dittnavn>-<tilfeldigtall>"
}

variable "lock_table_name" {
  description = "Navn på DynamoDB-tabellen som brukes til state-låsing."
  type        = string
  default     = "tfstate-locks"
}
