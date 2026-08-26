variable "aws_region" {
  description = "AWS region where the state resources are created."
  type        = string
  default     = "eu-north-1" # Stockholm - closest to Norway
}

variable "state_bucket_name" {
  description = "Globally unique name for the S3 bucket that stores the Terraform state. MUST be changed before apply."
  type        = string
  # Example: "tfstate-cloud-sec-baseline-<your-name>-<random-number>"
}

variable "lock_table_name" {
  description = "Name of the DynamoDB table used for state locking."
  type        = string
  default     = "tfstate-locks"
}
