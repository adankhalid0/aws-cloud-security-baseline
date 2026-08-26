variable "name" {
  description = "Navneprefiks for VPC-ressursene."
  type        = string
  default     = "cloud-sec-baseline"
}

variable "vpc_cidr" {
  description = "CIDR-blokk for VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR-blokker for offentlige subnett (én per AZ)."
  type        = list(string)
  default     = ["10.0.0.0/24", "10.0.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR-blokker for private subnett (én per AZ)."
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "flow_log_retention_days" {
  description = "Antall dager VPC flow logs beholdes i CloudWatch Logs."
  type        = number
  default     = 365
}
