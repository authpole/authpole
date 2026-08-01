variable "aws_region" {
  description = "AWS Region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use for credentials"
  type        = string
  default     = "default"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "production"
}

variable "domain_name" {
  description = "Primary root domain name"
  type        = string
  default     = "swii.sh"
}

variable "api_subdomain" {
  description = "Domain name for Authpole Server API"
  type        = string
  default     = "authpole.swii.sh"
}

variable "admin_subdomain" {
  description = "Domain name for Authpole Admin Console UI"
  type        = string
  default     = "authpole-admin.swii.sh"
}

variable "manage_dns" {
  description = "Set to true if using AWS Route53 for automated DNS validation record creation"
  type        = bool
  default     = false
}

variable "s3_bucket_name" {
  description = "AWS S3 Bucket name for Authpole CAS object storage"
  type        = string
  default     = "authpole-production-storage"
}

variable "instance_type" {
  description = "EC2 instance type for Authpole Unikraft compute nodes"
  type        = string
  default     = "t3.micro"
}
