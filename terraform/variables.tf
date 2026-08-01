variable "aws_region" {
  description = "AWS Region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "production"
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
