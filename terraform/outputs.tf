output "alb_dns_name" {
  description = "Public DNS address of Application Load Balancer"
  value       = aws_lb.authpole_alb.dns_name
}

output "s3_bucket_name" {
  description = "AWS S3 Bucket name created for Authpole CAS storage"
  value       = aws_s3_bucket.authpole_storage.id
}

output "s3_bucket_arn" {
  description = "AWS S3 Bucket ARN"
  value       = aws_s3_bucket.authpole_storage.arn
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.authpole_vpc.id
}
