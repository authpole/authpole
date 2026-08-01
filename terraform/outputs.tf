output "alb_dns_name" {
  description = "Public DNS address of Application Load Balancer"
  value       = aws_lb.authpole_alb.dns_name
}

output "api_url" {
  description = "Production Authpole Server API HTTPS URL"
  value       = "https://${var.api_subdomain}"
}

output "admin_ui_url" {
  description = "Production Authpole Admin Console UI HTTPS URL"
  value       = "https://${var.admin_subdomain}"
}

output "cloudfront_domain_name" {
  description = "CloudFront CDN domain name for Admin Console UI"
  value       = aws_cloudfront_distribution.admin_ui_cdn.domain_name
}

output "acm_certificate_arn" {
  description = "ACM SSL/TLS Certificate ARN"
  value       = aws_acm_certificate.domain_cert.arn
}

output "acm_certificate_status" {
  description = "ACM Certificate Validation Status"
  value       = aws_acm_certificate.domain_cert.status
}

output "acm_dns_validation_records" {
  description = "CNAME DNS validation records required by AWS ACM to issue the SSL certificate"
  value = {
    for dvo in aws_acm_certificate.domain_cert.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }
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
