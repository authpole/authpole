# ACM Certificate for swii.sh, authpole.swii.sh, and authpole-admin.swii.sh
resource "aws_acm_certificate" "domain_cert" {
  domain_name               = var.domain_name
  subject_alternative_names = [var.api_subdomain, var.admin_subdomain, "*.${var.domain_name}"]
  validation_method         = "DNS"

  tags = {
    Name = "authpole-acm-certificate"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Optional Route53 Hosted Zone lookup & DNS Validation (if using AWS Route53)
data "aws_route53_zone" "primary" {
  count        = var.manage_dns ? 1 : 0
  name         = var.domain_name
  private_zone = false
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.manage_dns ? {
    for dvo in aws_acm_certificate.domain_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.primary[0].zone_id
}

resource "aws_acm_certificate_validation" "domain_cert_validation" {
  count                   = var.manage_dns ? 1 : 0
  certificate_arn         = aws_acm_certificate.domain_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}
