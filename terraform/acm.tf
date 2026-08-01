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
