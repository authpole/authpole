# Route53 Alias Record for Authpole Server API (authpole.swii.sh -> ALB)
resource "aws_route53_record" "api_subdomain" {
  count   = var.manage_dns ? 1 : 0
  zone_id = data.aws_route53_zone.primary[0].zone_id
  name    = var.api_subdomain
  type    = "A"

  alias {
    name                   = aws_lb.authpole_alb.dns_name
    zone_id                = aws_lb.authpole_alb.zone_id
    evaluate_target_health = true
  }
}

# Route53 Alias Record for Authpole Admin Console UI (authpole-admin.swii.sh -> CloudFront)
resource "aws_route53_record" "admin_subdomain" {
  count   = var.manage_dns ? 1 : 0
  zone_id = data.aws_route53_zone.primary[0].zone_id
  name    = var.admin_subdomain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.admin_ui_cdn.domain_name
    zone_id                = aws_cloudfront_distribution.admin_ui_cdn.hosted_zone_id
    evaluate_target_health = false
  }
}
