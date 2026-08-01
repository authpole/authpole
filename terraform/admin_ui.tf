# S3 Bucket for Admin Console UI Static Website (Option A)
resource "aws_s3_bucket" "admin_ui_bucket" {
  bucket = var.admin_subdomain

  tags = {
    Name = "authpole-admin-ui-bucket"
  }
}

resource "aws_s3_bucket_website_configuration" "admin_ui_website" {
  bucket = aws_s3_bucket.admin_ui_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "admin_ui_public_access" {
  bucket = aws_s3_bucket.admin_ui_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "admin_ui_policy" {
  depends_on = [aws_s3_bucket_public_access_block.admin_ui_public_access]
  bucket     = aws_s3_bucket.admin_ui_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.admin_ui_bucket.arn}/*"
      }
    ]
  })
}

# CloudFront CDN Distribution for authpole-admin.swii.sh
resource "aws_cloudfront_distribution" "admin_ui_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  aliases             = [var.admin_subdomain]

  origin {
    domain_name = aws_s3_bucket_website_configuration.admin_ui_website.website_endpoint
    origin_id   = "S3-Admin-UI"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-Admin-UI"

    forwarded_values {
      query_string = true
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.domain_cert.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  tags = {
    Name = "authpole-admin-ui-cdn"
  }
}
