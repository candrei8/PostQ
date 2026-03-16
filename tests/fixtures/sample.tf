resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_kms_key" "main" {
  customer_master_key_spec = "RSA_2048"
  key_usage                = "ENCRYPT_DECRYPT"
}

resource "aws_lb_listener" "https" {
  ssl_policy = "ELBSecurityPolicy-2016-08"
}

resource "aws_cloudfront_distribution" "cdn" {
  viewer_certificate {
    minimum_protocol_version = "TLSv1"
  }
}
