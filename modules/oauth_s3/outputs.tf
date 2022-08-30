output "oauth_redirect_uri" {
  value = var.cloudfront_alias != null ? "https://${var.cloudfront_alias}/login" : "https://${aws_cloudfront_distribution.auth.domain_name}/login"
}
