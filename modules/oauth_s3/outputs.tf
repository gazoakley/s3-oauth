output "oauth_redirect_uri" {
  value = var.cloudfront_alias != null ? "https://${var.cloudfront_alias}/login" : "https://${aws_cloudfront_distribution.auth.domain_name}/login"
}

output "cloudfront_domain_name" {
  value       = aws_cloudfront_distribution.auth.domain_name
  description = "The domain name corresponding to the distribution."
}

output "cloudfront_hosted_zone_id" {
  value       = aws_cloudfront_distribution.auth.hosted_zone_id
  description = "The CloudFront Route 53 zone ID that can be used to route an Alias Resource Record Set to."
}
