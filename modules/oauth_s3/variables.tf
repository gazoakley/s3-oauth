locals {
  project      = "${var.name}-s3-oauth"
  s3_origin_id = local.project
}

variable "name" {
  type        = string
  description = "Name of the project which uses this module. Resource names will be prefixed with this value."
}

variable "s3_bucket_name" {
  type        = string
  description = "Name of the existing S3 bucket to protect."
}

variable "s3_bucket_default_root_object" {
  type        = string
  description = "Default object to serve when no path is specified in the request."
}

variable "s3_bucket_policy_enabled" {
  type        = bool
  description = "Creates an S3 bucket policy for the bucket."
  default     = true
}

variable "cloudfront_origin_access_identity" {
  type        = string
  description = "The CloudFront origin access identity to associate with the origin."
  default     = null
}

variable "cloudfront_alias" {
  type        = string
  description = "Alias (domain or subdomain name) that can be used to access the S3 static website bucket."
  default     = null
}

variable "cloudfront_acm_certificate_arn" {
  type        = string
  description = "ARN of the ACM certificate to use if cloudfront_alias is set."
  default     = null
}

variable "oauth_client_id" {
  type        = string
  description = "OAuth client ID"
}

variable "oauth_client_secret" {
  type        = string
  description = "OAuth client secret"
}

variable "oauth_domain" {
  type        = string
  description = "OAuth domain"
}

variable "auth_cookie_name" {
  type        = string
  description = "Name of the authentication cookie (default: {var.project}-s3-oauth)."
  default     = null
}

variable "auth_cookie_ttl_sec" {
  type        = number
  description = "TTL (in seconds) of the authentication cookie."
  default     = 3600
}
