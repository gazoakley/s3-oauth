locals {
  ssm_prefix = var.ssm_prefix != null ? var.ssm_prefix : "${var.name}-"
}

resource "aws_ssm_parameter" "jwt_secret" {
  name  = "${local.ssm_prefix}jwt-secret"
  type  = "SecureString"
  value = random_password.jwt_secret.result
}

resource "aws_ssm_parameter" "oauth_client_id" {
  name  = "${local.ssm_prefix}oauth-client-id"
  type  = "SecureString"
  value = var.oauth_client_id
}

resource "aws_ssm_parameter" "oauth_client_secret" {
  name  = "${local.ssm_prefix}oauth-client-secret"
  type  = "SecureString"
  value = var.oauth_client_secret
}

resource "aws_ssm_parameter" "oauth_domain" {
  name  = "${local.ssm_prefix}oauth-domain"
  type  = "SecureString"
  value = var.oauth_domain
}

resource "aws_ssm_parameter" "auth_cookie_name" {
  name  = "${local.ssm_prefix}auth-cookie-name"
  type  = "SecureString"
  value = var.auth_cookie_name == null ? local.project : var.auth_cookie_name
}

resource "aws_ssm_parameter" "auth_cookie_ttl_sec" {
  name  = "${local.ssm_prefix}auth-cookie-ttl-sec"
  type  = "SecureString"
  value = var.auth_cookie_ttl_sec
}
