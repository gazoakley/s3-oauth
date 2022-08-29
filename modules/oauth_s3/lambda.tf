resource "local_file" "auth_lambda_file" {
  filename = "${path.module}/oauth_lambda_package/oauth.js"
  content = templatefile("${path.module}/oauth.tpl.js", {
    ssm_param_name_jwt_secret          = aws_ssm_parameter.jwt_secret.name,
    ssm_param_name_oauth_client_id     = aws_ssm_parameter.oauth_client_id.name,
    ssm_param_name_oauth_client_secret = aws_ssm_parameter.oauth_client_secret.name,
    ssm_param_name_oauth_domain        = aws_ssm_parameter.oauth_domain.name,
    ssm_param_name_auth_cookie_name    = aws_ssm_parameter.auth_cookie_name.name,
    ssm_param_name_auth_cookie_ttl_sec = aws_ssm_parameter.auth_cookie_ttl_sec.name
  })
}

data "archive_file" "auth_lambda_package" {
  depends_on  = [local_file.auth_lambda_file]
  type        = "zip"
  source_dir  = "${path.module}/oauth_lambda_package"
  output_path = "${path.module}/oauth.zip"
}

resource "aws_lambda_function" "auth" {
  function_name    = "${local.project}-auth"
  role             = aws_iam_role.auth_lambda.arn
  filename         = data.archive_file.auth_lambda_package.output_path
  source_code_hash = data.archive_file.auth_lambda_package.output_base64sha256
  runtime          = "nodejs12.x"
  handler          = "oauth.handler"
  publish          = true
}
