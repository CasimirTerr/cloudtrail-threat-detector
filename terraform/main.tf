terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "cloudtrail-threat-detector"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Every eventName a detection rule looks at. Only these reach the Lambda,
  # which keeps invocations (and cost) close to zero.
  watched_events = [
    "ConsoleLogin",
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "DeleteDetector", "UpdateDetector",
    "CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "AuthorizeSecurityGroupIngress",
    "DeleteBucketPublicAccessBlock", "PutBucketPublicAccessBlock", "PutBucketPolicy", "PutBucketAcl",
    "ScheduleKeyDeletion", "DisableKey",
  ]
}

# ------------------------------------------------------------------ alerts

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ------------------------------------------------------------------ lambda

data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../detector"
  output_path = "${path.module}/build/detector.zip"
  excludes    = ["__init__.py", "__pycache__"]
}

resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${var.name_prefix}"
  retention_in_days = 30
}

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "detector" {
  name               = "${var.name_prefix}-lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

# Least privilege: write its own logs and publish to its own topic. Nothing else.
data "aws_iam_policy_document" "detector" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.detector.arn}:*"]
  }
  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "detector" {
  name   = "${var.name_prefix}-policy"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}

resource "aws_lambda_function" "detector" {
  function_name    = var.name_prefix
  role             = aws_iam_role.detector.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      MIN_SEVERITY  = var.min_severity
      IGNORE_ACTORS = join(",", var.ignore_actors)
    }
  }

  depends_on = [aws_cloudwatch_log_group.detector, aws_iam_role_policy.detector]
}

# ------------------------------------------------------------------ eventbridge

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "${var.name_prefix}-events"
  description = "Risky CloudTrail events -> threat detector Lambda"

  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = local.watched_events
    }
  })
}

resource "aws_cloudwatch_event_target" "detector" {
  rule = aws_cloudwatch_event_rule.cloudtrail.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail.arn
}
