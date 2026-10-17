output "sns_topic_arn" {
  description = "Subscribe more endpoints (Slack via Chatbot, SMS, a SIEM) to this topic."
  value       = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.detector.function_name
}

output "eventbridge_rule" {
  value = aws_cloudwatch_event_rule.cloudtrail.name
}

output "trail_bucket" {
  value = var.create_trail ? aws_s3_bucket.trail[0].id : "(using existing trail)"
}
