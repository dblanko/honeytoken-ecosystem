output "canary_access_key_id" {
  description = "Access Key ID of the honeytoken -- this is what you scatter in decoy locations (see the main README)."
  value       = aws_iam_access_key.canary.id
}

output "canary_secret_access_key" {
  description = "Secret Access Key of the honeytoken."
  value       = aws_iam_access_key.canary.secret
  sensitive   = true
}

output "canary_user_arn" {
  description = "ARN of the honeytoken IAM user -- this is what the EventBridge rule filters on."
  value       = aws_iam_user.canary.arn
}

output "decoy_bucket_name" {
  description = "Name of the decoy S3 bucket. Data events are logged for this bucket, so `aws s3 ls s3://<this>` with the honeytoken credentials should trigger an alert. Use this to test the data-event path."
  value       = aws_s3_bucket.decoy.id
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule watching for this honeytoken's use."
  value       = aws_cloudwatch_event_rule.canary_triggered.name
}
