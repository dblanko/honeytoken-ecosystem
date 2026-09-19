variable "aws_region" {
  description = "AWS region where the honeytoken IAM user gets created. Match this to whatever region your AWS CLI profile defaults to, or you'll spend an afternoon wondering why nothing fires."
  type        = string
  default     = "us-east-1"
}

variable "canary_user_name" {
  description = "Name of the honeytoken IAM user. Make it sound plausible (e.g. 'backup-service-prod') so it doesn't stick out at a glance."
  type        = string
  default     = "svc-backup-legacy"
}

variable "decoy_bucket_prefix" {
  description = <<-EOT
    Name prefix for the decoy S3 bucket (the account ID gets appended, since
    bucket names must be globally unique). Pick something an attacker would
    want to open -- the whole point is that it looks worth looking inside.
    Data events are logged for this bucket, so any attempt to list or read
    its contents triggers an alert.
  EOT
  type        = string
  default     = "company-db-backups"
}

variable "worker_alert_url" {
  description = <<-EOT
    Full URL of your Cloudflare Worker's alert endpoint, e.g.
    https://canary.example.com/hit/<canary_id>

    Use the canary_id that `honeytoken generate` created for the AWS
    token, so this alert lands in the same dedup/tracking stream as
    the rest of your decoys.
  EOT
  type = string
}

variable "worker_shared_secret" {
  description = <<-EOT
    Optional shared secret EventBridge sends as the X-Canary-Secret
    header when calling worker_alert_url. Useful for telling real
    hits apart from random noise hitting the same path. Leave blank
    to skip the header entirely.
  EOT
  type      = string
  default   = ""
  sensitive = true
}
