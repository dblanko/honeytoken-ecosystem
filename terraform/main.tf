############################################
# 1. IAM user with NO permissions at all
############################################
# This user's access key IS the honeytoken. No attached policy means
# any API call made with this key is guaranteed to fail with
# AccessDenied -- but the attempt itself is still visible in CloudTrail.

resource "aws_iam_user" "canary" {
  name = var.canary_user_name
  path = "/"

  tags = {
    Purpose   = "honeytoken-canary"
    ManagedBy = "honeytoken-terraform-module"
  }
}

resource "aws_iam_access_key" "canary" {
  user = aws_iam_user.canary.name
}

# Explicit deny-all on top of "no policy at all" -- redundant right
# now, but it protects you from future-you accidentally attaching a
# managed policy to this user and quietly turning the honeytoken into
# a real credential.
resource "aws_iam_user_policy" "explicit_deny" {
  name = "explicit-deny-all"
  user = aws_iam_user.canary.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

############################################
# 1.5. CloudTrail Trail -- REQUIRED for EventBridge delivery
############################################
# Learned this the hard way while testing: the free 90-day CloudTrail
# Event History does NOT feed EventBridge on its own. Only events
# captured by an actual configured Trail get delivered there. Skip
# this block and the rule below will never fire on real AWS API calls
# -- it'll look like everything's wired up correctly (the manual
# `aws events put-events` test will even fire fine, since that skips
# CloudTrail entirely), but nothing real will ever come through.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "trail_logs" {
  bucket        = "honeytoken-trail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Purpose = "honeytoken-canary-trail-storage"
  }
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "honeytoken_trail" {
  name                          = "honeytoken-canary-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

  event_selector {
    read_write_type           = "All" # catches both AccessDenied attempts and read-only recon like ListBuckets
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.trail_logs]
}

############################################
# 2. EventBridge: rule for any API call made
#    as this IAM user
############################################
# state = ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS matters a lot
# here. The default "ENABLED" state silently drops read-only events
# like GetCallerIdentity, ListBuckets, DescribeXxx -- which is exactly
# the kind of recon an attacker does first. A honeytoken that only
# catches write attempts misses most of what actually happens.

resource "aws_cloudwatch_event_rule" "canary_triggered" {
  name        = "honeytoken-${var.canary_user_name}-triggered"
  description = "Fires on ANY AWS API call made as the honeytoken IAM user ${var.canary_user_name}, including read-only calls"
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        arn = [aws_iam_user.canary.arn]
      }
    }
  })

  depends_on = [aws_cloudtrail.honeytoken_trail]
}

############################################
# 3. API Destination -- POSTs straight to your
#    Cloudflare Worker, no Lambda needed
############################################

resource "aws_cloudwatch_event_connection" "worker_connection" {
  name               = "honeytoken-worker-connection"
  authorization_type = "API_KEY"

  auth_parameters {
    api_key {
      key   = "X-Canary-Secret"
      value = var.worker_shared_secret != "" ? var.worker_shared_secret : "unused"
    }
  }
}

resource "aws_cloudwatch_event_api_destination" "worker" {
  name                              = "honeytoken-worker-destination"
  invocation_endpoint               = var.worker_alert_url
  http_method                       = "POST"
  invocation_rate_limit_per_second  = 10
  connection_arn                    = aws_cloudwatch_event_connection.worker_connection.arn
}

resource "aws_iam_role" "eventbridge_invoke_role" {
  name = "honeytoken-eventbridge-invoke-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_invoke_policy" {
  name = "invoke-api-destination"
  role = aws_iam_role.eventbridge_invoke_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "events:InvokeApiDestination"
        Resource = aws_cloudwatch_event_api_destination.worker.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "to_worker" {
  rule     = aws_cloudwatch_event_rule.canary_triggered.name
  arn      = aws_cloudwatch_event_api_destination.worker.arn
  role_arn = aws_iam_role.eventbridge_invoke_role.arn

  # Forward the useful bits into the POST body -- the Worker already
  # logs and forwards whatever body it gets, so this just makes the
  # Telegram alert readable instead of a wall of raw CloudTrail JSON.
  input_transformer {
    input_paths = {
      user    = "$.detail.userIdentity.arn"
      ip      = "$.detail.sourceIPAddress"
      event   = "$.detail.eventName"
      time    = "$.detail.eventTime"
      errCode = "$.detail.errorCode"
    }
    input_template = <<-EOT
      {
        "source": "aws-cloudtrail-honeytoken",
        "iam_user": <user>,
        "source_ip": <ip>,
        "api_call": <event>,
        "event_time": <time>,
        "error_code": <errCode>
      }
    EOT
  }
}
