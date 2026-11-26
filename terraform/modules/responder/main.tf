# ==========================================================================
# Responder: the triage Lambda every detection rule targets.
#
#   detection rule ─► (input transformer adds rule metadata) ─► Lambda ─► SNS
#                                      │ on failure after retries
#                                      └────────────► SQS dead-letter queue
#
# Publishes to the baseline's KMS-encrypted SNS topic. The baseline key
# policy delegates to IAM (EnableIAMPolicies), so this role is granted the
# key here and the baseline is not modified.
# ==========================================================================

data "aws_region" "current" {}

data "archive_file" "triage" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/build/triage.zip"
  excludes    = ["__pycache__"]
}

# ---- Logs: one year retention, encrypted with the baseline key ----------
# The baseline key policy already allows the CloudWatch Logs service for
# any log group in this account and region (AllowCloudWatchLogs).
resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/${var.project_name}-triage"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

# ---- Dead-letter queue: alerts that could not be delivered --------------
# Used by the EventBridge targets (rule could not invoke the Lambda) and by
# the Lambda itself (function failed after async retries). A message here
# means a detection fired and nobody was told, so it is worth an alarm.
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.project_name}-triage-dlq"
  message_retention_seconds = 1209600 # 14 days, the SQS maximum
  sqs_managed_sse_enabled   = true
}

# ---- IAM: least privilege for the triage function -----------------------
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "triage" {
  name               = "${var.project_name}-triage"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "triage" {
  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [var.topic_arn]
  }

  # SNS encrypts with the topic's key on the caller's behalf, so the caller
  # needs data-key permissions. ViaService limits them to SNS requests.
  statement {
    sid       = "UseTopicKeyViaSnsOnly"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sns.${data.aws_region.current.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.triage.arn}:*"]
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  # X-Ray does not support resource-level permissions.
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "triage" {
  name   = "triage"
  role   = aws_iam_role.triage.id
  policy = data.aws_iam_policy_document.triage.json
}

# ---- The function --------------------------------------------------------
resource "aws_lambda_function" "triage" {
  #checkov:skip=CKV_AWS_117:No VPC. The function only calls public AWS APIs (SNS, and IAM for containment later); a VPC would need NAT or endpoints at extra cost with no data-path benefit.
  #checkov:skip=CKV_AWS_272:Code signing needs AWS Signer and a signing profile; out of scope for a single-author portfolio repo. Code integrity comes from git plus CI.
  #checkov:skip=CKV_AWS_115:Reserved concurrency would cut into the account's unreserved pool, which is only 10 on new accounts. Volume is a handful of events per day.
  #checkov:skip=CKV_AWS_173:The only environment variable is the SNS topic ARN, which is not a secret. Lambda encrypts environment variables at rest with an AWS-managed key by default.
  function_name    = "${var.project_name}-triage"
  description      = "Formats detection events and publishes alerts to the baseline SNS topic"
  role             = aws_iam_role.triage.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.triage.output_path
  source_code_hash = data.archive_file.triage.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      TOPIC_ARN = var.topic_arn
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.triage.name
  }

  depends_on = [aws_iam_role_policy.triage]
}
