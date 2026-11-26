# ==========================================================================
# Detections: one EventBridge rule per YAML file in var.detections_dir.
#
# Why EventBridge rules and not CloudWatch metric filters (the baseline's
# approach for CIS alarms): EventBridge sees the full event in near real
# time and can route it to a Lambda with the details intact. A metric
# filter only produces a count, so a responder would have to go back and
# search the logs to learn who did what.
#
# The rule file is the source of truth. Terraform only reads it.
# ==========================================================================

locals {
  files = fileset(var.detections_dir, "*.yml")

  detections = {
    for f in local.files :
    trimsuffix(f, ".yml") => yamldecode(file("${var.detections_dir}/${f}"))
  }

  # Rule metadata handed to the triage Lambda with every matched event.
  metadata = {
    for k, d in local.detections : k => jsonencode({
      id           = d.id
      title        = d.title
      severity     = d.severity
      technique_id = d.attack.technique_id
      technique    = d.attack.technique
      response     = d.response
    })
  }
}

resource "aws_cloudwatch_event_rule" "detection" {
  for_each = local.detections

  name        = "${var.project_name}-${each.value.id}"
  description = substr("${each.value.attack.technique_id} ${each.value.title}", 0, 512)

  # The YAML event_pattern is passed through unchanged.
  event_pattern = jsonencode(each.value.event_pattern)

  tags = {
    DetectionId     = each.value.id
    AttackTechnique = each.value.attack.technique_id
    Severity        = each.value.severity
  }
}

# ---- Targets: every rule sends its event to the triage Lambda -----------
# The input transformer wraps the matched event with the rule's metadata
# from the YAML file, so the Lambda knows which detection fired without
# looking anything up. <aws.events.event.json> is the full original event.
resource "aws_cloudwatch_event_target" "triage" {
  for_each = local.detections

  rule      = aws_cloudwatch_event_rule.detection[each.key].name
  target_id = "triage"
  arn       = var.triage_function_arn

  input_transformer {
    input_template = "{\"detection\": ${local.metadata[each.key]}, \"event\": <aws.events.event.json>}"
  }

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  dead_letter_config {
    arn = var.dlq_arn
  }
}

# Lambda resource policy: each rule may invoke the function, nothing else.
resource "aws_lambda_permission" "triage" {
  for_each = local.detections

  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = var.triage_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection[each.key].arn
}

# The dead-letter queue accepts messages only from these rules.
data "aws_iam_policy_document" "dlq" {
  statement {
    sid       = "EventBridgeRulesOnly"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [for r in aws_cloudwatch_event_rule.detection : r.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = var.dlq_url
  policy    = data.aws_iam_policy_document.dlq.json
}
