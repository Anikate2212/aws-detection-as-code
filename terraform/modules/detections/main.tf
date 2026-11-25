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

# Targets (the response Lambda) are added in a later build step.
