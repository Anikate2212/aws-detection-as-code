# ==========================================================================
# Detection-as-code: root module
#
# Builds on cloud-security-baseline (CloudTrail, GuardDuty, SNS already
# deployed there). This stack only adds detections and containment.
#
# Data flow (target state):
#   API call ─► CloudTrail ─► EventBridge ─► detection rule ─┐
#   GuardDuty finding ──────► EventBridge ─► detection rule ─┼─► response Lambda ─► SNS
#                                                            └─► (contain: e.g. disable key)
#
# Each detection is a YAML file in ../detections. Adding a detection means
# adding a file, not writing Terraform.
# ==========================================================================

# Baseline resources this stack reuses (looked up, never managed here).
data "aws_sns_topic" "alerts" {
  name = var.alert_topic_name
}

data "aws_kms_key" "alerts" {
  key_id = var.alert_kms_key_id
}

module "responder" {
  source       = "./modules/responder"
  project_name = var.project_name
  source_dir   = "${path.root}/../src/triage"
  topic_arn    = data.aws_sns_topic.alerts.arn
  kms_key_arn  = data.aws_kms_key.alerts.arn
}

module "detections" {
  source               = "./modules/detections"
  project_name         = var.project_name
  detections_dir       = "${path.root}/../detections"
  triage_function_arn  = module.responder.function_arn
  triage_function_name = module.responder.function_name
  dlq_arn              = module.responder.dlq_arn
  dlq_url              = module.responder.dlq_url
}
