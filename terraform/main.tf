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

module "detections" {
  source         = "./modules/detections"
  project_name   = var.project_name
  detections_dir = "${path.root}/../detections"
}
