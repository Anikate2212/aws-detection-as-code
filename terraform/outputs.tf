output "detection_rules" {
  description = "Detection ID to EventBridge rule name"
  value       = module.detections.rule_names
}
