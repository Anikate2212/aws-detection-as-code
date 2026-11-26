output "detection_rules" {
  description = "Detection ID to EventBridge rule name"
  value       = module.detections.rule_names
}

output "triage_function_name" {
  description = "Triage Lambda that every detection rule targets"
  value       = module.responder.function_name
}

output "triage_dlq_url" {
  description = "Dead-letter queue: events that fired but could not be delivered"
  value       = module.responder.dlq_url
}

output "count_rule_alarms" {
  description = "Detection ID to CloudWatch alarm name (count rules)"
  value       = module.detections.alarm_names
}
