output "rule_names" {
  value = { for k, r in aws_cloudwatch_event_rule.detection : k => r.name }
}
