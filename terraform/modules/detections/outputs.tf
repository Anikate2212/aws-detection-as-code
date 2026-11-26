output "rule_names" {
  value = { for k, r in aws_cloudwatch_event_rule.detection : k => r.name }
}

output "alarm_names" {
  value = { for k, a in aws_cloudwatch_metric_alarm.count : k => a.alarm_name }
}
