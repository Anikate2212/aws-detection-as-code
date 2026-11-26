output "function_arn" {
  value = aws_lambda_function.triage.arn
}

output "function_name" {
  value = aws_lambda_function.triage.function_name
}

output "dlq_arn" {
  value = aws_sqs_queue.dlq.arn
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}
