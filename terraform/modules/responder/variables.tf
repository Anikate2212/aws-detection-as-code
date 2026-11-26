variable "project_name" {
  type = string
}

variable "source_dir" {
  description = "Directory holding the triage Lambda source (handler.py)"
  type        = string
}

variable "topic_arn" {
  description = "Baseline SNS topic that receives alerts"
  type        = string
}

variable "kms_key_arn" {
  description = "Baseline KMS key that encrypts the SNS topic (also used for the Lambda log group)"
  type        = string
}
