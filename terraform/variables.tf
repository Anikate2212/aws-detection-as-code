variable "aws_region" {
  description = "Region for the detection rules. IAM and other global-service events are delivered to EventBridge in us-east-1 only."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "detection-as-code"
}

variable "alert_topic_name" {
  description = "SNS topic created by cloud-security-baseline"
  type        = string
  default     = "cloud-security-baseline-security-alerts"
}

variable "alert_kms_key_id" {
  description = "Key ID of the baseline KMS key that encrypts the alert topic. Set in terraform.tfvars (gitignored)."
  type        = string
}

variable "protected_users" {
  description = "IAM users that containment never touches (enforced in code and by an explicit IAM Deny)"
  type        = list(string)
  default     = ["anikate-cli"]
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch Logs group the baseline trail delivers to (count rules filter it)"
  type        = string
  default     = "/aws/cloudtrail/cloud-security-baseline"
}
