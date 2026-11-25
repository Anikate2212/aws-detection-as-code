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
