variable "project_name" {
  type = string
}

variable "detections_dir" {
  description = "Directory holding one YAML file per detection"
  type        = string
}

variable "triage_function_arn" {
  description = "Triage Lambda that every rule targets"
  type        = string
}

variable "triage_function_name" {
  type = string
}

variable "dlq_arn" {
  description = "Dead-letter queue for events EventBridge could not deliver"
  type        = string
}

variable "dlq_url" {
  type = string
}
