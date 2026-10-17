variable "aws_region" {
  description = "Region to deploy in. Use us-east-1: global events (IAM, console sign-in) are delivered to EventBridge there."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "cloudtrail-threat-detector"
}

variable "alert_email" {
  description = "Email address that receives alerts. AWS sends a confirmation link first."
  type        = string
  default     = ""
}

variable "min_severity" {
  description = "Lowest severity that triggers an alert: CRITICAL, HIGH, MEDIUM or LOW."
  type        = string
  default     = "MEDIUM"

  validation {
    condition     = contains(["CRITICAL", "HIGH", "MEDIUM", "LOW"], var.min_severity)
    error_message = "min_severity must be CRITICAL, HIGH, MEDIUM or LOW."
  }
}

variable "ignore_actors" {
  description = "Actors to never alert on, e.g. [\"user/terraform-ci\"] for a known automation user."
  type        = list(string)
  default     = []
}

variable "create_trail" {
  description = "Create a multi-region CloudTrail trail. Set false if the account already has one."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Days to keep CloudTrail log files in S3."
  type        = number
  default     = 90
}

variable "lab_mode" {
  description = "Allow `terraform destroy` to delete the log bucket even when it has logs in it. Keep false in real accounts."
  type        = bool
  default     = true
}
