# SCP Module Variables

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "target_ou_ids" {
  description = "Map of OU names to OU IDs for SCP attachment"
  type        = map(string)
  default     = {}
}
