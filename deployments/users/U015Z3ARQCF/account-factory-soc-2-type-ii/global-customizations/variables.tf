# Global Customizations Variables

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "primary_region" {
  description = "Primary AWS Region"
  type        = string
  default     = "us-east-1"
}
