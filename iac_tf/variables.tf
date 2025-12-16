# Account-Specific Variables (override these per account via .tfvars)
variable "region" {
  description = "The Alibaba Cloud region to deploy resources in"
  type        = string
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+-[0-9]+$", var.region))
    error_message = "Region must be a valid Alibaba Cloud region format (e.g., eu-central-1)."
  }
}

variable "availability_zone" {
  description = "Availability zone for the vSwitch"
  type        = string
}

variable "image_id" {
  description = "ID of the OS image"
  type        = string
}

variable "key_name" {
  description = "Name of the SSH key pair"
  type        = string
}

variable "role_name" {
  description = "Name of the RAM role for ECS sync"
  type        = string
  default     = "ECSSyncRole"
}

variable "vpc_name" {
  description = "Name of the VPC"
  type        = string
  default     = "terraform-vpc"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vswitch_name" {
  description = "Name of the vSwitch"
  type        = string
  default     = "terraform-vswitch"
}

variable "vswitch_cidr" {
  description = "CIDR block for the vSwitch"
  type        = string
  default     = "10.0.1.0/24"
}

variable "security_group_name" {
  description = "Name of the security group"
  type        = string
  default     = "terraform-sg"
}

# General Variables (defaults okay, override if needed)
variable "instance_name" {
  description = "The name of the ECS instance"
  type        = string
  default     = "terraform-simple-ecs"
}

variable "instance_type" {
  description = "The ECS instance type"
  type        = string
  default     = "ecs.g9i.large"
}

variable "system_disk_category" {
  description = "Category of the system disk"
  type        = string
  default     = "cloud_essd"
}

variable "internet_max_bandwidth_out" {
  description = "Maximum outbound internet bandwidth (Mbps). Set to >0 for public IP assignment"
  type        = number
  default     = 10
  validation {
    condition     = var.internet_max_bandwidth_out >= 0
    error_message = "Bandwidth must be non-negative."
  }
}

variable "instance_charge_type" {
  description = "Billing method for the instance"
  type        = string
  default     = "PostPaid"
}

variable "sls_project_name" {
  description = "Name of the SLS project for backup sync logs"
  type        = string
  default     = "oss-eos-sync-logs"
}

variable "sls_logstore_name" {
  description = "Name of the SLS logstore for backup sync logs"
  type        = string
  default     = "sync-logstore"
}

variable "sls_retention_days" {
  description = "Log retention period in days for the SLS logstore"
  type        = number
  default     = 30
  validation {
    condition     = var.sls_retention_days > 0
    error_message = "Retention days must be positive."
  }
}