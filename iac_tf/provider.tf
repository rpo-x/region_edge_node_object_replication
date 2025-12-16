terraform {
  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.227.0"  # Use a recent version; check Terraform Registry for latest
    }
  }
  required_version = ">= 1.5.0"
}

provider "alicloud" {
  region = var.region
}