output "instance_id" {
  description = "ID of the created ECS instance"
  value       = alicloud_instance.instance.id
}

output "public_ip" {
  description = "Public IP of the instance (if assigned)"
  value       = alicloud_instance.instance.public_ip
}

output "sls_project_name" {
  description = "Name of the SLS project"
  value       = alicloud_log_project.sync_logs.project_name
}

output "sls_logstore_name" {
  description = "Name of the SLS logstore"
  value       = alicloud_log_store.sync_logstore.logstore_name
}