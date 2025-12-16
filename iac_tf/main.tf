# Create VPC
resource "alicloud_vpc" "main" {
  vpc_name   = var.vpc_name
  cidr_block = var.vpc_cidr
}

# Create vSwitch
resource "alicloud_vswitch" "main" {
  vswitch_name = var.vswitch_name
  vpc_id       = alicloud_vpc.main.id
  cidr_block   = var.vswitch_cidr
  zone_id      = var.availability_zone
}

# Create Security Group
resource "alicloud_security_group" "main" {
  name   = var.security_group_name
  vpc_id = alicloud_vpc.main.id
}

# Create RAM Role for ECS
resource "alicloud_ram_role" "ecs_sync_role" {
  name        = var.role_name
  document    = jsonencode({
    Version = "1"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = {
          Service = ["ecs.aliyuncs.com"]
        }
      }
    ]
  })
  description = "RAM role for OSS-EOS sync on ECS instance"
}

resource "alicloud_instance" "instance" {
  availability_zone    = alicloud_vswitch.main.zone_id
  security_groups      = [alicloud_security_group.main.id]
  instance_type        = var.instance_type
  system_disk_category = var.system_disk_category
  image_id             = var.image_id
  instance_name        = var.instance_name
  vswitch_id           = alicloud_vswitch.main.id
  internet_max_bandwidth_out = var.internet_max_bandwidth_out
  key_name             = var.key_name
  instance_charge_type = var.instance_charge_type
  role_name            = alicloud_ram_role.ecs_sync_role.name

  user_data = templatefile("${path.module}/templates/user_data.tpl", {
    sls_endpoint = "${var.region}-intranet.log.aliyuncs.com"
    sls_project  = alicloud_log_project.sync_logs.project_name
    sls_logstore = alicloud_log_store.sync_logstore.logstore_name
  })
}

resource "alicloud_log_project" "sync_logs" {
  project_name = var.sls_project_name
  description  = "SLS project for OSS-EOS backup sync logs"
}

resource "alicloud_log_store" "sync_logstore" {
  project_name          = alicloud_log_project.sync_logs.project_name
  logstore_name         = var.sls_logstore_name
  retention_period      = var.sls_retention_days
  shard_count           = 1
  auto_split            = true
  max_split_shard_count = 64
  append_meta           = true
}

data "alicloud_ram_policies" "sls_full_access" {
  name_regex = "^AliyunLogFullAccess$"
  type       = "System"
}

resource "alicloud_ram_role_policy_attachment" "attach_sls" {
  role_name    = alicloud_ram_role.ecs_sync_role.name
  policy_name  = data.alicloud_ram_policies.sls_full_access.policies[0].policy_name
  policy_type  = "System"
}

data "alicloud_ram_policies" "admin_access" {
  name_regex = "^AdministratorAccess$"
  type       = "System"
}

resource "alicloud_ram_role_policy_attachment" "attach_admin" {
  role_name    = alicloud_ram_role.ecs_sync_role.name
  policy_name  = data.alicloud_ram_policies.admin_access.policies[0].policy_name
  policy_type  = "System"
}