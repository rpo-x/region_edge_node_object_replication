# accounts/account1.tfvars
region              = "eu-central-1"
availability_zone   = "eu-central-1a"
image_id            = "ubuntu_24_04_x64_20G_alibase_20250702.vhd"
key_name            = "SSH-Keypair-OSS-EOS-ECS"
role_name           = "ECSSyncRole"
sls_project_name    = "oss-eos-sync-logs"
sls_logstore_name   = "sync-logstore"