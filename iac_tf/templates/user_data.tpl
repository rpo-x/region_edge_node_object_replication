#!/bin/bash
set -e  # Exit on error

apt update -y
apt upgrade -y
apt install -y python3-pip python3-venv || { echo "Apt install failed" > /root/setup.log; exit 1; }

# Create venv and install packages
python3 -m venv /root/oss-env
/root/oss-env/bin/pip install oss2 cryptography tenacity alibabacloud_credentials alibabacloud_kms20160120 alibabacloud_tea_openapi alibabacloud_tea_util python-json-logger aliyun-log-python-sdk || { echo "Pip install failed" > /root/setup.log; exit 1; }

export SLS_ENDPOINT="${sls_endpoint}"
export SLS_PROJECT="${sls_project}"
export SLS_LOGSTORE="${sls_logstore}"

echo "Setup complete" > /root/setup.log