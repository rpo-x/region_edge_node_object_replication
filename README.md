### 3. SSH and Setup Environment
- SSH: `ssh ubuntu@<public-ip>` (use key/password from creation).
- As root (or sudo): Update and install venv:
  ```
  sudo apt update
  sudo apt install python3-venv
  ```
- Create/activate virtual env:
  ```
  python3 -m venv ~/venv
  source ~/venv/bin/activate
  ```
- Install packages:
  ```
  pip install oss2 alibabacloud_credentials
  pip install cryptography
  ```