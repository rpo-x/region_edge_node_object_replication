#!/usr/bin/env python3
import os
import argparse
import logging
import hashlib
import base64
import json
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oss2
from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_credentials.models import Config as CredConfig
from oss2 import CredentialsProvider, ProviderAuth
from oss2.credentials import Credentials
from alibabacloud_kms20160120.client import Client as KmsClient
from alibabacloud_kms20160120.models import DecryptRequest
from alibabacloud_tea_openapi.models import Config as TeaConfig
from alibabacloud_tea_util.models import RuntimeOptions
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential_jitter,
    retry_if_exception_type,
    before_sleep_log,
)

# Suppress logs
logging.getLogger("apscheduler").setLevel(logging.WARNING)
oss2_logger = logging.getLogger("oss2")
oss2_logger.setLevel(logging.WARNING)
cred_provider_logger = logging.getLogger("alibabacloud_credentials.provider")
cred_provider_logger.setLevel(logging.WARNING)
tenacity_logger = logging.getLogger("tenacity")
tenacity_logger.setLevel(logging.WARNING)

# Basic logging
logging.basicConfig(level=logging.INFO, format="%(message)s")


# CredentialProviderWrapper
class CredentialProviderWrapper(CredentialsProvider):
    def __init__(self, client):
        self.client = client

    def get_credentials(self):
        credential = self.client.get_credential()
        return Credentials(
            credential.access_key_id,
            credential.access_key_secret,
            credential.security_token,
        )


# CONFIG
EOS_ENDPOINT = "eos.aliyuncs.com"
EOS_BUCKET = "oss-back-up-istanbul"
KMS_KEY_ID = os.getenv("KMS_KEY_ID")
if not KMS_KEY_ID:
    raise ValueError("KMS_KEY_ID must be set in environment")
KMS_REGION_ID = os.getenv("KMS_REGION_ID", "eu-central-1")

# Setup creds and auth
cred_config = CredConfig(type="ecs_ram_role")
cred_client = CredClient(cred_config)
credentials_provider = CredentialProviderWrapper(cred_client)
auth = ProviderAuth(credentials_provider)

# KMS client
kms_config = TeaConfig(
    credential=cred_client,
    region_id=KMS_REGION_ID,
    endpoint=f"kms.{KMS_REGION_ID}.aliyuncs.com",
)
kms_client = KmsClient(kms_config)


# Parse prefix
def parse_prefix(partial_data: bytes) -> dict | None:
    try:
        if len(partial_data) < 4:
            return None
        json_len = struct.unpack(">I", partial_data[:4])[0]
        if len(partial_data) < 4 + json_len:
            return None
        metadata_json = partial_data[4 : 4 + json_len]
        return json.loads(metadata_json.decode("utf-8"))
    except (struct.error, json.JSONDecodeError, UnicodeDecodeError):
        return None


# KMS decrypt DEK with retry
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential_jitter(initial=1, max=10),
    retry=retry_if_exception_type(Exception),
    before_sleep=before_sleep_log(logging.getLogger(), logging.WARNING),
    reraise=True,
)
def kms_decrypt(ciphertext_blob: str) -> bytes:
    request = DecryptRequest(
        ciphertext_blob=ciphertext_blob,
    )
    runtime = RuntimeOptions()
    response = kms_client.decrypt_with_options(request, runtime)
    return base64.b64decode(response.body.plaintext)


# Decrypt single object (streaming)
def decrypt_object(key: str, output_dir: str):
    bucket = oss2.Bucket(auth, EOS_ENDPOINT, EOS_BUCKET)
    try:
        partial = bucket.get_object(key, byte_range=(0, 2048 - 1)).read()
        metadata = parse_prefix(partial)
        if not metadata:
            logging.warning(f"Invalid prefix for {key}, skipping")
            return False

        encrypted_dek = metadata["encrypted_dek"]
        nonce = base64.b64decode(metadata["nonce"])
        tag = base64.b64decode(metadata["tag"])
        logging.info(f"Parsed metadata for {key}")

        plaintext_dek = kms_decrypt(encrypted_dek)

        cipher = Cipher(
            algorithms.AES(plaintext_dek),
            modes.GCM(nonce, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        prefix_len = 4 + struct.unpack(">I", partial[:4])[0]
        md5 = hashlib.md5()
        output_path = os.path.join(output_dir, key)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            obj = bucket.get_object(key, byte_range=(prefix_len, None))
            while True:
                chunk = obj.read(4096)
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                f.write(decrypted_chunk)
                md5.update(decrypted_chunk)
            f.write(decryptor.finalize())

        decrypted_md5 = md5.hexdigest()
        logging.info(f"Decrypted {key} to {output_path}. MD5: {decrypted_md5}")
        return True
    except Exception as e:
        logging.error(f"Failed to decrypt {key}: {e}")
        return False


# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt EOS object")
    parser.add_argument("--key", help="EOS key to decrypt (single file mode)")
    parser.add_argument(
        "--output-dir",
        default="./restored",
        help="Output directory for decrypted files",
    )
    args = parser.parse_args()

    if args.key:
        decrypt_object(args.key, args.output_dir)
    else:
        logging.error("Provide --key for single file")
