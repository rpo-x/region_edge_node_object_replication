#!/usr/bin/env python3
import os
import sys
import logging
import hashlib
import time
import base64
import json  # New: for prefix JSON
import struct  # New: for binary length prefix
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oss2
import oss2.exceptions
from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_credentials.models import Config as CredConfig
from oss2 import CredentialsProvider, ProviderAuth
from oss2.credentials import Credentials

# New imports for KMS
from alibabacloud_kms20160120.client import Client as KmsClient
from alibabacloud_kms20160120.models import GenerateDataKeyRequest
from alibabacloud_tea_openapi.models import Config as TeaConfig
from alibabacloud_tea_util.models import RuntimeOptions

# New: For retries
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential_jitter,
    retry_if_exception_type,
    before_sleep_log,
    retry_if_exception,
)

# Suppress OSS2 SDK INFO logs
oss2_logger = logging.getLogger("oss2")
oss2_logger.setLevel(logging.WARNING)

# ———— INITIAL LOGGING SETUP ————
logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.info(f"▶ Running script at: {os.path.abspath(__file__)}")
logging.info(f"  CWD = {os.getcwd()}")
logging.info(f"  ARGV = {sys.argv}")


# Moved up: Define CredentialProviderWrapper early (reused from your original script)
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


# ---- CONFIGURATION ----
OSS_ENDPOINT = "oss-eu-central-1.aliyuncs.com"
OSS_BUCKET = "oss-back-up-frankfurt"

EOS_ENDPOINT = "eos.aliyuncs.com"
EOS_BUCKET = "oss-back-up-istanbul"

REGION_ID = "eu-central-1"  # For OSS and KMS

# New: KMS config (from env)
KMS_KEY_ID = os.getenv("KMS_KEY_ID")
if not KMS_KEY_ID:
    raise ValueError("KMS_KEY_ID must be set in environment")
KMS_REGION_ID = os.getenv("KMS_REGION_ID", REGION_ID)

# Config for ECS RAM Role (reuse for OSS/EOS and KMS)
cred_config = CredConfig(type="ecs_ram_role")
cred_client = CredClient(cred_config)
credentials_provider = CredentialProviderWrapper(cred_client)  # Your existing wrapper
auth = ProviderAuth(credentials_provider)

# New: KMS client setup
kms_config = TeaConfig(
    credential=cred_client,  # Reuse RAM role creds directly
    region_id=KMS_REGION_ID,
    endpoint=f"kms.{KMS_REGION_ID}.aliyuncs.com",  # KMS endpoint
)
kms_client = KmsClient(kms_config)

# New: Prefix size for range GET (adjust if JSON often larger)
PREFIX_RANGE_BYTES = 2048  # Safe buffer for JSON prefix


def md5sum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential_jitter(initial=1, max=10),
    retry=retry_if_exception_type(
        (oss2.exceptions.ServerError, oss2.exceptions.RequestError)
    ),
    before_sleep=before_sleep_log(logging.getLogger(), logging.WARNING),
    reraise=True,
)
def list_bucket(bucket, label):
    logging.info(f"Listing objects in {label} ({bucket.bucket_name}):")
    keys = []
    for obj in oss2.ObjectIterator(bucket):
        logging.info(f"  - {obj.key}")
        keys.append(obj.key)
    return keys


# Updated: Encrypt function now returns full prefixed data
def envelope_encrypt(data: bytes, oss_etag: str) -> bytes:
    # Generate DEK via KMS with retry
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=1, max=10),
        retry=retry_if_exception(
            lambda e: not (hasattr(e, "code") and e.code == "Rejected.Disabled")
        ),  # Custom condition to skip 409
        before_sleep=before_sleep_log(logging.getLogger(), logging.WARNING),
        reraise=True,
    )
    def generate_dek():
        request = GenerateDataKeyRequest(key_id=KMS_KEY_ID, number_of_bytes=32)
        runtime = RuntimeOptions()
        return kms_client.generate_data_key_with_options(request, runtime)

    response = generate_dek()

    plaintext_dek = base64.b64decode(response.body.plaintext)  # Bytes
    ciphertext_blob = base64.b64decode(response.body.ciphertext_blob)  # Encrypted DEK

    # Random nonce for AES-GCM
    nonce = os.urandom(12)

    # Encrypt data
    cipher = Cipher(
        algorithms.AES(plaintext_dek), modes.GCM(nonce), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag  # 16 bytes

    # Create JSON metadata
    metadata = {
        "encrypted_dek": base64.b64encode(ciphertext_blob).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "source_etag": oss_etag,
        "encryption_scheme": "aes-gcm-kms-envelope-v1",
    }
    metadata_json = json.dumps(metadata).encode("utf-8")

    # Prefix: 4-byte big-endian length + JSON
    prefix = struct.pack(">I", len(metadata_json)) + metadata_json

    # Full data: prefix + ciphertext
    return prefix + ciphertext


# New: Function to parse prefix from partial EOS object data
def parse_prefix(partial_data: bytes) -> str | None:
    try:
        if len(partial_data) < 4:
            return None
        json_len = struct.unpack(">I", partial_data[:4])[0]
        if len(partial_data) < 4 + json_len:
            return None
        metadata_json = partial_data[4 : 4 + json_len]
        metadata = json.loads(metadata_json.decode("utf-8"))
        return metadata.get("source_etag")
    except (struct.error, json.JSONDecodeError, UnicodeDecodeError):
        return None


def main():
    oss_bucket = oss2.Bucket(auth, OSS_ENDPOINT, OSS_BUCKET, region=REGION_ID)
    eos_bucket = oss2.Bucket(auth, EOS_ENDPOINT, EOS_BUCKET)  # No region for EOS

    oss_keys = list_bucket(oss_bucket, "Frankfurt")
    eos_keys = set(list_bucket(eos_bucket, "Istanbul"))  # Set for faster lookup

    failed_keys = []  # Track keys that fail processing

    for key in oss_keys:
        try:
            # HEAD OSS for ETag with retry
            @retry(
                stop=stop_after_attempt(3),
                wait=wait_exponential_jitter(initial=1, max=10),
                retry=retry_if_exception_type(
                    (oss2.exceptions.ServerError, oss2.exceptions.RequestError)
                ),
                before_sleep=before_sleep_log(logging.getLogger(), logging.WARNING),
                reraise=True,
            )
            def head_oss():
                return oss_bucket.head_object(key)

            oss_head = head_oss()
            oss_etag = oss_head.etag.strip('"')

            need_upload = True
            if key in eos_keys:
                try:
                    # Range GET prefix from EOS with retry
                    @retry(
                        stop=stop_after_attempt(3),
                        wait=wait_exponential_jitter(initial=1, max=10),
                        retry=retry_if_exception_type(
                            (oss2.exceptions.ServerError, oss2.exceptions.RequestError)
                        ),
                        before_sleep=before_sleep_log(
                            logging.getLogger(), logging.WARNING
                        ),
                        reraise=True,
                    )
                    def get_partial():
                        return eos_bucket.get_object(
                            key, byte_range=(0, PREFIX_RANGE_BYTES - 1)
                        ).read()

                    partial = get_partial()
                    stored_etag = parse_prefix(partial)
                    if stored_etag == oss_etag:
                        logging.info(f"✓ {key} unchanged (prefix ETag match), skip")
                        need_upload = False
                    else:
                        logging.info(
                            f"• {key} exists but changed (prefix ETag mismatch), will update"
                        )
                except oss2.exceptions.ServerError as e:
                    if e.status == 416:  # Invalid range (object too small)
                        logging.info(f"• {key} too small for prefix, will update")
                    else:
                        raise
                except Exception as ex:
                    logging.warning(
                        f"Failed to parse prefix for {key}: {ex}, will update"
                    )

            if not need_upload:
                continue

            # Download full OSS with retry
            @retry(
                stop=stop_after_attempt(3),
                wait=wait_exponential_jitter(initial=1, max=10),
                retry=retry_if_exception_type(
                    (oss2.exceptions.ServerError, oss2.exceptions.RequestError)
                ),
                before_sleep=before_sleep_log(logging.getLogger(), logging.WARNING),
                reraise=True,
            )
            def get_data():
                return oss_bucket.get_object(key).read()

            data = get_data()
            src_md5 = md5sum(data)  # Optional for logging

            full_data = envelope_encrypt(data, oss_etag)
            encrypted_md5 = md5sum(full_data)  # For verification

            # PUT to EOS with retry
            @retry(
                stop=stop_after_attempt(3),
                wait=wait_exponential_jitter(initial=1, max=10),
                retry=retry_if_exception_type(
                    (oss2.exceptions.ServerError, oss2.exceptions.RequestError)
                ),
                before_sleep=before_sleep_log(logging.getLogger(), logging.WARNING),
                reraise=True,
            )
            def put_to_eos():
                return eos_bucket.put_object(key, full_data)

            up_result = put_to_eos()
            up_etag = up_result.etag.strip('"')

            if up_etag != encrypted_md5:
                logging.error(
                    f"✗ {key} upload ETag mismatch ({up_etag} ≠ {encrypted_md5})"
                )
            else:
                logging.info(f"✓ {key} copied OK (envelope encrypted with prefix)")

        except oss2.exceptions.ServerError as e:
            if e.status == 404 and "eos" in str(e).lower():  # EOS 404
                logging.info(f"• {key} not found in EOS, will copy")
                # Proceed to download/encrypt/upload
            else:
                logging.error(f"Server error for {key}: {e}")
                failed_keys.append(key)  # Add to failed list
        except Exception as ex:
            logging.error(f"Fatal error processing {key}: {ex}")
            failed_keys.append(key)  # Add to failed list
            continue  # Ensure we move to next key

    # Summarize failed keys
    if failed_keys:
        logging.error(
            f"Summary: Failed to process keys: {failed_keys}. Retry these manually."
        )
    else:
        logging.info("All keys processed successfully.")

    logging.info("Waiting 30s for EOS list consistency…")
    time.sleep(30)
    list_bucket(eos_bucket, "Istanbul (after sync)")


if __name__ == "__main__":
    main()
