#!/usr/bin/env python3
import os
import sys
import logging
import hashlib
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oss2
import oss2.exceptions
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config
from oss2 import CredentialsProvider, ProviderAuth
from oss2.credentials import Credentials

# Suppress OSS2 SDK INFO logs
oss2_logger = logging.getLogger("oss2")
oss2_logger.setLevel(logging.WARNING)

# ———— INITIAL LOGGING SETUP ————
logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.info(f"▶ Running script at: {os.path.abspath(__file__)}")
logging.info(f"  CWD = {os.getcwd()}")
logging.info(f"  ARGV = {sys.argv}")

# ---- CONFIGURATION ----
OSS_ENDPOINT = "oss-eu-central-1.aliyuncs.com"
OSS_BUCKET = "oss-back-up-frankfurt"

EOS_ENDPOINT = "eos.aliyuncs.com"
EOS_BUCKET = "oss-back-up-istanbul"

REGION_ID = "eu-central-1"  # Only for OSS

# Client-side encryption key (32-byte AES key, base64-encoded; store in env for prod)
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    encryption_key = os.urandom(32)  # Generate 32-byte AES key
    ENCRYPTION_KEY = base64.urlsafe_b64encode(encryption_key).decode("utf-8")
    # logging.warning(f"Generated test key (save for prod): {ENCRYPTION_KEY}")
    logging.warning(
        "Generated test key (for testing only); please set ENCRYPTION_KEY in production"
    )
else:
    encryption_key = base64.urlsafe_b64decode(ENCRYPTION_KEY)
    if len(encryption_key) != 32:
        raise ValueError(
            f"Invalid encryption key length: {len(encryption_key)} bytes (must be 32)"
        )

# -----------------------------------------------


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


# Config for ECS RAM Role
config = Config(type="ecs_ram_role")
cred = Client(config)
credentials_provider = CredentialProviderWrapper(cred)

# Auth with V2 signature (for EOS compatibility)
auth = ProviderAuth(credentials_provider)


def md5sum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def list_bucket(bucket, label):
    logging.info(f"Listing objects in {label} ({bucket.bucket_name}):")
    keys = []
    for obj in oss2.ObjectIterator(bucket):
        logging.info(f"  - {obj.key}")
        keys.append(obj.key)
    return keys


def deterministic_encrypt(data: bytes, encryption_key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return nonce + tag + ciphertext  # Prepend nonce and tag for decryption


def main():
    oss_bucket = oss2.Bucket(auth, OSS_ENDPOINT, OSS_BUCKET, region=REGION_ID)
    eos_bucket = oss2.Bucket(auth, EOS_ENDPOINT, EOS_BUCKET)  # No region for EOS

    oss_keys = list_bucket(oss_bucket, "Frankfurt")
    eos_keys = list_bucket(eos_bucket, "Istanbul")

    for key in oss_keys:
        try:
            data = oss_bucket.get_object(key).read()
            src_md5 = md5sum(data)

            # Generate fixed nonce from file key (unique per file)
            nonce = hashlib.sha256(key.encode("utf-8")).digest()[
                :12
            ]  # GCM nonce 12 bytes

            encrypted_data = deterministic_encrypt(data, encryption_key, nonce)

            encrypted_md5 = md5sum(encrypted_data)

            # HEAD on EOS
            try:
                dest_etag = eos_bucket.head_object(key).etag.strip('"')
                if dest_etag == encrypted_md5:
                    logging.info(f"✓ {key} exists and encrypted, skip")
                    continue
                else:
                    logging.info(f"• {key} exists but MD5 differs, overwrite")
            except oss2.exceptions.ServerError as e:
                if e.status == 404:
                    logging.info(f"• {key} not found in EOS, will copy")
                else:
                    logging.error(
                        f"Unexpected server error for head_object on {key}: {e}"
                    )
                    continue
            except Exception as e:
                logging.error(f"Unexpected non-server error for {key}: {e}")
                continue

            # PUT to EOS
            up_etag = eos_bucket.put_object(key, encrypted_data).etag.strip('"')
            if up_etag != encrypted_md5:
                logging.error(
                    f"✗ {key} upload ETag mismatch ({up_etag} ≠ {encrypted_md5})"
                )
            else:
                logging.info(f"✓ {key} copied OK (client-side encrypted)")

        except Exception as ex:
            logging.error(f"Fatal error processing {key}: {ex}")

    logging.info("Waiting 30s for EOS list consistency…")
    time.sleep(30)
    list_bucket(eos_bucket, "Istanbul (after sync)")


if __name__ == "__main__":
    main()
