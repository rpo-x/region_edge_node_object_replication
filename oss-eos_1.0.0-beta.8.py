#!/usr/bin/env python3
import os
import sys
import logging
import hashlib
import time
import base64
import json  # New: for prefix JSON
import struct  # New: for binary length prefix
from pythonjsonlogger import (
    jsonlogger,
)  # New: For JSON logging
from aliyun.log import LogClient, PutLogsRequest, LogItem  # SLS SDK
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

# Suppress credential scheduler logs
logging.getLogger("apscheduler").setLevel(logging.WARNING)

# Updated logging to JSON
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# JSON formatter with custom fields
json_handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter(
    "%(asctime)s %(levelname)s %(message)s %(key)s %(status)s %(duration_sec)s %(size_bytes)s",
    rename_fields={"asctime": "timestamp", "levelname": "level"},
)
json_handler.setFormatter(formatter)
logger.addHandler(json_handler)

# Suppress other loggers as before
logging.getLogger("apscheduler").setLevel(logging.WARNING)
oss2_logger = logging.getLogger("oss2")
oss2_logger.setLevel(logging.WARNING)
cred_logger = logging.getLogger("alibabacloud_credentials")
cred_logger.setLevel(logging.WARNING)
tea_logger = logging.getLogger("alibabacloud_tea_util")
tea_logger.setLevel(logging.WARNING)

logger.info(f"▶ Running script at: {os.path.abspath(__file__)}")
logger.info(f"  CWD = {os.getcwd()}")
logger.info(f"  ARGV = {sys.argv}")


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

sls_endpoint = os.getenv("SLS_ENDPOINT")
sls_project = os.getenv("SLS_PROJECT")
sls_logstore = os.getenv("SLS_LOGSTORE")
if not all([sls_endpoint, sls_project, sls_logstore]):
    raise ValueError(
        "SLS env vars must be set: SLS_ENDPOINT, SLS_PROJECT, SLS_LOGSTORE"
    )

credential = cred_client.get_credential()
sls_client = LogClient(
    endpoint=sls_endpoint,
    accessKeyId=credential.access_key_id,
    accessKey=credential.access_key_secret,
    securityToken=credential.security_token,
)

# New: Prefix size for range GET (adjust if JSON often larger)
PREFIX_RANGE_BYTES = 2048  # Safe buffer for JSON prefix

# Optional validation after upload (env var, default false to save costs)
VALIDATE_UPLOADS = os.getenv("VALIDATE_UPLOADS", "false").lower() == "true"

DELETE_ORPHANS = os.getenv("DELETE_ORPHANS", "false").lower() == "true"
# Dry-run for orphan deletions (default true for safety)
DRY_RUN_DELETES = os.getenv("DRY_RUN_DELETES", "true").lower() == "true"

LAST_SYNC_FILE = os.getenv(
    "LAST_SYNC_FILE", "last_sync.txt"
)  # Local file for last sync timestamp

RESET_SYNC = os.getenv("RESET_SYNC", "false").lower() == "true"


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
def list_bucket(bucket, label, modified_since=0, skip_logging=False):
    logger.info(
        f"Listing objects in {label} ({bucket.bucket_name}), modified since {time.ctime(modified_since)}"
        if modified_since
        else "all objects"
    )
    keys = []
    for obj in oss2.ObjectIterator(bucket):
        if obj.last_modified > modified_since or modified_since == 0:
            if not skip_logging:
                logger.info("Object", extra={"key": obj.key})
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

    # Securely erase plaintext DEK from memory
    plaintext_dek = b"\x00" * len(plaintext_dek)

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


def log_to_sls(
    key,
    status,
    duration,
    size_bytes,
    src_md5,
    encrypted_md5,
    log_batch,
    sls_project,
    sls_logstore,
    sls_client,
):
    log_item = LogItem()
    log_item.set_time(int(time.time()))
    log_item.push_back("key", key)
    log_item.push_back("status", status)
    log_item.push_back("duration_sec", str(duration))
    log_item.push_back("size_bytes", str(size_bytes))
    log_item.push_back("src_md5", src_md5)
    log_item.push_back("encrypted_md5", encrypted_md5)
    log_batch.append(log_item)

    # Send batch if full
    if len(log_batch) >= 10:
        try:
            request = PutLogsRequest(
                sls_project, sls_logstore, "backup-sync-topic", "", log_batch
            )
            sls_client.put_logs(request)
            log_batch = []
        except Exception as e:
            logger.warning(f"SLS batch send failed: {e}", extra={"key": key})


def main():
    oss_bucket = oss2.Bucket(auth, OSS_ENDPOINT, OSS_BUCKET, region=REGION_ID)
    eos_bucket = oss2.Bucket(auth, EOS_ENDPOINT, EOS_BUCKET)  # No region for EOS

    last_sync_time = 0
    if os.path.exists(LAST_SYNC_FILE):
        with open(LAST_SYNC_FILE, "r") as f:
            last_sync_time = int(f.read().strip() or 0)
    logger.info(
        f"Last sync time: {time.ctime(last_sync_time)}"
        if last_sync_time
        else "No previous sync"
    )

    if RESET_SYNC:
        last_sync_time = 0
        logger.info("Reset sync enabled - full backup")

    oss_keys = list_bucket(oss_bucket, "Frankfurt", modified_since=last_sync_time)
    full_oss_keys = list_bucket(
        oss_bucket, "Frankfurt full for deletions", modified_since=0, skip_logging=True
    )
    eos_keys = set(
        list_bucket(
            eos_bucket, "Istanbul for deletions", modified_since=0, skip_logging=True
        )
    )

    # Local lock file for idempotency (tracks in-progress keys)
    lock_file = "in_progress.txt"
    if os.path.exists(lock_file):
        with open(lock_file, "r") as f:
            in_progress = set(line.strip() for line in f)
    else:
        in_progress = set()

    failed_keys = []  # Track keys that fail processing

    total_objects = 0
    total_bytes = 0
    total_errors = 0
    start_run = time.time()

    log_batch = []  # Collect LogItems for SLS batch sending

    for key in oss_keys:
        if key in in_progress:
            logger.warning(
                "Skipping key - already in progress from previous run",
                extra={"key": key},
            )

            total_objects += 1
            status = "in_progress_skip"
            duration = 0  # Minimal processing
            logger.info(
                "Processed key",
                extra={
                    "key": key,
                    "status": status,
                    "duration_sec": duration,
                    "size_bytes": 0,
                    "src_md5": None,
                    "encrypted_md5": None,
                },
            )
            log_to_sls(
                key=key,
                status=status,
                duration=duration,
                size_bytes=size_bytes,
                src_md5=src_md5 if "src_md5" in locals() else "",
                encrypted_md5=encrypted_md5 if "encrypted_md5" in locals() else "",
                log_batch=log_batch,
                sls_project=sls_project,
                sls_logstore=sls_logstore,
                sls_client=sls_client,
            )

            continue
        start_time = time.time()
        total_objects += 1
        status = "error"  # Default; override on success
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

            with open(lock_file, "a") as lock_f:
                lock_f.write(key + "\n")
                lock_f.flush()  # Lock the key

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
                        logger.info(
                            "Key unchanged (prefix ETag match), skip",
                            extra={"key": key},
                        )
                        need_upload = False
                    else:
                        logger.info(
                            "Key exists but changed (prefix ETag mismatch), will update",
                            extra={"key": key},
                        )
                except oss2.exceptions.ServerError as e:
                    if e.status == 416:  # Invalid range (object too small)
                        logger.info(
                            "Key too small for prefix, will update", extra={"key": key}
                        )
                    else:
                        raise
                except Exception as ex:
                    logger.warning(
                        f"Failed to parse prefix: {ex}, will update", extra={"key": key}
                    )

            if not need_upload:
                status = "skipped"  # Or "unchanged" for clarity
                duration = time.time() - start_time
                size_bytes = 0  # No data processed
                logger.info(
                    "Processed key",
                    extra={
                        "key": key,
                        "status": status,
                        "duration_sec": duration,
                        "size_bytes": size_bytes,
                        "src_md5": None,
                        "encrypted_md5": None,
                    },
                )
                log_to_sls(
                    key=key,
                    status=status,
                    duration=duration,
                    size_bytes=size_bytes,
                    src_md5=src_md5 if "src_md5" in locals() else "",
                    encrypted_md5=encrypted_md5 if "encrypted_md5" in locals() else "",
                    log_batch=log_batch,
                    sls_project=sls_project,
                    sls_logstore=sls_logstore,
                    sls_client=sls_client,
                )
                continue

            # Remove lock on skip
            in_progress.remove(key) if key in in_progress else None

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
                logger.error(
                    f"Key upload ETag mismatch ({up_etag} ≠ {encrypted_md5})",
                    extra={"key": key},
                )
            else:
                logger.info(
                    "Key copied OK (envelope encrypted with prefix)", extra={"key": key}
                )

                if VALIDATE_UPLOADS:
                    time.sleep(5)  # Wait for EOS consistency

                    # Re-fetch prefix for validation
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
                    def validate_partial():
                        return eos_bucket.get_object(
                            key, byte_range=(0, PREFIX_RANGE_BYTES - 1)
                        ).read()

                    partial_val = validate_partial()
                    validated_etag = parse_prefix(partial_val)
                    if validated_etag == oss_etag:
                        logger.info(
                            "Key validated OK (ETag matches after upload)",
                            extra={"key": key},
                        )
                    else:
                        logger.error(
                            "Key validation failed (ETag mismatch after upload)",
                            extra={"key": key},
                        )
                        failed_keys.append(key)  # Mark as failed for retry
                        total_errors += 1

                # Remove lock on success
                in_progress.remove(key) if key in in_progress else None

            status = "success" if up_etag == encrypted_md5 else "error"
            total_errors += 1 if status == "error" else 0

            # New: Log per-object metrics as extra fields (JSON will include them)
            duration = time.time() - start_time
            size_bytes = len(full_data) if "full_data" in locals() else 0
            total_bytes += size_bytes
            logger.info(
                "Processed key",
                extra={
                    "key": key,
                    "status": status,
                    "duration_sec": duration,
                    "size_bytes": size_bytes,
                    "src_md5": src_md5 if "src_md5" in locals() else None,
                    "encrypted_md5": (
                        encrypted_md5 if "encrypted_md5" in locals() else None
                    ),
                },
            )
            log_to_sls(
                key=key,
                status=status,
                duration=duration,
                size_bytes=size_bytes,
                src_md5=src_md5 if "src_md5" in locals() else "",
                encrypted_md5=encrypted_md5 if "encrypted_md5" in locals() else "",
                log_batch=log_batch,
                sls_project=sls_project,
                sls_logstore=sls_logstore,
                sls_client=sls_client,
            )

        except oss2.exceptions.ServerError as e:
            if e.status == 404 and "eos" in str(e).lower():  # EOS 404
                logger.info("Key not found in EOS, will copy", extra={"key": key})
                # Proceed to download/encrypt/upload
            else:
                logger.error(f"Server error: {e}", extra={"key": key})
                failed_keys.append(key)  # Add to failed list

                total_errors += 1
                duration = time.time() - start_time
                logger.info(
                    "Processed key",
                    extra={
                        "key": key,
                        "status": "error",
                        "duration_sec": duration,
                        "size_bytes": 0,
                    },
                )
                log_to_sls(
                    key=key,
                    status=status,
                    duration=duration,
                    size_bytes=size_bytes,
                    src_md5=src_md5 if "src_md5" in locals() else "",
                    encrypted_md5=encrypted_md5 if "encrypted_md5" in locals() else "",
                    log_batch=log_batch,
                    sls_project=sls_project,
                    sls_logstore=sls_logstore,
                    sls_client=sls_client,
                )

        except Exception as ex:
            logger.error(f"Fatal error processing: {ex}", extra={"key": key})
            failed_keys.append(key)  # Add to failed list

            total_errors += 1
            duration = time.time() - start_time
            logger.info(
                "Processed key",
                extra={
                    "key": key,
                    "status": "error",
                    "duration_sec": duration,
                    "size_bytes": 0,
                },
            )
            log_to_sls(
                key=key,
                status=status,
                duration=duration,
                size_bytes=size_bytes,
                src_md5=src_md5 if "src_md5" in locals() else "",
                encrypted_md5=encrypted_md5 if "encrypted_md5" in locals() else "",
                log_batch=log_batch,
                sls_project=sls_project,
                sls_logstore=sls_logstore,
                sls_client=sls_client,
            )
            continue  # Ensure we move to next key

    if DELETE_ORPHANS:
        # Refresh EOS keys (in case changes during run)
        eos_keys = set(list_bucket(eos_bucket, "Istanbul"))
        orphans = eos_keys - set(full_oss_keys)
        if orphans:
            logger.info(f"Found {len(orphans)} orphans in EOS to delete")
            for orphan in orphans:
                try:

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
                    def delete_from_eos():
                        eos_bucket.delete_object(orphan)

                    if DRY_RUN_DELETES:
                        logger.info(
                            "Dry-run: Skipped deletion for orphan",
                            extra={"key": orphan},
                        )
                        # Still log to SLS as skipped for audit
                        log_to_sls(
                            key=orphan,
                            status="skipped_orphan_dry_run",
                            duration=0,
                            size_bytes=0,
                            src_md5="",
                            encrypted_md5="",
                            log_batch=log_batch,
                            sls_project=sls_project,
                            sls_logstore=sls_logstore,
                            sls_client=sls_client,
                        )
                        continue  # Skip actual deletion

                    # # Safety confirmation for deletions (remove for automated runs)
                    # confirm = input(f"Confirm delete orphan {orphan}? (y/n): ")
                    # if confirm.lower() != "y":
                    #     logger.info(
                    #         "Skipped deletion for orphan", extra={"key": orphan}
                    #     )
                    #     continue

                    delete_from_eos()
                    logger.info("Deleted orphan from EOS", extra={"key": orphan})
                    # Optional SLS log for deletion
                    log_to_sls(
                        key=orphan,
                        status="deleted_orphan",
                        duration=0,
                        size_bytes=0,
                        src_md5="",
                        encrypted_md5="",
                        log_batch=log_batch,
                        sls_project=sls_project,
                        sls_logstore=sls_logstore,
                        sls_client=sls_client,
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to delete orphan {orphan}: {e}", extra={"key": orphan}
                    )
                    failed_keys.append(orphan)  # Track for summary
        else:
            logger.info("No orphans found in EOS")

    # Clean up lock file (rewrite without successful keys)
    with open(lock_file, "w") as lock_f:
        for k in in_progress:
            lock_f.write(k + "\n")

    # Summarize failed keys
    if failed_keys:
        logging.error(
            f"Summary: Failed to process keys: {failed_keys}. Retry these manually."
        )
    else:
        logging.info("All keys processed successfully.")

    run_duration = time.time() - start_run
    error_rate = (total_errors / total_objects) * 100 if total_objects > 0 else 0
    logger.info(
        "Run summary",
        extra={
            "total_objects": total_objects,
            "total_bytes": total_bytes,
            "total_errors": total_errors,
            "error_rate_pct": error_rate,
            "run_duration_sec": run_duration,
            "failed_keys": ",".join(failed_keys) if failed_keys else "",
            "filtered_count": (
                len(full_oss_keys) - len(oss_keys) if "full_oss_keys" in locals() else 0
            ),
        },
    )
    # Send remaining per-object batch
    if log_batch:
        try:
            request = PutLogsRequest(
                sls_project, sls_logstore, "backup-sync-topic", "", log_batch
            )
            sls_client.put_logs(request)
        except Exception as e:
            logger.warning(f"SLS remaining batch send failed: {e}")

    # Send aggregate as single LogItem
    try:
        agg_item = LogItem()
        agg_item.set_time(int(time.time()))
        agg_item.push_back("total_objects", str(total_objects))
        agg_item.push_back("total_bytes", str(total_bytes))
        agg_item.push_back("total_errors", str(total_errors))
        agg_item.push_back("error_rate_pct", str(error_rate))
        agg_item.push_back("run_duration_sec", str(run_duration))
        agg_item.push_back("failed_keys", ",".join(failed_keys) if failed_keys else "")
        sls_client.put_logs(
            PutLogsRequest(
                sls_project, sls_logstore, "backup-sync-topic", "", [agg_item]
            )
        )
    except Exception as e:
        logger.warning(f"SLS aggregate send failed: {e}")

    if total_errors == 0:  # Update only on successful run
        with open(LAST_SYNC_FILE, "w") as f:
            f.write(str(int(time.time())))
        logger.info("Updated last sync time")
    else:
        logger.warning("Run had errors—skipping last sync time update")

    logging.info("Waiting 30s for EOS list consistency…")
    time.sleep(30)
    list_bucket(eos_bucket, "Istanbul (after sync)")


if __name__ == "__main__":
    main()
