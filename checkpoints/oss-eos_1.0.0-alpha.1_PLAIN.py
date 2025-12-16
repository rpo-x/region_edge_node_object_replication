#!/usr/bin/env python3
import os
import sys
import logging
import hashlib
import time
import oss2
import oss2.exceptions

# Suppress OSS2 SDK INFO logs
oss2_logger = logging.getLogger("oss2")
oss2_logger.setLevel(logging.WARNING)

# ———— INITIAL LOGGING SETUP ————
logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.info(f"▶ Running script at: {os.path.abspath(__file__)}")
logging.info(f"  CWD = {os.getcwd()}")
logging.info(f"  ARGV = {sys.argv}")

# ---- CONFIGURATION (move to env in prod) ----
ACCESS_KEY_ID = os.getenv("ALIYUN_ACCESS_KEY_ID", "YOUR_ACCESS_KEY_ID")
ACCESS_KEY_SECRET = os.getenv("ALIYUN_ACCESS_KEY_SECRET", "YOUR_ACCESS_KEY_SECRET")

OSS_ENDPOINT = os.getenv("OSS_ENDPOINT", "oss-eu-central-1.aliyuncs.com")
OSS_BUCKET = os.getenv("OSS_BUCKET", "oss-back-up-frankfurt")

EOS_ENDPOINT = os.getenv("EOS_ENDPOINT", "eos.aliyuncs.com")
EOS_BUCKET = os.getenv("EOS_BUCKET", "oss-back-up-istanbul")
# -----------------------------------------------


def md5sum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def list_bucket(bucket, label):
    logging.info(f"Listing objects in {label} ({bucket.bucket_name}):")
    keys = []
    for obj in oss2.ObjectIterator(bucket):
        logging.info(f"  - {obj.key}")
        keys.append(obj.key)
    return keys


def main():
    auth = oss2.Auth(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    oss_bucket = oss2.Bucket(auth, OSS_ENDPOINT, OSS_BUCKET)
    eos_bucket = oss2.Bucket(auth, EOS_ENDPOINT, EOS_BUCKET)

    oss_keys = list_bucket(oss_bucket, "Frankfurt")
    eos_keys = list_bucket(eos_bucket, "Istanbul")

    for key in oss_keys:
        try:
            data = oss_bucket.get_object(key).read()
            src_md5 = md5sum(data)

            # HEAD on EOS
            try:
                dest_etag = eos_bucket.head_object(key).etag.strip('"')
                if dest_etag == src_md5:
                    logging.info(f"✓ {key} exists with same ETag, skip")
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
            up_etag = eos_bucket.put_object(key, data).etag.strip('"')
            if up_etag != src_md5:
                logging.error(f"✗ {key} upload ETag mismatch ({up_etag} ≠ {src_md5})")
            else:
                logging.info(f"✓ {key} copied OK")

        except Exception as ex:
            logging.error(f"Fatal error processing {key}: {ex}")

    logging.info("Waiting 30s for EOS list consistency…")
    time.sleep(30)
    list_bucket(eos_bucket, "Istanbul (after sync)")


if __name__ == "__main__":
    main()
