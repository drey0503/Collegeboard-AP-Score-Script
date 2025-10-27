#!/usr/bin/env python3
# """
# sftp_upload.py

# Robust SFTP uploader created by Dreyson Clark:
# - loads config from creds.env or environment
# - supports key-based or password auth
# - uploads files atomically (.part -> final)
# - retries transient upload errors with backoff
# - creates remote directories recursively
# - deletes local files only after successful upload
# - optional dry-run mode and logging
# """

from __future__ import annotations
import os
import time
import logging
import argparse
from pathlib import Path
from typing import Optional
import paramiko

from pathlib import Path


def load_env_explicit():
    # look in script directory first
    script_dir = Path(__file__).resolve().parent
    candidate = script_dir / "creds.env"
    if not candidate.exists():
        candidate = script_dir / ".env"
    if not candidate.exists():
        candidate = Path.cwd() / "creds.env"
    if not candidate.exists():
        candidate = Path.cwd() / ".env"

    print(f"[DEBUG] Checking env file: {candidate}")
    if not candidate.exists():
        print("[DEBUG] No .env found")
        return

    for line in candidate.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"\'')
        if k not in os.environ:
            os.environ[k] = v
    print("[DEBUG] Env loaded from", candidate)


# call it early
load_env_explicit()

# -------------------------
# Configuration from env
# -------------------------
SFTP_HOST = os.environ.get("SFTP_HOST", "ft.technolutions.net")
SFTP_PORT = int(os.environ.get("SFTP_PORT", "22"))
SFTP_USER = os.environ.get("SFTP_USER")  # required
SFTP_PASS = os.environ.get("SFTP_PASS")  # optional if using key
REMOTE_DIR = os.environ.get(
    "SFTP_REMOTE_DIR", "/incoming/AP_Score_Data_File_Collegeboard")
LOCAL_DIR = Path(os.environ.get(
    "LOCAL_DIR", r"C:\Users\dreyson\Desktop\SAT_Files"))
MAX_UPLOAD_RETRIES = int(os.environ.get("MAX_UPLOAD_RETRIES", "3"))
# seconds base for exponential backoff
BACKOFF_BASE = float(os.environ.get("BACKOFF_BASE", "2"))
# adjust as needed; set empty to allow all
ALLOWED_EXTENSIONS = {".csv", ".txt"}
DRY_RUN_DEFAULT = False

# -------------------------
# Logging
# -------------------------
logger = logging.getLogger("sftp_uploader")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)

# you can also add a FileHandler if you want persistent logs:
logfile = Path(__file__).resolve().parent / "sftp_upload.log"
file_handler = logging.FileHandler(logfile, encoding="utf-8")
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)


# -------------------------
# Helpers
# -------------------------
def remote_mkdirs(sftp: paramiko.SFTPClient, remote_path: str) -> None:
    # """Create remote directory path recursively (like mkdir -p)."""
    remote_path = remote_path.rstrip("/")
    if remote_path == "":
        return
    parts = remote_path.split("/")
    cur = ""
    # handle leading slash
    if remote_path.startswith("/"):
        cur = "/"
    for part in parts:
        if not part:
            continue
        if cur == "/":
            cur = f"/{part}"
        else:
            cur = f"{cur}/{part}"
        try:
            sftp.stat(cur)
        except IOError:
            try:
                sftp.mkdir(cur)
                logger.debug(f"Created remote directory: {cur}")
            except Exception as e:
                # Race conditions or permission issues possible; re-check existence
                try:
                    sftp.stat(cur)
                except Exception:
                    raise


def choose_auth(transport: paramiko.Transport) -> paramiko.SFTPClient:
    # """
    # Connect transport using key or password based on env.
    # Returns connected SFTP client.
    # """
    # This function will not directly login transport; we'll establish Transport and then open SFTP.
    raise NotImplementedError("use connect_sftp() below")


def connect_sftp(host: str, port: int, username: str, password: str, timeout=30):
    # """
    # Connect to SFTP using password authentication only.
    # Returns (transport, sftp_client). Caller must close both.
    # """
    logger.info(f"Connecting to SFTP {host}:{port} as {username}")
    transport = paramiko.Transport((host, port))
    transport.banner_timeout = timeout
    try:
        if not password:
            raise RuntimeError("Password is required for SFTP authentication.")
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        logger.info("SFTP connection established (password auth).")
        return transport, sftp
    except Exception as e:
        transport.close()
        logger.error(f"SFTP connection failed: {e}")
        raise


def is_allowed_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name.startswith("."):
        return False
    if ALLOWED_EXTENSIONS:
        return path.suffix.lower() in ALLOWED_EXTENSIONS
    return True


def upload_file_atomic(sftp: paramiko.SFTPClient, local_path: Path, remote_dir: str, max_retries: int = 3) -> None:
    # """
    # Uploads a single file using a .part temporary filename then renames it to final.
    # Retries transient errors.
    # """
    remote_dir = remote_dir.rstrip("/")
    remote_name = local_path.name
    remote_tmp = f"{remote_dir}/{remote_name}.part"
    remote_final = f"{remote_dir}/{remote_name}"

    attempt = 0
    last_exc = None
    while attempt < max_retries:
        attempt += 1
        try:
            logger.info(
                f"Uploading {local_path} -> {remote_final} (attempt {attempt}/{max_retries})")
            # ensure remote_dir exists
            remote_mkdirs(sftp, remote_dir)

            # Use SFTP put with file-like streaming
            sftp.put(str(local_path), remote_tmp, callback=None)
            # atomic rename
            try:
                # try remove existing if any (optional)
                sftp.remove(remote_final)
            except IOError:
                pass
            sftp.rename(remote_tmp, remote_final)
            logger.info(f"Upload successful: {remote_final}")
            return
        except Exception as e:
            last_exc = e
            logger.warning(
                f"Upload attempt {attempt} failed for {local_path}: {e}")
            # remove partial remote if exists
            try:
                sftp.remove(remote_tmp)
            except Exception:
                pass
            if attempt < max_retries:
                backoff = BACKOFF_BASE ** attempt
                logger.info(f"Retrying in {backoff:.1f}s...")
                time.sleep(backoff)
                continue
            else:
                logger.error(
                    f"Failed to upload {local_path} after {max_retries} attempts.")
                raise last_exc


# -------------------------
# Main upload flow
# -------------------------
def upload_folder(local_folder: Path, remote_folder: str, dry_run: bool = False):
    if not local_folder.exists():
        raise FileNotFoundError(f"Local folder not found: {local_folder}")

    uploaded_files = []

    # Connect
    transport = None
    sftp = None
    try:
        transport, sftp = connect_sftp(
            SFTP_HOST, SFTP_PORT, SFTP_USER, SFTP_PASS)

        # iterate files (non-recursive)
        for p in sorted(local_folder.iterdir()):
            if not is_allowed_file(p):
                logger.debug(f"Skipping: {p}")
                continue
            if dry_run:
                logger.info(
                    f"[DRY RUN] Would upload: {p.name} -> {remote_folder}/{p.name}")
                continue
            try:
                upload_file_atomic(sftp, p, remote_folder,
                                   max_retries=MAX_UPLOAD_RETRIES)
                uploaded_files.append(p)
            except Exception as e:
                logger.error(f"Error uploading {p}: {e}")
                # continue to next file; decide if you want to abort here instead
                continue

    finally:
        if sftp:
            try:
                sftp.close()
            except Exception:
                pass
        if transport:
            try:
                transport.close()
            except Exception:
                pass

    # Delete local files only if uploaded successfully
    for f in uploaded_files:
        try:
            f.unlink()
            logger.info(f"Deleted local file after upload: {f}")
        except Exception as e:
            logger.warning(f"Failed to delete {f}: {e}")

    logger.info("Upload run complete.")
    return uploaded_files


# -------------------------
# CLI
# -------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="SFTP upload folder.")
    ap.add_argument("--local", "-l", default=None,
                    help="Local folder to upload (overrides LOCAL_DIR env)")
    ap.add_argument("--remote", "-r", default=None,
                    help="Remote folder to upload to (overrides REMOTE_DIR env)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Do not actually upload or delete; just show actions")
    return ap.parse_args()


def main():
    args = parse_args()
    local = Path(args.local) if args.local else LOCAL_DIR
    remote = args.remote if args.remote else REMOTE_DIR
    dry_run = args.dry_run or DRY_RUN_DEFAULT

    logger.info(
        f"Starting upload: local={local}, remote={remote}, dry_run={dry_run}")
    try:
        upload_folder(local, remote, dry_run=dry_run)
    except Exception as e:
        logger.exception(f"Upload failed: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
