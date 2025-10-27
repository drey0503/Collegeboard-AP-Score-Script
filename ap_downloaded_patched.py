#!/usr/bin/env python3
# """
# ap_download_patched.py (auth-on-get + expiry-safe + email per-file + summary email)

# Sends:
#  - immediate email with attachment when a file is downloaded successfully
#  - final summary email after the run completes (list of downloaded files)
# Configuration via creds.env or environment variables (same vars as before).
# """

from __future__ import annotations
import base64
import json
import os
import sys
import time
import smtplib
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Optional, List
import urllib.parse as up

import requests
from requests.exceptions import RequestException, HTTPError

# ---------------------------
# Configuration / constants
# ---------------------------
HTTP_TIMEOUT = 120   # seconds
BASE_GW = "https://aposrd-api-gw.collegeboard.org/aposrd-api-prod"
ENDPOINTS = {
    "auth": f"{BASE_GW}/webServiceAuth",
    "file_generation": f"{BASE_GW}/fileGeneration",
    "record_download": f"{BASE_GW}/webServiceDownloaded",
}
# Change this path to a folder you create
DEFAULT_OUT_DIR = Path(r"C:\Users\dreyson\Desktop\APScores")
TRACKER_FILENAME = ".ap_downloads.json"

DEFAULT_DICODE = os.environ.get("AP_DICODE", "5818")
DEFAULT_FORMAT = "CSV"
DEFAULT_DOWNLOAD_TYPE = "full"

# Retry/backoff settings
MAX_POST_RETRIES = int(os.environ.get("MAX_POST_RETRIES", "6"))
MAX_GET_RETRIES = int(os.environ.get("MAX_GET_RETRIES", "6"))
BASE_BACKOFF = float(os.environ.get("BASE_BACKOFF", "1.0"))
POLL_ATTEMPTS = int(os.environ.get("POLL_ATTEMPTS", "8"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))

# Presigned expiry safety
PRESIGNED_SAFETY_MARGIN = int(os.environ.get(
    "PRESIGNED_SAFETY_MARGIN", "2"))   # seconds

# ---------------------------
# Robust .env loader
# ---------------------------
_ENV_LOADED = False


def _parse_env_text(s: str) -> Dict[str, str]:
    vars: Dict[str, str] = {}
    for raw_line in s.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and ((v[0] == v[-1]) and v[0] in ('"', "'")):
            v = v[1:-1]
        vars[k] = v
    return vars


def load_env_explicit():
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    script_dir = Path(__file__).resolve(
    ).parent if "__file__" in globals() else Path.cwd()
    candidate = script_dir / "creds.env"
    if not candidate.exists():
        candidate = script_dir / ".env"
    if not candidate.exists():
        candidate = Path.cwd() / "creds.env"
    if not candidate.exists():
        candidate = Path.cwd() / ".env"

    print(f"[DEBUG] Explicit .env path checked: {candidate}")
    if not candidate.exists():
        print("[DEBUG] No env file found at expected locations; continuing (you may set AP_AUTH_TOKEN env var).")
        _ENV_LOADED = True
        return

    raw = candidate.read_bytes()
    text = None
    for dec in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = raw.decode(dec)
            break
        except Exception:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")
    parsed = _parse_env_text(text)
    for k, v in parsed.items():
        if k not in os.environ:
            os.environ[k] = v

    _email = os.environ.get("AP_EMAIL")
    _pwd = os.environ.get("AP_PASSWORD")
    print("[DEBUG] AP_EMAIL present:", bool(_email))
    print("[DEBUG] AP_PASSWORD present:", bool(_pwd))
    _ENV_LOADED = True


# Load env early
try:
    load_env_explicit()
except Exception as e:
    print("[WARN] env loader raised:", e)

# ---------------------------
# Helpers
# ---------------------------


def b64_encode_password(pw: str) -> str:
    return base64.b64encode(pw.encode("utf-8")).decode("ascii")


def _sleep_backoff_simple(attempt: int):
    time.sleep(BASE_BACKOFF * (2 ** (attempt - 1)))


def _parse_expires_from_url(url: str) -> Optional[int]:
    try:
        q = up.urlparse(url).query
        params = up.parse_qs(q)
        if "Expires" in params:
            return int(params["Expires"][0])
    except Exception:
        pass
    return None


def human_time_from_expires(expires_val: Optional[str]) -> Optional[str]:
    try:
        if expires_val is None:
            return None
        t = int(expires_val)
        return datetime.fromtimestamp(t, tz=timezone.utc).astimezone().isoformat()
    except Exception:
        return None

# ---------------------------
# HTTP helpers (POST)
# ---------------------------


def do_post(url: str, headers: dict, body: dict, timeout: int = HTTP_TIMEOUT) -> dict:
    last_exc = None
    for attempt in range(1, MAX_POST_RETRIES + 1):
        try:
            resp = requests.post(url, headers=headers,
                                 json=body, timeout=timeout)
            if resp.status_code == 504:
                print(
                    f"[WARN] POST {url} returned 504 (attempt {attempt}/{MAX_POST_RETRIES}). Retrying...")
                last_exc = HTTPError("504 Gateway Timeout")
            else:
                resp.raise_for_status()
                try:
                    return resp.json()
                except ValueError:
                    return {"raw_text": resp.text, "status_code": resp.status_code}
        except RequestException as e:
            last_exc = e
            code = getattr(e, "response", None) and getattr(
                e.response, "status_code", None)
            if code and 400 <= code < 500 and code not in (408, 429, 500, 502, 503, 504):
                print(
                    f"[ERROR] Non-retryable HTTP error {code} on POST {url}: {e}")
                raise
            print(
                f"[WARN] POST {url} attempt {attempt} failed: {e}. Backing off...")
        _sleep_backoff_simple(attempt)
    raise RuntimeError(
        f"POST {url} failed after {MAX_POST_RETRIES} attempts. Last error: {last_exc}")


def do_post_debug(url: str, headers: dict, body: dict, timeout: int = HTTP_TIMEOUT) -> dict:
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=timeout)
    except RequestException as e:
        print(f"[ERROR] Network/request error when POSTing to {url}: {e}")
        raise
    status = resp.status_code
    if 200 <= status < 300:
        try:
            return resp.json()
        except ValueError:
            return {"raw_text": resp.text, "status_code": status}
    print(f"[DEBUG] POST {url} returned HTTP {status}")
    print("[DEBUG] Request headers (tokens redacted):")
    for k, v in headers.items():
        if "Authorization" in k or "Authentication" in k or "auth" in k.lower():
            print(f"  {k}: <redacted>")
        else:
            print(f"  {k}: {v}")
    print("[DEBUG] Request body (snippet):")
    try:
        print(" ", json.dumps(body, indent=2)[:1000])
    except Exception:
        print(" ", str(body)[:1000])
    print("[DEBUG] Response headers:")
    for k, v in resp.headers.items():
        if k.lower() in ("content-type", "content-length", "server", "x-request-id", "date"):
            print(f"  {k}: {v}")
    try:
        j = resp.json()
        print("[DEBUG] Response JSON:")
        print(json.dumps(j, indent=2)[:4000])
    except ValueError:
        text = resp.text or "<empty response body>"
        print("[DEBUG] Response text (first 4000 chars):")
        print(text[:4000])
    resp.raise_for_status()
    return {"raw_text": resp.text, "status_code": status}

# ---------------------------
# Login / token
# ---------------------------


def login_and_get_token(email: str, password_plain: str) -> str:
    url = ENDPOINTS["auth"]
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-CB-Catapult-Authorization-Token": "CBLogin",
        "X-CB-Catapult-Authentication-Token": "CBLogin Web Service",
    }
    body = {"u": email, "p": b64_encode_password(password_plain)}
    print(f"[INFO] Logging in as {email}")
    resp = do_post(url, headers, body)
    if not resp.get("success"):
        raise RuntimeError(f"Login failed: {resp}")
    token = resp.get("authToken")
    if not token:
        raise RuntimeError(f"No authToken returned in response: {resp}")
    print("[INFO] Login successful. Token obtained.")
    return token

# ---------------------------
# fileGeneration with polling
# ---------------------------


def generate_file_with_poll(auth_token: str, di_code: str, fmt: str = "CSV", download_type: str = "full") -> dict:
    url = ENDPOINTS["file_generation"]
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-CB-Catapult-Authorization-Token": auth_token,
        "X-CB-Catapult-Authentication-Token": "CBLogin Web Service",
    }
    body = {"diCode": di_code, "format": fmt, "downloadType": download_type}

    last_resp = None
    for attempt in range(1, POLL_ATTEMPTS + 1):
        print(
            f"[INFO] fileGeneration attempt {attempt}/{POLL_ATTEMPTS} for DI={di_code}")
        try:
            resp = do_post(url, headers, body)
        except Exception as e:
            last_resp = {"error": str(e)}
            print(f"[WARN] fileGeneration attempt {attempt} raised: {e}")
            if attempt < POLL_ATTEMPTS:
                print(f"[INFO] Waiting {POLL_INTERVAL}s before retrying")
                time.sleep(POLL_INTERVAL)
                continue
            else:
                break
        last_resp = resp
        if isinstance(resp, dict) and resp.get("url"):
            return resp
        msg = resp.get("message") if isinstance(resp, dict) else str(resp)
        print(
            f"[INFO] fileGeneration response lacks 'url'. message/status: {msg!r}")
        if attempt < POLL_ATTEMPTS:
            time.sleep(POLL_INTERVAL)
    raise RuntimeError(
        f"fileGeneration did not return a pre-signed URL after {POLL_ATTEMPTS} attempts. Last response: {last_resp}")

# ---------------------------
# GET presigned URL (minimal headers + required X-CB headers)
# ---------------------------


def do_get_stream_presigned(url: str, out_path: Path, auth_token: str) -> None:
    """
    Download a presigned URL using minimal headers PLUS the required X-CB auth headers.
    Saves any 403 response body to last_403_response.xml.
    """
    session = requests.Session()
    headers = {
        "User-Agent": "APScoreDownloader/1.0",
        "Accept": "text/csv, */*",
        "X-CB-Catapult-Authorization-Token": auth_token,
        "X-CB-Catapult-Authentication-Token": "CBLogin Web Service",
    }
    session.headers.update(headers)

    last_exc = None
    for attempt in range(1, MAX_GET_RETRIES + 1):
        try:
            with session.get(url, stream=True, timeout=HTTP_TIMEOUT, allow_redirects=True) as r:
                if r.status_code == 403:
                    body_snip = (r.text or "")[:4000]
                    print(
                        f"[WARN] GET {url} returned 403 Forbidden (attempt {attempt}/{MAX_GET_RETRIES}). Response snippet: {body_snip!r}")
                    try:
                        out_dir = out_path.parent
                        (out_dir / "last_403_response.xml").write_text(r.text or "",
                                                                       encoding="utf-8")
                        print(
                            f"[WARN] Saved full 403 response to {out_dir / 'last_403_response.xml'}")
                    except Exception as e:
                        print(f"[WARN] Failed saving 403 response: {e}")
                    last_exc = HTTPError("403 Forbidden")
                    if attempt >= 3:
                        print(
                            "[ERROR] Persistent 403 Forbidden. Likely invalid/expired presigned URL or server-side permission issue.")
                        break
                    _sleep_backoff_simple(attempt)
                    continue
                if r.status_code == 504:
                    print(
                        f"[WARN] GET {url} returned 504 Gateway Timeout (attempt {attempt}/{MAX_GET_RETRIES}). Retrying...")
                    last_exc = HTTPError("504 Gateway Timeout")
                    _sleep_backoff_simple(attempt)
                    continue
                r.raise_for_status()
                with open(out_path, "wb") as fh:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            fh.write(chunk)
                print(f"[INFO] Successfully downloaded to {out_path}")
                return
        except RequestException as e:
            last_exc = e
            print(f"[WARN] GET attempt {attempt} failed: {e}")
            _sleep_backoff_simple(attempt)
    raise RuntimeError(
        f"GET {url} failed after {MAX_GET_RETRIES} attempts. Last error: {last_exc}")

# ---------------------------
# Expiry-safe download helper (auth on get)
# ---------------------------


def download_with_expiry_safety(auth_token: str, di_code: str, initial_file_resp: dict, out_dir: Path, max_regens: int = 2) -> dict:
    attempts = 0
    last_exc = None
    file_resp = initial_file_resp

    while attempts <= max_regens:
        attempts += 1
        pre_signed_url = file_resp.get("url")
        file_name = file_resp.get("fileName")
        download_id = str(file_resp.get("downloadId", ""))

        if not pre_signed_url or not file_name:
            raise RuntimeError(
                f"fileGeneration response missing url/fileName: {file_resp}")

        out_path = out_dir / file_name

        # parse expires
        expires_epoch = _parse_expires_from_url(pre_signed_url)
        now_epoch = int(time.time())
        if expires_epoch:
            expires_human = datetime.fromtimestamp(
                expires_epoch, tz=timezone.utc).astimezone().isoformat()
            print(
                f"[DEBUG] Presigned URL Expires at {expires_human} (epoch {expires_epoch}), now {datetime.fromtimestamp(now_epoch).isoformat()}")
            if now_epoch + PRESIGNED_SAFETY_MARGIN >= expires_epoch:
                print(
                    "[WARN] Presigned URL already expired or too close to expiry. Will regenerate if allowed.")
                last_exc = RuntimeError(
                    "Presigned URL expired before download attempt")
                if attempts <= max_regens:
                    print(
                        f"[INFO] Regenerating presigned URL (attempt {attempts}/{max_regens})...")
                    try:
                        file_resp = generate_file_with_poll(
                            auth_token, di_code, DEFAULT_FORMAT, DEFAULT_DOWNLOAD_TYPE)
                        continue
                    except Exception as e:
                        last_exc = e
                        print(f"[WARN] Regeneration failed: {e}")
                        continue

        # attempt immediate GET using auth headers
        try:
            do_get_stream_presigned(pre_signed_url, out_path, auth_token)
            # success
            return file_resp
        except Exception as e:
            print(f"[WARN] Immediate GET attempt failed: {e}")
            last_exc = e
            if attempts <= max_regens:
                print(
                    "[INFO] Regenerating presigned URL and retrying (will call fileGeneration again).")
                try:
                    file_resp = generate_file_with_poll(
                        auth_token, di_code, DEFAULT_FORMAT, DEFAULT_DOWNLOAD_TYPE)
                    continue
                except Exception as regen_exc:
                    last_exc = regen_exc
                    print(f"[WARN] Regeneration failed: {regen_exc}")
                    continue
            break

    raise RuntimeError(
        f"Failed to download after {max_regens+1} generation attempts. Last error: {last_exc}")

# ---------------------------
# record download call
# ---------------------------


def record_download(auth_token: str, download_id: str, fmt: str = "CSV") -> dict:
    url = ENDPOINTS["record_download"]
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-CB-Catapult-Authorization-Token": auth_token,
        "X-CB-Catapult-Authentication-Token": "CBLogin Web Service",
    }
    body = {"downloadId": download_id, "format": fmt}
    print(f"[INFO] Recording download {download_id}")
    resp = do_post(url, headers, body)
    if not resp.get("success"):
        print(f"[WARN] webServiceDownloaded returned non-success: {resp}")
    else:
        print("[INFO] Download recorded successfully.")
    return resp

# ---------------------------
# Email helper (same as previous)
# ---------------------------


def send_email_notification(smtp_host: str,
                            smtp_port: int,
                            smtp_user: Optional[str],
                            smtp_pass: Optional[str],
                            use_tls: bool,
                            from_addr: str,
                            to_addr: str,
                            subject: str,
                            body: str,
                            attachment_path: Optional[Path] = None) -> None:
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    if attachment_path:
        try:
            with open(attachment_path, "rb") as f:
                data = f.read()
            maintype = "application"
            subtype = "octet-stream"
            if attachment_path.suffix.lower() == ".csv":
                maintype, subtype = "text", "csv"
            msg.add_attachment(data, maintype=maintype,
                               subtype=subtype, filename=attachment_path.name)
        except Exception as e:
            print(f"[WARN] Failed to attach file {attachment_path}: {e}")

    try:
        port = int(smtp_port)
    except Exception:
        port = 587

    if port == 465:
        with smtplib.SMTP_SSL(smtp_host, port, timeout=30) as server:
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, port, timeout=30) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)

    print(f"[INFO] Email sent to {to_addr} (subject: {subject})")

# ---------------------------
# Tracker helpers
# ---------------------------


def load_tracker(tracker_path: Path) -> Dict[str, dict]:
    if not tracker_path.exists():
        return {}
    try:
        return json.loads(tracker_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Failed reading tracker {tracker_path}: {e}")
        return {}


def save_tracker(tracker_path: Path, data: Dict[str, dict]) -> None:
    tmp = tracker_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(tracker_path)

# ---------------------------
# Main flow
# ---------------------------


def main():
    out_dir = DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    tracker_path = out_dir / TRACKER_FILENAME
    tracker = load_tracker(tracker_path)

    # For run summary
    run_downloads: List[Dict[str, str]] = []
    run_notes: List[str] = []

    env_token = os.environ.get("AP_AUTH_TOKEN")
    email = os.environ.get("AP_EMAIL")
    password = os.environ.get("AP_PASSWORD")

    if env_token:
        auth_token = env_token
        print("[INFO] Using AP_AUTH_TOKEN from environment.")
    else:
        if not email or not password:
            print(
                "[ERROR] Missing AP_EMAIL or AP_PASSWORD. Add them to creds.env or .env next to the script.")
            sys.exit(1)
        auth_token = login_and_get_token(email, password)

    di_code = os.environ.get("AP_DICODE", DEFAULT_DICODE)
    fmt = DEFAULT_FORMAT
    download_type = DEFAULT_DOWNLOAD_TYPE

    # First generate a file (this polls until a url is returned)
    try:
        initial_file_resp = generate_file_with_poll(
            auth_token, di_code, fmt, download_type)
    except Exception as e:
        print(f"[ERROR] Failed to generate file: {e}")
        run_notes.append(f"fileGeneration failed: {e}")
        # Send a failure summary email before exiting
        try:
            _send_summary_email(run_downloads, run_notes, success=False)
        except Exception:
            pass
        sys.exit(2)

    file_name = initial_file_resp.get("fileName")
    download_id = str(initial_file_resp.get("downloadId", ""))
    pre_signed_url = initial_file_resp.get("url")
    expires = None
    if pre_signed_url and "Expires=" in pre_signed_url:
        try:
            q = up.urlparse(pre_signed_url).query
            params = up.parse_qs(q)
            if "Expires" in params:
                expires = params["Expires"][0]
        except Exception:
            expires = None

    print(
        f"[INFO] fileGeneration returned fileName={file_name}, downloadId={download_id}, expires={human_time_from_expires(expires)}")

    # Duplicate checks: if we've already recorded this download, skip
    if download_id in tracker:
        note = f"Download ID {download_id} already recorded -> skipping."
        print(f"[INFO] {note}")
        run_notes.append(note)
        # send summary and exit
        try:
            _send_summary_email(run_downloads, run_notes, success=True)
        except Exception:
            pass
        return

    out_path = out_dir / file_name
    if out_path.exists():
        note = f"File {out_path} already exists locally -> skipping and recording."
        print(f"[INFO] {note}")
        tracker[download_id] = {"fileName": file_name, "path": str(
            out_path), "dicode": di_code, "format": fmt, "timestamp_utc": int(time.time())}
        save_tracker(tracker_path, tracker)
        run_notes.append(note)
        try:
            _send_summary_email(run_downloads, run_notes, success=True)
        except Exception:
            pass
        return

    # Attempt immediate download with expiry-safety (this will regenerate if needed)
    try:
        successful_resp = download_with_expiry_safety(
            auth_token, di_code, initial_file_resp, out_dir, max_regens=2)
    except Exception as e:
        print(
            f"[ERROR] Failed to generate/download file within expiry constraints: {e}")
        run_notes.append(f"Download failed: {e}")
        # Save 403 response if present already done in helper
        try:
            _send_summary_email(run_downloads, run_notes, success=False)
        except Exception:
            pass
        sys.exit(4)

    # On success, extract final info
    final_file_name = successful_resp.get("fileName")
    final_download_id = str(successful_resp.get("downloadId", ""))
    final_out_path = out_dir / final_file_name

    # Send per-file success email (attachment included if SMTP configured)
    email_sent = False
    try:
        notify_to = os.environ.get(
            "AP_NOTIFY_TO") or os.environ.get("AP_EMAIL")
        smtp_host = os.environ.get("SMTP_HOST")
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_user = os.environ.get("SMTP_USER")
        smtp_pass = os.environ.get("SMTP_PASS")
        smtp_use_tls = os.environ.get(
            "SMTP_USE_TLS", "True").lower() in ("1", "true", "yes")
        smtp_from = os.environ.get("SMTP_FROM") or os.environ.get("AP_EMAIL")

        if smtp_host and notify_to:
            subject = f"AP file downloaded: {final_file_name}"
            body = (f"The AP file {final_file_name} (downloadId={final_download_id}) was downloaded and saved to {final_out_path}.\n\n"
                    f"DI code: {di_code}\nExpires: {human_time_from_expires(expires)}")
            send_email_notification(
                smtp_host=smtp_host,
                smtp_port=smtp_port,
                smtp_user=smtp_user,
                smtp_pass=smtp_pass,
                use_tls=smtp_use_tls,
                from_addr=smtp_from,
                to_addr=notify_to,
                subject=subject,
                body=body,
                attachment_path=final_out_path
            )
            email_sent = True
        else:
            print(
                "[INFO] SMTP_HOST or notify recipient not set; skipping per-file email notification.")
    except Exception as e:
        print(f"[WARN] Failed to send per-file email notification: {e}")
        run_notes.append(f"Per-file email failed: {e}")

    # Record download back to AP service
    try:
        record_download(auth_token, final_download_id, fmt)
    except Exception as e:
        print(f"[WARN] Failed to call webServiceDownloaded: {e}")
        run_notes.append(f"record_download failed: {e}")

    # Update tracker
    tracker[final_download_id] = {
        "fileName": final_file_name,
        "path": str(final_out_path),
        "dicode": di_code,
        "format": fmt,
        "timestamp_utc": int(time.time())
    }
    save_tracker(tracker_path, tracker)
    run_downloads.append({"fileName": final_file_name, "downloadId": final_download_id, "path": str(
        final_out_path), "email_sent": str(email_sent)})
    print("[INFO] Download complete and tracker updated.")

    # Final summary email
    try:
        _send_summary_email(run_downloads, run_notes, success=True)
    except Exception as e:
        print(f"[WARN] Failed to send summary email: {e}")


def _send_summary_email(downloads: List[Dict[str, str]], notes: List[str], success: bool):
    """Compose and send a compact summary email for the run."""
    notify_to = os.environ.get("AP_NOTIFY_TO") or os.environ.get("AP_EMAIL")
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_use_tls = os.environ.get(
        "SMTP_USE_TLS", "True").lower() in ("1", "true", "yes")
    smtp_from = os.environ.get("SMTP_FROM") or os.environ.get("AP_EMAIL")

    if not smtp_host or not notify_to:
        print("[INFO] SMTP_HOST or notify recipient not set; skipping summary email.")
        return

    status_text = "SUCCESS" if success else "FAILURE"
    subject = f"AP Download run complete: {status_text}"
    lines = [f"AP Download run status: {status_text}",
             f"Time: {datetime.now().astimezone().isoformat()}"]
    if downloads:
        lines.append("")
        lines.append("Downloaded files:")
        for d in downloads:
            lines.append(
                f" - {d.get('fileName')}  (downloadId={d.get('downloadId')}) saved to {d.get('path')} | email_sent={d.get('email_sent')}")
    else:
        lines.append("")
        lines.append("No files were downloaded in this run.")

    if notes:
        lines.append("")
        lines.append("Notes / warnings:")
        for n in notes:
            lines.append(f" - {n}")

    body = "\n".join(lines)

    # send summary (no attachments)
    send_email_notification(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_pass=smtp_pass,
        use_tls=smtp_use_tls,
        from_addr=smtp_from,
        to_addr=notify_to,
        subject=subject,
        body=body,
        attachment_path=None
    )


if __name__ == "__main__":
    main()

