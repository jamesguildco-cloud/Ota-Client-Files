#!/usr/bin/env python3
"""
OTA Client

Secure model:
- device generates its own private key locally
- device generates its own CSR locally
- server signs the CSR and returns only the certificate
- server must not generate or return the device private key

Modes:
- virtual: macOS/local testing, no real flashing or reboot
- device: Linux-style flashing workflow using slot paths / fw_setenv
"""

import argparse
import base64
import gzip
import hashlib
import json
import logging
import lzma
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, UTC
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.oid import NameOID


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def resolve_config_path():
    explicit = Path(sys.argv[sys.argv.index("--config") + 1]) if "--config" in sys.argv else None
    if explicit:
        return explicit
    env_path = Path(Path.cwd() / "ota_client.yaml") if not bool(Path("/etc/ota/config.yaml").exists()) else Path("/etc/ota/config.yaml")
    return Path(__import__("os").environ.get("OTA_CONFIG_PATH", str(env_path)))


def sh(cmd, check=True):
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed: {cmd} :: {result.stderr.strip()}")
    return result.stdout.strip(), result.stderr.strip()


def safe_text(resp):
    try:
        return resp.text[:2000]
    except Exception:
        return ""


class EventLogger:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.last_hash = self._load_last_hash()

    def _load_last_hash(self):
        if not self.log_path.exists():
            return "0" * 64
        last = None
        with open(self.log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line.strip().split("|")[-1]
        return last or "0" * 64

    def record(self, event_type, data=None):
        ts = datetime.now(UTC).isoformat()
        payload = json.dumps(data or {}, sort_keys=True)
        digest = hashlib.sha256(f"{ts}|{event_type}|{payload}|{self.last_hash}".encode()).hexdigest()
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(f"{ts}|{event_type}|{payload}|{digest}\n")
        self.last_hash = digest


class OTAState:
    def __init__(self, path: Path):
        self.path = path
        self.data = {
            "phase": "idle",
            "firmware_id": None,
            "version": None,
            "downloaded_bytes": 0,
            "total_bytes": 0,
            "artifact_path": None,
            "target_slot": None,
        }
        self.load()

    def load(self):
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text()))
            except Exception:
                self.save()

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2))

    def set_phase(self, phase):
        self.data["phase"] = phase
        self.save()


class OTAConfig:
    def __init__(self, path: Path):
        self.path = path
        if not path.exists():
            raise FileNotFoundError(f"missing config file: {path}")

        cfg = yaml.safe_load(path.read_text()) or {}
        self.raw = cfg

        def cfg_path(key, default):
            value = cfg.get(key)
            return Path(value) if value else Path(default)

        self.server = str(cfg["server_url"]).rstrip("/")
        self.device_id = str(cfg["device_id"])
        self.tenant_id = cfg.get("tenant_id")
        self.channel = cfg.get("channel", "stable")
        self.model = cfg.get("model", "virtual-device")
        self.current_version = cfg.get("current_version")
        self.mode = cfg.get("mode", "virtual")
        self.provisioning_token = cfg.get("provisioning_token")
        self.claim_token = cfg.get("claim_token")
        self.jwt = cfg.get("token")
        self.retry_backoff = int(cfg.get("retry_backoff", 5))
        self.retry_limit = int(cfg.get("retry_limit", 5))

        base_dir = cfg_path("base_dir", path.parent)
        self.work_dir = cfg_path("work_dir", base_dir / "ota_work")
        self.state_path = cfg_path("state_path", base_dir / "ota_state.json")
        self.event_log = cfg_path("event_log", base_dir / "ota_events.log")
        self.client_cert = cfg_path("client_cert", base_dir / "client.crt")
        self.client_key = cfg_path("client_key", base_dir / "client.key")
        self.public_key = cfg_path("public_key", base_dir / "client.pub")
        self.virtual_slot_dir = cfg_path("virtual_slot_dir", base_dir / "virtual_slots")
        self.slotA = cfg.get("slotA", "/dev/mmcblk0p1")
        self.slotB = cfg.get("slotB", "/dev/mmcblk0p2")

        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.virtual_slot_dir.mkdir(parents=True, exist_ok=True)

    def cert_tuple(self):
        if self.client_cert.exists() and self.client_key.exists():
            return (str(self.client_cert), str(self.client_key))
        return None

    def save(self):
        data = dict(self.raw)
        data.update({
            "server_url": self.server,
            "device_id": self.device_id,
            "tenant_id": self.tenant_id,
            "channel": self.channel,
            "model": self.model,
            "current_version": self.current_version,
            "mode": self.mode,
            "retry_backoff": self.retry_backoff,
            "retry_limit": self.retry_limit,
            "client_cert": str(self.client_cert),
            "client_key": str(self.client_key),
            "public_key": str(self.public_key),
            "work_dir": str(self.work_dir),
            "state_path": str(self.state_path),
            "event_log": str(self.event_log),
            "virtual_slot_dir": str(self.virtual_slot_dir),
        })
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(yaml.safe_dump(data, sort_keys=False))
        self.raw = data


CFG = OTAConfig(resolve_config_path())
EVENTS = EventLogger(CFG.event_log)
STATE = OTAState(CFG.state_path)


def get_device_fingerprint():
    material = f"{CFG.device_id}|{CFG.mode}|{sys.platform}"
    return hashlib.sha256(material.encode()).hexdigest()


def ensure_local_keypair():
    if CFG.client_key.exists() and CFG.public_key.exists():
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    CFG.client_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CFG.public_key.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key():
    ensure_local_keypair()
    return serialization.load_pem_private_key(CFG.client_key.read_bytes(), password=None)


def build_csr_pem():
    key = load_private_key()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, CFG.device_id),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GuildCo OTA"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def save_certificate(cert_pem):
    if cert_pem:
        CFG.client_cert.write_text(cert_pem)


def plain_headers(extra=None):
    headers = {}
    if CFG.tenant_id:
        headers["x-tenant-id"] = CFG.tenant_id
    if extra:
        headers.update(extra)
    return headers


def mtls_headers(extra=None):
    headers = plain_headers(extra)
    if CFG.jwt:
        headers["Authorization"] = f"Bearer {CFG.jwt}"
    return headers


def http_get(url, **kwargs):
    return requests.get(url, headers=mtls_headers(kwargs.pop("headers", {})), cert=CFG.cert_tuple(), **kwargs)


def http_post(url, json_body=None, **kwargs):
    return requests.post(url, json=json_body, headers=mtls_headers(kwargs.pop("headers", {})), cert=CFG.cert_tuple(), **kwargs)


def bootstrap_post(url, json_body=None, **kwargs):
    return requests.post(url, json=json_body, headers=plain_headers(kwargs.pop("headers", {})), **kwargs)


def download_get(url, **kwargs):
    parsed = urlparse(url)
    server_host = urlparse(CFG.server).hostname
    if parsed.hostname and server_host and parsed.hostname != server_host:
        return requests.get(url, **kwargs)
    return http_get(url, **kwargs)


def bootstrap_if_needed(force=False):
    cert_exists = CFG.client_cert.exists() and CFG.client_key.exists()
    if cert_exists and not force:
        return False

    EVENTS.record("bootstrap_start", {"mode": CFG.mode})
    payload = {
        "device_id": CFG.device_id,
        "fingerprint": get_device_fingerprint(),
        "csr": build_csr_pem(),
    }
    if CFG.provisioning_token:
        payload["token"] = CFG.provisioning_token
    if CFG.claim_token:
        payload["claim_token"] = CFG.claim_token

    response = bootstrap_post(f"{CFG.server}/provisioning/bootstrap", json_body=payload, timeout=30)
    if response.status_code != 200:
        body = safe_text(response)
        EVENTS.record("bootstrap_fail", {"code": response.status_code, "body": body})
        raise RuntimeError(f"bootstrap failed ({response.status_code}): {body}")

    data = response.json()
    save_certificate(data.get("certificate"))
    if data.get("tenant_id"):
        CFG.tenant_id = data["tenant_id"]
    if data.get("server_url"):
        CFG.server = str(data["server_url"]).rstrip("/")
    if data.get("channel"):
        CFG.channel = data["channel"]
    CFG.save()

    EVENTS.record("bootstrap_ok", {"tenant_id": CFG.tenant_id, "device_id": CFG.device_id})
    return True


def register_device():
    payload = {
        "model": CFG.model,
        "channel": CFG.channel,
        "current_version": CFG.current_version,
        "metadata": {
            "runtime": {
                "mode": CFG.mode,
                "platform": sys.platform,
            }
        }
    }
    response = http_post(f"{CFG.server}/device/register", json_body=payload, timeout=20)
    if response.status_code != 200:
        body = safe_text(response)
        EVENTS.record("register_fail", {"code": response.status_code, "body": body})
        raise RuntimeError(f"register failed ({response.status_code}): {body}")
    EVENTS.record("register_ok", payload)
    return response.json()


def fetch_signing_key():
    response = requests.get(f"{CFG.server}/public/firmware-signing-key", headers=plain_headers(), timeout=20)
    if response.status_code != 200:
        raise RuntimeError(f"failed to fetch signing key ({response.status_code})")
    return response.text


def verify_signature(hex_digest, signature_b64):
    if not hex_digest or not signature_b64:
        return True

    public_key = load_pem_public_key(fetch_signing_key().encode())
    public_key.verify(
        base64.b64decode(signature_b64),
        bytes.fromhex(hex_digest),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        utils.Prehashed(hashes.SHA256()),
    )
    return True


def poll_next_update():
    EVENTS.record("check_update_start")
    try:
        response = http_get(f"{CFG.server}/device/next", params={"channel": CFG.channel}, timeout=20)
    except Exception as exc:
        EVENTS.record("check_update_error", {"err": str(exc)})
        return None

    if response.status_code == 204:
        EVENTS.record("check_update_none")
        return None
    if response.status_code != 200:
        EVENTS.record("check_update_fail", {"code": response.status_code, "body": safe_text(response)})
        return None

    fw = response.json()
    EVENTS.record("check_update_ok", {"firmware_id": fw.get("firmware_id"), "version": fw.get("version")})
    return fw


def report_progress(fw, downloaded, total, status="in_progress", lifecycle_state=None, error_code=None):
    downloaded = int(downloaded or 0)
    total = int(total or 0)
    payload = {
        "firmware_id": fw["firmware_id"],
        "percent": int(downloaded * 100 / total) if total > 0 else 0,
        "downloaded_bytes": downloaded,
        "total_bytes": total,
        "status": status,
        "version": fw.get("version"),
    }
    if lifecycle_state:
        payload["lifecycle_state"] = lifecycle_state
    if error_code:
        payload["error_code"] = error_code
    try:
        http_post(f"{CFG.server}/device/progress", json_body=payload, timeout=10)
    except Exception:
        pass


def resumable_download(fw):
    suffix = fw.get("format") or "bin"
    target = CFG.work_dir / f"fw.{suffix}"
    expected = fw.get("size") if fw.get("size") is not None else fw.get("size_bytes", 0)
    try:
        total_size = int(expected or 0)
    except (TypeError, ValueError):
        total_size = 0
    resume_pos = target.stat().st_size if target.exists() else 0

    STATE.data.update({
        "phase": "downloading",
        "firmware_id": fw["firmware_id"],
        "version": fw.get("version"),
        "artifact_path": str(target),
        "downloaded_bytes": resume_pos,
        "total_bytes": total_size,
    })
    STATE.save()

    if total_size > 0 and resume_pos >= total_size and target.exists():
        target.unlink()
        resume_pos = 0
        STATE.data["downloaded_bytes"] = 0
        STATE.save()

    headers = {"Range": f"bytes={resume_pos}-"} if resume_pos > 0 else {}
    response = download_get(fw["url"], headers=headers, stream=True, timeout=120, allow_redirects=True)
    if response.status_code == 416 and target.exists():
        target.unlink()
        resume_pos = 0
        STATE.data["downloaded_bytes"] = 0
        STATE.save()
        response = download_get(fw["url"], headers={}, stream=True, timeout=120, allow_redirects=True)
    if response.status_code not in (200, 206):
        raise RuntimeError(f"download failed ({response.status_code})")

    if total_size <= 0:
        if response.status_code == 206:
            content_range = response.headers.get("Content-Range", "")
            if "/" in content_range:
                try:
                    total_size = int(content_range.rsplit("/", 1)[1])
                except (TypeError, ValueError):
                    total_size = 0
        else:
            try:
                total_size = int(response.headers.get("Content-Length", 0) or 0)
            except (TypeError, ValueError):
                total_size = 0

        STATE.data["total_bytes"] = total_size
        STATE.save()

    mode = "ab" if resume_pos > 0 else "wb"
    with open(target, mode) as handle:
        for chunk in response.iter_content(1024 * 1024):
            if not chunk:
                continue
            handle.write(chunk)
            resume_pos += len(chunk)
            STATE.data["downloaded_bytes"] = resume_pos
            STATE.save()
            report_progress(fw, resume_pos, total_size, status="in_progress")

    report_progress(fw, resume_pos, total_size, status="completed")
    EVENTS.record("download_complete", {"bytes": resume_pos})
    return target


def verify_checksum(path: Path, expected: str):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest().lower()
    expected = (expected or "").lower()
    if not expected or actual != expected:
        raise RuntimeError(f"checksum mismatch: expected {expected}, got {actual}")
    return actual


def copy_to_target(src_handle, dest_path: Path):
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, "wb") as dst:
        shutil.copyfileobj(src_handle, dst, 1024 * 1024)


def stream_decompress_or_copy(path: Path, output_path: Path):
    if path.suffix == ".gz":
        with open(path, "rb") as probe:
            magic = probe.read(2)
        if magic != b"\x1f\x8b":
            raise RuntimeError(
                f"artifact format mismatch: expected gzip based on '{path.name}', "
                f"but file starts with {magic.hex()}"
            )
        with gzip.open(path, "rb") as src:
            copy_to_target(src, output_path)
    elif path.suffix == ".xz":
        with open(path, "rb") as probe:
            magic = probe.read(6)
        if magic != b"\xfd7zXZ\x00":
            raise RuntimeError(
                f"artifact format mismatch: expected xz based on '{path.name}', "
                f"but file starts with {magic.hex()}"
            )
        with lzma.open(path, "rb") as src:
            copy_to_target(src, output_path)
    else:
        with open(path, "rb") as src:
            copy_to_target(src, output_path)


def get_active_slot():
    if CFG.mode == "virtual":
        return STATE.data.get("target_slot") or "A"
    try:
        out, _ = sh(["fw_printenv", "boot_part"], check=False)
        return "B" if "boot_part=B" in out else "A"
    except Exception:
        return "A"


def set_active_slot(slot):
    if CFG.mode == "virtual":
        STATE.data["target_slot"] = slot
        STATE.save()
        return
    sh(["fw_setenv", "boot_part", slot])


def mark_upgrade_available():
    if CFG.mode == "virtual":
        return
    try:
        sh(["fw_setenv", "upgrade_available", "1"])
    except Exception:
        pass


def clear_upgrade_available():
    if CFG.mode == "virtual":
        return
    try:
        sh(["fw_setenv", "upgrade_available", "0"])
    except Exception:
        pass


def check_boot_confirmation():
    if CFG.mode == "virtual":
        return
    out, _ = sh(["fw_printenv", "upgrade_available"], check=False)
    if STATE.data.get("phase") == "switching" and "upgrade_available=1" in out:
        return
    clear_upgrade_available()


def install_firmware(fw, artifact_path: Path):
    active = get_active_slot()
    inactive = "B" if active == "A" else "A"
    total_bytes = int(STATE.data.get("total_bytes") or 0)
    downloaded_bytes = int(STATE.data.get("downloaded_bytes") or total_bytes)

    if CFG.mode == "virtual":
        report_progress(fw, downloaded_bytes, total_bytes, status="completed", lifecycle_state="installing")
        target = CFG.virtual_slot_dir / f"slot_{inactive}.img"
        stream_decompress_or_copy(artifact_path, target)
        report_progress(fw, downloaded_bytes, total_bytes, status="completed", lifecycle_state="rebooting")
        CFG.current_version = fw.get("version")
        CFG.save()
        STATE.set_phase("idle")
        EVENTS.record("install_virtual_ok", {"slot": inactive, "path": str(target)})
        report_health(fw, "success")
        return

    report_progress(fw, downloaded_bytes, total_bytes, status="completed", lifecycle_state="installing")
    target = Path(CFG.slotB if inactive == "B" else CFG.slotA)
    stream_decompress_or_copy(artifact_path, target)
    set_active_slot(inactive)
    mark_upgrade_available()
    report_progress(fw, downloaded_bytes, total_bytes, status="completed", lifecycle_state="rebooting")
    STATE.set_phase("switching")
    EVENTS.record("install_reboot", {"slot": inactive})
    subprocess.Popen(["reboot"])
    time.sleep(2)
    sys.exit(0)


def report_health(fw, status, extra=None):
    payload = {
        "status": status,
        "metrics": {
            "version": fw.get("version")
        }
    }
    if extra:
        payload["metrics"].update(extra)
    try:
        http_post(f"{CFG.server}/device/health", json_body=payload, timeout=15)
    except Exception as exc:
        EVENTS.record("health_report_fail", {"err": str(exc)})
        return False
    EVENTS.record("health_report_ok", {"status": status})
    return True


def run_ota_once():
    check_boot_confirmation()
    fw = poll_next_update()
    if not fw:
        print("No update available")
        return False

    artifact = resumable_download(fw)
    total_bytes = int(STATE.data.get("total_bytes") or 0)
    downloaded_bytes = int(STATE.data.get("downloaded_bytes") or total_bytes)
    report_progress(fw, downloaded_bytes, total_bytes, status="completed", lifecycle_state="verifying")
    digest = verify_checksum(artifact, fw.get("checksum_sha256"))
    if fw.get("signature"):
        verify_signature(digest, fw["signature"])
    install_firmware(fw, artifact)
    print(f"OTA applied for version {fw.get('version')}")
    return True


def backoff_sleep(attempt):
    delay = max(1, min(CFG.retry_backoff * (2 ** attempt), 3600))
    time.sleep(delay)


def ota_supervisor_loop():
    attempt = 0
    while True:
        try:
            run_ota_once()
            attempt = 0
            time.sleep(300)
        except Exception as exc:
            EVENTS.record("fatal_error", {"err": str(exc)})
            attempt += 1
            if attempt > CFG.retry_limit:
                raise
            backoff_sleep(attempt)


class DiagnosticsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({
            "server": CFG.server,
            "device_id": CFG.device_id,
            "tenant_id": CFG.tenant_id,
            "mode": CFG.mode,
            "state": STATE.data,
            "last_event_hash": EVENTS.last_hash
        }, indent=2)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())


def start_diagnostics_server():
    def run():
        HTTPServer(("127.0.0.1", 8081), DiagnosticsHandler).serve_forever()
    threading.Thread(target=run, daemon=True).start()


def ota_startup(force_bootstrap=False):
    EVENTS.record("startup_begin", {"mode": CFG.mode})
    bootstrap_if_needed(force=force_bootstrap)
    register_device()
    start_diagnostics_server()
    EVENTS.record("startup_complete")


def main():
    parser = argparse.ArgumentParser(description="OTA client")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--once", action="store_true", help="run one OTA cycle")
    parser.add_argument("--bootstrap-only", action="store_true", help="bootstrap and exit")
    parser.add_argument("--register-only", action="store_true", help="register and exit")
    parser.add_argument("--force-bootstrap", action="store_true", help="re-bootstrap even if cert exists")
    parser.add_argument("--diagnostics-only", action="store_true", help="run diagnostics server only")
    args = parser.parse_args()

    if args.diagnostics_only:
        start_diagnostics_server()
        print("Diagnostics: http://127.0.0.1:8081/health")
        while True:
            time.sleep(3600)

    if args.bootstrap_only:
        bootstrap_if_needed(force=True)
        return

    if args.register_only:
        bootstrap_if_needed(force=args.force_bootstrap)
        register_device()
        return

    ota_startup(force_bootstrap=args.force_bootstrap)

    if args.once:
        try:
            run_ota_once()
            return
        except Exception as exc:
            print(f"OTA failed: {exc}")
            raise

    ota_supervisor_loop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        EVENTS.record("shutdown_keyboard")
    except Exception as exc:
        EVENTS.record("shutdown_error", {"err": str(exc)})
        raise
