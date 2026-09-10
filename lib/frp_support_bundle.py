#!/usr/bin/env python3
"""Collect a sanitized, read-only Support Bundle archive.

Never mutates services. Never writes raw secrets into the archive.
Sanitize-before-write: redact text and strip secret JSON fields before any
archive member is created.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Tuple

FORMAT = "frp-auto-deploy-support-bundle"
SCHEMA_VERSION = 1

# Filenames that must never be copied into a support bundle.
FORBIDDEN_NAME_RE = re.compile(
    r"(^|[/\\])("
    r"ca\.key|server\.key|client-identity\.key|"
    r"server_token|.*\.pem|"
    r".*private.*key.*|"
    r"bootstrap.*ticket.*|"
    r"enrollment.*secret.*|"
    r".*mgmt_mac_key.*"
    r")$",
    re.IGNORECASE,
)

SECRET_KEY_RE = re.compile(
    r"(^|_)(token|secret|password|passwd|private_key|privkey|api_key|apikey|"
    r"auth_token|access_token|refresh_token|mac_key|mgmt_mac_key|"
    r"enrollment_code|enrollment_secret|enroll_secret|bootstrap_ticket|"
    r"frp_bootstrap_ticket|authorization|cookie|credential)(_|$)|"
    r"token_ciphertext|auth\.token|server_token|frp_token",
    re.IGNORECASE,
)

REDACTED = "<redacted>"


def fail(message: str) -> "NoReturn":
    print("ERROR: %s" % message, file=sys.stderr)
    raise SystemExit(1)


def _load_doctor():
    here = Path(__file__).resolve().parent
    candidates = (
        here / "frp_doctor.py",
        Path("/usr/local/lib/drlink/frp_doctor.py"),
        Path("/Library/Application Support/drlink/lib/frp_doctor.py"),
    )
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location("frp_doctor", str(path))
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(module)
            return module
    raise RuntimeError("frp_doctor.py is unavailable")


def _doctor():
    if not hasattr(_doctor, "_mod"):
        _doctor._mod = _load_doctor()  # type: ignore[attr-defined]
    return _doctor._mod  # type: ignore[attr-defined]


def redact_text(text: Any) -> str:
    doctor = _doctor()
    return doctor.redact("" if text is None else str(text))


def now_utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_hostname() -> str:
    raw = socket.gethostname() or "unknown"
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip(".-")
    return (cleaned or "unknown")[:64]


def run_cmd(args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "command not found: %s" % args[0]
    except PermissionError:
        return 126, "", "permission denied: %s" % args[0]
    except OSError as exc:
        return 125, "", "os error: %s" % exc
    except subprocess.TimeoutExpired:
        return 124, "", "timed out: %s" % " ".join(args)
    out = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
    err = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
    return proc.returncode, out, err


def _is_symlink(path: Path) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _lexists(path: Path) -> bool:
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _reject_symlink_components(path: Path, what: str) -> None:
    parts = path.parts
    if not parts:
        fail("refusing empty %s" % what)
    acc = Path(parts[0])
    prefixes = [acc]
    for part in parts[1:]:
        acc = acc / part
        prefixes.append(acc)
    for prefix in prefixes:
        if _is_symlink(prefix):
            fail("refusing %s that traverses a symlink" % what)


def validate_output_path(raw: str) -> Path:
    if not raw or raw in {".", "..", "/", "//", "-"}:
        fail("refusing unsafe output path")
    path = Path(raw)
    if not path.is_absolute():
        path = Path.cwd() / path
    if ".." in path.parts or "\\" in raw:
        fail("refusing unsafe output path")
    _reject_symlink_components(path, "output path")
    return path


def is_forbidden_source(path: Path) -> bool:
    name = path.name
    if FORBIDDEN_NAME_RE.search(name):
        return True
    if name.endswith(".key") and name not in {"client-identity.pub"}:
        # Public keys may use .pub; private keys typically .key
        if not name.endswith(".pub"):
            return True
    return False


def sanitize_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            key_s = str(key)
            if SECRET_KEY_RE.search(key_s):
                out[key_s] = REDACTED
            else:
                out[key_s] = sanitize_json_value(item)
        return out
    if isinstance(value, list):
        return [sanitize_json_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sanitized = redact_text(text)
    fd, tmp = tempfile.mkstemp(prefix=".frp-sb-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(sanitized)
            if sanitized and not sanitized.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def write_json(path: Path, payload: Any, *, mode: int = 0o600) -> None:
    clean = sanitize_json_value(payload)
    write_text(path, json.dumps(clean, indent=2, sort_keys=True) + "\n", mode=mode)


def read_identity(path: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not path.is_file() or path.is_symlink():
        return result
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {
            "PROJECT_VERSION",
            "FRP_VERSION",
            "RELEASE_CHANNEL",
            "SOURCE_REF",
            "BUNDLE_SHA256",
        }:
            result[key.lower()] = value
    return result


def map_path(root: Path, abs_path: str) -> Path:
    if abs_path.startswith("/"):
        rel = abs_path[1:]
    else:
        rel = abs_path
    return root / rel


class BundleBuilder:
    def __init__(self, root: Path):
        self.root = root
        self.sections: List[str] = []
        self.redactions: List[str] = []
        self.skipped: List[str] = []
        self.role = "uninstalled"
        self.role_label = "Uninstalled"
        self.stage: Optional[Path] = None
        self._doctor = _doctor()

    def note_redaction(self, reason: str) -> None:
        if reason not in self.redactions:
            self.redactions.append(reason)

    def add_section(self, name: str) -> None:
        if name not in self.sections:
            self.sections.append(name)

    def skip(self, name: str, reason: str) -> None:
        self.skipped.append("%s (%s)" % (name, reason))

    def path(self, abs_path: str) -> Path:
        # Reuse doctor's Paths.p so Darwin installs map /etc/frp → macOS state root.
        doctor = self._doctor
        root_s = "" if self.root == Path("/") else str(self.root)
        return doctor.Paths(root_s).p(abs_path)

    def safe_read_text(self, abs_path: str) -> Optional[str]:
        path = self.path(abs_path)
        if _is_symlink(path):
            self.note_redaction("skipped symlink: %s" % abs_path)
            return None
        if is_forbidden_source(path):
            self.note_redaction("omitted secret file: %s" % abs_path)
            return None
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def safe_read_json(self, abs_path: str) -> Tuple[Optional[Any], Optional[str]]:
        text = self.safe_read_text(abs_path)
        if text is None:
            return None, "missing or omitted"
        try:
            return json.loads(text), None
        except json.JSONDecodeError as exc:
            return None, "invalid JSON (%s)" % exc

    def stage_write(self, rel: str, text: str) -> None:
        assert self.stage is not None
        write_text(self.stage / rel, text)

    def stage_json(self, rel: str, payload: Any) -> None:
        assert self.stage is not None
        write_json(self.stage / rel, payload)

    def collect(self) -> Path:
        doctor = self._doctor
        paths = doctor.Paths(str(self.root) if str(self.root) != "/" else "")
        # When root is "/", Paths expects empty root string.
        if self.root == Path("/"):
            paths = doctor.Paths("")
        else:
            paths = doctor.Paths(str(self.root))
        role_info = doctor.detect_role(paths)
        self.role = role_info.get("role") or "uninstalled"
        self.role_label = role_info.get("label") or self.role

        tmp = tempfile.mkdtemp(prefix=".frp-support-")
        self.stage = Path(tmp)
        try:
            self._write_meta(role_info)
            self._write_versions()
            self._write_os_info()
            self._write_service_status()
            self._write_doctor(paths)
            self._write_product_config()
            self._write_registry_summary()
            self._write_client_summary()
            self._write_generated_config()
            self._write_certs_public_only()
            self._write_logs()
            self._write_network()
            self._write_processes()
            self._write_disk()
            self._write_access_control()
            self._write_target_health_optional()
            self._write_manifest()
            return self.stage
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            self.stage = None
            raise

    def _write_meta(self, role_info: dict) -> None:
        identity = read_identity(self.path("/etc/drlink/version"))
        payload = {
            "format": FORMAT,
            "schema_version": SCHEMA_VERSION,
            "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "hostname": safe_hostname(),
            "role": self.role,
            "role_label": self.role_label,
            "role_detection": {
                "confidence": role_info.get("confidence"),
                "server_signals": role_info.get("server_signals"),
                "client_signals": role_info.get("client_signals"),
            },
            "project_version": identity.get("project_version", "unknown"),
            "frp_version": identity.get("frp_version", "unknown"),
            "release_channel": identity.get("release_channel", "unknown"),
            "source_ref": identity.get("source_ref", "unknown"),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "read_only": True,
            "secrets_policy": "sanitize-before-write; private keys and tokens omitted",
        }
        self.stage_json("meta.json", payload)
        self.add_section("meta")

    def _write_versions(self) -> None:
        identity = read_identity(self.path("/etc/drlink/version"))
        lines = [
            "PROJECT_VERSION=%s" % identity.get("project_version", "unknown"),
            "FRP_VERSION=%s" % identity.get("frp_version", "unknown"),
            "RELEASE_CHANNEL=%s" % identity.get("release_channel", "unknown"),
            "SOURCE_REF=%s" % identity.get("source_ref", "unknown"),
            "BUNDLE_SHA256=%s" % identity.get("bundle_sha256", "unknown"),
        ]
        for binary in ("/usr/local/bin/frps", "/usr/local/bin/frpc"):
            path = self.path(binary)
            if path.is_file() and not path.is_symlink() and os.access(path, os.X_OK):
                rc, out, err = run_cmd([str(path), "--version"], timeout=5)
                lines.append("")
                lines.append("# %s" % binary)
                lines.append(redact_text(out.strip() or err.strip() or ("exit=%s" % rc)))
            elif path.is_file() and not path.is_symlink():
                lines.append("")
                lines.append("# %s (present, not executable)" % binary)
        self.stage_write("versions.txt", "\n".join(lines) + "\n")
        self.add_section("versions")

    def _write_os_info(self) -> None:
        chunks: List[str] = []
        for args in (
            ["uname", "-a"],
            ["uname", "-srm"],
        ):
            rc, out, err = run_cmd(args, timeout=5)
            chunks.append("$ %s" % " ".join(args))
            chunks.append(out.strip() or err.strip() or ("exit=%s" % rc))
            chunks.append("")
        os_release = self.safe_read_text("/etc/os-release")
        if os_release:
            chunks.append("# /etc/os-release")
            chunks.append(os_release.rstrip())
            chunks.append("")
        sw_vers = shutil.which("sw_vers")
        if sw_vers:
            rc, out, err = run_cmd([sw_vers], timeout=5)
            chunks.append("$ sw_vers")
            chunks.append(out.strip() or err.strip())
            chunks.append("")
        self.stage_write("os-info.txt", "\n".join(chunks))
        self.add_section("os-info")

    def _write_service_status(self) -> None:
        lines: List[str] = []
        units = [
            "frps",
            "drlink-allocator",
            "drlink-access",
            "drlink-frontend",
            "frpc",
        ]
        if shutil.which("systemctl") and os.environ.get("FRP_SKIP_SYSTEMD") != "1":
            for unit in units:
                unit_path = self.path("/etc/systemd/system/%s.service" % unit)
                if not unit_path.is_file() and unit not in ("frps", "frpc"):
                    continue
                lines.append("=== systemctl status %s ===" % unit)
                rc, out, err = run_cmd(
                    ["systemctl", "show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState"],
                    timeout=8,
                )
                lines.append(out.strip() or err.strip() or ("exit=%s" % rc))
                lines.append("")
        elif sys.platform == "darwin" or os.environ.get("FRP_TEST_UNAME_S") == "Darwin":
            label = os.environ.get("FRP_MACOS_LAUNCHD_LABEL") or "com.datarelay.drlink.frpc"
            lines.append("=== launchctl print system/%s ===" % label)
            rc, out, err = run_cmd(["launchctl", "print", "system/%s" % label], timeout=8)
            lines.append(redact_text(out.strip() or err.strip() or ("exit=%s" % rc)))
        else:
            lines.append("service status probes skipped (no usable systemd/launchd in this environment)")
        # Windows stub marker for fixture/portability.
        if sys.platform.startswith("win"):
            lines.append("Windows service status is collected by the Windows client stub when available.")
        self.stage_write("service-status.txt", "\n".join(lines) + "\n")
        self.add_section("service-status")

    def _write_doctor(self, paths) -> None:
        doctor = self._doctor
        try:
            # Prefer library entry when available; fall back to subprocess.
            argv = [
                sys.executable,
                str(Path(doctor.__file__).resolve()),
                "--root",
                "" if self.root == Path("/") else str(self.root),
                "--format",
                "human",
                "--skip-network",
            ]
            env = os.environ.copy()
            env["FRP_DOCTOR_SKIP_NETWORK"] = "1"
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            try:
                proc = subprocess.run(
                    argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=90,
                    check=False,
                    env=env,
                )
                text = (proc.stdout or b"").decode("utf-8", errors="replace")
                err = (proc.stderr or b"").decode("utf-8", errors="replace")
                if err.strip():
                    text = (text + "\n# stderr\n" + err).strip() + "\n"
                self.stage_write("doctor.txt", text or "(doctor produced no output)\n")
                self.add_section("doctor")
                self.note_redaction("doctor output sanitized via redact()")
            except Exception as exc:
                self.stage_write("doctor.txt", "doctor collection failed: %s\n" % redact_text(exc))
                self.skip("doctor", "collection failed")
        finally:
            pass
        # Also attempt JSON for machine parsing.
        try:
            argv_json = [
                sys.executable,
                str(Path(doctor.__file__).resolve()),
                "--root",
                "" if self.root == Path("/") else str(self.root),
                "--format",
                "json",
                "--skip-network",
            ]
            env = os.environ.copy()
            env["FRP_DOCTOR_SKIP_NETWORK"] = "1"
            proc = subprocess.run(
                argv_json,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=90,
                check=False,
                env=env,
            )
            raw = (proc.stdout or b"").decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw) if raw.strip() else {"error": "empty doctor json"}
            except json.JSONDecodeError:
                payload = {"raw": redact_text(raw), "error": "invalid doctor json"}
            self.stage_json("doctor.json", payload)
            self.add_section("doctor-json")
        except Exception as exc:
            self.stage_write("doctor.json.error.txt", "doctor json failed: %s\n" % redact_text(exc))

    def _write_product_config(self) -> None:
        data, err = self.safe_read_json("/etc/drlink/config.json")
        if data is None:
            self.skip("product-config", err or "missing")
            return
        # Explicitly redact known secret-bearing fields even if key regex misses.
        if isinstance(data, dict):
            for key in list(data.keys()):
                if SECRET_KEY_RE.search(str(key)) or str(key).lower() in {
                    "token",
                    "server_token",
                    "mgmt_mac_key",
                }:
                    data[key] = REDACTED
                    self.note_redaction("product config field: %s" % key)
        self.stage_json("product-config.sanitized.json", data)
        self.add_section("product-config")
        self.note_redaction("product config sanitized")

    def _registry_client_summary(self, client: dict) -> dict:
        services_in = client.get("services") or {}
        services_out = {}
        if isinstance(services_in, dict):
            for sid, svc in services_in.items():
                if not isinstance(svc, dict):
                    continue
                services_out[str(sid)] = {
                    "enabled": svc.get("enabled", True),
                    "type": svc.get("type") or svc.get("protocol"),
                    "local_ip": svc.get("local_ip"),
                    "local_port": svc.get("local_port"),
                    "remote_port": svc.get("remote_port"),
                    "ssh_user": svc.get("ssh_user"),
                }
        return {
            "label": client.get("label"),
            "hostname": client.get("hostname"),
            "platform": client.get("platform") or client.get("os"),
            "group": client.get("group") or client.get("groups"),
            "tags": client.get("tags"),
            "note": client.get("note"),
            "last_seen": client.get("last_seen") or client.get("last_seen_at"),
            "services": services_out,
        }

    def _write_registry_summary(self) -> None:
        data, err = self.safe_read_json("/var/lib/drlink/registry.json")
        if data is None:
            if self.role in ("server", "dual", "partial_server"):
                self.skip("registry-summary", err or "missing")
            return
        clients_in = (data or {}).get("clients") or {}
        clients_out = {}
        if isinstance(clients_in, dict):
            for mid, client in clients_in.items():
                if isinstance(client, dict):
                    clients_out[str(mid)] = self._registry_client_summary(client)
                else:
                    clients_out[str(mid)] = {"present": True}
        groups = (data or {}).get("groups") or {}
        summary = {
            "schema_version": (data or {}).get("schema_version"),
            "client_count": len(clients_out),
            "clients": clients_out,
            "groups": sanitize_json_value(groups) if isinstance(groups, dict) else {},
        }
        self.stage_json("registry-summary.json", summary)
        self.add_section("registry-summary")
        self.note_redaction("registry summary excludes identity keys and tokens")

    def _service_summary_entry(self, svc: dict) -> dict:
        local_ip = svc.get("local_ip") or "127.0.0.1"
        local_port = svc.get("local_port")
        target = None
        if local_port is not None and str(local_port) != "":
            target = "%s:%s" % (local_ip, local_port)
        entry: Dict[str, Any] = {
            "enabled": svc.get("enabled", True),
            "type": svc.get("type") or svc.get("protocol") or svc.get("preset"),
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_port": svc.get("remote_port"),
            "name": svc.get("name"),
            "target": target,
        }
        hc = svc.get("health_check")
        if isinstance(hc, dict) and hc:
            entry["health_check"] = sanitize_json_value(hc)
        return entry

    def _write_client_summary(self) -> None:
        state, err = self.safe_read_json("/etc/frp/client-state.json")
        if state is None:
            if self.role in ("client", "dual", "partial_client"):
                self.skip("client-summary", err or "missing")
            return
        if not isinstance(state, dict):
            self.skip("client-summary", "invalid")
            return
        services = state.get("services") or {}
        svc_out = {}
        if isinstance(services, dict):
            for sid, svc in services.items():
                if isinstance(svc, dict):
                    svc_out[str(sid)] = self._service_summary_entry(svc)
        machine_id = state.get("machine_id") or state.get("client_id")
        summary = {
            "machine_id": machine_id,
            "client_id": state.get("client_id") or machine_id,
            "label": state.get("label"),
            "hostname": state.get("hostname"),
            "allocator_url": state.get("allocator_url"),
            "frp_server": state.get("frp_server") or state.get("server_addr") or state.get("server"),
            "frp_server_port": state.get("frp_server_port"),
            "frp_transport": state.get("frp_transport") or state.get("transport"),
            "services": svc_out,
        }
        # Drop any secret-looking leftovers.
        summary = sanitize_json_value(summary)
        self.stage_json("client-summary.json", summary)
        self.add_section("client-summary")
        # Metadata companion if present.
        meta_text = self.safe_read_text("/etc/frp/access-info.txt")
        if meta_text is not None:
            self.stage_write("client-access-info.txt", meta_text)
            self.add_section("client-metadata")

    def _sanitize_toml_text(self, text: str) -> str:
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("auth.token") or "token" in lower and "=" in lower:
                key, _, _ = line.partition("=")
                lines.append("%s = %s" % (key.rstrip(), json.dumps(REDACTED)))
                self.note_redaction("toml token line redacted")
                continue
            if "begin" in lower and "private key" in lower:
                lines.append("# <private key omitted>")
                self.note_redaction("toml private key omitted")
                continue
            lines.append(redact_text(line))
        return "\n".join(lines) + "\n"

    def _write_generated_config(self) -> None:
        for rel in ("/etc/frp/frps.toml", "/etc/frp/frpc.toml", "/etc/drlink/frontend.conf"):
            text = self.safe_read_text(rel)
            if text is None:
                continue
            name = Path(rel).name + ".sanitized"
            if rel.endswith(".toml"):
                self.stage_write("generated/%s" % name, self._sanitize_toml_text(text))
            else:
                self.stage_write("generated/%s" % name, text)
            self.add_section("generated-config")

    def _write_certs_public_only(self) -> None:
        for rel in (
            "/etc/drlink/pki/ca.crt",
            "/etc/drlink/pki/server.crt",
            "/etc/drlink/allocator-ca.crt",
            "/etc/frp/allocator-ca.crt",
            "/etc/frp/client-identity.pub",
        ):
            path = self.path(rel)
            if _is_symlink(path) or not path.is_file():
                continue
            if is_forbidden_source(path):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if "PRIVATE KEY" in text:
                self.note_redaction("refused cert file containing private key: %s" % rel)
                continue
            dest = "certs/%s" % Path(rel).name
            self.stage_write(dest, text)
            self.add_section("public-certs")
        # Explicitly record omitted private material.
        omitted = []
        for rel in (
            "/etc/drlink/pki/ca.key",
            "/etc/drlink/pki/server.key",
            "/etc/frp/client-identity.key",
            "/etc/frp/server_token",
        ):
            if self.path(rel).exists():
                omitted.append(rel)
        if omitted:
            self.stage_write(
                "certs/OMITTED_SECRETS.txt",
                "The following secret files exist on disk but were intentionally omitted:\n"
                + "\n".join(omitted)
                + "\n",
            )
            self.note_redaction("private keys and tokens omitted from certs/")

    def _write_logs(self) -> None:
        lines: List[str] = []
        if shutil.which("journalctl") and os.environ.get("FRP_SKIP_SYSTEMD") != "1":
            for unit in ("frps", "drlink-allocator", "drlink-access", "frpc", "drlink-frontend"):
                rc, out, err = run_cmd(
                    ["journalctl", "-u", unit, "-n", "80", "--no-pager", "-o", "short-iso"],
                    timeout=12,
                )
                if rc == 0 and out.strip():
                    lines.append("=== journalctl -u %s -n 80 ===" % unit)
                    lines.append(out.rstrip())
                    lines.append("")
        # Local product logs (sanitized); never include raw bootstrap tickets.
        log_dir = self.path("/var/log/drlink")
        if log_dir.is_dir() and not log_dir.is_symlink():
            for name in ("audit.jsonl", "access-conn.jsonl"):
                path = log_dir / name
                if path.is_file() and not path.is_symlink():
                    try:
                        # Tail last ~100KB
                        data = path.read_bytes()
                        if len(data) > 100_000:
                            data = data[-100_000:]
                        text = data.decode("utf-8", errors="replace")
                        self.stage_write("logs/%s" % name, text)
                        self.add_section("logs")
                    except OSError:
                        pass
        if lines:
            self.stage_write("logs/journal.txt", "\n".join(lines) + "\n")
            self.add_section("logs")
            self.note_redaction("journal/log text sanitized")
        elif "logs" not in self.sections:
            self.skip("logs", "no journal or product logs available")

    def _write_network(self) -> None:
        chunks: List[str] = []
        for args in (
            ["ss", "-lntup"],
            ["ss", "-lnt"],
            ["netstat", "-lntup"],
            ["netstat", "-an"],
        ):
            if not shutil.which(args[0]):
                continue
            rc, out, err = run_cmd(args, timeout=10)
            if rc == 0 and out.strip():
                chunks.append("$ %s" % " ".join(args))
                chunks.append(out.rstrip())
                chunks.append("")
                break
        if not chunks:
            chunks.append("listening socket summary unavailable on this host")
        self.stage_write("network-listen.txt", "\n".join(chunks) + "\n")
        self.add_section("network")

    def _write_processes(self) -> None:
        chunks: List[str] = []
        for args in (
            ["ps", "aux"],
            ["ps", "-ef"],
        ):
            if not shutil.which(args[0]):
                continue
            rc, out, err = run_cmd(args, timeout=10)
            if rc != 0:
                continue
            filtered = []
            for line in out.splitlines():
                if re.search(r"\b(frps|frpc|drlink-allocator|frp-access|drlink-frontend)\b", line):
                    filtered.append(redact_text(line))
            chunks.append("$ %s | grep frp*" % " ".join(args))
            chunks.extend(filtered or ["(no matching FRP processes)"])
            chunks.append("")
            break
        self.stage_write("process-info.txt", "\n".join(chunks) + "\n")
        self.add_section("processes")

    def _write_disk(self) -> None:
        chunks: List[str] = []
        targets = [
            str(self.path("/var/lib/drlink")),
            str(self.path("/etc/frp")),
            str(self.path("/etc/drlink")),
            str(self.root),
        ]
        if shutil.which("df"):
            for target in targets:
                if not Path(target).exists():
                    continue
                rc, out, err = run_cmd(["df", "-h", target], timeout=5)
                chunks.append("$ df -h %s" % target)
                chunks.append(out.strip() or err.strip() or ("exit=%s" % rc))
                chunks.append("")
        self.stage_write("disk.txt", "\n".join(chunks) + "\n" if chunks else "disk info unavailable\n")
        self.add_section("disk")

    def _write_access_control(self) -> None:
        data, err = self.safe_read_json("/var/lib/drlink/access-control.json")
        if data is None:
            self.skip("access-control", err or "not present")
            return
        lists = (data or {}).get("access_lists") or {}
        service_access = (data or {}).get("service_access") or {}
        summary = {
            "schema_version": (data or {}).get("schema_version"),
            "access_list_count": len(lists) if isinstance(lists, dict) else 0,
            "access_lists": {},
            "service_access_bindings": len(service_access) if isinstance(service_access, dict) else 0,
            "service_access": sanitize_json_value(service_access),
        }
        if isinstance(lists, dict):
            for name, entry in lists.items():
                if not isinstance(entry, dict):
                    summary["access_lists"][str(name)] = {"present": True}
                    continue
                entries = entry.get("entries") or []
                summary["access_lists"][str(name)] = {
                    "entry_count": len(entries) if isinstance(entries, list) else 0,
                    "entries": sanitize_json_value(entries),
                    "description": entry.get("description"),
                }
        self.stage_json("access-control-summary.json", summary)
        self.add_section("access-control")

    def _health_entries_from_services(
        self, services: Any, *, source: str, client_id: Optional[str] = None
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if not isinstance(services, dict):
            return out
        for sid, svc in services.items():
            if not isinstance(svc, dict):
                continue
            hc = svc.get("health_check")
            if not isinstance(hc, dict) or not hc:
                continue
            local_ip = svc.get("local_ip") or "127.0.0.1"
            local_port = svc.get("local_port")
            target = None
            if local_port is not None and str(local_port) != "":
                target = "%s:%s" % (local_ip, local_port)
            key = str(sid) if client_id is None else "%s/%s" % (client_id, sid)
            out[key] = {
                "source": source,
                "service_id": str(sid),
                "health_check": sanitize_json_value(hc),
                "remote_port": svc.get("remote_port"),
                "target": target,
                "enabled": svc.get("enabled", True),
            }
            if client_id is not None:
                out[key]["client_id"] = client_id
        return out

    def _write_target_health_optional(self) -> None:
        """Build Target Health from services[*].health_check in client/registry state."""
        services_out: Dict[str, Any] = {}

        state, _err = self.safe_read_json("/etc/frp/client-state.json")
        if isinstance(state, dict):
            services_out.update(
                self._health_entries_from_services(
                    state.get("services"), source="client-state"
                )
            )

        if self.role in ("server", "dual", "partial_server"):
            registry, _rerr = self.safe_read_json("/var/lib/drlink/registry.json")
            clients = (registry or {}).get("clients") if isinstance(registry, dict) else None
            if isinstance(clients, dict):
                for mid, client in clients.items():
                    if not isinstance(client, dict):
                        continue
                    services_out.update(
                        self._health_entries_from_services(
                            client.get("services"),
                            source="registry",
                            client_id=str(mid),
                        )
                    )

        if services_out:
            self.stage_json(
                "target-health/from-state.json",
                {"services": services_out},
            )
            self.add_section("target-health")
            self.note_redaction("target-health built from state health_check fields")
        else:
            self.skip("target-health", "no health_check in state")

    def _write_manifest(self) -> None:
        payload = {
            "format": FORMAT,
            "schema_version": SCHEMA_VERSION,
            "role": self.role,
            "sections": list(self.sections),
            "skipped": list(self.skipped),
            "redaction_summary": list(self.redactions),
            "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        }
        self.stage_json("manifest.json", payload)
        self.add_section("manifest")


def _add_tree_to_tar(archive: tarfile.TarFile, stage: Path) -> None:
    """Add files from stage; refuse symlink members."""
    for path in sorted(stage.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink():
            fail("refusing to archive symlink member: %s" % path)
        if not path.is_file():
            continue
        rel = path.relative_to(stage).as_posix()
        if ".." in Path(rel).parts:
            fail("refusing path traversal in archive member: %s" % rel)
        archive.add(path, arcname=rel, recursive=False)


def create_support_bundle(root: Path, output: Path, *, secure_parent: bool) -> Dict[str, Any]:
    parent = output.parent
    if secure_parent:
        parent.mkdir(parents=True, exist_ok=True)
        if _is_symlink(parent):
            fail("refusing to write through a symlink parent directory")
        os.chmod(parent, 0o700)
        if os.geteuid() == 0:
            try:
                os.chown(parent, 0, 0)
            except OSError:
                pass
    else:
        if not parent.is_dir() or _is_symlink(parent):
            fail("output parent directory does not exist")
    if _lexists(output) and _is_symlink(output):
        fail("refusing to overwrite a symlink")
    if _lexists(output) and not output.is_file():
        fail("output must be a regular file path")

    builder = BundleBuilder(root)
    stage = builder.collect()
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".frp-support-", suffix=".tar.gz", dir=str(parent))
        os.close(fd)
        temp_archive = Path(temp_name)
        try:
            os.chmod(temp_archive, 0o600)
            with tarfile.open(temp_archive, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                _add_tree_to_tar(archive, stage)
            os.chmod(temp_archive, 0o600)
            os.replace(temp_archive, output)
            os.chmod(output, 0o600)
        finally:
            if temp_archive.exists():
                try:
                    temp_archive.unlink()
                except OSError:
                    pass
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    size = output.stat().st_size if output.is_file() else 0
    return {
        "path": str(output),
        "size": size,
        "sections": builder.sections,
        "skipped": builder.skipped,
        "redaction_summary": builder.redactions,
        "role": builder.role,
        "role_label": builder.role_label,
    }


def default_output_path(root: Path) -> Path:
    stamp = now_utc_stamp()
    name = "frp-support-%s-%s.tar.gz" % (safe_hostname(), stamp)
    return root / "var/lib/drlink/support-bundles" / name


def print_summary(result: Dict[str, Any]) -> None:
    size = int(result.get("size") or 0)
    if size >= 1024 * 1024:
        size_h = "%.1f MiB" % (size / (1024 * 1024))
    elif size >= 1024:
        size_h = "%.1f KiB" % (size / 1024)
    else:
        size_h = "%d B" % size
    print("Support bundle created")
    print("  path     : %s" % result.get("path"))
    print("  size     : %s (%d bytes)" % (size_h, size))
    print("  role     : %s" % (result.get("role_label") or result.get("role")))
    sections = result.get("sections") or []
    print("  sections : %s" % (", ".join(sections) if sections else "(none)"))
    redactions = result.get("redaction_summary") or []
    if redactions:
        print("  redaction:")
        for item in redactions:
            print("    - %s" % item)
    else:
        print("  redaction: none recorded (no secret-bearing sources found)")
    skipped = result.get("skipped") or []
    if skipped:
        print("  skipped  :")
        for item in skipped:
            print("    - %s" % item)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="frp-support-bundle",
        description="Create a sanitized read-only Data Relay Link support bundle.",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="PATH",
        help="Output .tar.gz path (default: /var/lib/drlink/support-bundles/...)",
    )
    parser.add_argument(
        "--root",
        default="",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    test_root = os.environ.get("FRP_DEPLOY_TEST_ROOT", "") or args.root
    if os.geteuid() != 0 and not test_root:
        fail("run with sudo")
    root = Path(test_root or "/")
    if args.output:
        output = validate_output_path(args.output)
        parent = output.parent
        if not parent.is_dir() or _is_symlink(parent):
            fail("output parent directory does not exist")
        result = create_support_bundle(root, output, secure_parent=False)
    else:
        output = default_output_path(root)
        # In test roots, ensure parent exists with secure mode.
        result = create_support_bundle(root, output, secure_parent=True)
    print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
