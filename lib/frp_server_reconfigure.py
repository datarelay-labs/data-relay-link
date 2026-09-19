#!/usr/bin/env python3
"""Guided server public-endpoint reconfiguration (no secrets / no token rotation)."""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def text(value, default=""):
    return str(value or "").strip() or default


def prompt(label, default=""):
    suffix = " [%s]" % default if default else ""
    try:
        raw = input("%s%s: " % (label, suffix))
    except EOFError as exc:
        raise SystemExit(1) from exc
    raw = raw.strip()
    return raw if raw else default


def valid_https(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.scheme.lower() == "https" and bool(parsed.hostname)


def url_host(url):
    parsed = urlparse(url)
    return parsed.hostname or ""


def format_url(host, port, path="/enroll"):
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    if str(port) in ("443", ""):
        return "https://%s%s" % (host, path)
    return "https://%s:%s%s" % (host, port, path)


def client_count(reg_path: Path) -> int:
    if not reg_path.is_file():
        return 0
    try:
        data = json.loads(reg_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    clients = data.get("clients") if isinstance(data, dict) else None
    return len(clients) if isinstance(clients, dict) else 0


def load_pki(pki_py: Path | None):
    if not pki_py or not pki_py.is_file():
        return None
    spec = importlib.util.spec_from_file_location("frp_pki", str(pki_py))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_reconfigure(cfg_path: Path, reg_path: Path, pki_dir: Path, pki_py: Path | None, test_root: str = "") -> int:
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict):
        raise SystemExit("ERROR: server config.json is invalid")

    cur_ip = text(cfg.get("public_ip") or cfg.get("public_host"))
    cur_host = text(cfg.get("public_hostname"))
    cur_alloc = text(cfg.get("allocator_public_url"))
    alloc_port = cfg.get("allocator_public_port") or cfg.get("allocator_port") or 6099
    try:
        parsed_port = urlparse(cur_alloc).port
        if parsed_port:
            alloc_port = parsed_port
    except Exception:
        pass

    print()
    print("Server Public Endpoint")
    print("======================")
    print()
    print("Current:")
    print("  Public IP       : %s" % (cur_ip or "-"))
    print("  Public hostname : %s" % (cur_host or "-"))
    print("  Allocator URL   : %s" % (cur_alloc or "-"))
    print()

    new_ip = prompt("New public IP", cur_ip)
    new_host = prompt("New public hostname", cur_host)

    default_alloc_host = new_host or new_ip or cur_ip
    default_alloc = format_url(default_alloc_host, alloc_port, "/enroll") if default_alloc_host else cur_alloc
    if cur_alloc and cur_host and new_host and cur_host != new_host:
        try:
            parsed = urlparse(cur_alloc)
            if (parsed.hostname or "") == cur_host:
                default_alloc = format_url(new_host, parsed.port or alloc_port, parsed.path or "/enroll")
        except Exception:
            pass
    new_alloc = prompt("Allocator URL", default_alloc or cur_alloc)

    if not new_ip:
        raise SystemExit("ERROR: Public IP is required.")
    if not valid_https(new_alloc):
        raise SystemExit("ERROR: Allocator URL must be a valid https:// URL.")
    try:
        ipaddress.ip_address(new_ip)
    except ValueError as exc:
        raise SystemExit("ERROR: Public IP must be an IPv4 or IPv6 address.") from exc
    if new_host and not HOSTNAME_RE.match(new_host):
        raise SystemExit("ERROR: Public hostname is invalid.")

    ip_changed = new_ip != cur_ip
    host_changed = new_host != cur_host
    alloc_changed = new_alloc != cur_alloc
    tls_needed = host_changed or alloc_changed or ip_changed

    if not (ip_changed or host_changed or alloc_changed):
        print()
        print("No changes.")
        return 0

    if ip_changed and client_count(reg_path) > 0:
        raise SystemExit(
            "ERROR: Public IP cannot be changed while registered clients exist."
        )

    print()
    print("Changes")
    print("-------")
    print("Public IP       : %s" % ("unchanged" if not ip_changed else "%s -> %s" % (cur_ip, new_ip)))
    print(
        "Public hostname : %s"
        % ("unchanged" if not host_changed else "%s -> %s" % (cur_host or "(none)", new_host or "(none)"))
    )
    print("Allocator URL   : %s" % ("unchanged" if not alloc_changed else "%s -> %s" % (cur_alloc, new_alloc)))
    if tls_needed:
        san_host = url_host(new_alloc) or new_host or new_ip
        print("TLS certificate : regenerate for %s" % san_host)
    print()
    confirm = prompt("Apply? [y/N]", "N").lower()
    if confirm not in ("y", "yes"):
        print("Cancelled.")
        return 0

    cfg["public_ip"] = new_ip
    cfg["public_host"] = new_ip
    if new_host:
        cfg["public_hostname"] = new_host
    else:
        cfg.pop("public_hostname", None)
    cfg["allocator_public_url"] = new_alloc

    tmp = cfg_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    tmp.replace(cfg_path)

    tls_action = "skipped"
    mod = load_pki(pki_py)
    if tls_needed and mod is not None and pki_dir.is_dir():
        extra = []
        uh = url_host(new_alloc)
        if uh and uh != new_ip:
            extra.append(uh)
        if new_host and new_host not in extra and new_host != new_ip:
            extra.append(new_host)
        result = mod.ensure_pki(str(pki_dir), new_ip, extra)
        tls_action = result.get("action") or "updated"

    restarted = False
    if not test_root and shutil.which("systemctl"):
        for unit in ("frp-port-allocator", "frp-frontend"):
            try:
                rc = subprocess.run(
                    ["systemctl", "restart", unit],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )
                if rc.returncode == 0:
                    restarted = True
            except Exception:
                pass

    print()
    print("Public endpoint updated.")
    print("TLS certificate : %s" % tls_action)
    if restarted:
        print("Allocator       : restarted")
    elif tls_needed:
        print("Allocator       : restart manually if certificate/URL changed")
    print()
    print("Note: DNS is not changed automatically.")
    print("Client identities and FRP tokens were not rotated.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reconfigure FRP server public endpoint")
    parser.add_argument("--config", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--pki-py", default="")
    parser.add_argument("--test-root", default="")
    args = parser.parse_args(argv)
    return run_reconfigure(
        Path(args.config),
        Path(args.registry),
        Path(args.pki_dir),
        Path(args.pki_py) if args.pki_py else None,
        args.test_root or "",
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        pass
