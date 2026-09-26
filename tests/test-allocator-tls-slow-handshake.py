#!/usr/bin/env python3
"""AUDIT-004: stalled ClientHello must not monopolize allocator accept.

Opens raw TCP connections that send no/partial ClientHello and hold the
socket open, then independently GETs /healthz over valid TLS. Healthz must
return 200 within a short bound even with several stalled peers.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import frp_pki  # noqa: E402

# Partial TLS ClientHello record header (incomplete length) — enough to start
# a handshake parse without completing it.
PARTIAL_CLIENT_HELLO = bytes(
    [
        0x16,  # handshake
        0x03,
        0x01,  # TLS 1.0 record version (common ClientHello wrapper)
        0x00,
        0x80,  # claims 128 bytes follow — we send far fewer
        0x01,  # HandshakeType client_hello
        0x00,
        0x00,
        0x7C,  # handshake length (incomplete payload below)
        0x03,
        0x03,  # client version TLS 1.2
    ]
)

STALLED_COUNT = 6
HEALTHZ_BOUND_SEC = 3.0
HOLD_SEC = 8.0


def pass_(name):
    print("PASS %s" % name)


def fail(name, detail=""):
    print("FAIL %s %s" % (name, detail), file=sys.stderr)
    raise SystemExit(1)


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def write_env(tmp, listen_port):
    pki_dir = Path(tmp) / "pki"
    result = frp_pki.ensure_pki(str(pki_dir), "127.0.0.1")
    cfg = {
        "public_host": "203.0.113.10",
        "public_ip": "203.0.113.10",
        "frp_control_public_port": 8443,
        "frp_control_listen_port": 443,
        "port_start": 19000,
        "port_end": 19010,
        "listen_host": "127.0.0.1",
        "listen_port": listen_port,
        "allocator_listen_port": listen_port,
        "allocator_public_port": listen_port,
        "tls_ca_cert": result["ca_crt"],
        "tls_server_cert": result["server_crt"],
        "tls_server_key": result["server_key"],
        "registry_file": str(Path(tmp) / "registry.json"),
        "enrollments_dir": str(Path(tmp) / "enrollments"),
        "token_file": str(Path(tmp) / "server_token"),
    }
    Path(cfg["enrollments_dir"]).mkdir(parents=True, exist_ok=True)
    Path(cfg["token_file"]).write_text("test-frp-token-do-not-use\n")
    os.chmod(cfg["token_file"], 0o600)
    Path(cfg["registry_file"]).write_text(
        json.dumps({"schema_version": 2, "reserved": [], "clients": {}}) + "\n"
    )
    cfg_path = Path(tmp) / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
    return cfg_path, result


def start_allocator(cfg_path):
    return subprocess.Popen(
        [sys.executable, str(ROOT / "server" / "frp-port-allocator.py"), "--config", str(cfg_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def stop_allocator(proc, timeout=5):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass


def wait_ready(url, ca, timeout=8.0):
    ctx = ssl.create_default_context(cafile=str(ca))
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=1) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last = exc
            time.sleep(0.05)
    raise RuntimeError("allocator not ready: %s" % last)


def get_healthz(url, ca, timeout):
    ctx = ssl.create_default_context(cafile=str(ca))
    with urllib.request.urlopen(url, context=ctx, timeout=timeout) as resp:
        return resp.status, resp.read()


def hold_stalled(host, port, partial, hold_sec, ready_event, done_event):
    socks = []
    try:
        for i in range(STALLED_COUNT):
            s = socket.create_connection((host, port), timeout=2)
            s.settimeout(None)
            if i % 2 == 0:
                # Completely silent peer (no ClientHello).
                pass
            else:
                s.sendall(partial)
            socks.append(s)
        ready_event.set()
        time.sleep(hold_sec)
    except Exception:
        ready_event.set()
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        done_event.set()


def main():
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        cfg, pki = write_env(tmp, port)
        url = "https://127.0.0.1:%d/healthz" % port
        proc = start_allocator(cfg)
        try:
            wait_ready(url, pki["ca_crt"])
            pass_("allocator ready before stall")

            ready = threading.Event()
            done = threading.Event()
            stall = threading.Thread(
                target=hold_stalled,
                args=("127.0.0.1", port, PARTIAL_CLIENT_HELLO, HOLD_SEC, ready, done),
                daemon=True,
            )
            stall.start()
            if not ready.wait(timeout=5):
                fail("stalled peers", "failed to open stalled sockets")

            # Give the server a moment to block on handshake if vulnerable.
            time.sleep(0.3)

            t0 = time.monotonic()
            try:
                status, body = get_healthz(url, pki["ca_crt"], timeout=HEALTHZ_BOUND_SEC)
            except Exception as exc:
                elapsed = time.monotonic() - t0
                fail(
                    "healthz under stalled ClientHello",
                    "elapsed=%.2fs bound=%.1fs error=%s" % (elapsed, HEALTHZ_BOUND_SEC, exc),
                )
            elapsed = time.monotonic() - t0
            if status != 200:
                fail("healthz status", "got %s body=%r" % (status, body[:200]))
            if elapsed > HEALTHZ_BOUND_SEC:
                fail(
                    "healthz latency",
                    "elapsed=%.2fs exceeds bound %.1fs" % (elapsed, HEALTHZ_BOUND_SEC),
                )
            pass_(
                "healthz 200 in %.2fs with %d stalled peers (bound %.1fs)"
                % (elapsed, STALLED_COUNT, HEALTHZ_BOUND_SEC)
            )
        finally:
            stop_allocator(proc)


if __name__ == "__main__":
    main()
