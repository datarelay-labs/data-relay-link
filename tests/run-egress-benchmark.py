#!/usr/bin/env python3
"""Reproducible Controlled Egress CONNECT benchmark harness (local / lab).

Does not claim production capacity. Records concurrent CONNECT setup latency
against a local origin + gateway under FRP_DEPLOY_TEST_ROOT sandboxing.

Usage:
  python3 tests/run-egress-benchmark.py [--concurrency 100] [--churn 0]
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _cpu_info() -> str:
    try:
        out = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
        for line in out.splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
        cores = sum(1 for line in out.splitlines() if line.lower().startswith("processor"))
        return "%s logical CPUs" % cores
    except OSError:
        return "unknown"


def _ram_mb() -> str:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return "%d" % (kb // 1024)
    except (OSError, ValueError, IndexError):
        pass
    return "unknown"


def _rss_mb() -> float:
    try:
        # Self RSS; caller may sample gateway PID separately.
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        return 0.0


def build_client_hello(hostname: str) -> bytes:
    # Minimal TLS 1.2 ClientHello with SNI (same shape as unit tests).
    host = hostname.encode("idna")
    ext_sni = b"\x00\x00" + (len(host) + 5).to_bytes(2, "big") + (len(host) + 3).to_bytes(
        2, "big"
    ) + b"\x00" + len(host).to_bytes(2, "big") + host
    extensions = ext_sni
    hello_body = (
        b"\x03\x03"
        + os.urandom(32)
        + b"\x00"
        + b"\x00\x02\x00\x2f"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--churn", type=int, default=0, help="new CONNECTs per second (0=skip)")
    parser.add_argument("--hold-ms", type=int, default=200)
    args = parser.parse_args()

    # Reuse the existing unit harness by invoking pytest-style module briefly is heavy;
    # instead shell out to a minimal inline gateway via test helpers when available.
    print("TEST_SERVER_CPU=%s" % _cpu_info())
    print("TEST_SERVER_RAM=%s" % _ram_mb())

    # Prefer dedicated scripted gateway if present; otherwise report NOT_RUN structure.
    helper = ROOT / "tests" / "test-egress-control.py"
    if not helper.is_file():
        print("PERFORMANCE_BENCHMARK=NOT_RUN")
        print("FAILURE_RATE=n/a")
        return 1

    # Lightweight: measure authorize+connect path via subprocess running unit bench section.
    env = os.environ.copy()
    env["DRLINK_EGRESS_BENCH"] = "1"
    env["DRLINK_EGRESS_BENCH_CONCURRENCY"] = str(args.concurrency)
    env["DRLINK_EGRESS_BENCH_HOLD_MS"] = str(args.hold_ms)
    env["DRLINK_EGRESS_BENCH_CHURN"] = str(args.churn)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "run-egress-benchmark-worker.py")],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        print("PERFORMANCE_BENCHMARK=FAIL")
        return proc.returncode
    print("PERFORMANCE_BENCHMARK=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
