#!/usr/bin/env python3
"""Shared Service ID generation for FRP Auto Deploy client UX.

Service IDs remain immutable once created. Operators normally never choose
one; this helper allocates the next free ID from committed + pending drafts.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional, Set

SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
SERVICE_ID_MAX = 32


def normalize_used_ids(ids: Optional[Iterable[str]] = None) -> Set[str]:
    out: Set[str] = set()
    for item in ids or []:
        text = str(item or "").strip().lower()
        if text:
            out.add(text)
    return out


def collect_used_ids(*maps_or_lists) -> Set[str]:
    """Union Service IDs from service maps (dict) or id lists."""
    used: Set[str] = set()
    for blob in maps_or_lists:
        if blob is None:
            continue
        if isinstance(blob, dict):
            for key in blob:
                text = str(key or "").strip().lower()
                if text:
                    used.add(text)
        else:
            used |= normalize_used_ids(blob)
    return used


def _truncate_base(base: str, suffix: str) -> str:
    """Ensure base + suffix fits SERVICE_ID_MAX and remains valid."""
    room = SERVICE_ID_MAX - len(suffix)
    if room < 1:
        # Extremely defensive: keep a minimal stem.
        room = 1
        suffix = suffix[-(SERVICE_ID_MAX - 1) :]
    stem = base[:room]
    while stem and not SERVICE_ID_RE.match(stem + suffix if suffix else stem):
        stem = stem[:-1]
    if not stem:
        stem = "svc"
        while len(stem) + len(suffix) > SERVICE_ID_MAX and len(stem) > 1:
            stem = stem[:-1]
    candidate = stem + suffix
    if not SERVICE_ID_RE.match(candidate):
        # Last resort: sanitize to safe characters.
        cleaned = re.sub(r"[^a-z0-9._-]", "-", candidate.lower())
        cleaned = cleaned.strip(".-_") or "svc"
        if cleaned[0] not in "abcdefghijklmnopqrstuvwxyz0123456789":
            cleaned = "s" + cleaned
        candidate = cleaned[:SERVICE_ID_MAX]
    return candidate


def base_service_id(preset: str, target_port: Optional[int] = None) -> str:
    """Return the unsuffixed base ID for a service type."""
    preset = str(preset or "custom").strip().lower()
    if preset in ("ssh", "http", "https"):
        return preset
    port = int(target_port) if target_port is not None else None
    if port is None or port < 1 or port > 65535:
        raise ValueError("target_port is required for custom services")
    return "tcp-%s" % port


def suggest_service_id(
    preset: str,
    used_ids: Optional[Iterable[str]] = None,
    target_port: Optional[int] = None,
) -> str:
    """Allocate the next free Service ID for preset (+ port for custom).

    Examples (empty used set):
      ssh -> ssh, http -> http, custom:3389 -> tcp-3389
    With ssh already used:
      next ssh -> ssh-2
    """
    used = normalize_used_ids(used_ids)
    base = base_service_id(preset, target_port=target_port)
    if base not in used and SERVICE_ID_RE.match(base):
        return base
    n = 2
    while True:
        suffix = "-%d" % n
        candidate = _truncate_base(base, suffix)
        if candidate not in used and SERVICE_ID_RE.match(candidate):
            return candidate
        n += 1
        if n > 10000:
            raise RuntimeError("unable to allocate a free service id")


def validate_service_id(sid: str) -> str:
    text = str(sid or "").strip().lower()
    if not SERVICE_ID_RE.match(text or ""):
        raise ValueError("invalid service id; use [a-z0-9][a-z0-9._-]{0,31}")
    return text


TARGET_HOST_HELP = (
    "Target host is the service machine as seen from this FRP client.\n"
    "\n"
    "Use:\n"
    "  127.0.0.1       service runs on this FRP client\n"
    "  192.168.x.x     another server reachable on the LAN\n"
    "  hostname        another resolvable internal host"
)


SERVICE_ADD_CONCEPT_HELP = """\
Add a published service
=======================

A service maps a public FRP port to a TCP target reachable
from this FRP client.

The target can be on this machine:

  127.0.0.1:22
  127.0.0.1:80

or another machine reachable from this client:

  192.168.10.20:22
  192.168.10.30:80

Available:

  ssh       SSH, default TCP/22
  http      HTTP, default TCP/80
  https     HTTPS, default TCP/443
  custom    Any TCP service
  profile   Start from a server Service Profile

Examples:

  service add ssh --ssh-user aella
  service add ssh --target-host 192.168.10.20 --ssh-user root
  service add http --target-host 192.168.10.30
  service add custom --target-host 192.168.10.40 --target-port 8080

Service IDs are generated automatically.

Public ports are allocated automatically when you run:

  service apply

To throw away pending changes:

  service discard
"""


def pending_change_footer(service_id: Optional[str] = None, *, added: bool = True) -> str:
    lines = []
    if service_id:
        if added:
            lines.append("Pending service '%s' added." % service_id)
        else:
            lines.append("Pending change saved.")
    else:
        lines.append("Pending change saved.")
    lines.extend(
        [
            "",
            "Apply:",
            "  service apply",
            "",
            "Discard:",
            "  service discard",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        raise SystemExit(2)
    action = sys.argv[1]
    if action == "suggest":
        preset = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] not in ("", "-") else None
        used = json.loads(sys.argv[4]) if len(sys.argv) > 4 else []
        print(suggest_service_id(preset, used_ids=used, target_port=port))
    elif action == "target-host-help":
        print(TARGET_HOST_HELP)
    elif action == "add-help":
        print(SERVICE_ADD_CONCEPT_HELP.rstrip())
    else:
        raise SystemExit(2)
