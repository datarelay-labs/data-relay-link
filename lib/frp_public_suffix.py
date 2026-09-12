#!/usr/bin/env python3
"""Public Suffix List helpers for Controlled Egress wildcard safety.

Source:
  https://publicsuffix.org/list/public_suffix_list.dat
License:
  Mozilla Public License, v. 2.0 (see list header)
Pinned snapshot:
  VERSION: 2026-09-08_12-18-37_UTC
  COMMIT: 3955e3ec29b94c3cca7bd4509c5f14a7c0959e26
  File: lib/data/public_suffix_list.dat

Update procedure:
  1. Download only from https://publicsuffix.org/list/public_suffix_list.dat
  2. Replace lib/data/public_suffix_list.dat
  3. Update VERSION/COMMIT in this module docstring and AUTHORS note
  4. Run tests/test-egress-control.py wildcard/PSL cases

Used at policy create/import/load — not per packet.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

PSL_VERSION = "2026-09-08_12-18-37_UTC"
PSL_COMMIT = "3955e3ec29b94c3cca7bd4509c5f14a7c0959e26"
PSL_SOURCE_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

_lock = threading.Lock()
_rules: Optional[tuple[set[str], set[str], set[str]]] = None  # (exact, wildcard, exception)


def _psl_path() -> Path:
    here = Path(__file__).resolve().parent
    return here / "data" / "public_suffix_list.dat"


def psl_metadata() -> dict:
    return {
        "version": PSL_VERSION,
        "commit": PSL_COMMIT,
        "source_url": PSL_SOURCE_URL,
        "path": str(_psl_path()),
        "loaded": _rules is not None,
    }


def _parse_psl(text: str) -> tuple[set[str], set[str], set[str]]:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        # Punycode / IDNA labels in the list are already ASCII for most entries.
        rule = line.lower()
        if rule.startswith("!"):
            exception.add(rule[1:])
            continue
        if rule.startswith("*."):
            wildcard.add(rule[2:])
            continue
        exact.add(rule)
    return exact, wildcard, exception


def load_psl(*, force: bool = False) -> tuple[set[str], set[str], set[str]]:
    global _rules
    with _lock:
        if _rules is not None and not force:
            return _rules
        path = _psl_path()
        if not path.is_file():
            raise FileNotFoundError("Public Suffix List missing: %s" % path)
        text = path.read_text(encoding="utf-8")
        _rules = _parse_psl(text)
        return _rules


def is_public_suffix(domain: str) -> bool:
    """Return True if domain is itself a public suffix (e.g. com, co.uk, github.io)."""
    exact, wildcard, exception = load_psl()
    name = str(domain or "").strip().lower().rstrip(".")
    if not name:
        return False
    if name in exception:
        return False
    if name in exact:
        return True
    # Wildcard PSL rules: *.ck means label.ck is a public suffix.
    labels = name.split(".")
    if len(labels) >= 2:
        parent = ".".join(labels[1:])
        if parent in wildcard:
            return True
    return False


def assert_wildcard_public_suffix_safe(policy_host: str) -> None:
    """Reject dangerous wildcards whose suffix is a public suffix.

    Examples rejected: *.com, *.net, *.co.uk, *.github.io
    Examples allowed: *.ubuntu.com, *.example.com (when example.com is not a PSL)
    """
    text = str(policy_host or "").strip().lower()
    if not text.startswith("*."):
        return
    suffix = text[2:]
    if not suffix:
        raise ValueError("invalid wildcard hostname")
    if is_public_suffix(suffix):
        raise ValueError(
            "wildcard destination suffix is a public suffix (too broad): %s" % text
        )
