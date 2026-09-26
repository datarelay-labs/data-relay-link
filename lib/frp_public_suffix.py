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


def idna_ascii(name: str) -> Optional[str]:
    """Return the lowercase IDNA/punycode ASCII form of a dotted name.

    Returns None when the name cannot be represented in IDNA ASCII. Labels that
    are already ASCII are lowercased without running the codec so entries the
    stdlib codec rejects (long or otherwise unusual ASCII labels) survive.
    """
    text = str(name or "").strip().lower().rstrip(".")
    if not text:
        return None
    out = []
    for label in text.split("."):
        if not label:
            return None
        try:
            label.encode("ascii")
        except UnicodeEncodeError:
            try:
                label = label.encode("idna").decode("ascii").lower()
            except (UnicodeError, ValueError):
                return None
        out.append(label)
    return ".".join(out)


def _add_rule(dest: set[str], rule: str) -> None:
    """Store a PSL rule in both its literal and IDNA-ASCII forms.

    The list ships Unicode entries (e.g. ``公司.cn``) while policy hostnames are
    IDNA-canonicalized before lookup, so a Unicode-only rule would let
    ``*.xn--55qx5d.cn`` slip past the public-suffix wildcard guard.
    """
    dest.add(rule)
    ascii_form = idna_ascii(rule)
    if ascii_form:
        dest.add(ascii_form)


def _parse_psl(text: str) -> tuple[set[str], set[str], set[str]]:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.lower()
        if rule.startswith("!"):
            _add_rule(exception, rule[1:])
            continue
        if rule.startswith("*."):
            _add_rule(wildcard, rule[2:])
            continue
        _add_rule(exact, rule)
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


def _name_forms(name: str) -> list[str]:
    """Literal and IDNA-ASCII spellings of a name, so either matches a rule."""
    forms = [name]
    ascii_form = idna_ascii(name)
    if ascii_form and ascii_form != name:
        forms.append(ascii_form)
    return forms


def is_public_suffix(domain: str) -> bool:
    """Return True if domain is itself a public suffix (e.g. com, co.uk, github.io)."""
    exact, wildcard, exception = load_psl()
    name = str(domain or "").strip().lower().rstrip(".")
    if not name:
        return False
    forms = _name_forms(name)
    if any(form in exception for form in forms):
        return False
    if any(form in exact for form in forms):
        return True
    # Wildcard PSL rules: *.ck means label.ck is a public suffix.
    for form in forms:
        labels = form.split(".")
        if len(labels) < 2:
            continue
        parent = ".".join(labels[1:])
        if any(candidate in wildcard for candidate in _name_forms(parent)):
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
