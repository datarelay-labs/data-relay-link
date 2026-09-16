#!/usr/bin/env bash
# Public repository operational-metadata scan.
#
# Distinguishes:
#   - safe documentation examples (RFC5737 / private / localhost)
#   - intentional test/lab defaults (env-overridable fixtures under tests/)
#   - unexpected leaked operational metadata in release-facing paths
#   - actual secrets (delegated to scripts/secret-scan.sh; not weakened here)
#
# Scope is intentionally broader than docs-only Markdown so release gates do not
# claim stronger coverage than they provide.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - "$ROOT" <<'PY'
import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])

# Release-facing / operator-facing paths always scanned hard.
HARD_GLOBS = (
    "docs/**/*.md",
    "README.md",
    "GITHUB_SETUP.md",
    "CHANGELOG.md",
    "packaging/**/*",
    "dist/**/*",
)

# Operational / test paths: scan for unexpected live metadata, but allow
# explicit lab fixtures declared via environment or known placeholder nets.
SOFT_GLOBS = (
    "tests/**/*.{sh,py,ps1,json,yml,yaml}",
    "scripts/**/*.{sh,py}",
    "*.sh",
    "lib/**/*.{sh,py}",
    "server/**/*.{sh,py,service}",
    "tools/**/*",
    "client/**/*",
    "windows/**/*",
    ".github/workflows/**/*.{yml,yaml}",
)

SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
}

# Lab defaults may be configured via environment (preferred over hardcoding).
LAB_ALLOW_IPV4 = {
    x.strip()
    for x in os.environ.get("FRP_PUBLIC_METADATA_LAB_IPV4", "").split(",")
    if x.strip()
}
# Documented historical lab fixtures that remain intentional in tests only.
# These must NEVER appear outside tests/scripts harness files.
TEST_ONLY_LAB_IPV4 = {
    "221.139.249.113",  # established Real E2E server fixture (env-overridable)
    "221.139.249.114",
    # The retired .110 lab address remains forbidden by secret-scan and must
    # never appear as a literal anywhere in the tracked tree.
}

def is_doc_or_nonpublic(ip: str) -> bool:
    parts = [int(x) for x in ip.split(".")]
    a, b = parts[0], parts[1]
    if ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113."):
        return True
    if a == 10 or a == 127 or a == 0:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a >= 224:
        return True
    # X.509 / ASN.1 OID dotted forms frequently match the IPv4 regex
    # (e.g. 2.5.29.17 SubjectAltName). These are not host addresses.
    if ip.startswith(("1.2.840.", "1.3.6.1.", "2.5.29.", "2.5.4.")):
        return True
    return False

ipv4_re = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
# IPv6 literals (compressed or full). Exclude pure hex without colons.
ipv6_re = re.compile(
    r"\b(?:(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})\b"
)
client_id_re = re.compile(r"\b[0-9a-f]{32}\b")
fingerprint_re = re.compile(
    r"SHA256:[A-Za-z0-9+/]{20,}={0,2}|\b(?:MD5|SHA256):(?:[0-9a-f]{2}:){7,}[0-9a-f]{2}\b",
    re.I,
)

allow_cid = {
    "00112233445566778899aabbccddeeff",
    "aabbccdd00112233445566778899aabb",
    "24cd7856000000000000000000000000",
}

def expand(patterns):
    out = []
    for pat in patterns:
        if "*" in pat or "?" in pat or "[" in pat:
            out.extend(sorted(root.glob(pat)))
        else:
            p = root / pat
            if p.is_file():
                out.append(p)
    return out

def classify_path(path: Path) -> str:
    rel = path.relative_to(root).as_posix()
    if rel.startswith("docs/") or path.name in ("README.md", "GITHUB_SETUP.md", "CHANGELOG.md"):
        return "hard"
    if rel.startswith("packaging/") or rel.startswith("dist/"):
        return "hard"
    if rel.startswith("tests/") or rel.startswith("scripts/"):
        return "soft"
    return "soft"

targets = []
seen = set()
for path in expand(HARD_GLOBS) + expand(SOFT_GLOBS):
    if not path.is_file():
        continue
    if any(part in SKIP_DIR_NAMES for part in path.parts):
        continue
    # Skip generated binary-ish or large checksums noise where needed
    if path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".gz", ".tgz", ".zip"}:
        continue
    key = path.resolve()
    if key in seen:
        continue
    seen.add(key)
    targets.append(path)

live_ip_hard = []
live_ip_soft_unexpected = []
live_ip_lab = []
live_cid = []
live_fp = []
ipv6_publicish = []

DOC_IPV6_PREFIXES = (
    "2001:db8:",  # documentation
    "fe80:",      # link-local
    "::1",
    "fc00:",
    "fd00:",
)

for path in targets:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    rel = path.relative_to(root).as_posix()
    bucket = classify_path(path)
    for m in ipv4_re.finditer(text):
        ip = m.group(0)
        if is_doc_or_nonpublic(ip):
            continue
        if ip in LAB_ALLOW_IPV4:
            live_ip_lab.append(f"{rel}:{ip}")
            continue
        if ip in TEST_ONLY_LAB_IPV4 and (rel.startswith("tests/") or rel.startswith("scripts/")):
            live_ip_lab.append(f"{rel}:{ip} (intentional-lab-fixture)")
            continue
        if bucket == "hard":
            live_ip_hard.append(f"{rel}:{ip}")
        else:
            # Soft paths: still fail on unexpected public IPv4 that is not an
            # intentional lab fixture — forces env-configured lab addresses.
            live_ip_soft_unexpected.append(f"{rel}:{ip}")
    for m in ipv6_re.finditer(text):
        lit = m.group(0)
        if any(lit.lower().startswith(p) or lit.lower() == p.rstrip(":") for p in DOC_IPV6_PREFIXES):
            continue
        # Ignore git SHAs mistaken via loose pattern by requiring >=2 colons.
        if lit.count(":") < 2:
            continue
        ipv6_publicish.append(f"{rel}:{lit}")
    if bucket == "hard":
        for m in client_id_re.finditer(text):
            cid = m.group(0)
            if cid in allow_cid:
                continue
            line_start = text.rfind("\n", 0, m.start()) + 1
            line = text[line_start:text.find("\n", m.start())]
            if re.search(r"\b(sha|commit|checksum|digest)\b", line, re.I):
                continue
            live_cid.append(f"{rel}:{cid}")
        for m in fingerprint_re.finditer(text):
            live_fp.append(f"{rel}:{m.group(0)[:48]}")

print("PUBLIC_DOC_LIVE_IPV4=%d" % len(live_ip_hard))
print("PUBLIC_SOFT_UNEXPECTED_IPV4=%d" % len(live_ip_soft_unexpected))
print("PUBLIC_LAB_FIXTURE_IPV4=%d" % len(live_ip_lab))
print("PUBLIC_DOC_LIVE_CLIENT_IDS=%d" % len(live_cid))
print("PUBLIC_DOC_LIVE_SSH_FINGERPRINTS=%d" % len(live_fp))
print("PUBLIC_NONDOC_IPV6_LITERALS=%d" % len(ipv6_publicish))
for row in live_ip_hard[:20]:
    print("LIVE_IPV4_HARD", row)
for row in live_ip_soft_unexpected[:30]:
    print("LIVE_IPV4_SOFT", row)
for row in live_ip_lab[:20]:
    print("LAB_IPV4", row)
for row in live_cid[:20]:
    print("LIVE_CLIENT_ID", row)
for row in live_fp[:20]:
    print("LIVE_FINGERPRINT", row)
for row in ipv6_publicish[:20]:
    print("LIVE_IPV6", row)

# Hard failures: docs/packaging/dist public IPv4, fingerprints.
if live_ip_hard or live_fp:
    raise SystemExit(1)
if live_cid:
    raise SystemExit(1)
# Soft unexpected public IPv4 outside declared lab fixtures fails the gate so
# operators migrate to FRP_PUBLIC_METADATA_LAB_IPV4 / env-configured labs.
if live_ip_soft_unexpected:
    raise SystemExit(1)
# Non-doc IPv6 literals that are not documentation/ULA/link-local fail closed.
# (Intentional lab IPv6 can be allowlisted later via env when needed.)
if ipv6_publicish:
    # Only fail when found in hard paths; soft paths report but currently warn
    # via exit if in docs/packaging already covered. Soft IPv6: fail to force review.
    raise SystemExit(1)
print("PUBLIC_METADATA_SCAN=PASS")
PY

pass "PUBLIC_METADATA_SCAN"
