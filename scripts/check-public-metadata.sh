#!/usr/bin/env bash
# Public documentation operational-metadata scan.
# Scope: docs/ + top-level user-facing markdown. Does not hardcode live lab IPs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - "$ROOT" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
targets = []
for base in (root / "docs",):
    if base.is_dir():
        targets.extend(sorted(base.rglob("*.md")))
for name in ("README.md", "GITHUB_SETUP.md", "CHANGELOG.md"):
    p = root / name
    if p.is_file():
        targets.append(p)

# RFC 5737 documentation nets + localhost/link-local/private are allowed.
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
    if a >= 224:  # multicast / reserved — ignore
        return True
    return False

ipv4_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
# 32-hex CLIENT ID style literals (exclude markdown anchors / git SHAs in code fences loosely)
client_id_re = re.compile(r"\b[0-9a-f]{32}\b")
fingerprint_re = re.compile(r"SHA256:[A-Za-z0-9+/]{20,}={0,2}|\b(?:MD5|SHA256):(?:[0-9a-f]{2}:){7,}[0-9a-f]{2}\b", re.I)

live_ip = []
live_cid = []
live_fp = []
# Allowlisted documentation placeholders / examples
allow_cid = {
    "00112233445566778899aabbccddeeff",
    "aabbccdd00112233445566778899aabb",
    "24cd7856000000000000000000000000",
}

for path in targets:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root))
    for m in ipv4_re.finditer(text):
        ip = m.group(0)
        if not is_doc_or_nonpublic(ip):
            live_ip.append(f"{rel}:{ip}")
    # Skip CHANGELOG historical notes for 32-hex? Still scan docs primarily.
    if path.parent.name == "docs" or path.name in ("README.md", "GITHUB_SETUP.md"):
        for m in client_id_re.finditer(text):
            cid = m.group(0)
            if cid in allow_cid:
                continue
            # Ignore git-like mentions inside long hex only when labeled sha
            line_start = text.rfind("\n", 0, m.start()) + 1
            line = text[line_start:text.find("\n", m.start())]
            if re.search(r"\b(sha|commit|checksum|digest)\b", line, re.I):
                continue
            live_cid.append(f"{rel}:{cid}")
        for m in fingerprint_re.finditer(text):
            live_fp.append(f"{rel}:{m.group(0)[:48]}")

print("PUBLIC_DOC_LIVE_IPV4=%d" % len(live_ip))
print("PUBLIC_DOC_LIVE_CLIENT_IDS=%d" % len(live_cid))
print("PUBLIC_DOC_LIVE_SSH_FINGERPRINTS=%d" % len(live_fp))
for row in live_ip[:20]:
    print("LIVE_IPV4", row)
for row in live_cid[:20]:
    print("LIVE_CLIENT_ID", row)
for row in live_fp[:20]:
    print("LIVE_FINGERPRINT", row)
if live_ip or live_fp:
    # CLIENT IDs in historical docs may be truncated examples; treat full
    # public IPv4 + fingerprints as hard failures.
    raise SystemExit(1)
if live_cid:
    # Soft: report but fail so operators scrub operational checklists.
    raise SystemExit(1)
print("PUBLIC_METADATA_SCAN=PASS")
PY

pass "PUBLIC_METADATA_SCAN"
