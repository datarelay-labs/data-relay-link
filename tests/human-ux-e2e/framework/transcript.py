"""Transcript recording and secret sanitization."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

# One-time tickets, bootstrap packages, hex digests that look like secrets.
_SECRET_PATTERNS = [
    (re.compile(r"(/i/)[^/?\s#]+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(FRP_BOOTSTRAP_TICKET\s*=\s*)\S+", re.I), r"\1<REDACTED>"),
    (re.compile(r"\bbt1\.[A-Za-z0-9._-]{8,}\b"), "bt1.<REDACTED>"),
    (re.compile(r"\bzt1\.[A-Za-z0-9._-]{8,}\b"), "zt1.<REDACTED>"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-+=/]{8,}\b", re.I), "Bearer <REDACTED>"),
    (re.compile(r"(--token(?:=|\s+))\S+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(token=)[A-Za-z0-9._\-+=/]{8,}", re.I), r"\1<REDACTED>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "<PRIVATE_KEY_REDACTED>"),
    (re.compile(r"\b[a-f0-9]{64}\b"), "<HEX64_REDACTED>"),
]


def sanitize(text: str) -> str:
    out = text or ""
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


@dataclass
class TranscriptRecorder:
    scenario_id: str
    execution_context: str
    interaction_mode: str
    lines: List[str] = field(default_factory=list)

    def mark(self, label: str) -> None:
        self.lines.append("## %s" % label)

    def note(self, text: str) -> None:
        self.lines.append(sanitize(text.rstrip("\n")))

    def command(self, role: str, cmdline: str) -> None:
        self.lines.append("[%s] $ %s" % (role, sanitize(cmdline)))

    def output(self, text: str, *, stream: str = "stdout") -> None:
        body = sanitize(text.rstrip("\n"))
        if not body:
            self.lines.append("(%s empty)" % stream)
            return
        self.lines.append("--- %s ---" % stream)
        self.lines.append(body)

    def keys(self, description: str) -> None:
        self.lines.append("[keys] %s" % description)

    def render(self) -> str:
        header = [
            "SCENARIO=%s" % self.scenario_id,
            "EXECUTION_CONTEXT=%s" % self.execution_context,
            "INTERACTION_MODE=%s" % self.interaction_mode,
            "",
        ]
        return "\n".join(header + self.lines) + "\n"
