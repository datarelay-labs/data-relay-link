"""Output extractors for cross-command consistency checks."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


SSH_RE = re.compile(
    r"ssh\s+(?:-p\s+(?P<port>\d+)\s+)?(?:(?P<user>[^\s@]+)@)?(?P<host>[A-Za-z0-9._\-]+)",
    re.I,
)
URL_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)(?::(\d+))?(/[^\s'\"]*)?", re.I)
PORT_HINT_RE = re.compile(
    r"(?:public\s+)?(?:port|endpoint)[^\d\n]{0,40}(?P<port>\d{2,5})",
    re.I,
)
ENDPOINT_RE = re.compile(
    r"(?P<host>[A-Za-z0-9._\-]+):(?P<port>\d{2,5})",
)
VERSION_RE = re.compile(
    r"(?P<display>\d+\.\d+\.\d+(?:-dev\+g[0-9a-f]+)?)",
    re.I,
)
SHA_RE = re.compile(r"\b(?P<sha>[0-9a-f]{40})\b", re.I)
GUIDANCE_RE = re.compile(
    r"(?im)^(?:Next:|Recommended action:|Use:|Run:|Try:)\s*(.+)$"
)
DRLINK_CMD_RE = re.compile(
    r"(?:sudo\s+)?drlink\s+(.+)$|^(show|set|unset|test|system|create|menu|help)\b.*$",
    re.I | re.M,
)


@dataclass
class EndpointFact:
    host: str
    port: int
    source: str = ""


@dataclass
class SshHint:
    host: str
    port: Optional[int]
    user: Optional[str]
    raw: str


def extract_ssh_hints(text: str) -> list[SshHint]:
    out: list[SshHint] = []
    for m in SSH_RE.finditer(text or ""):
        out.append(
            SshHint(
                host=m.group("host"),
                port=int(m.group("port")) if m.group("port") else None,
                user=m.group("user"),
                raw=m.group(0),
            )
        )
    return out


def extract_urls(text: str) -> list[tuple[str, Optional[int], str]]:
    out = []
    for m in URL_RE.finditer(text or ""):
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else None
        out.append((host, port, m.group(0)))
    return out


def extract_ports(text: str) -> list[int]:
    ports: list[int] = []
    for m in PORT_HINT_RE.finditer(text or ""):
        ports.append(int(m.group("port")))
    for m in ENDPOINT_RE.finditer(text or ""):
        ports.append(int(m.group("port")))
    # de-dupe preserve order
    seen = set()
    uniq = []
    for p in ports:
        if p not in seen and 1 <= p <= 65535:
            seen.add(p)
            uniq.append(p)
    return uniq


def extract_endpoints(text: str) -> list[EndpointFact]:
    facts: list[EndpointFact] = []
    for m in ENDPOINT_RE.finditer(text or ""):
        facts.append(EndpointFact(host=m.group("host"), port=int(m.group("port")), source=m.group(0)))
    return facts


def extract_version_display(text: str) -> Optional[str]:
    m = VERSION_RE.search(text or "")
    return m.group("display") if m else None


def extract_source_head(text: str) -> Optional[str]:
    m = SHA_RE.search(text or "")
    return m.group("sha") if m else None


def extract_guidance_lines(text: str) -> list[str]:
    return [m.group(1).strip() for m in GUIDANCE_RE.finditer(text or "")]


def extract_drlink_commands(text: str) -> list[str]:
    cmds: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip().lstrip(">").strip()
        if not s:
            continue
        # Strip leading prompt markers
        s = re.sub(r"^drlink>\s*", "", s)
        m = re.match(r"^(?:sudo\s+)?drlink\s+(.+)$", s, re.I)
        if m:
            cmds.append(m.group(1).strip())
            continue
        if re.match(r"^(show|set|unset|test|system|create|menu|help|\?)\b", s, re.I):
            cmds.append(s)
    # Also guidance lines that embed commands
    for g in extract_guidance_lines(text):
        m = re.match(r"^(?:sudo\s+)?drlink\s+(.+)$", g, re.I)
        if m:
            cmds.append(m.group(1).strip())
        elif re.match(r"^(show|set|unset|test|system|create)\b", g, re.I):
            cmds.append(g)
    # de-dupe
    seen = set()
    out = []
    for c in cmds:
        key = " ".join(c.split())
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def mentions_agent_host(text: str) -> bool:
    return "agent host" in (text or "").lower()


def mentions_private_host_leak(text: str, *, allowed_public: Optional[str] = None) -> list[str]:
    """Return suspicious hostnames that should not dominate public endpoint UX."""
    bad = []
    for host, _port, raw in extract_urls(text):
        h = host.lower()
        if allowed_public and h == allowed_public.lower():
            continue
        if h in ("drlink.local", "localhost", "127.0.0.1"):
            bad.append(raw)
    for ep in extract_endpoints(text):
        h = ep.host.lower()
        if allowed_public and h == allowed_public.lower():
            continue
        if h in ("drlink.local", "localhost"):
            bad.append(ep.source)
    return bad
