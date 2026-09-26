#!/usr/bin/env python3
"""Fail if obsolete public CLI grammar leaks outside allowed legacy sections.

Scans README / key docs (code fences + command-like lines) and live help
surfaces. Explicitly marked legacy / historical / compatibility blocks are
allowed to mention old forms. Menu labels like "Add client" are not CLI.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DOC_FILES = [
    ROOT / "README.md",
    ROOT / "docs" / "CLI_REFERENCE.md",
    ROOT / "docs" / "PRODUCT_MASTER.md",
    ROOT / "docs" / "CONTROLLED_EGRESS.md",
    ROOT / "docs" / "SECURITY.md",
    ROOT / "docs" / "FRP_UPGRADE.md",
    ROOT / "docs" / "OCI_ACCEPTANCE.md",
    ROOT / "docs" / "Data Relay Link CLI Information Architecture.md",
]

# Obsolete forms that must not be taught as current public commands.
OBSOLETE_CMD = re.compile(
    r"(?ix)"
    r"(?:^|\n)\s*(?:\$\s*)?(?:sudo\s+)?(?:drlink(?:>|\s+))?"
    r"(?:"
    r"create\s+zero-touch|"
    r"create\s+enrollment|"
    r"create\s+service-profile|"
    r"create\s+egress[\w-]*|"
    r"add\s+client\b|"
    r"remove\s+client\b|"
    r"add\s+egress[\w-]*|"
    r"remove\s+egress[\w-]*|"
    r"enable\s+egress[\w-]*|"
    r"disable\s+egress[\w-]*|"
    r"delete\s+egress[\w-]*|"
    r"set\s+access-assign\b|"
    r"set\s+access-public\b|"
    r"delete\s+access-list\b|"
    r"delete\s+service-profile\b|"
    r"import\s+egress\b|"
    r"export\s+egress\b|"
    r"diff\s+egress\b|"
    r"server\s+upstream\b|"
    r"show\s+upstream\b|"
    r"update\s+product\s+--check\b|"
    r"update\s+engine\s+--check\b"
    r")"
    r"(?:\s+\S+)*"
    r"\s*$"
)

# Bare root commands that must not be advertised (exact command lines only).
OBSOLETE_ROOT_ONLY = re.compile(
    r"(?ix)(?:^|\n)\s*(?:\$\s*)?(?:sudo\s+)?(?:drlink(?:>|\s+)?)?(?:doctor|history|clear)\s*$"
)

OBSOLETE_INLINE = re.compile(
    r"(?ix)`(?:sudo\s+)?(?:drlink\s+)?"
    r"(?:"
    r"create\s+zero-touch|"
    r"create\s+enrollment|"
    r"create\s+service-profile|"
    r"add\s+egress[\w-]*|"
    r"enable\s+egress[\w-]*|"
    r"disable\s+egress[\w-]*|"
    r"create\s+egress[\w-]*|"
    r"delete\s+egress[\w-]*|"
    r"set\s+access-assign|"
    r"set\s+access-public|"
    r"delete\s+access-list|"
    r"delete\s+service-profile|"
    r"server\s+upstream|"
    r"show\s+upstream|"
    r"update\s+product\s+--check|"
    r"update\s+engine\s+--check|"
    r"drlink\s+access\b|"
    r"(?<!system\s)doctor"
    r")`"
)

LEGACY_MARKERS = (
    "help legacy",
    "legacy compatibility",
    "hidden compatibility",
    "compatibility alias",
    "historical",
    "migration",
    "not the advertised",
    "not current public",
    "future candidate",
    "older resource-first",
    "older `egress",
    "older egress",
    "internal implementation",
    "internal completion",
    "internal entrypoint",
    "may still run as hidden",
    "there is no public",
    "no public `",
    "do not use",
    "forbidden",
)


def _allowed(text: str, start: int) -> bool:
    window = text[max(0, start - 280) : min(len(text), start + 120)].lower()
    return any(m in window for m in LEGACY_MARKERS)


def _iter_fenced_blocks(text: str):
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("```"):
            start = i
            i += 1
            body = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            end = i
            preamble = "".join(lines[max(0, start - 6) : start]).lower()
            yield preamble, "".join(body)
            i = end + 1
            continue
        i += 1


def scan_doc(label: str, text: str, failures: list[str]) -> None:
    for preamble, body in _iter_fenced_blocks(text):
        if any(m in preamble or m in body.lower() for m in LEGACY_MARKERS):
            continue
        # Skip non-CLI fences (tables of feature names, Korean prose blocks, etc.)
        if not re.search(
            r"(?m)^\s*(?:\$\s*)?(?:sudo\s+)?(?:drlink(?:>|\s+)?)?(?:show|set|unset|test|system|create|add|remove|enable|disable|delete|import|export|diff|server|doctor|history|clear)\b",
            body,
        ):
            continue
        for m in list(OBSOLETE_CMD.finditer("\n" + body)) + list(
            OBSOLETE_ROOT_ONLY.finditer("\n" + body)
        ):
            if _allowed(preamble + body, 0):
                continue
            hit = m.group(0).strip()
            failures.append("%s fence: %r" % (label, hit))
    for m in OBSOLETE_INLINE.finditer(text):
        if _allowed(text, m.start()):
            continue
        failures.append("%s inline: %r" % (label, m.group(0)))
    # Conceptual stale claims
    if re.search(r"(?i)direct command resource remains access-list", text):
        if not _allowed(text, text.lower().find("access-list")):
            failures.append("%s: claims direct resource remains access-list" % label)
    if re.search(r"(?i)named reusable access lists|named access lists", text):
        if "legacy" not in text.lower() and "historical" not in text.lower():
            # allow if only under clearly marked legacy sections via nearby markers
            for m in re.finditer(r"(?i)named(?:\s+reusable)?\s+access\s+lists?", text):
                if not _allowed(text, m.start()):
                    failures.append("%s: Named Access Lists as current vocab near %r" % (label, m.group(0)))
                    break


def scan_help(label: str, text: str, failures: list[str]) -> None:
    if not text:
        return
    # help legacy intentionally lists old forms
    if label.startswith("help_legacy"):
        return
    low = text.lower()
    banned_help = [
        "create zero-touch",
        "create enrollment",
        "create service-profile",
        "add egress",
        "enable egress",
        "disable egress",
        "create egress",
        "delete egress",
        "set access-assign",
        "set access-public",
        "delete access-list",
        "show upstream",
        "server upstream",
        "named access list",
        "drlink access",
        "\ndoctor\n",
        "\nhistory\n",
        "\nclear\n",
        "show egress",
        "show egress-profiles",
    ]
    for item in banned_help:
        idx = low.find(item)
        if idx < 0:
            continue
        if _allowed(text, idx):
            continue
        failures.append("%s help leaked %r" % (label, item.strip()))


def load_mod(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    failures: list[str] = []
    for path in DOC_FILES:
        if not path.is_file():
            failures.append("missing %s" % path)
            continue
        scan_doc(str(path.relative_to(ROOT)), path.read_text(encoding="utf-8"), failures)

    catalog = load_mod("frp_cli_catalog", "lib/frp_cli_catalog.py")
    grammar = load_mod("frp_ctl_grammar", "lib/frp_ctl_grammar.py")
    for role in ("server", "client", "both"):
        for label, text in (
            ("root_help:%s" % role, catalog.root_help(role)),
            ("concise_root:%s" % role, catalog.concise_root(role)),
            ("workflow_help:%s" % role, catalog.workflow_help(role)),
            ("domain_clients:%s" % role, catalog.domain_help("clients", role) or ""),
            ("domain_services:%s" % role, catalog.domain_help("services", role) or ""),
            ("domain_internet:%s" % role, catalog.domain_help("internet", role) or ""),
            ("domain_system:%s" % role, catalog.domain_help("system", role) or ""),
            ("commands_help:%s" % role, catalog.commands_help(role)),
            ("shell_usage:%s" % role, "\n".join(catalog.shell_usage_lines(role))),
            ("help_text:%s" % role, grammar.help_text([], role) or ""),
            ("unset_client_q:%s" % role, grammar.context_help(["unset", "client"], role) or ""),
            ("system_update_q:%s" % role, grammar.context_help(["system", "update"], role) or ""),
        ):
            scan_help(label, text, failures)

    # Public command metadata must not teach backend --options.
    flag_leak = re.compile(
        r"(?i)(--protocol|--ttl|--yes|--force|--preset|--target-host|--target-port)\b"
    )
    for cmd in catalog.COMMANDS:
        if cmd.get("hidden"):
            continue
        blob = "\n".join(
            [
                str(cmd.get("summary") or ""),
                str(cmd.get("detail") or ""),
                "\n".join(cmd.get("examples") or ()),
                catalog.command_help(cmd),
            ]
        )
        for m in flag_leak.finditer(blob):
            if _allowed(blob, m.start()):
                continue
            failures.append(
                "public cmd %s leaked %r" % (" ".join(cmd["path"]), m.group(1))
            )

    # Normal composed help must not advertise hidden roots/aliases.
    bare_help = grammar.help_text([], "server") or ""
    for bad in ("\ncreate\n", "\ndoctor\n", "\nhistory\n", "\nclear\n", "exit, quit", "quit, q"):
        if bad.lower() in bare_help.lower():
            failures.append("normal help leaked hidden form near %r" % bad.strip())

    unset_q = grammar.context_help(["unset", "client"], "server") or ""
    for needle in (
        "unset client <CLIENT> trust",
        "unset client <CLIENT> service <SERVICE>",
        "unset client <CLIENT>",
    ):
        if needle not in unset_q:
            failures.append("unset client ? missing %r" % needle)

    upd_q = grammar.context_help(["system", "update"], "server") or ""
    for needle in ("product", "engine", "check-engine"):
        if needle not in upd_q:
            failures.append("system update ? missing %r" % needle)

    roots = grammar.completion_candidates("", "server", [], {}, [], trailing=False)
    expected = ["show", "set", "unset", "test", "system", "menu", "help", "exit"]
    if roots != expected:
        failures.append("public roots got %r expected %r" % (roots, expected))

    after_client = grammar.completion_candidates(
        "unset client 24cd7856 ",
        "server",
        ["24cd7856"],
        {"24cd7856": ["ssh"]},
        [],
        trailing=True,
    )
    if "ssh" in after_client:
        failures.append("ambiguous Tab service id still offered: %r" % after_client)
    for need in ("trust", "service"):
        if need not in after_client:
            failures.append("Tab after unset client <ID> missing %r in %r" % (need, after_client))

    update_tab = grammar.completion_candidates(
        "system update ", "server", [], {}, [], trailing=True
    )
    for need in ("product", "engine", "check-engine"):
        if need not in update_tab:
            failures.append("system update <Tab> missing %r in %r" % (need, update_tab))

    if failures:
        print("PUBLIC_CLI_GRAMMAR_PARITY=FAIL")
        for item in failures[:50]:
            print(" -", item)
        if len(failures) > 50:
            print(" - ... and %d more" % (len(failures) - 50))
        return 1
    print("PUBLIC_CLI_GRAMMAR_PARITY=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
