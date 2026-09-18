#!/usr/bin/env python3
"""Run deterministic development-governance gates locally and in CI."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def run(label: str, command: list[str]) -> None:
    print(f"== {label} ==")
    proc = subprocess.run(command, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)

def require_files() -> None:
    required = (
        "governance/DEFINITION_OF_DONE.md",
        "governance/BRANCH_PROTECTION.md",
        "automation/governance/audit_architecture.py",
        "automation/tela_sync/render_canonical.py",
        ".github/workflows/governance.yml",
        ".github/workflows/security.yml",
        ".github/workflows/architecture-drift.yml",
        ".github/dependabot.yml",
        "scripts/configure-main-protection.sh",
        "scripts/configure-repository-security.sh",
    )
    missing = [p for p in required if not (ROOT / p).is_file()]
    if missing:
        raise SystemExit("GOVERNANCE_FILES_MISSING=" + ",".join(missing))

def check_tela_config() -> None:
    path = ROOT / "automation" / "tela_sync" / "config.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"project", "atlas_project_id", "space_id", "canonical_page_id", "canonical_page_title"}
    unexpected = set(data) - allowed
    sensitive = [k for k in data if re.search(r"(token|secret|key|password|credential)", k, re.I)]
    if unexpected or sensitive:
        raise SystemExit(
            f"TELA_CONFIG_UNSAFE unexpected={sorted(unexpected)} sensitive={sorted(sensitive)}"
        )
    print("TELA_CONFIG=PASS")

def check_new_workflow_pins() -> None:
    for name in ("governance.yml", "security.yml", "architecture-drift.yml"):
        path = ROOT / ".github" / "workflows" / name
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith("- uses:"):
                continue
            ref = stripped.split("@", 1)[1] if "@" in stripped else ""
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                raise SystemExit(f"UNPINNED_ACTION={path.relative_to(ROOT)}:{lineno}:{stripped}")
    print("WORKFLOW_ACTION_PINS=PASS")
def main() -> int:
    require_files()
    check_tela_config()
    check_new_workflow_pins()

    run("OpenSpec doctor", ["openspec", "doctor", "--json"])
    run("OpenSpec strict validation", ["openspec", "validate", "--all", "--strict"])
    run("Decision Capture tests", ["python3", "tests/test-decision-capture.py"])
    run("Tela knowledge tests", ["python3", "tests/test-tela-knowledge-sync.py"])
    run("Governance tests", ["python3", "tests/test-governance.py"])
    run("Canonical projection freshness",
        ["python3", "automation/tela_sync/render_canonical.py", "--check"])
    run("Repository secret scan", ["bash", "scripts/secret-scan.sh"])
    run("Blocking architecture drift",
        ["python3", "automation/governance/audit_architecture.py", "--blocking-only"])

    print("GOVERNANCE_DOD_AUTOMATIC=PASS")
    print("REAL_E2E=EVIDENCE_BASED")
    print("GOVERNANCE_STATUS=PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
