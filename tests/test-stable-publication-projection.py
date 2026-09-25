#!/usr/bin/env python3
"""Tag-time stable projection: no commit after the qualified provenance HEAD."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "scripts" / "project-stable-release.py"
BIND = ROOT / "scripts" / "check-release-attest-binding.py"
GIT_ENV = os.environ.copy()
GIT_ENV.update(
    {
        "GIT_AUTHOR_NAME": "projection-test",
        "GIT_AUTHOR_EMAIL": "projection-test@example.com",
        "GIT_COMMITTER_NAME": "projection-test",
        "GIT_COMMITTER_EMAIL": "projection-test@example.com",
    }
)


def fail(message: str) -> None:
    print("FAIL %s" % message, file=sys.stderr)
    raise SystemExit(1)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=GIT_ENV,
    )
    return proc.stdout.strip()


def write(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def manifest(git_ref: str, source_head: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "project_version": "1.2.3",
            "frp_version": "0.71.0",
            "channel": "development",
            "git_ref": git_ref,
            "source_head": source_head,
            "immutable_source_ref": git_ref,
            "features": {"mcp_included": True},
            "artifacts": {
                "bootstrap-client.sh": {
                    "path": "dist/bootstrap-client.sh",
                    "sha256": "ab" * 32,
                }
            },
        },
        indent=2,
    ) + "\n"


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, capture_output=True, text=True, env=GIT_ENV)


def evidence(head: str, **overrides: str) -> dict:
    data = {
        "status": "PASS",
        "pass1_head": head,
        "pass2_head": head,
        "final_qualified_head": head,
    }
    data.update(overrides)
    return data


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        git(repo, "init", "-b", "main")
        write(
            repo,
            "VERSION",
            "PROJECT_VERSION=1.2.3\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=development\n",
        )
        write(repo, "lib/product.sh", "echo product\n")
        write(repo, "release-manifest.json", manifest("0" * 40, "0" * 40))
        write(repo, "dist/bootstrap-client.sh", "echo payload\n")
        content = commit_all(repo, "content")
        write(repo, "release-manifest.json", manifest(content, content))
        write(repo, "dist/bootstrap-client.sh", "echo payload-stamped\n")
        provenance = commit_all(repo, "provenance")
        committed = (repo / "release-manifest.json").read_bytes()
        count = git(repo, "rev-list", "--count", "HEAD")
        outside = Path(tempfile.mkdtemp(prefix="stable-projection-"))
        ev = outside / "evidence.json"
        out = outside / "projected-release-manifest.json"
        ev.write_text(json.dumps(evidence(provenance)), encoding="utf-8")
        missing_tag = run(
            [sys.executable, str(PROJECT), "--root", str(repo), "--evidence", str(ev), "--output", str(out)]
        )
        if missing_tag.returncode == 0:
            fail("projected without a tag")

        git(repo, "tag", "v1.2.3", content)
        wrong_tag = run(
            [sys.executable, str(PROJECT), "--root", str(repo), "--evidence", str(ev), "--output", str(out)]
        )
        if wrong_tag.returncode == 0 or "FINAL_QUALIFIED_HEAD" not in wrong_tag.stderr:
            fail("tag on content commit was accepted: %s" % wrong_tag.stderr)
        git(repo, "tag", "-d", "v1.2.3")
        git(repo, "tag", "v1.2.3", provenance)

        ev.write_text(json.dumps({"real_e2e": "pending", "status": "pending"}), encoding="utf-8")
        pending = run(
            [sys.executable, str(PROJECT), "--root", str(repo), "--evidence", str(ev), "--output", str(out)]
        )
        if pending.returncode == 0 or "PASS" not in pending.stderr:
            fail("pending evidence accepted: %s" % pending.stderr)

        ev.write_text(
            json.dumps(evidence(provenance, pass2_head="b" * 40)),
            encoding="utf-8",
        )
        mismatch = run(
            [sys.executable, str(PROJECT), "--root", str(repo), "--evidence", str(ev), "--output", str(out)]
        )
        if mismatch.returncode == 0:
            fail("mismatched pass heads accepted")

        ev.write_text(json.dumps(evidence(provenance)), encoding="utf-8")
        first = run(
            [sys.executable, str(PROJECT), "--root", str(repo), "--evidence", str(ev), "--output", str(out)]
        )
        if first.returncode != 0:
            fail(first.stderr)
        second = run(
            [sys.executable, str(PROJECT), "--root", str(repo), "--evidence", str(ev), "--output", str(out)]
        )
        if second.returncode != 0 or first.stdout != second.stdout:
            fail("projection was not deterministic")
        if (repo / "release-manifest.json").read_bytes() != committed:
            fail("projection rewrote the committed manifest")
        if git(repo, "rev-list", "--count", "HEAD") != count:
            fail("projection created a commit")
        projected = json.loads(out.read_text(encoding="utf-8"))
        original = json.loads(committed.decode())
        if projected["artifacts"] != original["artifacts"]:
            fail("artifact payload changed")
        if projected["channel"] != "stable" or projected["git_ref"] != "v1.2.3":
            fail("publication identity %s" % projected)
        qual = projected["qualification"]
        if [qual["pass1_head"], qual["pass2_head"], qual["final_qualified_head"]] != [provenance] * 3:
            fail("qualification heads %s" % qual)
        if projected["source_head"] != content:
            fail("source_head moved off the content parent")
        print("PASS TAG_TIME_PROJECTION")

        env = GIT_ENV.copy()
        env.update(
            {
                "INPUT_REF": "v1.2.3",
                "WORKFLOW_REF": "refs/tags/v1.2.3",
                "WORKFLOW_SHA": provenance,
            }
        )
        missing_evidence = subprocess.run(
            [sys.executable, str(BIND), "--root", str(repo)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        if missing_evidence.returncode == 0 or "FINAL_QUALIFIED_HEAD" not in missing_evidence.stderr:
            fail("tag attest without PASS evidence was accepted: %s" % missing_evidence.stderr)
        env.update(
            {
                "QUALIFICATION_PASS1_HEAD": provenance,
                "QUALIFICATION_PASS2_HEAD": provenance,
                "QUALIFICATION_FINAL_HEAD": provenance,
            }
        )
        bound = subprocess.run(
            [sys.executable, str(BIND), "--root", str(repo)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        if bound.returncode != 0:
            fail(bound.stderr)
        if "content_commit=%s" % content not in bound.stdout:
            fail(bound.stdout)
        bound_outputs = dict(
            line.split("=", 1) for line in bound.stdout.splitlines() if "=" in line
        )
        if bound_outputs.get("channel") != "stable":
            fail(
                "effective channel %s; verifier would skip sourceRepositoryRef"
                % bound_outputs.get("channel")
            )
        if json.loads((repo / "release-manifest.json").read_text(encoding="utf-8"))["channel"] != "development":
            fail("committed manifest channel changed")
        if git(repo, "rev-list", "--count", "HEAD") != count:
            fail("attest binding created a commit")
        print("PASS RELEASE_ATTEST_TAG_EQUALS_QUALIFIED_HEAD")

    contract = (ROOT / ".engineering" / "release.yaml").read_text(encoding="utf-8")
    for needle in (
        "full_e2e_passes: 2",
        "artifact_hash_required: true",
        "provenance_required: true",
        "sbom_required: true",
        "qualification_command: bash scripts/check-release-governance.sh",
        "operational_e2e_command: bash tests/run-release-qualification-pass.sh",
        "bash scripts/verify-sha256sums.sh",
        "bash scripts/verify-sbom.sh",
    ):
        if needle not in contract:
            fail("release.yaml missing %s" % needle)
    if "operational_e2e_command: bash tests/run-release-qualification-passes.sh" in contract:
        fail("contract would run the two-pass wrapper once per full_e2e_passes")
    if "221.139.249.113" in contract or "129.225.184.60" in contract:
        fail("release.yaml contains a lab or live address")
    print("PASS RELEASE_CONTRACT")
    print("STABLE_PUBLICATION_PROJECTION_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
