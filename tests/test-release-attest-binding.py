#!/usr/bin/env python3
"""Regression coverage for the provenance-commit release-attest binding."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-release-attest-binding.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_release_attest_binding", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load %s" % SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = load_checker()

GIT_ENV = os.environ.copy()
GIT_ENV.update(
    {
        "GIT_AUTHOR_NAME": "binding-test",
        "GIT_AUTHOR_EMAIL": "binding-test@example.com",
        "GIT_COMMITTER_NAME": "binding-test",
        "GIT_COMMITTER_EMAIL": "binding-test@example.com",
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


def manifest(channel: str, git_ref: str, source_head: str, version: str = "1.2.3") -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "project_version": version,
            "frp_version": "0.71.0",
            "channel": channel,
            "git_ref": git_ref,
            "source_head": source_head,
            "immutable_source_ref": git_ref,
            "features": {"mcp_included": True},
            "artifacts": {
                "bootstrap-client.sh": {
                    "path": "dist/bootstrap-client.sh",
                    "sha256": "a" * 64,
                }
            },
        },
        indent=2,
    ) + "\n"


def init_repo(repo: Path, channel: str = "development") -> None:
    git(repo, "init", "-b", "main")
    write(
        repo,
        "VERSION",
        "PROJECT_VERSION=1.2.3\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=%s\n" % channel,
    )
    write(repo, "lib/product.sh", "echo product\n")
    write(repo, "release-manifest.json", manifest(channel, "0" * 40, "0" * 40))
    write(repo, "dist/bootstrap-client.sh", "echo bootstrap-v0\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "content")


def stamp(
    repo: Path,
    channel: str,
    git_ref: str,
    source_head: str,
    version: str = "1.2.3",
) -> str:
    write(repo, "release-manifest.json", manifest(channel, git_ref, source_head, version=version))
    write(repo, "dist/bootstrap-client.sh", "echo bootstrap-%s\n" % source_head[:12])
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "provenance")
    return git(repo, "rev-parse", "HEAD")


def run_cli(
    repo: Path,
    input_ref: str,
    workflow_ref: str,
    workflow_sha: str,
    qualified_head: str = "",
) -> subprocess.CompletedProcess[str]:
    env = GIT_ENV.copy()
    env.update(
        {
            "INPUT_REF": input_ref,
            "WORKFLOW_REF": workflow_ref,
            "WORKFLOW_SHA": workflow_sha,
        }
    )
    if qualified_head:
        env.update(
            {
                "QUALIFICATION_PASS1_HEAD": qualified_head,
                "QUALIFICATION_PASS2_HEAD": qualified_head,
                "QUALIFICATION_FINAL_HEAD": qualified_head,
            }
        )
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(repo)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def assert_fail(proc: subprocess.CompletedProcess[str], needle: str) -> None:
    if proc.returncode == 0:
        fail("expected failure containing %r, stdout=%s" % (needle, proc.stdout))
    if needle not in proc.stderr:
        fail("stderr missing %r: %s" % (needle, proc.stderr))


def test_workflow_uses_checker() -> None:
    text = (ROOT / ".github/workflows/release-attest.yml").read_text(encoding="utf-8")
    if "scripts/check-release-attest-binding.py" not in text:
        fail("release-attest.yml does not call the binding checker")
    if "scripts/project-stable-release.py" not in text:
        fail("release-attest.yml does not project the stable manifest")
    if "QUALIFICATION_FINAL_HEAD" not in text:
        fail("release-attest.yml does not bind qualification evidence to the tag")
    if "source_head '$SOURCE_HEAD' != checked-out HEAD" in text:
        fail("release-attest.yml still rejects a content source_head")
    print("PASS WORKFLOW_CALLS_BINDING_CHECKER")


def test_development_provenance_commit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        init_repo(repo)
        content = git(repo, "rev-parse", "HEAD")
        provenance = stamp(repo, "development", content, content)
        proc = run_cli(
            repo,
            provenance,
            "refs/heads/main",
            provenance,
        )
        if proc.returncode != 0:
            fail(proc.stderr)
        outputs = dict(
            line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
        )
        if outputs.get("release_commit") != provenance:
            fail("release_commit %s" % outputs)
        if outputs.get("content_commit") != content:
            fail("content_commit %s" % outputs)
        if outputs.get("channel") != "development":
            fail("channel %s" % outputs)
    print("PASS DEVELOPMENT_PROVENANCE_COMMIT")


def test_rejects_product_diff_and_mutable_ref() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        init_repo(repo)
        content = git(repo, "rev-parse", "HEAD")
        write(repo, "lib/product.sh", "echo changed\n")
        provenance = stamp(repo, "development", content, content)
        proc = run_cli(repo, provenance, "refs/heads/main", provenance)
        assert_fail(proc, "non-generated paths")
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        init_repo(repo)
        content = git(repo, "rev-parse", "HEAD")
        provenance = stamp(repo, "development", "main", content)
        proc = run_cli(repo, provenance, "refs/heads/main", provenance)
        assert_fail(proc, "40-char content SHA")
    print("PASS REJECT_UNQUALIFIED_TREE_AND_MUTABLE_REF")


def test_rejects_non_parent_and_wrong_dispatch() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        init_repo(repo)
        first = git(repo, "rev-parse", "HEAD")
        write(repo, "lib/product.sh", "echo second\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-m", "more product")
        parent = git(repo, "rev-parse", "HEAD")
        provenance = stamp(repo, "development", first, first)
        proc = run_cli(repo, provenance, "refs/heads/main", provenance)
        assert_fail(proc, "!= content parent %s" % parent)

        init_repo(repo)
        content = git(repo, "rev-parse", "HEAD")
        provenance = stamp(repo, "development", content, content)
        proc = run_cli(repo, content, "refs/heads/main", provenance)
        assert_fail(proc, "must be the provenance commit SHA")
        proc = run_cli(repo, provenance, "refs/heads/main", content)
        assert_fail(proc, "github.sha")
    print("PASS REJECT_NON_PARENT_AND_WRONG_DISPATCH")


def test_stable_and_rc_tags_point_at_provenance_commit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        init_repo(repo, channel="stable")
        content = git(repo, "rev-parse", "HEAD")
        write(
            repo,
            "VERSION",
            "PROJECT_VERSION=1.2.3\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=stable\n",
        )
        provenance = stamp(repo, "stable", "v1.2.3", content)
        git(repo, "tag", "v1.2.3", provenance)
        proc = run_cli(repo, "v1.2.3", "refs/tags/v1.2.3", provenance)
        assert_fail(proc, "FINAL_QUALIFIED_HEAD")
        proc = run_cli(repo, "v1.2.3", "refs/tags/v1.2.3", provenance, content)
        assert_fail(proc, "FINAL_QUALIFIED_HEAD")
        proc = run_cli(repo, "v1.2.3", "refs/tags/v1.2.3", provenance, provenance)
        if proc.returncode != 0:
            fail(proc.stderr)
        git(repo, "tag", "-d", "v1.2.3")
        git(repo, "tag", "v1.2.3", content)
        proc = run_cli(repo, "v1.2.3", "refs/tags/v1.2.3", provenance)
        assert_fail(proc, "not provenance HEAD")

        shutil.rmtree(repo)
        repo.mkdir()
        init_repo(repo, channel="preview")
        content = git(repo, "rev-parse", "HEAD")
        provenance = stamp(repo, "preview", "v1.2.3-rc.1", content)
        git(repo, "tag", "v1.2.3-rc.1", provenance)
        proc = run_cli(repo, "v1.2.3-rc.1", "refs/tags/v1.2.3-rc.1", provenance)
        if proc.returncode != 0:
            fail(proc.stderr)
        proc = run_cli(repo, "v1.2.3-rc.1", "refs/heads/main", provenance)
        assert_fail(proc, "dispatch this workflow from refs/tags/v1.2.3-rc.1")
    print("PASS STABLE_AND_RC_BIND_PROVENANCE_COMMIT")


def attestation_want_ref(channel: str, tag: str) -> str | None:
    """Same rule as release-attest.yml post-attestation verification."""
    return "refs/tags/%s" % tag if channel == "stable" else None


def test_validated_stable_tag_exposes_effective_channel() -> None:
    """Development manifest plus a qualified stable tag publishes as stable.

    Current behavior returns channel=development, so the verifier skips
    sourceRepositoryRef. This must fail until the effective channel is stable.
    """
    workflow = (ROOT / ".github/workflows/release-attest.yml").read_text(encoding="utf-8")
    if "want_ref = 'refs/tags/%s' % tag if channel == 'stable' else None" not in workflow:
        fail("post-attestation verifier does not key sourceRepositoryRef off channel")
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        init_repo(repo)
        write(
            repo,
            "VERSION",
            "PROJECT_VERSION=2.4.0\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=development\n",
        )
        git(repo, "add", "-A")
        git(repo, "commit", "-m", "set product version")
        content = git(repo, "rev-parse", "HEAD")
        before = git(repo, "rev-list", "--count", "HEAD")
        provenance = stamp(repo, "development", content, content, version="2.4.0")
        git(repo, "tag", "v2.4.0", provenance)
        committed = (repo / "release-manifest.json").read_text(encoding="utf-8")
        if '"channel": "development"' not in committed:
            fail("fixture manifest is not development")
        proc = run_cli(repo, "v2.4.0", "refs/tags/v2.4.0", provenance, provenance)
        if proc.returncode != 0:
            fail(proc.stderr)
        outputs = dict(
            line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
        )
        if outputs.get("channel") != "stable":
            fail(
                "effective channel %s; verifier would skip sourceRepositoryRef refs/tags/v2.4.0"
                % outputs.get("channel")
            )
        if outputs.get("expected_tag") != "v2.4.0":
            fail("expected_tag %s" % outputs)
        want_ref = attestation_want_ref(outputs["channel"], outputs["expected_tag"])
        if want_ref != "refs/tags/v2.4.0":
            fail("sourceRepositoryRef want %s" % want_ref)
        if (repo / "release-manifest.json").read_text(encoding="utf-8") != committed:
            fail("binding rewrote the committed manifest")
        if json.loads(committed)["channel"] != "development":
            fail("committed manifest channel is no longer development")
        if git(repo, "rev-list", "--count", "HEAD") != str(int(before) + 1):
            fail("binding created a post-qualification commit")
        if git(repo, "status", "--porcelain"):
            fail("binding dirtied the worktree")
    print("PASS EFFECTIVE_STABLE_TAG_CHANNEL")


def test_self_reference_is_rejected() -> None:
    head = "a" * 40
    parent = "b" * 40
    facts = checker.BindingFacts(
        project_version="1.2.3",
        manifest_version="1.2.3",
        channel="development",
        git_ref=head,
        source_head=head,
        immutable_source_ref=head,
        head=head,
        parent=parent,
        input_ref=head,
        workflow_ref="refs/heads/main",
        workflow_sha=head,
        changed_paths=("release-manifest.json",),
        tag_commits={},
        clean=True,
    )
    try:
        checker.evaluate(facts)
    except checker.BindingError as exc:
        if not any("self-referential" in err for err in exc.errors):
            fail("errors=%s" % exc.errors)
    else:
        fail("self-referential source_head was accepted")
    print("PASS REJECT_SELF_REFERENTIAL_SHA")


def main() -> int:
    test_workflow_uses_checker()
    test_development_provenance_commit()
    test_rejects_product_diff_and_mutable_ref()
    test_rejects_non_parent_and_wrong_dispatch()
    test_stable_and_rc_tags_point_at_provenance_commit()
    test_validated_stable_tag_exposes_effective_channel()
    test_self_reference_is_rejected()
    print("RELEASE_ATTEST_BINDING_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
