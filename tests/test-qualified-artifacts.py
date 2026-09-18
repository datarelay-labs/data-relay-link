#!/usr/bin/env python3
"""Pinned v2.4 Server-local Agent/FRP artifact lookup and fail-closed checks."""
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import drlink_qualified_artifacts as qa  # noqa: E402
import frp_zero_touch as zt  # noqa: E402


def pass_(name):
    print("PASS %s" % name)


def fail(name, detail=""):
    print("FAIL %s %s" % (name, detail), file=sys.stderr)
    raise SystemExit(1)


def test_pin():
    assert qa.DRLINK_VERSION == "2.4.0"
    assert qa.FRP_VERSION == "0.71.0"
    assert qa.FRP_UPSTREAM_TAG == "v0.71.0"
    assert qa.FRP_UPSTREAM_COMMIT == "4a23aa181c1d7e28eecaa8216024ed753b9d27c8"
    assert qa.QUALIFICATION_STATUS == "PASS"
    meta = qa.lookup_frp("linux", "amd64")
    assert meta["sha256"] == "84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
    pass_("ARTIFACT_PIN")


def test_urls():
    alloc = "https://203.0.113.10:6099/enroll"
    assert qa.allocator_origin(alloc) == "https://203.0.113.10:6099"
    assert qa.agent_installer_url(alloc, "linux").endswith("/artifacts/agent/bootstrap-client.sh")
    assert qa.agent_installer_url(alloc, "windows").endswith("/artifacts/agent/bootstrap-client.ps1")
    assert "fatedier" not in qa.frp_archive_url(alloc, "linux", "amd64")
    assert zt.sha256sums_url_for_installer(qa.agent_installer_url(alloc)) == (
        "https://203.0.113.10:6099/artifacts/SHA256SUMS"
    )
    assert zt.linux_installer_sum_names(qa.agent_installer_url(alloc)) == (
        "agent/bootstrap-client.sh",
    )
    pass_("ARTIFACT_URLS")


def test_install_and_lookup():
    agent_linux = ROOT / "dist" / "bootstrap-client.sh"
    agent_win = ROOT / "dist" / "bootstrap-client.ps1"
    if not agent_linux.is_file() or not agent_win.is_file():
        fail("install lookup", "dist bootstrap clients missing")
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "artifacts"
        manifest = qa.install_artifacts(str(ROOT), str(dest), str(agent_linux), str(agent_win))
        assert manifest["frp_upstream_commit"] == qa.FRP_UPSTREAM_COMMIT
        item = qa.lookup_installed(dest, "frp-archive", "linux", "amd64")
        assert Path(item["path"]).is_file()
        agent = qa.lookup_installed(dest, "agent-installer", "linux", "any")
        assert Path(agent["path"]).is_file()
        resolved = qa.resolve_http_path(dest, "/artifacts/manifest.json")
        assert resolved.name == "manifest.json"
        try:
            qa.resolve_http_path(dest, "/artifacts/../LICENSE")
            fail("path traversal allowed")
        except qa.ArtifactError:
            pass
        try:
            qa.lookup_installed(dest, "frp-archive", "linux", "ppc64")
            fail("unsupported arch allowed")
        except qa.ArtifactError as exc:
            if "No changes were applied" not in exc.public_message:
                fail("missing error", exc.public_message)
        corrupt = dest / "frp" / qa.FRP_VERSION / "frp_0.71.0_linux_amd64.tar.gz"
        corrupt.write_bytes(corrupt.read_bytes() + b"x")
        try:
            qa.lookup_installed(dest, "frp-archive", "linux", "amd64")
            fail("corrupt checksum allowed")
        except qa.ArtifactError as exc:
            if "failed verification" not in exc.public_message:
                fail("checksum error", exc.public_message)
    pass_("ARTIFACT_INSTALL_LOOKUP")
    pass_("MISSING_ARTIFACT")
    pass_("CHECKSUM_NEGATIVE")
    pass_("PLATFORM_ARCH_NEGATIVE")


def test_no_public_fallback_constants():
    src = (ROOT / "install-client.sh").read_text(encoding="utf-8")
    if "frp_release_url" in src:
        fail("install-client still calls frp_release_url")
    if "github.com/fatedier" in src:
        fail("install-client still references fatedier")
    server = (ROOT / "install-server.sh").read_text(encoding="utf-8")
    if "github.com/fatedier/frp/releases" in server:
        fail("install-server still downloads fatedier releases")
    pass_("NO_PUBLIC_FALLBACK")


def main():
    test_pin()
    test_urls()
    test_install_and_lookup()
    test_no_public_fallback_constants()
    print("QUALIFIED_ARTIFACT_UNIT_TESTS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
