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
    assert qa.is_forbidden_public_installer_url(
        "https://raw.githubusercontent.com/datarelay-labs/data-relay-link/main/dist/bootstrap-client.sh"
    )
    assert qa.is_forbidden_public_installer_url(
        "https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz"
    )
    assert not qa.is_forbidden_public_installer_url(
        "https://203.0.113.10:6099/artifacts/agent/bootstrap-client.sh"
    )
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


def _assert_no_public_installer(url, name):
    text = str(url or "")
    for marker in (
        "raw.githubusercontent.com",
        "github.com/datarelay-labs",
        "github.com/fatedier",
    ):
        if marker in text.lower():
            fail(name, "public fallback in %s" % text)


def _load_create_client():
    import importlib.machinery
    import importlib.util

    path = ROOT / "tools" / "frp-create-client"
    spec = importlib.util.spec_from_loader(
        "frp_create_client_qa",
        loader=importlib.machinery.SourceFileLoader("frp_create_client_qa", str(path)),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_create_client_installer_resolution():
    import contextlib
    import io

    create = _load_create_client()
    alloc = "https://203.0.113.10:6099/enroll"
    expected_linux = "https://203.0.113.10:6099/artifacts/agent/bootstrap-client.sh"
    expected_win = "https://203.0.113.10:6099/artifacts/agent/bootstrap-client.ps1"
    former_linux = (
        "https://raw.githubusercontent.com/datarelay-labs/data-relay-link/"
        "be3e403cf1babf4829406ff773e7daa3a816976f/dist/bootstrap-client.sh"
    )
    former_win = (
        "https://raw.githubusercontent.com/datarelay-labs/data-relay-link/"
        "be3e403cf1babf4829406ff773e7daa3a816976f/dist/bootstrap-client.ps1"
    )
    fatedier = (
        "https://github.com/fatedier/frp/releases/download/v0.71.0/"
        "frp_0.71.0_linux_amd64.tar.gz"
    )

    missing = {"allocator_public_url": alloc}
    linux = create.resolve_configured_installer_url(missing, windows=False)
    if linux != expected_linux:
        fail("CONFIG_MISSING_LINUX_INSTALLER_URL_USES_SERVER_LOCAL", linux)
    _assert_no_public_installer(linux, "CONFIG_MISSING_LINUX_INSTALLER_URL_USES_SERVER_LOCAL")
    pass_("CONFIG_MISSING_LINUX_INSTALLER_URL_USES_SERVER_LOCAL")

    windows = create.resolve_configured_installer_url(missing, windows=True)
    if windows != expected_win:
        fail("CONFIG_MISSING_WINDOWS_INSTALLER_URL_USES_SERVER_LOCAL", windows)
    _assert_no_public_installer(windows, "CONFIG_MISSING_WINDOWS_INSTALLER_URL_USES_SERVER_LOCAL")
    pass_("CONFIG_MISSING_WINDOWS_INSTALLER_URL_USES_SERVER_LOCAL")

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        try:
            create.resolve_configured_installer_url(
                {"enrollments_dir": "/var/lib/drlink/enrollments"},
                windows=False,
            )
            fail("CONFIG_MISSING_INSTALLER_URL_WITHOUT_ALLOCATOR_FAILS_CLOSED", "did not fail")
        except SystemExit as exc:
            if int(getattr(exc, "code", 0) or 0) == 0:
                fail("CONFIG_MISSING_INSTALLER_URL_WITHOUT_ALLOCATOR_FAILS_CLOSED", "zero exit")
    closed = stderr.getvalue()
    if "No changes were applied" not in closed:
        fail("CONFIG_MISSING_INSTALLER_URL_WITHOUT_ALLOCATOR_FAILS_CLOSED", closed)
    if "Traceback" in closed:
        fail("CONFIG_MISSING_INSTALLER_URL_WITHOUT_ALLOCATOR_FAILS_CLOSED", "traceback")
    _assert_no_public_installer(closed, "CONFIG_MISSING_INSTALLER_URL_WITHOUT_ALLOCATOR_FAILS_CLOSED")
    pass_("CONFIG_MISSING_INSTALLER_URL_WITHOUT_ALLOCATOR_FAILS_CLOSED")

    linux = create.resolve_configured_installer_url(
        {"allocator_public_url": alloc, "client_installer_url": former_linux},
        windows=False,
    )
    if linux != expected_linux:
        fail("FORMER_PUBLIC_LINUX_INSTALLER_URL_NOT_USED", linux)
    _assert_no_public_installer(linux, "FORMER_PUBLIC_LINUX_INSTALLER_URL_NOT_USED")
    pass_("FORMER_PUBLIC_LINUX_INSTALLER_URL_NOT_USED")

    windows = create.resolve_configured_installer_url(
        {"allocator_public_url": alloc, "windows_client_installer_url": former_win},
        windows=True,
    )
    if windows != expected_win:
        fail("FORMER_PUBLIC_WINDOWS_INSTALLER_URL_NOT_USED", windows)
    _assert_no_public_installer(windows, "FORMER_PUBLIC_WINDOWS_INSTALLER_URL_NOT_USED")
    pass_("FORMER_PUBLIC_WINDOWS_INSTALLER_URL_NOT_USED")

    linux = create.resolve_configured_installer_url(
        {"allocator_public_url": alloc, "client_installer_url": expected_linux},
        windows=False,
    )
    if linux != expected_linux:
        fail("CONFIGURED_SERVER_LOCAL_LINUX_URL_PRESERVE", linux)
    pass_("CONFIGURED_SERVER_LOCAL_LINUX_URL_PRESERVE")

    windows = create.resolve_configured_installer_url(
        {"allocator_public_url": alloc, "windows_client_installer_url": expected_win},
        windows=True,
    )
    if windows != expected_win:
        fail("CONFIGURED_SERVER_LOCAL_WINDOWS_URL_PRESERVE", windows)
    pass_("CONFIGURED_SERVER_LOCAL_WINDOWS_URL_PRESERVE")

    linux = create.resolve_configured_installer_url(
        {"allocator_public_url": alloc, "client_installer_url": fatedier},
        windows=False,
    )
    if linux != expected_linux:
        fail("NO_FATEDIER_INSTALLER_FALLBACK", linux)
    _assert_no_public_installer(linux, "NO_FATEDIER_INSTALLER_FALLBACK")
    pass_("NO_FATEDIER_INSTALLER_FALLBACK")

    datarelay = (
        "https://github.com/datarelay-labs/data-relay-link/raw/main/"
        "dist/bootstrap-client.sh"
    )
    linux = create.resolve_configured_installer_url(
        {"allocator_public_url": alloc, "client_installer_url": datarelay},
        windows=False,
    )
    if linux != expected_linux:
        fail("NO_PUBLIC_DATALINK_INSTALLER_FALLBACK", linux)
    _assert_no_public_installer(linux, "NO_PUBLIC_DATALINK_INSTALLER_FALLBACK")
    default_linux = create.default_client_installer_url()
    default_win = create.default_windows_client_installer_url()
    _assert_no_public_installer(default_linux, "NO_PUBLIC_DATALINK_INSTALLER_FALLBACK")
    _assert_no_public_installer(default_win, "NO_PUBLIC_DATALINK_INSTALLER_FALLBACK")
    os.environ["FRP_EXPECTED_SOURCE_REF"] = "be3e403cf1babf4829406ff773e7daa3a816976f"
    try:
        _assert_no_public_installer(
            create.default_client_installer_url(),
            "NO_PUBLIC_DATALINK_INSTALLER_FALLBACK",
        )
        _assert_no_public_installer(
            create.default_windows_client_installer_url(),
            "NO_PUBLIC_DATALINK_INSTALLER_FALLBACK",
        )
    finally:
        os.environ.pop("FRP_EXPECTED_SOURCE_REF", None)
    pass_("NO_PUBLIC_DATALINK_INSTALLER_FALLBACK")


def main():
    test_pin()
    test_urls()
    test_install_and_lookup()
    test_no_public_fallback_constants()
    test_create_client_installer_resolution()
    print("QUALIFIED_ARTIFACT_UNIT_TESTS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
