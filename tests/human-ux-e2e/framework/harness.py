"""Isolated Server/Agent fixtures for Human UX scenarios."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[3]


@dataclass
class DualRoleHarness:
    server_root: Path
    agent_root: Path
    server_plane: object
    agent_plane: object
    mgmt_httpd: object = None
    mgmt_base: str = ""
    machine_id: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    hostname: str = "agent-host"
    public_hostname: str = "remote.xdr.ooo"
    public_ip: str = "203.0.113.10"

    def close(self) -> None:
        try:
            if self.mgmt_httpd is not None:
                import drlink_mgmt_sync as mgmt

                mgmt.stop_mgmt_server(self.mgmt_httpd)
        except Exception:
            pass
        try:
            self.server_plane.close()
        except Exception:
            pass
        try:
            self.agent_plane.close()
        except Exception:
            pass
        for path in (self.server_root, self.agent_root):
            shutil.rmtree(path, ignore_errors=True)
        for key in (
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_CONFIRM",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_MGMT_URL",
            "DRLINK_TEST_RUNTIME_UNIT",
        ):
            os.environ.pop(key, None)


def _write_server_tree(root: Path, *, public_hostname: str, public_ip: str) -> None:
    (root / "etc/drlink").mkdir(parents=True, exist_ok=True)
    (root / "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
    (root / "etc/frp").mkdir(parents=True, exist_ok=True)
    cfg = {
        "public_hostname": public_hostname,
        "public_ip": public_ip,
        "bind_port": 7000,
    }
    (root / "etc/frp/frps.toml").write_text(
        'bindPort = 7000\n# public_hostname=%s\n' % public_hostname,
        encoding="utf-8",
    )
    (root / "etc/frp/server-config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")


def _write_agent_tree(root: Path, *, machine_id: str, hostname: str) -> tuple[str, str, str]:
    import frp_mgmt_auth as MGMT

    frp = root / "etc/frp"
    frp.mkdir(parents=True, exist_ok=True)
    (frp / "client-state.json").write_text(
        json.dumps(
            {"schema_version": 1, "machine_id": machine_id, "hostname": hostname, "label": hostname, "services": {}},
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (frp / "frpc.toml").write_text("[common]\n", encoding="utf-8")
    key = frp / "client-identity.key"
    pub = frp / "client-identity.pub"
    MGMT.generate_keypair(key, pub)
    os.chmod(key, 0o600)
    mac = MGMT.new_mac_key()
    mac_path = frp / "client-identity.mac"
    mac_path.write_text(mac, encoding="utf-8")
    os.chmod(mac_path, 0o600)
    return str(key), pub.read_text(encoding="utf-8"), mac


def create_server_only(*, public_hostname: str = "remote.xdr.ooo") -> DualRoleHarness:
    import drlink_v24 as v24
    from drlink_control_plane import ControlPlane

    server_tmp = Path(tempfile.mkdtemp(prefix="hux-srv-"))
    agent_tmp = Path(tempfile.mkdtemp(prefix="hux-agt-unused-"))
    _write_server_tree(server_tmp, public_hostname=public_hostname, public_ip="203.0.113.10")
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(server_tmp)
    os.environ["DRLINK_CONFIRM"] = "yes"
    os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
    plane = ControlPlane(str(server_tmp))
    v24.ensure_v2_schema(plane.conn)
    # Seed common service objects used by wizards/rules.
    for name, port in (("ssh", 22), ("http", 80), ("https", 443), ("rdp", 3389)):
        try:
            v24.set_service_object(plane, name, type="tcp", port=port, oneshot=True)
        except Exception:
            pass
    return DualRoleHarness(
        server_root=server_tmp,
        agent_root=agent_tmp,
        server_plane=plane,
        agent_plane=plane,
        public_hostname=public_hostname,
    )


def create_agent_only(*, hostname: str = "agent-host") -> DualRoleHarness:
    import drlink_v24 as v24
    from drlink_control_plane import ControlPlane

    agent_tmp = Path(tempfile.mkdtemp(prefix="hux-agt-"))
    server_tmp = Path(tempfile.mkdtemp(prefix="hux-srv-unused-"))
    machine_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    _write_agent_tree(agent_tmp, machine_id=machine_id, hostname=hostname)
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(agent_tmp)
    os.environ["DRLINK_CONFIRM"] = "yes"
    os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
    plane = ControlPlane(str(agent_tmp))
    v24.ensure_v2_schema(plane.conn)
    return DualRoleHarness(
        server_root=server_tmp,
        agent_root=agent_tmp,
        server_plane=plane,
        agent_plane=plane,
        machine_id=machine_id,
        hostname=hostname,
    )


def create_dual_with_mgmt(*, public_hostname: str = "remote.xdr.ooo", hostname: str = "agent-host") -> DualRoleHarness:
    """Server + Agent with in-memory management path (safe, ephemeral)."""
    import drlink_v24 as v24
    import drlink_mgmt_sync as mgmt
    from drlink_control_plane import ControlPlane

    server_tmp = Path(tempfile.mkdtemp(prefix="hux-dual-srv-"))
    agent_tmp = Path(tempfile.mkdtemp(prefix="hux-dual-agt-"))
    machine_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    _write_server_tree(server_tmp, public_hostname=public_hostname, public_ip="203.0.113.10")
    _key, pub, mac = _write_agent_tree(agent_tmp, machine_id=machine_id, hostname=hostname)

    os.environ["DRLINK_CONFIRM"] = "yes"
    os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
    os.environ.pop("DRLINK_MGMT_TOKEN", None)

    server = ControlPlane(str(server_tmp))
    v24.ensure_v2_schema(server.conn)
    for name, port in (("ssh", 22), ("http", 80), ("https", 443), ("rdp", 3389)):
        try:
            v24.set_service_object(server, name, type="tcp", port=port, oneshot=True)
        except Exception:
            pass
    server.upsert_client(machine_id, label=hostname, hostname=hostname)

    verifier = mgmt.InMemoryMgmtVerifier()
    verifier.enroll(machine_id, pub, mac_key=mac, hostname=hostname)
    httpd, base, _ = mgmt.start_mgmt_server(server, verifier=verifier)
    os.environ["DRLINK_MGMT_URL"] = base
    (agent_tmp / "etc/frp/server-endpoint.json").write_text(
        json.dumps({"mgmt_url": base, "public_hostname": public_hostname}) + "\n",
        encoding="utf-8",
    )
    # Prefer public hostname in client-visible config when helpers read it.
    (agent_tmp / "etc/frp/client-state.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "machine_id": machine_id,
                "hostname": hostname,
                "label": hostname,
                "public_hostname": public_hostname,
                "services": {},
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    agent = ControlPlane(str(agent_tmp))
    v24.ensure_v2_schema(agent.conn)
    return DualRoleHarness(
        server_root=server_tmp,
        agent_root=agent_tmp,
        server_plane=server,
        agent_plane=agent,
        mgmt_httpd=httpd,
        mgmt_base=base,
        machine_id=machine_id,
        hostname=hostname,
        public_hostname=public_hostname,
    )


def repo_root() -> Path:
    return ROOT
