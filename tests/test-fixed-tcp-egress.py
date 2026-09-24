#!/usr/bin/env python3
"""Fixed TCP Egress schema, policy, and runtime regressions."""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys_path_lib = str(ROOT / "lib")
import sys

sys.path.insert(0, sys_path_lib)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


EG = _load("frp_egress_control", ROOT / "lib" / "frp_egress_control.py")
RT = _load("frp_egress_runtime", ROOT / "lib" / "frp_egress_runtime.py")
TCP = _load("drlink_tcp_egress", ROOT / "server" / "drlink-tcp-egress.py")


class FixedTcpSchemaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.path = self.root / "var/lib/drlink/egress-control.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=self.path)
        self.cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json"}

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def test_empty_state_is_v3(self):
        state = EG.empty_egress_state()
        self.assertEqual(state["schema_version"], 3)
        self.assertEqual(state["tcp_relays"], {})
        EG.validate_egress_state(state)

    def test_v1_to_v3_migration(self):
        pid = "egp_" + ("a" * 12)
        sid = "egs_" + ("b" * 12)
        did = "egd_" + ("c" * 12)
        v1 = {
            "schema_version": 1,
            "egress_profiles": {
                pid: {
                    "id": pid,
                    "name": "legacy",
                    "enabled": False,
                    "description": "",
                    "sources": [{"id": sid, "cidr": "10.0.0.0/24"}],
                    "destinations": [{"id": did, "host": "example.com", "port": 443}],
                }
            },
        }
        cur = EG.migrate_egress_state_to_current(v1)
        EG.validate_egress_state(cur)
        self.assertEqual(cur["schema_version"], 3)
        self.assertEqual(cur["tcp_relays"], {})
        dest = cur["egress_profiles"][pid]["destinations"][0]
        self.assertEqual(dest["protocol"], "https")
        self.assertEqual(dest["id"], did)

    def test_v2_to_v3_migration(self):
        pid = "egp_" + ("d" * 12)
        sid = "egs_" + ("e" * 12)
        did = "egd_" + ("f" * 12)
        v2 = {
            "schema_version": 2,
            "egress_profiles": {
                pid: {
                    "id": pid,
                    "name": "v2prof",
                    "enabled": True,
                    "description": "keep",
                    "sources": [{"id": sid, "cidr": "10.1.0.0/24"}],
                    "destinations": [
                        {
                            "id": did,
                            "host": "api.example.com",
                            "port": 443,
                            "protocol": "https",
                            "match": "exact",
                        }
                    ],
                }
            },
        }
        cur = EG.migrate_egress_state_v2_to_v3(v2)
        EG.validate_egress_state(cur)
        self.assertEqual(cur["schema_version"], 3)
        self.assertEqual(cur["tcp_relays"], {})
        self.assertEqual(cur["egress_profiles"][pid]["name"], "v2prof")
        self.assertTrue(cur["egress_profiles"][pid]["enabled"])

    def test_corrupt_policy_fail_closed(self):
        self.path.write_text("{not-json", encoding="utf-8")
        with self.assertRaises(EG.EgressError):
            EG.load_egress_state(cfg=self.cfg)

    def test_create_disabled_and_enable_blockers(self):
        def mut(state):
            EG.create_profile(state, "vendor", enabled=False)
            EG.add_destination(
                state, "vendor", "license.example.com", 443, protocol="tcp"
            )
            return EG.create_tcp_relay(
                state,
                "vendor-license",
                profile_selector="vendor",
                destination_selector="license.example.com:443",
            )

        rid, relay = EG.mutate_egress_state(mut, cfg=self.cfg)
        self.assertFalse(relay["enabled"])
        self.assertTrue(6200 <= int(relay["listen_port"]) <= 6299)

        with self.assertRaises(EG.EgressError):
            EG.mutate_egress_state(
                lambda s: EG.set_tcp_relay_enabled(s, rid, True), cfg=self.cfg
            )

        EG.mutate_egress_state(lambda s: EG.add_source(s, "vendor", "10.20.30.0/24"), cfg=self.cfg)
        EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, "vendor", True), cfg=self.cfg)
        EG.mutate_egress_state(lambda s: EG.set_tcp_relay_enabled(s, rid, True), cfg=self.cfg)
        st = EG.load_egress_state(cfg=self.cfg)
        self.assertTrue(st["tcp_relays"][rid]["enabled"])

    def test_duplicate_and_protected_port_reject(self):
        def base(state):
            EG.create_profile(state, "p1", enabled=False)
            EG.add_source(state, "p1", "10.0.0.0/8")
            EG.add_destination(state, "p1", "a.example.com", 443, protocol="tcp")
            EG.create_tcp_relay(
                state,
                "r1",
                profile_selector="p1",
                destination_selector="a.example.com:443",
                listen_port=6201,
            )

        EG.mutate_egress_state(base, cfg=self.cfg)

        def dup(state):
            EG.create_profile(state, "p2", enabled=False)
            EG.add_destination(state, "p2", "b.example.com", 443, protocol="tcp")
            EG.create_tcp_relay(
                state,
                "r2",
                profile_selector="p2",
                destination_selector="b.example.com:443",
                listen_port=6201,
            )

        with self.assertRaises(EG.EgressError):
            EG.mutate_egress_state(dup, cfg=self.cfg)

        def protected(state):
            EG.create_tcp_relay(
                state,
                "r3",
                profile_selector="p1",
                destination_selector="a.example.com:443",
                listen_port=6102,  # HTTP egress default
            )

        with self.assertRaises(EG.EgressError):
            EG.mutate_egress_state(protected, cfg=self.cfg)

    def test_listen_addr_matches_ipv4_runtime(self):
        def seed(state):
            EG.create_profile(state, "p1", enabled=False)
            EG.add_source(state, "p1", "10.0.0.0/8")
            EG.add_destination(state, "p1", "a.example.com", 443, protocol="tcp")

        EG.mutate_egress_state(seed, cfg=self.cfg)
        before = self.path.read_bytes()

        def reject(addr, label):
            def mut(state):
                EG.create_tcp_relay(
                    state,
                    label,
                    profile_selector="p1",
                    destination_selector="a.example.com:443",
                    listen_addr=addr,
                    listen_port=6211,
                )

            with self.assertRaises(EG.EgressError) as ctx:
                EG.mutate_egress_state(mut, cfg=self.cfg)
            self.assertIn("unsupported listen_addr", str(ctx.exception))
            self.assertEqual(self.path.read_bytes(), before)

        for addr, label in (
            ("*", "bad-star"),
            ("::", "bad-v6wild"),
            ("::1", "bad-v6loop"),
            ("2001:db8::1", "bad-v6lit"),
        ):
            reject(addr, label)

        def accept(addr, port):
            def mut(state):
                return EG.create_tcp_relay(
                    state,
                    "ok-%s" % port,
                    profile_selector="p1",
                    destination_selector="a.example.com:443",
                    listen_addr=addr,
                    listen_port=port,
                )

            _rid, relay = EG.mutate_egress_state(mut, cfg=self.cfg)
            self.assertEqual(relay["listen_addr"], addr)
            self.assertFalse(relay["enabled"])

        accept("0.0.0.0", 6212)
        accept("127.0.0.1", 6213)
        saved = EG.load_egress_state(cfg=self.cfg)
        stored = {r["listen_addr"] for r in saved["tcp_relays"].values()}
        self.assertEqual(stored, {"0.0.0.0", "127.0.0.1"})

    def test_tcp_wildcard_destination_rejected(self):
        def mut(state):
            EG.create_profile(state, "wild", enabled=False)
            EG.add_destination(state, "wild", "*.example.com", 443, protocol="tcp")

        with self.assertRaises(EG.EgressError):
            EG.mutate_egress_state(mut, cfg=self.cfg)

    def test_authorize_tcp_relay_source_and_dns(self):
        def mut(state):
            EG.create_profile(state, "vendor", enabled=False)
            EG.add_source(state, "vendor", "10.20.30.0/24")
            EG.add_destination(
                state, "vendor", "license.example.com", 443, protocol="tcp"
            )
            EG.set_profile_enabled(state, "vendor", True)
            return EG.create_tcp_relay(
                state,
                "vendor-license",
                profile_selector="vendor",
                destination_selector="license.example.com:443",
            )

        rid, _relay = EG.mutate_egress_state(mut, cfg=self.cfg)
        EG.mutate_egress_state(lambda s: EG.set_tcp_relay_enabled(s, rid, True), cfg=self.cfg)
        state = EG.load_egress_state(cfg=self.cfg)

        allow = EG.authorize_tcp_relay(state, relay_selector=rid, source_ip="10.20.30.5")
        self.assertEqual(allow["decision"], EG.DECISION_ALLOW)

        deny = EG.authorize_tcp_relay(state, relay_selector=rid, source_ip="192.0.2.10")
        self.assertEqual(deny["decision"], EG.DECISION_DENY)
        self.assertEqual(deny["reason"], EG.REASON_SOURCE_NOT_ALLOWED)

        self.assertNotEqual(allow.get("hostname"), "1.2.3.4")

    def test_dns_unsafe_and_mixed_deny(self):
        with self.assertRaises(EG.EgressError):
            EG.validate_resolved_addresses(["127.0.0.1"])
        with self.assertRaises(EG.EgressError):
            EG.validate_resolved_addresses(["10.0.0.1"])
        with self.assertRaises(EG.EgressError):
            EG.validate_resolved_addresses(["169.254.169.254"])
        with self.assertRaises(EG.EgressError):
            EG.validate_resolved_addresses(["100.64.0.1"])
        with self.assertRaises(EG.EgressError):
            EG.validate_resolved_addresses(["8.8.8.8", "10.0.0.1"])
        ok = EG.validate_resolved_addresses(["8.8.8.8", "1.1.1.1"])
        self.assertEqual(ok, ["8.8.8.8", "1.1.1.1"])

    def test_recipe_apply_disabled(self):
        recipes = EG.list_recipes()
        self.assertGreaterEqual(len(recipes), 1)
        self.assertLessEqual(len(recipes), 3)

        def mut(state):
            return EG.apply_recipe(
                state, "tcp-fixed", source_cidr="10.0.0.0/24", cfg=self.cfg
            )

        EG.mutate_egress_state(mut, cfg=self.cfg)
        state = EG.load_egress_state(cfg=self.cfg)
        for _pid, prof in (state.get("egress_profiles") or {}).items():
            self.assertFalse(prof.get("enabled"))
        for _rid, relay in (state.get("tcp_relays") or {}).items():
            self.assertFalse(relay.get("enabled"))

    def test_explain_no_mutation(self):
        def mut(state):
            EG.create_profile(state, "vendor", enabled=False)
            EG.add_source(state, "vendor", "10.20.30.0/24")
            EG.add_destination(
                state, "vendor", "license.example.com", 443, protocol="tcp"
            )
            return EG.create_tcp_relay(
                state,
                "vendor-license",
                profile_selector="vendor",
                destination_selector="license.example.com:443",
            )

        rid, _ = EG.mutate_egress_state(mut, cfg=self.cfg)
        before = self.path.read_text(encoding="utf-8")
        state = EG.load_egress_state(cfg=self.cfg)
        decision = EG.authorize_tcp_relay(
            state, relay_selector=rid, source_ip="10.20.30.5", preview=True
        )
        self.assertIn(decision["decision"], (EG.DECISION_ALLOW, EG.DECISION_DENY))
        after = self.path.read_text(encoding="utf-8")
        self.assertEqual(before, after)


class FixedTcpRuntimeTests(unittest.TestCase):
    def setUp(self):
        raise unittest.SkipTest(
            "PRIOR_RELEASE_MIGRATION_TEST: Fixed TCP runtime now requires SQLite "
            "control-plane relays; JSON egress-control listener fixture retired"
        )
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.path = self.root / "var/lib/drlink/egress-control.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=self.path)
        self.cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json"}
        self.echo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.echo.bind(("127.0.0.1", 0))
        self.echo.listen(5)
        self.echo_port = self.echo.getsockname()[1]
        self._echo_stop = threading.Event()

        def _echo_serve():
            self.echo.settimeout(0.5)
            while not self._echo_stop.is_set():
                try:
                    conn, _addr = self.echo.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    data = conn.recv(65536)
                    if data:
                        conn.sendall(data)

        self._echo_thread = threading.Thread(target=_echo_serve, daemon=True)
        self._echo_thread.start()

    def tearDown(self):
        self._echo_stop.set()
        try:
            self.echo.close()
        except OSError:
            pass
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def test_exact_ip_connect_no_reresolve(self):
        resolved = {"license.example.com": ["8.8.8.8"]}
        connected = []

        def resolve_fn(host):
            return list(resolved[host])

        def connect_fn(ip, port, hostname, timeout):
            # Must receive validated IP, never re-resolve hostname.
            self.assertEqual(ip, "8.8.8.8")
            self.assertEqual(hostname, "license.example.com")
            connected.append((ip, port))
            # Connect to local echo, but report the validated peer for exact-IP checks.
            real = RT.default_connect("127.0.0.1", self.echo_port, hostname, timeout)

            class _PeerSock:
                def __init__(self, sock, peer):
                    self._sock = sock
                    self._peer = peer

                def getpeername(self):
                    return self._peer

                def __getattr__(self, name):
                    return getattr(self._sock, name)

            return _PeerSock(real, (ip, port))

        def mut(state):
            EG.create_profile(state, "vendor", enabled=False)
            EG.add_source(state, "vendor", "127.0.0.0/8")
            EG.add_destination(
                state, "vendor", "license.example.com", 443, protocol="tcp"
            )
            EG.set_profile_enabled(state, "vendor", True)
            rid, relay = EG.create_tcp_relay(
                state,
                "vendor-license",
                profile_selector="vendor",
                destination_selector="license.example.com:443",
                listen_addr="127.0.0.1",
                listen_port=6210,
            )
            EG.set_tcp_relay_enabled(state, rid, True)
            return rid, relay

        EG.mutate_egress_state(mut, cfg=self.cfg)
        cfg_path = self.root / "etc/drlink/config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(
            json.dumps(
                {
                    "egress_control_file": "/var/lib/drlink/egress-control.json",
                    "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (self.root / "var/log/drlink/egress").mkdir(parents=True, exist_ok=True)
        cache = RT.PolicyCache(cfg_path)
        cache.reload(force=True)
        st = TCP.TcpEgressState(
            cache, resolve_fn=resolve_fn, connect_fn=connect_fn, max_concurrent=8
        )
        TCP.sync_listeners(st)
        time.sleep(0.2)
        try:
            sock = socket.create_connection(("127.0.0.1", 6210), timeout=2)
            sock.sendall(b"ping")
            data = sock.recv(16)
            sock.close()
            self.assertEqual(data, b"ping")
            self.assertEqual(connected, [("8.8.8.8", 443)])
        finally:
            st.shutting_down = True
            for _rid, server in list(st._servers.items()):
                try:
                    server.shutdown()
                    server.server_close()
                except Exception:
                    pass
            st._servers.clear()

    def test_disabled_relay_denies(self):
        def mut(state):
            EG.create_profile(state, "vendor", enabled=False)
            EG.add_source(state, "vendor", "127.0.0.0/8")
            EG.add_destination(
                state, "vendor", "license.example.com", 443, protocol="tcp"
            )
            EG.set_profile_enabled(state, "vendor", True)
            return EG.create_tcp_relay(
                state,
                "vendor-license",
                profile_selector="vendor",
                destination_selector="license.example.com:443",
                listen_addr="127.0.0.1",
                listen_port=6211,
            )

        rid, _ = EG.mutate_egress_state(mut, cfg=self.cfg)
        # Relay remains disabled — connections deny.
        state = EG.load_egress_state(cfg=self.cfg)
        decision = EG.authorize_tcp_relay(
            state, relay_selector=rid, source_ip="127.0.0.1"
        )
        self.assertEqual(decision["decision"], EG.DECISION_DENY)
        self.assertEqual(decision["reason"], EG.REASON_RELAY_DISABLED)


if __name__ == "__main__":
    unittest.main()
