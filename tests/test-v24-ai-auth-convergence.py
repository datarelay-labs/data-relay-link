#!/usr/bin/env python3
"""P0: Canonical AI authorization convergence (MCP == test ai-access).

Proves MCP Bridge / authorize_ai_capability_v24 consume ai_policy_rules only,
ignore contradictory legacy ai_access_rules / ai_path_scopes, and fail closed
for file capabilities without canonical path scopes.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane, ControlPlaneError
import drlink_v24 as v24
from drlink_mcp_bridge import MCPBridge


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _verify(plane: ControlPlane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'active', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.conn.commit()


def _seed_legacy_allow(
    plane: ControlPlane,
    *,
    name: str,
    principal: str,
    endpoint: str,
    capability: str,
    paths: list[str] | None = None,
    action: str = "allow",
) -> None:
    """Seed contradictory legacy AI rule state that must not authorize MCP."""
    plane.set_ai_principal(principal, enabled=True)
    _verify(plane, principal)
    plane.set_ai_rule(name)
    plane.set_ai_rule_principal(name, principal)
    plane.set_ai_rule_target(name, "endpoint", endpoint)
    plane.set_ai_rule_capability(name, capability)
    for pattern in paths or []:
        plane.set_ai_rule_path(name, pattern)
    plane.set_ai_rule_action(name, action)
    plane.set_ai_rule_enabled(name, True)


class AiAuthConvergence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-ai-auth-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_AI_TEST_LOCAL_EXEC"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        self.vendor = Path(self.tmp) / "var" / "log" / "vendor"
        self.etc = Path(self.tmp) / "etc" / "vendor"
        self.out = Path(self.tmp) / "opt" / "vendor"
        for path in (self.vendor, self.etc, self.out):
            path.mkdir(parents=True, exist_ok=True)
        (self.vendor / "app.log").write_text("log-ok\n", encoding="utf-8")
        (self.etc / "config.yaml").write_text("k: v\n", encoding="utf-8")
        self.vendor_glob = str(self.vendor) + "/**"
        self.etc_glob = str(self.etc) + "/**"
        self.out_glob = str(self.out) + "/**"

        self.plane.upsert_client("client-a-aaaaaaaa", label="host-a", connected=True)
        self.plane.upsert_client("client-b-bbbbbbbb", label="host-b", connected=True)
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        self.principal = self.plane.get_principal("bot")

        v24.set_permission_object(
            self.plane,
            "read-only",
            permissions=["host-info", "process-read", "file-read"],
            oneshot=True,
        )
        v24.set_permission_object(
            self.plane,
            "exec-only",
            permissions=["command-exec"],
            oneshot=True,
        )
        v24.set_permission_object(
            self.plane,
            "write-pack",
            permissions=["file-write", "file-upload", "file-download"],
            oneshot=True,
        )
        v24.set_permission_group(
            self.plane, "ops", members=["read-only", "exec-only"], oneshot=True
        )
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)

    def tearDown(self):
        self.bridge.close()
        self.plane.close()
        for key in (
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_TEST_ROOT",
            "DRLINK_CONFIRM",
            "DRLINK_AI_TEST_LOCAL_EXEC",
        ):
            os.environ.pop(key, None)

    def _whitelist(self, name: str, *, destination: str, permission: str, enabled: bool = True):
        v24.set_ai_access_rule(
            self.plane,
            name,
            mode="whitelist",
            source="bot",
            destination=destination,
            permission=permission,
            enabled=enabled,
            oneshot=True,
        )

    def _eval(self, permission: str, destination: str = "host-a") -> dict:
        return v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination=destination, permission=permission
        )

    def _auth(self, capability: str, destination: str = "host-a", operand=None) -> dict:
        return v24.authorize_ai_capability_v24(
            self.plane,
            identity="bot",
            destination=destination,
            capability=capability,
            operand=operand,
        )

    def _call(self, capability: str, destination: str = "host-a", **arguments) -> dict:
        args = dict(arguments)
        if capability != "list_hosts":
            args.setdefault("endpoint", destination)
        return self.bridge.call_tool(self.principal, capability, args)

    def _text(self, result: dict) -> str:
        content = (result.get("content") or [{}])[0]
        return str(content.get("text") or "")

    def test_canonical_allow_legacy_deny(self):
        self._whitelist("allow-info", destination="host-a", permission="read-only")
        _seed_legacy_allow(
            self.plane,
            name="legacy-deny",
            principal="bot",
            endpoint="host-a",
            capability="get_system_info",
            action="deny",
        )
        ev = self._eval("host-info")
        auth = self._auth("get_system_info")
        self.assertEqual(ev["result"], "ALLOW")
        self.assertEqual(auth["action"], "ALLOW")
        self.assertEqual(auth["winner"]["name"], "allow-info")
        text = self._text(self._call("get_system_info"))
        self.assertNotIn("DENY", text.splitlines()[0] if text else "DENY")

    def test_canonical_deny_legacy_allow(self):
        # No canonical rule => WHITELIST DENY once mode exists via empty policy setup.
        v24.ensure_policy_mode(self.plane, "ai", "whitelist", oneshot=True)
        _seed_legacy_allow(
            self.plane,
            name="legacy-allow",
            principal="bot",
            endpoint="host-a",
            capability="get_system_info",
            action="allow",
        )
        # Legacy evaluator would ALLOW; canonical/MCP must DENY.
        legacy = self.plane.evaluate_ai_access("bot", "host-a", "get_system_info")
        self.assertEqual(legacy["action"], "ALLOW")
        ev = self._eval("host-info")
        auth = self._auth("get_system_info")
        self.assertEqual(ev["result"], "DENY")
        self.assertEqual(auth["action"], "DENY")
        text = self._text(self._call("get_system_info"))
        self.assertTrue(text.startswith("DENY"), text)

    def test_no_policy_and_enforcement_parity(self):
        # No AI policy configured => evaluate ALLOW after auth.
        ev = self._eval("host-info")
        auth = self._auth("get_system_info")
        self.assertIsNone(ev["mode"])
        self.assertEqual(ev["result"], "ALLOW")
        self.assertEqual(auth["action"], "ALLOW")
        self.assertEqual(auth["evaluation"]["result"], "ALLOW")

        self._whitelist("allow-info", destination="host-a", permission="read-only")
        v24.set_policy_enforcement(self.plane, "ai", False, confirm=True)
        ev2 = self._eval("command-exec")
        auth2 = self._auth("exec", operand="id")
        self.assertEqual(ev2["result"], "ALLOW")
        self.assertEqual(auth2["action"], "ALLOW")
        self.assertEqual(auth2["evaluation"]["result"], "ALLOW")

    def test_permission_object_expansion(self):
        self._whitelist("allow-info", destination="host-a", permission="read-only")
        self.assertEqual(self._auth("get_system_info")["action"], "ALLOW")
        self.assertEqual(self._auth("list_processes")["action"], "ALLOW")
        self.assertEqual(self._auth("exec", operand="id")["action"], "DENY")
        self.assertEqual(self._eval("host-info")["result"], "ALLOW")
        self.assertEqual(self._eval("command-exec")["result"], "DENY")

    def test_permission_group_expansion(self):
        self._whitelist("allow-ops", destination="host-a", permission="ops")
        self.assertEqual(self._auth("get_system_info")["action"], "ALLOW")
        self.assertEqual(self._auth("exec", operand="id")["action"], "ALLOW")
        self.assertEqual(self._eval("ops")["result"], "ALLOW")
        self.assertEqual(self._eval("file-write")["result"], "DENY")
        self.assertEqual(self._auth("write_file", operand=str(self.out / "x"))["action"], "DENY")

    def test_destination_identity_isolation(self):
        self._whitelist("allow-a", destination="host-a", permission="read-only")
        self.assertEqual(self._auth("get_system_info", "host-a")["action"], "ALLOW")
        self.assertEqual(self._auth("get_system_info", "host-b")["action"], "DENY")
        text = self._text(self._call("get_system_info", "host-b"))
        self.assertTrue(text.startswith("DENY"), text)

    def test_enabled_disabled_rule_parity(self):
        self._whitelist("allow-info", destination="host-a", permission="read-only", enabled=False)
        self.assertEqual(self._eval("host-info")["result"], "DENY")
        self.assertEqual(self._auth("get_system_info")["action"], "DENY")
        v24.set_ai_access_rule(self.plane, "allow-info", enabled=True)
        self.assertEqual(self._eval("host-info")["result"], "ALLOW")
        self.assertEqual(self._auth("get_system_info")["action"], "ALLOW")

    def test_first_match_order_attribution(self):
        self._whitelist("alpha-rule", destination="host-a", permission="read-only")
        self._whitelist("beta-rule", destination="host-a", permission="read-only")
        ev = self._eval("host-info")
        auth = self._auth("get_system_info")
        self.assertEqual(ev["matched_rules"], ["alpha-rule", "beta-rule"])
        self.assertEqual(auth["matched_rules"], ["alpha-rule", "beta-rule"])
        self.assertEqual(auth["winner"]["name"], "alpha-rule")

    def test_file_path_scope_fail_closed_and_bounded(self):
        self._whitelist("allow-read", destination="host-a", permission="read-only")
        # Missing canonical path scope must not grant unrestricted file access.
        denied = self._auth("read_file", operand=str(self.vendor / "app.log"))
        self.assertEqual(denied["action"], "DENY")
        self.assertIn("path scope", denied["reason"])

        v24.set_ai_policy_path_scopes(self.plane, "allow-read", [self.vendor_glob])
        allowed = self._auth("read_file", operand=str(self.vendor / "app.log"))
        self.assertEqual(allowed["action"], "ALLOW")
        self.assertEqual(allowed["patterns"], [self.vendor_glob])
        self.assertEqual(allowed["winner"]["name"], "allow-read")

        outside = self._auth("read_file", operand=str(self.etc / "config.yaml"))
        self.assertEqual(outside["action"], "DENY")
        self.assertIn("outside allowed scope", outside["reason"])

        # Traversal / symlink escape remains denied by path_allowed.
        escape = self._auth(
            "read_file",
            operand=str(self.vendor / ".." / "etc" / "vendor" / "config.yaml"),
        )
        self.assertEqual(escape["action"], "DENY")

        # MCP must DENY before local side effects for out-of-scope paths.
        text = self._text(
            self._call("read_file", path=str(self.etc / "config.yaml"))
        )
        self.assertTrue(text.startswith("DENY"), text)

        ok = self._call("read_file", path=str(self.vendor / "app.log"))
        payload = json.loads(self._text(ok))
        self.assertIn("content_b64", payload)
        self.assertEqual(payload.get("bytes"), 7)
        self.assertNotEqual(payload.get("result"), "DENY")

    def test_legacy_split_brain_ignored(self):
        self._whitelist("allow-info", destination="host-a", permission="read-only")
        v24.set_ai_policy_path_scopes(self.plane, "allow-info", [self.vendor_glob])
        # Legacy DENYs the same capability/path that canonical ALLOWs.
        _seed_legacy_allow(
            self.plane,
            name="legacy-deny-file",
            principal="bot",
            endpoint="host-a",
            capability="read_file",
            paths=[self.etc_glob],
            action="deny",
        )
        # And a second legacy ALLOW with different destination that must not leak.
        _seed_legacy_allow(
            self.plane,
            name="legacy-allow-b",
            principal="bot",
            endpoint="host-b",
            capability="get_system_info",
            action="allow",
        )
        self.assertEqual(self._auth("get_system_info", "host-a")["action"], "ALLOW")
        self.assertEqual(self._auth("get_system_info", "host-b")["action"], "DENY")
        self.assertEqual(
            self._auth("read_file", operand=str(self.vendor / "app.log"))["action"],
            "ALLOW",
        )
        # Legacy path scopes must not authorize outside canonical scopes.
        self.assertEqual(
            self._auth("read_file", operand=str(self.etc / "config.yaml"))["action"],
            "DENY",
        )

    def test_audit_attribution_uses_canonical_rule(self):
        self._whitelist("canon-host", destination="host-a", permission="read-only")
        _seed_legacy_allow(
            self.plane,
            name="legacy-other",
            principal="bot",
            endpoint="host-a",
            capability="get_system_info",
            action="allow",
        )
        self._call("get_system_info")
        row = self.plane.conn.execute(
            "SELECT principal_name, endpoint_name, capability, result, matched_rule "
            "FROM ai_activity ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["principal_name"], "bot")
        self.assertEqual(row["endpoint_name"], "host-a")
        self.assertEqual(row["capability"], "get_system_info")
        self.assertEqual(row["result"], "ALLOW")
        self.assertEqual(row["matched_rule"], "canon-host")
        self.assertNotEqual(row["matched_rule"], "legacy-other")


if __name__ == "__main__":
    unittest.main()
