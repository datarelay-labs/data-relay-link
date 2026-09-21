#!/usr/bin/env python3
"""ConfigurationBundle: declarative change-set input for the control plane.

YAML is an input representation only. SQLite remains the authoritative store.
All apply paths converge on ChangePlan → ControlPlane mutation semantics.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from drlink_control_db import ControlPlaneError, utc_now_iso
from drlink_control_plane import (
    AI_CAPABILITIES,
    ConfirmationRequired,
    ConcurrencyError,
    ControlPlane,
    NAME_RE,
    normalize_object_value,
)

API_VERSION = "drlink.datarelay.run/v1alpha1"
KIND = "ConfigurationBundle"
SCHEMA_VERSION = "v1alpha1"

RESOURCE_FAMILIES = (
    "objects",
    "objectGroups",
    "clientGroups",
    "servicePresets",
    "publishedServices",
    "remoteAccess",
    "internetAccess",
    "fixedTcp",
    "aiPrincipals",
    "aiAccess",
    "enrollmentPlans",
    "mcpTls",
    "tests",
)

# Fields that must never appear in a valid Bundle (fail closed).
PROHIBITED_SECRET_KEYS = frozenset(
    {
        "ticket",
        "bootstrap_ticket",
        "bootstrapTicket",
        "rawTicket",
        "raw_ticket",
        "installUrl",
        "install_url",
        "installationUrl",
        "installation_url",
        "privateKey",
        "private_key",
        "clientSecret",
        "client_secret",
        "oauthClientSecret",
        "oauth_client_secret",
        "bearerToken",
        "bearer_token",
        "staticBearer",
        "static_bearer",
        "token",
        "secret",
        "password",
        "caPrivateKey",
        "ca_private_key",
        "transportSecret",
        "transport_secret",
        "enrollmentSecret",
        "enrollment_secret",
        "credential",
        "credentials",
        "accountKey",
        "account_key",
        "acmeAccountKey",
        "acme_account_key",
        "tlsPrivateKey",
        "tls_private_key",
        "privkey",
        "privKey",
        "fullchain",
        "dnsApiKey",
        "dns_api_key",
        "dnsApiSecret",
        "dns_api_secret",
    }
)

PROHIBITED_KEY_SUBSTRINGS = (
    "privatekey",
    "clientsecret",
    "bearertoken",
    "bootstrapticket",
    "enrollmentsecret",
)


class BundleError(ControlPlaneError):
    """ConfigurationBundle validation/apply failure."""


@dataclass
class PlannedChange:
    op: str  # CREATE|UPDATE|DELETE|REORDER|ENABLE|DISABLE|NO_CHANGE|CLIENT_ACTION_REQUIRED
    family: str
    name: str
    summary: str
    apply_fn: Optional[Callable[[ControlPlane], Any]] = None
    security: str = "unchanged"  # broadened|reduced|unchanged|uncertain
    client_action: bool = False


@dataclass
class ChangePlan:
    base_revision: int
    bundle_name: str
    bundle_hash: str
    input_path: str  # file|stdin
    changes: list[PlannedChange] = field(default_factory=list)
    embedded_tests: list[dict] = field(default_factory=list)
    test_results: list[dict] = field(default_factory=list)
    access_broadened: bool = False
    destructive: bool = False
    client_action_required: bool = False
    validation_ok: bool = True
    validation_errors: list[str] = field(default_factory=list)
    current_revision: Optional[int] = None

    @property
    def mutating_changes(self) -> list[PlannedChange]:
        return [
            c
            for c in self.changes
            if c.op not in ("NO_CHANGE", "CLIENT_ACTION_REQUIRED") and c.apply_fn
        ]

    @property
    def needs_confirmation(self) -> bool:
        return self.access_broadened or self.destructive or any(
            c.security == "broadened" for c in self.mutating_changes
        )


def _yaml():
    """Load PyYAML only when ConfigurationBundle YAML is actually used."""
    try:
        import yaml as _mod
    except ImportError as exc:
        raise BundleError(
            "PyYAML is required for ConfigurationBundle YAML input and export.\n"
            "Install the python3-yaml (or PyYAML) package, then retry."
        ) from exc
    return _mod


def _safe_load_yaml(text: str) -> Any:
    yaml = _yaml()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise BundleError("Malformed YAML: %s" % exc) from exc
    return data


def _walk_forbid_secrets(node: Any, path: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            key_s = str(key)
            lower = key_s.lower().replace("-", "").replace("_", "")
            child = "%s.%s" % (path, key_s) if path else key_s
            if key_s in PROHIBITED_SECRET_KEYS or any(s in lower for s in PROHIBITED_KEY_SUBSTRINGS):
                raise BundleError(
                    "Bundle contains prohibited secret field: %s\n"
                    "No changes were applied."
                    % child
                )
            # Reject values that look like install URLs with tickets.
            if isinstance(value, str):
                v = value.strip()
                if "/i/" in v and ("http://" in v or "https://" in v):
                    raise BundleError(
                        "Bundle contains prohibited installation URL with credential: %s\n"
                        "No changes were applied."
                        % child
                    )
                if v.startswith("bt1.") or v.startswith("zt1."):
                    raise BundleError(
                        "Bundle contains prohibited ticket material: %s\n"
                        "No changes were applied."
                        % child
                    )
            _walk_forbid_secrets(value, child)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_forbid_secrets(item, "%s[%s]" % (path, i))


def bundle_content_hash(raw_text: str) -> str:
    normalized = raw_text.replace("\r\n", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def parse_bundle(raw_text: str) -> dict:
    data = _safe_load_yaml(raw_text)
    if data is None:
        raise BundleError("Empty ConfigurationBundle")
    if not isinstance(data, dict):
        raise BundleError("ConfigurationBundle root must be a mapping")
    _walk_forbid_secrets(data)
    api = str(data.get("apiVersion") or "").strip()
    kind = str(data.get("kind") or "").strip()
    if api != API_VERSION:
        raise BundleError(
            "Unsupported apiVersion %r (expected %s)" % (api, API_VERSION)
        )
    if kind != KIND:
        raise BundleError("Unsupported kind %r (expected %s)" % (kind, KIND))
    meta = data.get("metadata") or {}
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise BundleError("metadata must be a mapping")
    name = str(meta.get("name") or "unnamed").strip() or "unnamed"
    if not NAME_RE.fullmatch(name) and name != "unnamed":
        raise BundleError("metadata.name is invalid: %s" % name)
    spec = data.get("spec")
    if spec is None:
        spec = {}
    if not isinstance(spec, dict):
        raise BundleError("spec must be a mapping")
    unknown = sorted(set(spec.keys()) - set(RESOURCE_FAMILIES))
    if unknown:
        raise BundleError(
            "Unknown resource families in spec (fail closed): %s" % ", ".join(unknown)
        )
    return {
        "apiVersion": api,
        "kind": kind,
        "metadata": {"name": name, **{k: v for k, v in meta.items() if k != "name"}},
        "spec": spec,
        "raw_hash": bundle_content_hash(raw_text),
    }


def read_bundle_input(source: str) -> tuple[str, str]:
    """Return (raw_text, input_path_label). source may be '-' for stdin."""
    if source == "-":
        raw = io.TextIOWrapper(io.BufferedReader(io.FileIO(0)), encoding="utf-8").read()
        # Prefer sys.stdin when available via caller; this path is for tests.
        return raw, "stdin"
    path = Path(source)
    if not path.is_file():
        raise BundleError("Configuration file not found: %s" % source)
    return path.read_text(encoding="utf-8"), "file"


def read_bundle_from_path_or_stdin(source: str, stdin_text: Optional[str] = None) -> tuple[str, str]:
    if source == "-":
        if stdin_text is None:
            import sys

            stdin_text = sys.stdin.read()
        return stdin_text, "stdin"
    path = Path(source)
    if not path.is_file():
        raise BundleError("Configuration file not found: %s" % source)
    return path.read_text(encoding="utf-8"), "file"


def _resource_state(item: dict) -> str:
    state = str(item.get("state") or "present").strip().lower()
    if state not in ("present", "absent"):
        raise BundleError("state must be present or absent (got %r)" % state)
    return state


def _require_name(item: dict, family: str) -> str:
    name = str(item.get("name") or "").strip()
    if not name:
        raise BundleError("%s entry requires name" % family)
    if not NAME_RE.fullmatch(name):
        raise BundleError("Invalid %s name: %s" % (family, name))
    return name


def _parse_service_token(token: str) -> tuple[str, int]:
    text = str(token or "").strip().lower()
    if "/" in text:
        proto, port_s = text.split("/", 1)
    elif text.startswith("tcp") and text[3:].isdigit():
        proto, port_s = "tcp", text[3:]
    else:
        raise BundleError("Invalid service token %r (expected protocol/port)" % token)
    if proto in ("https",):
        proto, port_s = "tcp", port_s or "443"
    elif proto in ("http",):
        proto, port_s = "tcp", port_s or "80"
    if proto not in ("tcp", "udp"):
        raise BundleError("Invalid protocol in service token: %s" % token)
    try:
        port = int(port_s)
    except ValueError as exc:
        raise BundleError("Invalid port in service token: %s" % token) from exc
    if port < 1 or port > 65535:
        raise BundleError("Port out of range in service token: %s" % token)
    return proto, port


def _as_str_list(value: Any, *, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, list):
        out = []
        for item in value:
            text = str(item).strip()
            if text:
                out.append(text)
        return out
    raise BundleError("%s must be a string or list" % field_name)


def _normalize_policy_rule_item(item: dict, family: str) -> dict:
    """Accept AI-friendly singular aliases alongside canonical plural fields."""
    out = dict(item)
    if "sources" not in out and "source" in out:
        out["sources"] = _as_str_list(out.get("source"), field_name="%s.source" % family)
    if "destinations" not in out and "destination" in out:
        out["destinations"] = _as_str_list(
            out.get("destination"), field_name="%s.destination" % family
        )
    if "services" not in out and "service" in out:
        svc = out.get("service")
        if isinstance(svc, dict):
            proto = str(svc.get("protocol") or svc.get("proto") or "tcp").strip().lower()
            port = svc.get("port")
            if port is None:
                raise BundleError("%s.service.port is required" % family)
            out["services"] = ["%s/%s" % (proto, port)]
        else:
            out["services"] = _as_str_list(svc, field_name="%s.service" % family)
    return out


def _network_values_broaden(old_vals: list[str], new_vals: list[str]) -> bool:
    """True when proposed network/host values enlarge effective coverage."""
    import ipaddress

    old_set = set(old_vals)
    new_set = set(new_vals)
    added = new_set - old_set
    if not added:
        return False
    old_nets = []
    for v in old_vals:
        try:
            old_nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            continue
    if not old_nets:
        return True
    for v in added:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            return True
        # Broadens when new coverage is not contained in some prior network,
        # or when it properly contains a prior network (supernet expansion).
        if any(old.subnet_of(net) and old != net for old in old_nets):
            return True
        if not any(net.subnet_of(old) for old in old_nets):
            return True
    return False


def _normalize_type(raw: str) -> str:
    text = str(raw or "").strip().lower()
    mapping = {
        "host": "host",
        "network": "network",
        "fqdn": "fqdn",
        "managed_endpoint": "managed_endpoint",
        "managed-endpoint": "managed_endpoint",
        "managedendpoint": "managed_endpoint",
    }
    if text not in mapping:
        raise BundleError("Object type must be Host, Network, or FQDN (got %r)" % raw)
    if mapping[text] == "managed_endpoint":
        raise BundleError(
            "Managed Endpoint cannot be created by ConfigurationBundle.\n"
            "Managed Endpoints are created only by Client enrollment."
        )
    return mapping[text]


def export_configuration(plane: ControlPlane) -> str:
    """Redacted deterministic export of server-owned configuration."""
    rev = plane.current_revision()
    spec: dict[str, Any] = {}

    objects = []
    for obj in plane.list_objects():
        if obj.get("origin") == "managed" or obj.get("type") == "managed_endpoint":
            # Export as reference-only metadata without inventing fake endpoints.
            objects.append(
                {
                    "name": obj["name"],
                    "type": "ManagedEndpoint",
                    "origin": "managed",
                    "state": "present",
                    "note": "read-only export; enrollment-owned",
                }
            )
            continue
        type_map = {"host": "Host", "network": "Network", "fqdn": "FQDN"}
        objects.append(
            {
                "name": obj["name"],
                "type": type_map.get(obj["type"], obj["type"]),
                "values": list(obj.get("values") or []),
                "description": obj.get("description") or "",
                "state": "present",
            }
        )
    if objects:
        spec["objects"] = objects

    groups = []
    for g in plane.conn.execute("SELECT * FROM object_groups ORDER BY name"):
        members = []
        for m in plane.conn.execute(
            "SELECT member_kind, member_id FROM object_group_members WHERE group_id = ?",
            (g["id"],),
        ):
            if m["member_kind"] == "object":
                row = plane.conn.execute(
                    "SELECT name FROM objects WHERE id = ?", (m["member_id"],)
                ).fetchone()
            else:
                row = plane.conn.execute(
                    "SELECT name FROM object_groups WHERE id = ?", (m["member_id"],)
                ).fetchone()
            if row:
                members.append(row["name"])
        groups.append(
            {
                "name": g["name"],
                "members": members,
                "description": g["description"] or "",
                "state": "present",
            }
        )
    if groups:
        spec["objectGroups"] = groups

    client_groups = []
    for g in plane.conn.execute("SELECT * FROM client_groups ORDER BY name"):
        members = []
        for m in plane.conn.execute(
            "SELECT client_id FROM client_group_members WHERE group_id = ?", (g["id"],)
        ):
            c = plane.conn.execute(
                "SELECT label, id FROM clients WHERE id = ?", (m["client_id"],)
            ).fetchone()
            if c:
                members.append(c["label"] or c["id"])
        client_groups.append(
            {
                "name": g["name"],
                "members": members,
                "description": g["description"] or "",
                "state": "present",
            }
        )
    if client_groups:
        spec["clientGroups"] = client_groups

    for plane_name, key in (("remote", "remoteAccess"), ("internet", "internetAccess")):
        rules = []
        for rule in plane.list_rules(plane_name):
            rules.append(
                {
                    "name": rule["name"],
                    "sources": list(rule["sources"]),
                    "destinations": list(rule["destinations"]),
                    "services": list(rule["services"]),
                    "action": str(rule["action"]).upper(),
                    "enabled": bool(rule["enabled"]),
                    "description": rule.get("description") or "",
                    "state": "present",
                }
            )
        if rules:
            spec[key] = rules

    fixed = []
    for row in plane.conn.execute("SELECT * FROM fixed_tcp ORDER BY name"):
        fixed.append(
            {
                "name": row["name"],
                "destHost": row["dest_host"] or "",
                "destPort": row["dest_port"],
                "listenPort": row["listen_port"],
                "enabled": bool(row["enabled"]),
                "state": "present",
            }
        )
    if fixed:
        spec["fixedTcp"] = fixed

    principals = []
    for row in plane.conn.execute("SELECT * FROM ai_principals ORDER BY name"):
        principals.append(
            {
                "name": row["name"],
                "description": row["description"] or "",
                "enabled": bool(row["enabled"]),
                "authMode": row["auth_mode"] if "auth_mode" in row.keys() else "static-bearer",
                "credentialStatus": row["credential_status"] or "none",
                "credentialFingerprint": row["credential_fingerprint"] or "",
                "state": "present",
            }
        )
    if principals:
        spec["aiPrincipals"] = principals

    ai_rules = []
    for row in plane.conn.execute("SELECT * FROM ai_access_rules ORDER BY position, name"):
        # Export human selectors (never opaque object/client IDs).
        target_names = []
        for t in plane.conn.execute(
            "SELECT target_kind, target_id FROM ai_rule_targets WHERE rule_id = ?",
            (row["id"],),
        ):
            kind = str(t["target_kind"] or "")
            if kind == "endpoint":
                obj = plane.conn.execute(
                    "SELECT name FROM objects WHERE id = ?", (t["target_id"],)
                ).fetchone()
                target_names.append(obj["name"] if obj else t["target_id"])
            elif kind in ("client-group", "client_group"):
                g = plane.conn.execute(
                    "SELECT name FROM client_groups WHERE id = ?", (t["target_id"],)
                ).fetchone()
                target_names.append(g["name"] if g else t["target_id"])
            elif kind == "client":
                c = plane.conn.execute(
                    "SELECT label, id FROM clients WHERE id = ?", (t["target_id"],)
                ).fetchone()
                target_names.append((c["label"] or c["id"]) if c else t["target_id"])
            else:
                target_names.append(plane._ref_name(kind, t["target_id"]))
        caps = [
            r["capability"]
            for r in plane.conn.execute(
                "SELECT capability FROM ai_rule_capabilities WHERE rule_id = ?",
                (row["id"],),
            )
        ]
        paths = [
            p["pattern"]
            for p in plane.conn.execute(
                "SELECT pattern FROM ai_path_scopes WHERE rule_id = ?",
                (row["id"],),
            )
        ]
        principal = plane.conn.execute(
            "SELECT name FROM ai_principals WHERE id = ?", (row["principal_id"],)
        ).fetchone()
        ai_rules.append(
            {
                "name": row["name"],
                "principal": principal["name"] if principal else "",
                "targets": target_names,
                "capabilities": caps,
                "paths": paths,
                "action": str(row["action"]).upper(),
                "enabled": bool(row["enabled"]),
                "description": row["description"] or "",
                "state": "present",
            }
        )
    if ai_rules:
        spec["aiAccess"] = ai_rules

    plans = []
    try:
        for row in plane.conn.execute("SELECT * FROM enrollment_plans ORDER BY name"):
            plans.append(
                {
                    "name": row["name"],
                    "platform": row["platform"],
                    "clientGroups": json.loads(row["client_groups_json"] or "[]"),
                    "initialServices": json.loads(row["initial_services_json"] or "[]"),
                    "description": row["description"] or "",
                    "state": "present",
                }
            )
    except Exception:
        pass
    if plans:
        spec["enrollmentPlans"] = plans

    # Non-secret MCP TLS intent only (never keys/certs).
    try:
        import drlink_mcp_tls as mcp_tls

        tls = mcp_tls.load_state(plane)
        if tls.get("mode") or tls.get("hostname"):
            spec["mcpTls"] = {
                "state": "present",
                "mode": tls.get("mode") or "",
                "hostname": tls.get("hostname") or "",
                "acmeEnvironment": tls.get("acme_environment") or "",
                "contactEmail": tls.get("contact_email") or "",
                "acmeDirectoryUrl": tls.get("acme_directory_url") or "",
                "certificateStatus": tls.get("status") or "",
                "fingerprintSha256": tls.get("fingerprint_sha256") or "",
                "issuer": tls.get("issuer") or "",
                "notAfter": tls.get("not_after") or "",
                "autoRenewal": bool(tls.get("renewal_enabled")),
            }
    except Exception:
        pass

    doc = {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {
            "name": "exported-configuration",
            "sourceRevision": rev,
            "exportedAt": utc_now_iso(),
        },
        "spec": spec,
    }
    return _yaml().safe_dump(doc, sort_keys=False, default_flow_style=False)


def _dup_check(items: list[dict], family: str) -> None:
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise BundleError("%s entries must be mappings" % family)
        name = _require_name(item, family).lower()
        if name in seen:
            raise BundleError("Duplicate %s identity: %s" % (family, item.get("name")))
        seen.add(name)


def build_change_plan(
    plane: ControlPlane,
    bundle: dict,
    *,
    input_path: str = "file",
) -> ChangePlan:
    spec = bundle["spec"]
    meta = bundle.get("metadata") or {}
    current = plane.current_revision()
    reviewed = meta.get("sourceRevision", meta.get("source_revision"))
    if reviewed is None or reviewed == "":
        base_revision = current
    else:
        try:
            base_revision = int(reviewed)
        except (TypeError, ValueError) as exc:
            raise BundleError(
                "metadata.sourceRevision must be an integer (got %r)" % reviewed
            ) from exc
        if base_revision < 0:
            raise BundleError("metadata.sourceRevision must be >= 0")
    plan = ChangePlan(
        base_revision=base_revision,
        bundle_name=str(meta.get("name") or "unnamed"),
        bundle_hash=str(bundle.get("raw_hash") or ""),
        input_path=input_path,
        embedded_tests=list(spec.get("tests") or []),
        current_revision=current,
    )
    # --- objects ---
    objects = list(spec.get("objects") or [])
    _dup_check(objects, "objects")
    for item in objects:
        name = _require_name(item, "objects")
        state = _resource_state(item)
        existing = plane.get_object(name)
        type_key = str(item.get("type") or "").strip().lower().replace("-", "").replace("_", "")
        # Exported Managed Endpoints are reference-only (enrollment-owned).
        # Round-trip must be NO_CHANGE, never CREATE/UPDATE/DELETE.
        if item.get("origin") == "managed" or type_key == "managedendpoint":
            if state == "absent":
                raise BundleError(
                    "Cannot delete Managed Endpoint %s via ConfigurationBundle" % name
                )
            if existing is not None and (
                existing["origin"] == "managed" or existing["type"] == "managed_endpoint"
            ):
                plan.changes.append(
                    PlannedChange(
                        "NO_CHANGE",
                        "objects",
                        name,
                        "managed endpoint unchanged (enrollment-owned)",
                    )
                )
            else:
                raise BundleError(
                    "Managed Endpoint cannot be created by ConfigurationBundle.\n"
                    "Managed Endpoints are created only by Client enrollment."
                )
            continue
        if state == "absent":
            if existing is None:
                plan.changes.append(
                    PlannedChange("NO_CHANGE", "objects", name, "object already absent")
                )
            else:
                if existing["origin"] == "managed" or existing["type"] == "managed_endpoint":
                    raise BundleError(
                        "Cannot delete Managed Endpoint %s via ConfigurationBundle" % name
                    )
                plan.destructive = True

                def _del(p=plane, n=name):
                    return p.unset_object(n)

                plan.changes.append(
                    PlannedChange(
                        "DELETE",
                        "objects",
                        name,
                        "delete object %s" % name,
                        apply_fn=lambda pl, fn=_del: fn(),
                        security="reduced",
                    )
                )
            continue
        obj_type = _normalize_type(item.get("type") or "")
        values = item.get("values")
        if values is None:
            values = []
        if not isinstance(values, list):
            raise BundleError("objects.values must be a list for %s" % name)
        norm_values = [normalize_object_value(obj_type, v) for v in values]
        description = str(item.get("description") or "")
        if existing is None:
            def _create(pl, n=name, t=obj_type, vals=norm_values, d=description):
                pl.set_object_type(n, t)
                for v in vals:
                    pl.set_object_value(n, v)
                if d:
                    pl.set_object_description(n, d)
                return {"operation": "create", "entity": {"type": "object", "name": n}}

            plan.changes.append(
                PlannedChange(
                    "CREATE",
                    "objects",
                    name,
                    "create object %s" % name,
                    apply_fn=_create,
                    security="unchanged",
                )
            )
        else:
            cur_vals = sorted(plane._object_values(existing["id"]))
            want_vals = sorted(norm_values)
            same_type = existing["type"] == obj_type
            same_desc = (existing["description"] or "") == description
            if same_type and cur_vals == want_vals and same_desc:
                plan.changes.append(
                    PlannedChange("NO_CHANGE", "objects", name, "object unchanged")
                )
            else:
                def _update(pl, n=name, t=obj_type, vals=norm_values, d=description, cur=cur_vals):
                    if pl.get_object(n)["type"] != t:
                        pl.set_object_type(n, t)
                    for v in cur:
                        if v not in vals:
                            pl.unset_object_value(n, v)
                    for v in vals:
                        if v not in cur:
                            pl.set_object_value(n, v)
                    pl.set_object_description(n, d)
                    return {"operation": "update", "entity": {"type": "object", "name": n}}

                security = "unchanged"
                if obj_type in ("network", "host") and _network_values_broaden(
                    cur_vals, want_vals
                ):
                    security = "broadened"
                    plan.access_broadened = True
                plan.changes.append(
                    PlannedChange(
                        "UPDATE",
                        "objects",
                        name,
                        "update object %s" % name,
                        apply_fn=_update,
                        security=security,
                    )
                )

    # --- object groups ---
    ogroups = list(spec.get("objectGroups") or [])
    _dup_check(ogroups, "objectGroups")
    for item in ogroups:
        name = _require_name(item, "objectGroups")
        state = _resource_state(item)
        existing = plane.get_object_group(name)
        members = item.get("members") or []
        if not isinstance(members, list):
            raise BundleError("objectGroups.members must be a list")
        if state == "absent":
            if existing is None:
                plan.changes.append(
                    PlannedChange("NO_CHANGE", "objectGroups", name, "group already absent")
                )
            else:
                plan.destructive = True

                def _del_g(n=name):
                    return lambda pl: pl.unset_object_group(n)

                plan.changes.append(
                    PlannedChange(
                        "DELETE",
                        "objectGroups",
                        name,
                        "delete object group %s" % name,
                        apply_fn=lambda pl, n=name: pl.unset_object_group(n),
                        security="reduced",
                    )
                )
            continue
        description = str(item.get("description") or "")
        if existing is None:
            def _create_g(pl, n=name, mems=list(members), d=description):
                pl.set_object_group(n, d or None)
                for m in mems:
                    pl.set_object_group_member(n, m)
                return {"operation": "create", "entity": {"type": "object-group", "name": n}}

            plan.changes.append(
                PlannedChange(
                    "CREATE",
                    "objectGroups",
                    name,
                    "create object group %s" % name,
                    apply_fn=_create_g,
                )
            )
        else:
            cur = []
            for m in plane.conn.execute(
                "SELECT member_kind, member_id FROM object_group_members WHERE group_id = ?",
                (existing["id"],),
            ):
                if m["member_kind"] == "object":
                    row = plane.conn.execute(
                        "SELECT name FROM objects WHERE id = ?", (m["member_id"],)
                    ).fetchone()
                else:
                    row = plane.conn.execute(
                        "SELECT name FROM object_groups WHERE id = ?", (m["member_id"],)
                    ).fetchone()
                if row:
                    cur.append(row["name"])
            if sorted(x.lower() for x in cur) == sorted(str(x).lower() for x in members) and (
                existing["description"] or ""
            ) == description:
                plan.changes.append(
                    PlannedChange("NO_CHANGE", "objectGroups", name, "group unchanged")
                )
            else:
                def _upd_g(pl, n=name, mems=list(members), d=description, old=list(cur)):
                    pl.set_object_group(n, d or None)
                    for m in old:
                        if m not in mems:
                            pl.unset_object_group_member(n, m)
                    for m in mems:
                        if m not in old:
                            pl.set_object_group_member(n, m)
                    return {"operation": "update", "entity": {"type": "object-group", "name": n}}

                plan.changes.append(
                    PlannedChange(
                        "UPDATE",
                        "objectGroups",
                        name,
                        "update object group %s" % name,
                        apply_fn=_upd_g,
                    )
                )

    # Detect group cycles in proposed membership (structural).
    _validate_group_acyclic(plane, ogroups)

    # --- client groups ---
    cgroups = list(spec.get("clientGroups") or [])
    _dup_check(cgroups, "clientGroups")
    for item in cgroups:
        name = _require_name(item, "clientGroups")
        state = _resource_state(item)
        members = item.get("members") or []
        if not isinstance(members, list):
            raise BundleError("clientGroups.members must be a list")
        existing = plane.conn.execute(
            "SELECT * FROM client_groups WHERE lower(name)=lower(?)", (name,)
        ).fetchone()
        if state == "absent":
            if existing is None:
                plan.changes.append(
                    PlannedChange("NO_CHANGE", "clientGroups", name, "client group already absent")
                )
            else:
                plan.destructive = True
                plan.changes.append(
                    PlannedChange(
                        "DELETE",
                        "clientGroups",
                        name,
                        "delete client group %s" % name,
                        apply_fn=lambda pl, n=name: _delete_client_group(pl, n),
                        security="reduced",
                    )
                )
            continue
        description = str(item.get("description") or "")
        if existing is None:
            def _cg_create(pl, n=name, mems=list(members), d=description):
                pl.set_client_group(n, d or None)
                for m in mems:
                    pl.set_client_group_member(n, m)
                return {"operation": "create", "entity": {"type": "client-group", "name": n}}

            plan.changes.append(
                PlannedChange(
                    "CREATE",
                    "clientGroups",
                    name,
                    "create client group %s" % name,
                    apply_fn=_cg_create,
                )
            )
        else:
            cur_members = [
                _normalize_client_group_member_token(plane, m)
                for m in _client_group_member_names(plane, existing["id"])
            ]
            want_members = [
                _normalize_client_group_member_token(plane, m) for m in members
            ]
            same_members = sorted(cur_members) == sorted(want_members)
            same_desc = (existing["description"] or "") == description
            if same_members and same_desc:
                plan.changes.append(
                    PlannedChange(
                        "NO_CHANGE",
                        "clientGroups",
                        name,
                        "client group unchanged",
                    )
                )
            else:
                plan.changes.append(
                    PlannedChange(
                        "UPDATE",
                        "clientGroups",
                        name,
                        "update client group %s" % name,
                        apply_fn=lambda pl, n=name, mems=list(members), d=description: _sync_client_group(
                            pl, n, mems, d
                        ),
                    )
                )

    # --- remote / internet access ---
    for family, plane_name in (("remoteAccess", "remote"), ("internetAccess", "internet")):
        rules = list(spec.get(family) or [])
        _dup_check(rules, family)
        for item in rules:
            _plan_policy_rule(plane, plan, family, plane_name, item)

    # --- fixed TCP ---
    for item in list(spec.get("fixedTcp") or []):
        if not isinstance(item, dict):
            raise BundleError("fixedTcp entries must be mappings")
        name = _require_name(item, "fixedTcp")
        state = _resource_state(item)
        if state == "absent":
            plan.destructive = True
            plan.changes.append(
                PlannedChange(
                    "DELETE",
                    "fixedTcp",
                    name,
                    "delete fixed-tcp %s" % name,
                    apply_fn=lambda pl, n=name: pl.unset_fixed_tcp(n)
                    if hasattr(pl, "unset_fixed_tcp")
                    else _unset_fixed_tcp(pl, n),
                    security="reduced",
                )
            )
            continue
        dest_host = item.get("destHost") or item.get("dest_host")
        dest_port = item.get("destPort") or item.get("dest_port")
        listen_port = item.get("listenPort") or item.get("listen_port")
        enabled = item.get("enabled")
        plan.changes.append(
            PlannedChange(
                "UPDATE",
                "fixedTcp",
                name,
                "set fixed-tcp %s" % name,
                apply_fn=lambda pl, n=name, dh=dest_host, dp=dest_port, lp=listen_port, en=enabled: pl.set_fixed_tcp(
                    n,
                    dest_host=str(dh) if dh is not None else None,
                    dest_port=int(dp) if dp is not None else None,
                    listen_port=int(lp) if lp is not None else None,
                    enabled=bool(en) if en is not None else None,
                ),
            )
        )

    # --- AI principals ---
    for item in list(spec.get("aiPrincipals") or []):
        if not isinstance(item, dict):
            raise BundleError("aiPrincipals entries must be mappings")
        name = _require_name(item, "aiPrincipals")
        state = _resource_state(item)
        if state == "absent":
            plan.destructive = True
            plan.changes.append(
                PlannedChange(
                    "DELETE",
                    "aiPrincipals",
                    name,
                    "delete ai-principal %s" % name,
                    apply_fn=lambda pl, n=name: pl.unset_ai_principal(n),
                    security="reduced",
                )
            )
            continue
        description = str(item.get("description") or "")
        enabled = item.get("enabled")
        existing = plane.conn.execute(
            "SELECT * FROM ai_principals WHERE lower(name)=lower(?)", (name,)
        ).fetchone()
        if existing is not None:
            same_desc = (existing["description"] or "") == description
            same_enabled = True if enabled is None else (bool(existing["enabled"]) == bool(enabled))
            if same_desc and same_enabled:
                plan.changes.append(
                    PlannedChange(
                        "NO_CHANGE",
                        "aiPrincipals",
                        name,
                        "ai-principal unchanged",
                    )
                )
                continue
        plan.changes.append(
            PlannedChange(
                "UPDATE",
                "aiPrincipals",
                name,
                "set ai-principal %s" % name,
                apply_fn=lambda pl, n=name, d=description, en=enabled: pl.set_ai_principal(
                    n, description=d or None, enabled=bool(en) if en is not None else None
                ),
            )
        )

    # --- AI access ---
    for item in list(spec.get("aiAccess") or []):
        _plan_ai_rule(plane, plan, item)

    # --- published services: existing client local target changes ---
    for item in list(spec.get("publishedServices") or []):
        if not isinstance(item, dict):
            raise BundleError("publishedServices entries must be mappings")
        name = _require_name(item, "publishedServices")
        client = str(item.get("client") or "").strip()
        # Server can toggle enabled / public reservation metadata, but local
        # target_host/target_port changes on existing clients require client action.
        if item.get("targetHost") or item.get("target_host") or item.get("targetPort") or item.get(
            "target_port"
        ):
            plan.client_action_required = True
            plan.changes.append(
                PlannedChange(
                    "CLIENT_ACTION_REQUIRED",
                    "publishedServices",
                    name,
                    "local target change for %s/%s requires client action" % (client, name),
                    client_action=True,
                )
            )
            continue
        if "enabled" in item and client:
            enabled = bool(item.get("enabled"))
            op = "ENABLE" if enabled else "DISABLE"
            plan.changes.append(
                PlannedChange(
                    op,
                    "publishedServices",
                    name,
                    "%s published service %s" % (op.lower(), name),
                    apply_fn=lambda pl, c=client, n=name, en=enabled: pl.set_published_service_enabled(
                        c, n, en
                    ),
                )
            )

    # --- enrollment plans (intent only; zero tickets) ---
    eplans = list(spec.get("enrollmentPlans") or [])
    _dup_check(eplans, "enrollmentPlans")
    for item in eplans:
        name = _require_name(item, "enrollmentPlans")
        state = _resource_state(item)
        platform = str(item.get("platform") or "linux").strip().lower()
        if platform not in ("linux", "windows", "macos"):
            raise BundleError("enrollmentPlans.platform must be linux|windows|macos")
        client_groups = item.get("clientGroups") or item.get("client_groups") or []
        initial = item.get("initialServices") or item.get("initial_services") or []
        if not isinstance(client_groups, list) or not isinstance(initial, list):
            raise BundleError("enrollmentPlans clientGroups/initialServices must be lists")
        description = str(item.get("description") or "")
        if state == "absent":
            plan.changes.append(
                PlannedChange(
                    "DELETE",
                    "enrollmentPlans",
                    name,
                    "delete enrollment plan %s" % name,
                    apply_fn=lambda pl, n=name: pl.delete_enrollment_plan(n),
                )
            )
        else:
            existing = None
            try:
                existing = plane.conn.execute(
                    "SELECT * FROM enrollment_plans WHERE lower(name)=lower(?)", (name,)
                ).fetchone()
            except Exception:
                existing = None
            if existing is not None:
                try:
                    cur_cg = json.loads(existing["client_groups_json"] or "[]")
                    cur_iv = json.loads(existing["initial_services_json"] or "[]")
                except Exception:
                    cur_cg, cur_iv = [], []
                same = (
                    str(existing["platform"] or "").lower() == platform
                    and list(cur_cg) == list(client_groups)
                    and list(cur_iv) == list(initial)
                    and (existing["description"] or "") == description
                )
                if same:
                    plan.changes.append(
                        PlannedChange(
                            "NO_CHANGE",
                            "enrollmentPlans",
                            name,
                            "enrollment plan unchanged",
                        )
                    )
                    continue
            plan.changes.append(
                PlannedChange(
                    "UPDATE",
                    "enrollmentPlans",
                    name,
                    "upsert enrollment plan %s (issues 0 tickets)" % name,
                    apply_fn=lambda pl, n=name, p=platform, cg=list(client_groups), iv=list(initial), d=description: pl.upsert_enrollment_plan(
                        n, platform=p, client_groups=cg, initial_services=iv, description=d
                    ),
                )
            )

    # --- MCP TLS non-secret intent (no ACME network I/O during apply) ---
    mcp_tls_items = list(spec.get("mcpTls") or [])
    if mcp_tls_items:
        import drlink_mcp_tls as mcp_tls

        if len(mcp_tls_items) > 1:
            raise BundleError("mcpTls accepts at most one resource entry")
        item = mcp_tls_items[0]
        if not isinstance(item, dict):
            raise BundleError("mcpTls entries must be mappings")
        # Fail closed on any secret-looking keys.
        mcp_tls.bundle_intent_from_item(item)  # validates + rejects secrets
        state = _resource_state(item)
        if state == "absent":
            plan.destructive = True
            plan.changes.append(
                PlannedChange(
                    "DELETE",
                    "mcpTls",
                    "mcp-tls",
                    "clear MCP TLS intent (secrets not purged by Bundle)",
                    apply_fn=lambda pl: __import__("drlink_mcp_tls", fromlist=["clear_tls"]).clear_tls(
                        pl, pl.root, purge_secrets=False
                    ),
                    security="reduced",
                )
            )
        else:
            intent = mcp_tls.bundle_intent_from_item(item)

            def _apply_tls(pl, intent=intent):
                return mcp_tls.configure_intent(
                    pl,
                    mode=intent.get("mode"),
                    hostname=intent.get("hostname"),
                    contact_email=intent.get("contact_email"),
                    acme_environment=intent.get("acme_environment"),
                    acme_directory_url=intent.get("acme_directory_url"),
                )

            plan.changes.append(
                PlannedChange(
                    "UPDATE",
                    "mcpTls",
                    intent.get("hostname") or "mcp-tls",
                    "configure MCP TLS intent only (run system certificate issue/import for ACME side effects)",
                    apply_fn=_apply_tls,
                )
            )

    # Security impact aggregation
    for ch in plan.mutating_changes:
        if ch.security == "broadened":
            plan.access_broadened = True
        if ch.op == "DELETE":
            plan.destructive = True

    return plan


def _delete_client_group(plane: ControlPlane, name: str):
    row = plane.conn.execute(
        "SELECT id FROM client_groups WHERE lower(name)=lower(?)", (name,)
    ).fetchone()
    if not row:
        return {"operation": "absent"}
    # Reuse unset if present
    if hasattr(plane, "unset_client_group"):
        return plane.unset_client_group(name)

    def write():
        plane.conn.execute("DELETE FROM client_group_members WHERE group_id = ?", (row["id"],))
        plane.conn.execute("DELETE FROM client_groups WHERE id = ?", (row["id"],))
        return {"entity": {"type": "client-group", "id": row["id"], "name": name}, "operation": "delete"}

    return plane._mutate("unset client-group %s" % name, "delete client group", write)


def _client_group_member_names(plane: ControlPlane, group_id: str) -> list[str]:
    names = []
    for m in plane.conn.execute(
        "SELECT client_id FROM client_group_members WHERE group_id = ?", (group_id,)
    ):
        c = plane.conn.execute(
            "SELECT label, id FROM clients WHERE id = ?", (m["client_id"],)
        ).fetchone()
        if c:
            names.append(c["label"] or c["id"])
        else:
            names.append(m["client_id"])
    return names


def _normalize_client_group_member_token(plane: ControlPlane, token: str) -> str:
    """Map client id/label selectors to a stable label-or-id display token."""
    text = str(token or "").strip()
    if not text:
        return text
    row = plane.conn.execute(
        "SELECT label, id FROM clients WHERE id = ? OR lower(label)=lower(?)",
        (text, text),
    ).fetchone()
    if row:
        return row["label"] or row["id"]
    return text


def _sync_client_group(plane: ControlPlane, name: str, members: list, description: str):
    plane.set_client_group(name, description or None)
    row = plane.conn.execute(
        "SELECT id FROM client_groups WHERE lower(name)=lower(?)", (name,)
    ).fetchone()
    cur = []
    for m in plane.conn.execute(
        "SELECT client_id FROM client_group_members WHERE group_id = ?", (row["id"],)
    ):
        c = plane.conn.execute(
            "SELECT label, id FROM clients WHERE id = ?", (m["client_id"],)
        ).fetchone()
        if c:
            cur.append(c["label"] or c["id"])
    for m in cur:
        if m not in members:
            # best-effort unset
            try:
                plane.unset_client_group_member(name, m)
            except Exception:
                pass
    for m in members:
        plane.set_client_group_member(name, m)
    return {"operation": "update", "entity": {"type": "client-group", "name": name}}


def _unset_fixed_tcp(plane: ControlPlane, name: str):
    def write():
        plane.conn.execute("DELETE FROM fixed_tcp WHERE lower(name)=lower(?)", (name,))
        return {"entity": {"type": "fixed-tcp", "name": name}, "operation": "delete"}

    return plane._mutate("unset fixed-tcp %s" % name, "delete fixed tcp", write)


def _validate_group_acyclic(plane: ControlPlane, ogroups: list[dict]) -> None:
    """Reject nested-group cycles in the proposed membership graph."""
    edges: dict[str, list[str]] = {}
    for item in ogroups:
        if _resource_state(item) == "absent":
            continue
        name = _require_name(item, "objectGroups").lower()
        edges[name] = [str(m).lower() for m in (item.get("members") or [])]

    def visit(node: str, stack: set[str]):
        if node in stack:
            raise BundleError("Object Group cycle detected involving %s" % node)
        stack.add(node)
        for child in edges.get(node, []):
            # Only follow group→group edges from the bundle; also check existing groups.
            if child in edges:
                visit(child, stack)
            else:
                g = plane.get_object_group(child)
                if g:
                    # existing nested groups already validated by control plane on write
                    pass
        stack.remove(node)

    for node in list(edges):
        visit(node, set())


def _plan_policy_rule(plane: ControlPlane, plan: ChangePlan, family: str, plane_name: str, item: dict):
    item = _normalize_policy_rule_item(item, family)
    name = _require_name(item, family)
    state = _resource_state(item)
    existing = plane._get_rule(plane_name, name)
    if state == "absent":
        if existing is None:
            plan.changes.append(PlannedChange("NO_CHANGE", family, name, "rule already absent"))
            return
        plan.destructive = True
        plan.changes.append(
            PlannedChange(
                "DELETE",
                family,
                name,
                "delete %s rule %s" % (plane_name, name),
                apply_fn=lambda pl, pn=plane_name, n=name: pl.unset_rule(pn, n),
                security="uncertain",
            )
        )
        return

    sources = item.get("sources") or []
    destinations = item.get("destinations") or []
    services = item.get("services") or []
    action = str(item.get("action") or "ALLOW").strip().lower()
    if action not in ("allow", "deny"):
        raise BundleError("%s.action must be ALLOW or DENY" % family)
    enabled = bool(item.get("enabled")) if "enabled" in item else False
    description = str(item.get("description") or "")
    if not isinstance(sources, list) or not isinstance(destinations, list) or not isinstance(services, list):
        raise BundleError("%s sources/destinations/services must be lists" % family)
    parsed_services = [_parse_service_token(s) for s in services]
    if plane_name == "internet":
        for proto, _port in parsed_services:
            if proto == "udp":
                raise BundleError(
                    "Internet Access v2.4 has a TCP/HTTP/HTTPS CONNECT datapath only; "
                    "UDP Service Objects cannot be selected (rule %r)." % name
                )
    if plane_name == "remote":
        for proto, _port in parsed_services:
            if proto == "udp":
                raise BundleError(
                    "Remote Access supports TCP and Fixed TCP only; "
                    "UDP cannot be selected (rule %r)." % name
                )

    # Impact: enabling ALLOW or expanding sources/dests is broadening.
    security = "unchanged"
    if existing is None:
        if action == "allow" and enabled:
            security = "broadened"
            plan.access_broadened = True
        op = "CREATE"
    else:
        view = plane._rule_view(existing)
        if action == "allow" and enabled and (
            not view["enabled"] or view["action"] != "allow"
        ):
            security = "broadened"
            plan.access_broadened = True
        elif set(map(str.lower, sources)) - set(map(str.lower, view["sources"])):
            if action == "allow" and enabled:
                security = "broadened"
                plan.access_broadened = True
        op = "UPDATE"
        want_services = sorted("%s/%s" % (p, port) for p, port in parsed_services)
        if (
            sorted(map(str.lower, view["sources"])) == sorted(map(str.lower, sources))
            and sorted(map(str.lower, view["destinations"])) == sorted(map(str.lower, destinations))
            and sorted(view["services"]) == want_services
            and view["action"] == action
            and view["enabled"] == enabled
            and (view.get("description") or "") == description
        ):
            plan.changes.append(PlannedChange("NO_CHANGE", family, name, "rule unchanged"))
            return

    def _apply(pl, pn=plane_name, n=name, srcs=list(sources), dsts=list(destinations),
               svcs=list(parsed_services), act=action, en=enabled, d=description):
        pl.set_rule(pn, n)
        # Replace memberships: clear then set
        rule = pl._require_rule(pn, n)
        pl.conn.execute("DELETE FROM rule_sources WHERE rule_id = ?", (rule["id"],))
        pl.conn.execute("DELETE FROM rule_destinations WHERE rule_id = ?", (rule["id"],))
        pl.conn.execute("DELETE FROM rule_services WHERE rule_id = ?", (rule["id"],))
        for s in srcs:
            pl.set_rule_source(pn, n, s)
        for s in dsts:
            pl.set_rule_destination(pn, n, s)
        for proto, port in svcs:
            pl.set_rule_service(pn, n, proto, port)
        pl.set_rule_action(pn, n, act)
        if d:
            pl.set_rule_description(pn, n, d)
        pl.set_rule_enabled(pn, n, en)
        return {"operation": "set-rule", "entity": {"type": "%s-access" % pn, "name": n}}

    plan.changes.append(
        PlannedChange(
            op,
            family,
            name,
            "%s %s rule %s" % (op.lower(), plane_name, name),
            apply_fn=_apply,
            security=security,
        )
    )


def _plan_ai_rule(plane: ControlPlane, plan: ChangePlan, item: dict):
    if not isinstance(item, dict):
        raise BundleError("aiAccess entries must be mappings")
    name = _require_name(item, "aiAccess")
    state = _resource_state(item)
    if state == "absent":
        plan.destructive = True
        plan.changes.append(
            PlannedChange(
                "DELETE",
                "aiAccess",
                name,
                "delete ai-access %s" % name,
                apply_fn=lambda pl, n=name: pl.unset_ai_rule(n),
                security="reduced",
            )
        )
        return
    principal = str(item.get("principal") or "").strip()
    if not principal:
        raise BundleError("aiAccess.principal is required for %s" % name)
    targets = item.get("targets") or []
    caps = item.get("capabilities") or []
    paths = item.get("paths") or []
    action = str(item.get("action") or "ALLOW").strip().lower()
    if action not in ("allow", "deny"):
        raise BundleError("aiAccess.action must be ALLOW or DENY")
    enabled = bool(item.get("enabled")) if "enabled" in item else False
    description = str(item.get("description") or "")
    if not isinstance(targets, list) or not isinstance(caps, list) or not isinstance(paths, list):
        raise BundleError("aiAccess targets/capabilities/paths must be lists")
    for c in caps:
        if str(c) not in AI_CAPABILITIES:
            raise BundleError("Unknown AI capability: %s" % c)

    existing_row = plane.conn.execute(
        "SELECT * FROM ai_access_rules WHERE lower(name)=lower(?)", (name,)
    ).fetchone()
    if existing_row is not None:
        view = plane._ai_rule_view(existing_row)
        # Normalize client-group:name display from view back to bare names.
        cur_targets = []
        for t in view.get("targets") or []:
            text = str(t)
            if text.startswith("client-group:"):
                text = text.split(":", 1)[1]
            cur_targets.append(text)
        same = (
            (view.get("principal") or "") == principal
            and sorted(cur_targets) == sorted(str(t) for t in targets)
            and sorted(view.get("capabilities") or []) == sorted(str(c) for c in caps)
            and sorted(view.get("paths") or []) == sorted(str(p) for p in paths)
            and str(view.get("action") or "").lower() == action
            and bool(view.get("enabled")) == enabled
            and (view.get("description") or "") == description
        )
        if same:
            plan.changes.append(
                PlannedChange("NO_CHANGE", "aiAccess", name, "ai-access unchanged")
            )
            return

    security = "unchanged"
    if action == "allow" and enabled:
        security = "broadened"
        plan.access_broadened = True

    def _apply(
        pl,
        n=name,
        p=principal,
        tg=list(targets),
        cp=list(caps),
        ph=list(paths),
        act=action,
        en=enabled,
        desc=description,
    ):
        pl.set_ai_rule(n)
        pl.set_ai_rule_principal(n, p)
        if desc:
            try:
                pl.set_ai_rule_description(n, desc)
            except Exception:
                pass
        for t in tg:
            token = str(t)
            if token.startswith("client-group:"):
                token = token.split(":", 1)[1]
            obj = pl.get_object(token)
            if obj is not None and obj["type"] == "managed_endpoint":
                pl.set_ai_rule_target(n, "endpoint", token)
                continue
            grp = pl.conn.execute(
                "SELECT id FROM client_groups WHERE lower(name)=lower(?)", (token,)
            ).fetchone()
            if grp:
                pl.set_ai_rule_target(n, "client-group", token)
                continue
            raise BundleError(
                "AI Access target %r must be a Managed Endpoint or Client Group" % token
            )
        for c in cp:
            pl.set_ai_rule_capability(n, c)
        for path in ph:
            pl.set_ai_rule_path(n, str(path))
        pl.set_ai_rule_action(n, act)
        pl.set_ai_rule_enabled(n, en)
        return {"operation": "set-ai-rule", "entity": {"type": "ai-access", "name": n}}

    plan.changes.append(
        PlannedChange(
            "UPDATE",
            "aiAccess",
            name,
            "set ai-access %s" % name,
            apply_fn=_apply,
            security=security,
        )
    )


def run_embedded_tests(plane: ControlPlane, tests: list[dict]) -> list[dict]:
    results = []
    for idx, test in enumerate(tests or []):
        if not isinstance(test, dict):
            raise BundleError("tests[%s] must be a mapping" % idx)
        name = str(test.get("name") or "test-%s" % (idx + 1))
        kind = str(test.get("kind") or test.get("type") or "").strip().lower()
        expect = str(test.get("expect") or test.get("result") or "").strip().upper()
        if expect not in ("ALLOW", "DENY"):
            raise BundleError("tests[%s].expect must be ALLOW or DENY" % name)
        try:
            if kind in ("remote", "remote-access", "remoteaccess"):
                result = plane.evaluate_remote_access(
                    str(test["source"]),
                    str(test["destination"]),
                    str(test.get("protocol") or "tcp"),
                    int(test["port"]),
                )
                decision = str(
                    result.get("decision")
                    or result.get("action")
                    or result.get("result")
                    or ""
                ).upper()
            elif kind in ("internet", "internet-access", "internetaccess"):
                result = plane.evaluate_internet_access(
                    str(test["source"]),
                    str(test["destination"]),
                    int(test["port"]),
                    str(test.get("protocol") or "tcp"),
                )
                decision = str(
                    result.get("decision")
                    or result.get("action")
                    or result.get("result")
                    or ""
                ).upper()
            elif kind in ("ai", "ai-access", "aiaccess"):
                result = plane.evaluate_ai_access(
                    str(test["principal"]),
                    str(test["endpoint"]),
                    str(test["capability"]),
                    test.get("operand"),
                )
                decision = str(
                    result.get("decision")
                    or result.get("action")
                    or result.get("result")
                    or ""
                ).upper()
            else:
                raise BundleError("Unknown embedded test kind: %s" % kind)
            # Normalize decision tokens
            if decision in ("ALLOW", "ALLOWED", "PERMIT"):
                decision = "ALLOW"
            elif decision in ("DENY", "DENIED", "BLOCK"):
                decision = "DENY"
            ok = decision == expect
            results.append({"name": name, "ok": ok, "expect": expect, "got": decision})
        except BundleError:
            raise
        except Exception as exc:
            results.append({"name": name, "ok": False, "expect": expect, "got": "ERROR", "error": str(exc)})
    return results


def format_plan_review(plan: ChangePlan) -> str:
    creates = sum(1 for c in plan.changes if c.op == "CREATE")
    updates = sum(1 for c in plan.changes if c.op in ("UPDATE", "ENABLE", "DISABLE", "REORDER"))
    deletes = sum(1 for c in plan.changes if c.op == "DELETE")
    client_actions = sum(1 for c in plan.changes if c.op == "CLIENT_ACTION_REQUIRED")
    nochange = sum(1 for c in plan.changes if c.op == "NO_CHANGE")
    tests_ok = all(r.get("ok") for r in plan.test_results) if plan.test_results else True
    lines = [
        "Configuration validation: PASS",
        "Policy tests:             %s"
        % (
            "%s/%s PASS" % (sum(1 for r in plan.test_results if r.get("ok")), len(plan.test_results))
            if plan.test_results
            else "none"
        ),
        "Base revision:            %s" % plan.base_revision,
        "Current revision:         %s"
        % (
            plan.current_revision
            if plan.current_revision is not None
            else plan.base_revision
        ),
        "",
        "Planned changes:",
        "  + %s CREATE" % creates,
        "  ~ %s UPDATE" % updates,
        "  - %s DELETE" % deletes,
        "  = %s NO CHANGE" % nochange,
        "  ! %s CLIENT ACTION REQUIRED" % client_actions,
        "",
        "Security impact:",
        "  Access widened:      %s" % ("YES" if plan.access_broadened else "NO"),
        "  Resources deleted:   %s" % ("YES" if plan.destructive else "NO"),
        "  Client action req:   %s" % ("YES" if plan.client_action_required else "NO"),
        "",
    ]
    for ch in plan.changes:
        if ch.op == "NO_CHANGE":
            continue
        lines.append("  [%s] %s/%s — %s" % (ch.op, ch.family, ch.name, ch.summary))
    if not tests_ok:
        lines.append("")
        lines.append("Embedded policy tests FAILED:")
        for r in plan.test_results:
            if not r.get("ok"):
                lines.append("  - %s expect=%s got=%s" % (r["name"], r["expect"], r["got"]))
    return "\n".join(lines) + "\n"


def prepare_plan(
    plane: ControlPlane,
    raw_text: str,
    *,
    input_path: str = "file",
    run_tests: bool = True,
) -> ChangePlan:
    bundle = parse_bundle(raw_text)
    plan = build_change_plan(plane, bundle, input_path=input_path)
    if run_tests and plan.embedded_tests:
        # Evaluate tests against proposed state in a scratch transaction.
        plane.conn.execute("BEGIN IMMEDIATE")
        try:
            plane._batch_mode = True
            plane._batch_results = []
            try:
                def _prep_order(ch: PlannedChange) -> tuple:
                    family_rank = {
                        "remoteAccess": 10,
                        "internetAccess": 10,
                        "aiAccess": 10,
                        "fixedTcp": 20,
                        "publishedServices": 20,
                        "objectGroups": 30,
                        "clientGroups": 30,
                        "objects": 40,
                        "aiPrincipals": 50,
                        "servicePresets": 50,
                        "enrollmentPlans": 60,
                        "mcpTls": 70,
                    }
                    if ch.op == "DELETE":
                        return (0, family_rank.get(ch.family, 99), ch.name)
                    if ch.op == "CREATE":
                        return (1, -family_rank.get(ch.family, 99), ch.name)
                    return (2, family_rank.get(ch.family, 99), ch.name)

                for ch in sorted(plan.mutating_changes, key=_prep_order):
                    ch.apply_fn(plane)
                plan.test_results = run_embedded_tests(plane, plan.embedded_tests)
            finally:
                plane._batch_mode = False
                plane._batch_results = []
        finally:
            plane.conn.execute("ROLLBACK")
        if not all(r.get("ok") for r in plan.test_results):
            raise BundleError(
                "Embedded policy tests failed.\nNo changes were applied.\n%s"
                % format_plan_review(plan)
            )
    return plan


def apply_change_plan(
    plane: ControlPlane,
    plan: ChangePlan,
    *,
    confirm: Optional[bool] = None,
) -> dict:
    if not plan.mutating_changes and not plan.client_action_required:
        # Pure no-op: do not advance revision.
        plane._audit_bundle_attempt(plan, result="NO_CHANGE", result_revision=plan.base_revision)
        return {
            "status": "NO_CHANGE",
            "revision": plan.base_revision,
            "tickets_issued": 0,
            "client_action_required": plan.client_action_required,
        }

    if plan.needs_confirmation and not (
        confirm is True
        or str((__import__("os").environ.get("DRLINK_CONFIRM") or "")).strip().lower()
        in ("yes", "y", "1", "true")
    ):
        raise ConfirmationRequired(
            format_plan_review(plan) + "\nApply these changes? [y/N]",
            {
                "access_broadened": plan.access_broadened,
                "destructive": plan.destructive,
                "bundle": plan.bundle_name,
            },
        )

    if not plan.mutating_changes:
        # Only CLIENT_ACTION_REQUIRED entries — no server mutation.
        plane._audit_bundle_attempt(plan, result="CLIENT_ACTION_REQUIRED", result_revision=plan.base_revision)
        return {
            "status": "CLIENT_ACTION_REQUIRED",
            "revision": plan.base_revision,
            "tickets_issued": 0,
            "client_action_required": True,
        }

    def _apply_order(ch: PlannedChange) -> tuple:
        # Deletes of dependents before owners; creates of owners before dependents.
        family_rank = {
            "remoteAccess": 10,
            "internetAccess": 10,
            "aiAccess": 10,
            "fixedTcp": 20,
            "publishedServices": 20,
            "objectGroups": 30,
            "clientGroups": 30,
            "objects": 40,
            "aiPrincipals": 50,
            "servicePresets": 50,
            "enrollmentPlans": 60,
            "mcpTls": 70,
        }
        if ch.op == "DELETE":
            return (0, family_rank.get(ch.family, 99), ch.name)
        if ch.op == "CREATE":
            return (1, -family_rank.get(ch.family, 99), ch.name)
        return (2, family_rank.get(ch.family, 99), ch.name)

    ordered = sorted(plan.mutating_changes, key=_apply_order)

    plane.conn.execute("BEGIN IMMEDIATE")
    try:
        current = plane.current_revision()
        if current != plan.base_revision:
            raise ConcurrencyError(
                "REVISION_CONFLICT\n"
                "Base revision: %s\n"
                "Current revision: %s\n"
                "No changes were applied.\n"
                "Re-run diff/test against current state."
                % (plan.base_revision, current)
            )
        plane._batch_mode = True
        plane._batch_results = []
        try:
            for ch in ordered:
                ch.apply_fn(plane)
        finally:
            plane._batch_mode = False
        if not plane._batch_results:
            plane.conn.execute("ROLLBACK")
            plane._batch_results = []
            return {
                "status": "NO_CHANGE",
                "revision": plan.base_revision,
                "tickets_issued": 0,
                "client_action_required": plan.client_action_required,
            }
        meaningful = [
            r
            for r in plane._batch_results
            if not (
                isinstance(r, dict)
                and str(r.get("operation") or "") in ("noop", "exists", "absent")
            )
        ]
        if not meaningful:
            plane.conn.execute("ROLLBACK")
            plane._batch_results = []
            plane._audit_bundle_attempt(plan, result="NO_CHANGE", result_revision=plan.base_revision)
            return {
                "status": "NO_CHANGE",
                "revision": plan.base_revision,
                "tickets_issued": 0,
                "client_action_required": plan.client_action_required,
            }
        summary = "configuration-bundle:%s changes=%s" % (
            plan.bundle_name,
            len(meaningful),
        )
        rev = plane._write_revision(
            "system apply configuration",
            summary,
            snapshot={
                "bundle_name": plan.bundle_name,
                "bundle_hash": plan.bundle_hash,
                "input_path": plan.input_path,
                "change_count": len(meaningful),
            },
        )
        plane._audit(
            revision=rev,
            action="system apply configuration",
            entity_type="configuration-bundle",
            entity_id=plan.bundle_name,
            operation="apply",
            after=summary,
            impact=json.dumps(
                {
                    "bundle_hash": plan.bundle_hash,
                    "input_path": plan.input_path,
                    "access_broadened": plan.access_broadened,
                    "destructive": plan.destructive,
                    "base_revision": plan.base_revision,
                },
                sort_keys=True,
            )[:2000],
        )
        plane.conn.execute("COMMIT")
        plane._batch_results = []
    except ConfirmationRequired:
        plane.conn.execute("ROLLBACK")
        raise
    except ConcurrencyError:
        plane.conn.execute("ROLLBACK")
        raise
    except Exception:
        plane.conn.execute("ROLLBACK")
        raise
    try:
        plane.compile_runtime()
    except Exception as exc:
        plane._mark_generation_failed(str(exc))
        raise BundleError(
            "Configuration committed but runtime activation failed: %s" % exc
        ) from exc
    return {
        "status": "APPLIED",
        "revision": rev,
        "tickets_issued": 0,
        "client_action_required": plan.client_action_required,
        "bundle_hash": plan.bundle_hash,
    }
