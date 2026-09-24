#!/usr/bin/env python3
"""Data Relay Link MCP Bridge (MCP Streamable HTTP).

Transport: Streamable HTTP POST /mcp (stateless for 2026-07-28; classic
initialize handshake supported for OpenAI Plugin / older MCP hosts).
Authentication modes:
  Static Bearer — operator-issued drk_ tokens bound to an AI Identity
  OAuth         — built-in OAuth 2.1 authorization server (authorization_code+PKCE
                  S256 and client_credentials) issuing distinct expiring tokens
Protected Resource Metadata: RFC 9728
Authorization uses the canonical v2.4 AI Access model (ai_policy_rules /
authorize_ai_capability_v24) on every tools/call — the same semantics as
public ``test ai-access``. Legacy ai_access_rules are not an authority.
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from drlink_ai_agent import AgentLoop, execute_local
from drlink_control_db import ControlPlaneError, resolve_root
from drlink_control_plane import (
    AI_CAPABILITIES,
    ControlPlane,
    MCP_AUTH_MODEL,
    OAuthPendingCapacityError,
)
from frp_client_registry import request_source_ip
import drlink_v24 as v24

MCP_PROTOCOL_VERSION = "2026-07-28"
# Handshake-era versions accepted via classic initialize (OpenAI Plugin / older MCP hosts).
HANDSHAKE_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
LATEST_HANDSHAKE_VERSION = "2025-11-25"
MCP_TRANSPORT = "streamable-http"
MCP_SERVER_NAME = "data-relay-link"
MCP_SERVER_VERSION = "2.4.0"
MCP_SERVER_TITLE = "Data Relay Link"
MCP_INSTRUCTIONS = (
    "Data Relay Link MCP Bridge. Tools operate on Managed Hosts authorized by "
    "AI Access policy. Authenticated does not mean authorized. Every tool requires "
    "OAuth; DRLink re-evaluates AI Identity and AI Access on each tools/call."
)
SERVER_INFO_META = "io.modelcontextprotocol/serverInfo"
WWW_AUTHENTICATE_META = "mcp/www_authenticate"
DEFAULT_LISTEN = "127.0.0.1"
DEFAULT_PORT = 6103
HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022
INVALID_PARAMS = -32602
LOCAL_ORIGINS = ("http://127.0.0.1", "http://localhost", "https://127.0.0.1", "https://localhost")
PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPS_META = "io.modelcontextprotocol/clientCapabilities"
NAME_BEARING = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
OAUTH_TOOL_SECURITY_SCHEMES = ({"type": "oauth2", "scopes": ["drlink.ai"]},)
# Public MCP/OAuth rate limits and authorize admission key on a trusted source.
# Peer address is the source unless the TCP peer is loopback, in which case the
# local reverse proxy's X-Forwarded-For / X-Real-IP is accepted. Those headers
# must be overwritten by nginx from $remote_addr. Forwarded headers from any
# other peer are ignored.
OAUTH_AUTHORIZE_RATE_LIMIT = 12
OAUTH_AUTHORIZE_RATE_WINDOW_S = 60


def trusted_oauth_source(peer: str, headers) -> str:
    """Admission source for public OAuth authorize.

    Uses the repository trusted-peer rule: forwarded headers count only when the
    TCP peer is loopback. Any other peer is the source itself.
    """
    return str(request_source_ip(peer, headers) or "")


def public_rate_source(peer: str, headers) -> str:
    """Rate-limit identity for public MCP/OAuth surfaces.

    Same trusted-peer rule as authorize admission. An empty identity falls back
    to the socket peer so the bucket stays finite.
    """
    source = trusted_oauth_source(peer, headers)
    if source:
        return source
    text = str(peer or "").strip()
    return text or "unknown"

# name, title, description, props, annotations
TOOL_DEFS = (
    (
        "list_hosts",
        "List Managed Hosts",
        "List Managed Hosts this identity may target",
        {},
        {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
    ),
    (
        "get_host",
        "Get Managed Host",
        "Get one Managed Host",
        {"endpoint": "string"},
        {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
    ),
    (
        "get_system_info",
        "Get system info",
        "Read uname/system identity from a Managed Host",
        {"endpoint": "string"},
        {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
    ),
    (
        "exec",
        "Execute command",
        "Run a shell command on a Managed Host",
        {"endpoint": "string", "command": "string"},
        {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    ),
    (
        "read_file",
        "Read file",
        "Read a file within allowed path scopes",
        {"endpoint": "string", "path": "string"},
        {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
    ),
    (
        "write_file",
        "Write file",
        "Write a file within allowed path scopes",
        {"endpoint": "string", "path": "string", "content": "string"},
        {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    ),
    (
        "upload_file",
        "Upload file",
        "Upload bytes to an allowed path",
        {"endpoint": "string", "path": "string", "content": "string"},
        {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    ),
    (
        "download_file",
        "Download file",
        "Download a file from an allowed path",
        {"endpoint": "string", "path": "string"},
        {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
    ),
    (
        "list_processes",
        "List processes",
        "List processes on a Managed Host",
        {"endpoint": "string"},
        {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
    ),
)

ENDPOINT_TOOLS = frozenset(
    {
        "get_system_info",
        "exec",
        "read_file",
        "write_file",
        "upload_file",
        "download_file",
        "list_processes",
    }
)


def _server_info():
    return {
        "name": MCP_SERVER_NAME,
        "title": MCP_SERVER_TITLE,
        "version": MCP_SERVER_VERSION,
    }


def _with_server_meta(result):
    payload = dict(result) if isinstance(result, dict) else {"value": result}
    meta = dict(payload.get("_meta") or {})
    meta[SERVER_INFO_META] = _server_info()
    payload["_meta"] = meta
    return payload


def _jsonrpc_error(req_id, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _jsonrpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": _with_server_meta(result)}


def _text_result(text: str, *, is_error: bool = False) -> dict:
    out = {"content": [{"type": "text", "text": text}], "resultType": "complete"}
    if is_error:
        out["isError"] = True
    return out


def _structured_result(data, *, text: Optional[str] = None, is_error: bool = False) -> dict:
    """Return text content plus structuredContent for hosts that prefer typed results."""
    if text is None:
        text = json.dumps(data, indent=2)
    structured = data if isinstance(data, dict) else {"value": data}
    out = {
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "resultType": "complete",
    }
    if is_error:
        out["isError"] = True
    return out


def _tool_descriptor(name: str, title: str, desc: str, props: dict, annotations: dict) -> dict:
    schema_props = {k: {"type": v} for k, v in props.items()}
    required = list(props.keys())
    input_schema = {"type": "object", "properties": schema_props}
    if required:
        input_schema["required"] = required
    return {
        "name": name,
        "title": title,
        "description": desc,
        "inputSchema": input_schema,
        "annotations": dict(annotations),
        "securitySchemes": [dict(s) for s in OAUTH_TOOL_SECURITY_SCHEMES],
    }


def _header(headers, name: str) -> str:
    return headers.get(name) or headers.get(name.lower()) or headers.get(name.title()) or ""


def _decode_mcp_header(value: str) -> str:
    text = str(value or "")
    if text.startswith("=?base64?") and text.endswith("?="):
        import base64

        try:
            return base64.b64decode(text[len("=?base64?") : -2]).decode("utf-8")
        except Exception:
            return text
    return text


def _requested_protocol(body: dict, headers) -> Optional[str]:
    """Best-effort protocol version from classic initialize params, _meta, or HTTP header."""
    params = body.get("params") if isinstance(body.get("params"), dict) else None
    if isinstance(params, dict):
        classic = params.get("protocolVersion")
        if isinstance(classic, str) and classic.strip():
            return classic.strip()
        meta = params.get("_meta")
        if isinstance(meta, dict):
            modern = meta.get(PROTOCOL_VERSION_META)
            if isinstance(modern, str) and modern.strip():
                return modern.strip()
    hdr = _header(headers, "MCP-Protocol-Version")
    return hdr.strip() if hdr else None


def _is_handshake_version(version: Optional[str]) -> bool:
    return isinstance(version, str) and version in HANDSHAKE_PROTOCOL_VERSIONS


def _is_modern_version(version: Optional[str]) -> bool:
    return isinstance(version, str) and version == MCP_PROTOCOL_VERSION


def _negotiate_handshake_version(requested: Optional[str]) -> Optional[str]:
    if not requested:
        return LATEST_HANDSHAKE_VERSION
    if requested in HANDSHAKE_PROTOCOL_VERSIONS:
        return requested
    return None

class MCPBridge:
    def __init__(self, root: Optional[str] = None, plane: Optional[ControlPlane] = None, *, auto_agents: bool = False):
        self.root = root or resolve_root()
        self.plane = plane or ControlPlane(self.root)
        self.running_ops = {}
        self._lock = threading.Lock()
        self._agents = {}
        self._agent_stop = threading.Event()
        self._job_results = {}
        self.listen_host = DEFAULT_LISTEN
        self.listen_port = DEFAULT_PORT
        # Production default is False: Managed Host workers claim jobs themselves.
        # auto_agents is a hermetic test seam only (see refresh_local_agents).
        self.auto_agents = auto_agents

    def canonical_public_base(self) -> str:
        """Issuer/resource base from configured control identity, never request Host."""
        url = self.plane.mcp_public_url()
        if url and url != "Not configured":
            return url[:-4] if url.endswith("/mcp") else url.rstrip("/")
        return "http://%s:%s" % (self.listen_host, self.listen_port)

    def canonical_resource(self) -> str:
        url = self.plane.mcp_public_url()
        if url and url != "Not configured":
            return url
        return self.canonical_public_base() + "/mcp"

    def _require_canonical_resource(self, resource: str) -> str:
        wanted = self.canonical_resource()
        if str(resource or "") != wanted:
            raise ControlPlaneError("resource must be exactly %s" % wanted)
        return wanted

    def close(self) -> None:
        self._agent_stop.set()
        for _cid, (_stop, thread) in list(self._agents.items()):
            thread.join(timeout=1)
        self._agents.clear()

    def refresh_local_agents(self, base_url: Optional[str] = None) -> None:
        """Test-only: start in-process AgentLoop threads for connected clients.

        Production MCP Bridge must never impersonate Managed Hosts. This method
        requires both auto_agents=True and DRLINK_AI_TEST_LOCAL_AGENTS=1.
        """
        if not self.auto_agents:
            return
        if os.environ.get("DRLINK_AI_TEST_LOCAL_AGENTS") != "1":
            raise RuntimeError(
                "refresh_local_agents is a hermetic test seam only; "
                "set DRLINK_AI_TEST_LOCAL_AGENTS=1 or run a real Managed Host worker"
            )
        url = base_url or ("http://127.0.0.1:%s" % self.listen_port)
        for client in self.plane.connected_clients():
            cid = client["id"]
            if cid in self._agents:
                continue
            token = self.plane.issue_agent_credential(cid, rotate=True)
            if not token:
                continue
            stop = threading.Event()

            def _run(token=token, stop=stop, url=url):
                loop = AgentLoop(url, token, stop_event=stop)
                while not stop.is_set() and not self._agent_stop.is_set():
                    try:
                        loop.run_once()
                    except Exception:
                        pass
                    stop.wait(0.05)

            thread = threading.Thread(target=_run, daemon=True, name="drlink-ai-agent-%s" % cid[:8])
            thread.start()
            self._agents[cid] = (stop, thread)

    def authenticate(self, headers) -> Optional[Any]:
        auth = _header(headers, "Authorization")
        if not auth.lower().startswith("bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        if not token:
            return None
        resource = self.canonical_resource()
        with self._lock:
            return self.plane.authenticate_principal(token, resource=resource)

    def authenticate_agent(self, headers) -> Optional[str]:
        auth = _header(headers, "Authorization")
        if not auth.lower().startswith("bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        with self._lock:
            return self.plane.authenticate_agent(token)

    def oauth_metadata(self, headers=None) -> dict:
        base = self.canonical_public_base()
        resource = self.canonical_resource()
        return {
            "resource": resource,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["drlink.ai", "offline_access"],
            "resource_name": "Data Relay Link MCP Bridge",
            "resource_documentation": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization",
        }

    def as_metadata(self, headers=None) -> dict:
        base = self.canonical_public_base()
        return {
            "issuer": base,
            "authorization_endpoint": base + "/oauth/authorize",
            "token_endpoint": base + "/oauth/token",
            "registration_endpoint": base + "/oauth/register",
            "revocation_endpoint": base + "/oauth/revoke",
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
            "scopes_supported": ["drlink.ai", "offline_access"],
            "resource_indicators_supported": True,
            "client_id_metadata_document_supported": True,
        }

    def issue_oauth_token(self, fields: dict, headers=None) -> Optional[dict]:
        grant = str(fields.get("grant_type") or "")
        if grant == "refresh_token":
            resource = str(fields.get("resource") or "")
            return self.plane.exchange_refresh_token(
                refresh_token=str(fields.get("refresh_token") or ""),
                client_id=str(fields.get("client_id") or ""),
                resource=resource,
            )
        resource = self._require_canonical_resource(str(fields.get("resource") or ""))
        if grant == "client_credentials":
            issued = self.plane.client_credentials_token(
                str(fields.get("client_id") or ""),
                str(fields.get("client_secret") or ""),
                resource,
            )
            return issued
        if grant == "authorization_code":
            return self.plane.exchange_authorization_code(
                code=str(fields.get("code") or ""),
                verifier=str(fields.get("code_verifier") or ""),
                redirect_uri=str(fields.get("redirect_uri") or ""),
                resource=resource,
                client_id=str(fields.get("client_id") or ""),
            )
        return None

    def register_oauth_client(self, metadata: dict) -> dict:
        return self.plane.register_oauth_client(metadata)

    def revoke_oauth_credential(self, token: str) -> bool:
        return self.plane.revoke_oauth_credential(token)

    def validate_origin(self, headers) -> Optional[str]:
        origin = _header(headers, "Origin")
        if not origin:
            return None
        allowed = os.environ.get("DRLINK_MCP_ALLOWED_ORIGINS") or ""
        extras = [x.strip() for x in allowed.split(",") if x.strip()]
        host = (_header(headers, "Host") or "").split(":")[0].lower()
        local_host = host in ("127.0.0.1", "localhost", "::1")
        if origin.startswith(LOCAL_ORIGINS) or origin in extras:
            return None
        # Public MCP: allow HTTPS browser hosts (Cursor/Claude/ChatGPT) and
        # reject DNS-rebinding Origins against loopback plus plaintext http.
        if not local_host and origin.startswith("https://"):
            return None
        return origin

    def www_authenticate_value(self) -> str:
        base = self.canonical_public_base()
        return (
            'Bearer realm="drlink-mcp", '
            'resource_metadata="%s/.well-known/oauth-protected-resource", '
            'scope="drlink.ai", '
            'error="invalid_token", '
            'error_description="Authentication required"'
        ) % base

    def www_authenticate_meta(self) -> dict:
        return {WWW_AUTHENTICATE_META: [self.www_authenticate_value()]}

    def validate_headers(self, body: dict, headers) -> Optional[tuple]:
        req_id = body.get("id")
        method = str(body.get("method") or "")
        params = body.get("params") if isinstance(body.get("params"), dict) else None
        requested = _requested_protocol(body, headers)
        mcp_method = _header(headers, "Mcp-Method")

        # Classic initialize / initialized / ping may omit the 2026 _meta envelope.
        if method == "initialize":
            if mcp_method and mcp_method != method:
                return 400, _jsonrpc_error(
                    req_id,
                    HEADER_MISMATCH,
                    "Mcp-Method header does not match the request body's method",
                    {"name": "HeaderMismatch"},
                )
            # Only classic params.protocolVersion selects the handshake version.
            # Modern MCP-Protocol-Version / _meta stamps are ignored here so hosts
            # that probe initialize before discover still negotiate handshake-era.
            classic = None
            if isinstance(params, dict) and isinstance(params.get("protocolVersion"), str):
                classic = params.get("protocolVersion").strip() or None
            if _is_modern_version(classic):
                return 400, _jsonrpc_error(
                    req_id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "Unsupported protocol version for initialize; use server/discover for %s"
                    % MCP_PROTOCOL_VERSION,
                    {
                        "supported": [LATEST_HANDSHAKE_VERSION],
                        "modern": [MCP_PROTOCOL_VERSION],
                        "requested": classic,
                    },
                )
            if classic and not _is_handshake_version(classic):
                return 400, _jsonrpc_error(
                    req_id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "Unsupported protocol version",
                    {
                        "supported": list(HANDSHAKE_PROTOCOL_VERSIONS),
                        "modern": [MCP_PROTOCOL_VERSION],
                        "requested": classic,
                    },
                )
            return None

        if method in ("notifications/initialized", "ping"):
            if mcp_method and mcp_method != method:
                return 400, _jsonrpc_error(
                    req_id,
                    HEADER_MISMATCH,
                    "Mcp-Method header does not match the request body's method",
                    {"name": "HeaderMismatch"},
                )
            # ping is allowed on both eras; notifications/initialized is handshake-only.
            if method == "notifications/initialized" and _is_modern_version(requested):
                return 400, _jsonrpc_error(
                    req_id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "notifications/initialized is not used on %s; protocol is stateless"
                    % MCP_PROTOCOL_VERSION,
                    {"supported": list(HANDSHAKE_PROTOCOL_VERSIONS), "requested": requested},
                )
            if requested and not (_is_handshake_version(requested) or _is_modern_version(requested)):
                return 400, _jsonrpc_error(
                    req_id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "Unsupported protocol version",
                    {
                        "supported": list(HANDSHAKE_PROTOCOL_VERSIONS) + [MCP_PROTOCOL_VERSION],
                        "requested": requested,
                    },
                )
            return None

        # Handshake-era operational requests: header-based, no 2026 _meta envelope required.
        if _is_handshake_version(requested) or (
            not requested and isinstance(params, dict) and not isinstance(params.get("_meta"), dict)
        ):
            proto = _header(headers, "MCP-Protocol-Version")
            if proto and not _is_handshake_version(proto):
                return 400, _jsonrpc_error(
                    req_id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "Unsupported protocol version",
                    {"supported": list(HANDSHAKE_PROTOCOL_VERSIONS), "requested": proto},
                )
            if mcp_method and mcp_method != method:
                return 400, _jsonrpc_error(
                    req_id,
                    HEADER_MISMATCH,
                    "Mcp-Method header does not match the request body's method",
                    {"name": "HeaderMismatch"},
                )
            name_key = NAME_BEARING.get(method)
            if name_key is not None:
                body_value = params.get(name_key) if isinstance(params, dict) else None
                hdr_name = _decode_mcp_header(_header(headers, "Mcp-Name"))
                if body_value is not None and hdr_name and hdr_name != body_value:
                    return 400, _jsonrpc_error(
                        req_id,
                        HEADER_MISMATCH,
                        "Mcp-Name header does not match the request body's %r parameter" % name_key,
                        {"name": "HeaderMismatch"},
                    )
            return None

        # Modern 2026-07-28 streamable-http: require _meta envelope + header parity.
        meta = params.get("_meta") if isinstance(params, dict) else None
        if not isinstance(meta, dict):
            return 400, _jsonrpc_error(
                req_id,
                INVALID_PARAMS,
                "params._meta must be an object carrying the required %r and %r envelope keys"
                % (PROTOCOL_VERSION_META, CLIENT_CAPS_META),
            )
        missing = [key for key in (PROTOCOL_VERSION_META, CLIENT_CAPS_META) if key not in meta]
        if missing:
            return 400, _jsonrpc_error(
                req_id,
                INVALID_PARAMS,
                "params._meta is missing the required envelope key(s): %s" % ", ".join(missing),
            )
        proto_meta = meta.get(PROTOCOL_VERSION_META)
        proto = _header(headers, "MCP-Protocol-Version")
        if not proto or proto != proto_meta:
            return 400, _jsonrpc_error(
                req_id,
                HEADER_MISMATCH,
                "MCP-Protocol-Version header does not match the request envelope's protocol version",
                {"name": "HeaderMismatch"},
            )
        if mcp_method != method:
            return 400, _jsonrpc_error(
                req_id,
                HEADER_MISMATCH,
                "Mcp-Method header does not match the request body's method",
                {"name": "HeaderMismatch"},
            )
        name_key = NAME_BEARING.get(method)
        if name_key is not None:
            body_value = params.get(name_key) if isinstance(params, dict) else None
            hdr_name = _decode_mcp_header(_header(headers, "Mcp-Name"))
            if body_value is not None and hdr_name != body_value:
                return 400, _jsonrpc_error(
                    req_id,
                    HEADER_MISMATCH,
                    "Mcp-Name header does not match the request body's %r parameter" % name_key,
                    {"name": "HeaderMismatch"},
                )
            if name_key == "name" and method == "tools/call" and not hdr_name:
                return 400, _jsonrpc_error(
                    req_id,
                    HEADER_MISMATCH,
                    "Header mismatch: Mcp-Name is required",
                    {"name": "HeaderMismatch"},
                )
        if not isinstance(proto_meta, str) or proto_meta != MCP_PROTOCOL_VERSION:
            return 400, _jsonrpc_error(
                req_id,
                UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version",
                {"supported": [MCP_PROTOCOL_VERSION], "requested": proto_meta},
            )
        return None

    def handle_rpc(self, body: dict, headers, principal) -> tuple[int, dict]:
        mismatch = self.validate_headers(body, headers)
        if mismatch:
            return mismatch
        req_id = body.get("id")
        method = str(body.get("method") or "")
        params = body.get("params") or {}
        if method == "initialize":
            requested = None
            if isinstance(params, dict):
                requested = params.get("protocolVersion")
            negotiated = _negotiate_handshake_version(requested if isinstance(requested, str) else None)
            if negotiated is None:
                return 400, _jsonrpc_error(
                    req_id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "Unsupported protocol version",
                    {
                        "supported": list(HANDSHAKE_PROTOCOL_VERSIONS),
                        "modern": [MCP_PROTOCOL_VERSION],
                        "requested": requested,
                    },
                )
            return 200, _jsonrpc_result(
                req_id,
                {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {}},
                    "serverInfo": _server_info(),
                    "instructions": MCP_INSTRUCTIONS,
                },
            )
        if method == "notifications/initialized":
            # JSON-RPC notification: acknowledge without a result body.
            return 202, {}
        if method == "ping":
            # Compatible empty ping result for both eras.
            if req_id is None:
                return 202, {}
            return 200, _jsonrpc_result(req_id, {"resultType": "complete"})
        if method == "server/discover":
            return 200, _jsonrpc_result(
                req_id,
                {
                    "supportedVersions": [MCP_PROTOCOL_VERSION],
                    "capabilities": {"tools": {}},
                    "ttlMs": 5000,
                    "cacheScope": "private",
                    "resultType": "complete",
                    "instructions": MCP_INSTRUCTIONS,
                },
            )
        if method == "tools/list":
            tools = [_tool_descriptor(*entry) for entry in TOOL_DEFS]
            return 200, _jsonrpc_result(
                req_id,
                {
                    "tools": tools,
                    "ttlMs": 5000,
                    "cacheScope": "private",
                    "resultType": "complete",
                },
            )
        if method == "tools/call":
            name = (params.get("name") if isinstance(params, dict) else None) or ""
            args = params.get("arguments") if isinstance(params, dict) else {}
            try:
                result = self.call_tool(principal, name, args or {})
                return 200, _jsonrpc_result(req_id, result)
            except ControlPlaneError as exc:
                return 200, _jsonrpc_result(req_id, _text_result("DENY: %s" % exc, is_error=True))
            except Exception:
                return 200, _jsonrpc_error(req_id, -32603, "internal error")
        return 404, _jsonrpc_error(req_id, -32601, "Method not found")

    def _authorize(self, principal, endpoint: str, capability: str, operand=None) -> dict:
        return v24.authorize_ai_capability_v24(
            self.plane,
            identity=principal["name"],
            destination=endpoint,
            capability=capability,
            operand=operand,
        )

    @staticmethod
    def _rule_name(decision: dict):
        winner = decision.get("winner") if decision else None
        if isinstance(winner, dict):
            return winner.get("name")
        return None

    def call_tool(self, principal, name: str, arguments: dict) -> dict:
        if name not in AI_CAPABILITIES:
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=str(arguments.get("endpoint") or "-"),
                capability=name,
                result="DENY",
                operand="unknown capability",
            )
            return _text_result("DENY: unknown capability", is_error=True)
        if name == "list_hosts":
            hosts = []
            decision = None
            for obj in self.plane.list_objects():
                if obj["type"] != "managed_endpoint":
                    continue
                allowed = False
                for cap in ("list_hosts", "get_host", "get_system_info"):
                    decision = self._authorize(principal, obj["name"], cap)
                    if decision["action"] == "ALLOW":
                        allowed = True
                        break
                if allowed:
                    client = None
                    if obj.get("client_id"):
                        client = self.plane.conn.execute(
                            "SELECT * FROM clients WHERE id = ?", (obj["client_id"],)
                        ).fetchone()
                    hosts.append(
                        {
                            "name": obj["name"],
                            "status": obj.get("status"),
                            "client_id": obj.get("client_id"),
                            "connectivity": self.plane.managed_host_connectivity(client),
                            "ai_executor": self.plane.ai_executor_status(client),
                        }
                    )
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint="*",
                capability="list_hosts",
                result="ALLOW" if hosts else "DENY",
                rule=self._rule_name(decision),
            )
            return _structured_result({"hosts": hosts}, text=json.dumps(hosts, indent=2))
        endpoint = str(arguments.get("endpoint") or arguments.get("host") or "")
        if not endpoint:
            raise ControlPlaneError("endpoint is required")
        operand = arguments.get("path") or arguments.get("command") or arguments.get("operand")
        start = time.monotonic()
        decision = self._authorize(principal, endpoint, name, operand)
        if decision["action"] != "ALLOW":
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="DENY",
                rule=self._rule_name(decision),
                operand=operand,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            return _text_result("DENY\nReason: %s" % decision["reason"], is_error=True)
        ep = decision.get("endpoint_row")
        if ep is None:
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="UNAVAILABLE",
                rule=self._rule_name(decision),
                operand=operand,
            )
            return _text_result("Authorization: ALLOW\nDelivery: endpoint unavailable", is_error=True)
        if ep["status"] == "orphaned":
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="UNAVAILABLE",
                rule=self._rule_name(decision),
                operand=operand,
            )
            return _text_result("Authorization: ALLOW\nDelivery: endpoint unavailable (orphaned)", is_error=True)
        client = self.plane.client_for_endpoint(ep["id"])
        if client is None or not self.plane.client_effectively_connected(client):
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="UNAVAILABLE",
                rule=self._rule_name(decision),
                operand=operand,
            )
            return _text_result("Authorization: ALLOW\nDelivery: endpoint unavailable", is_error=True)
        if name == "get_host":
            view = {
                "name": ep["name"],
                "status": ep["status"],
                "type": ep["type"],
                "origin": ep["origin"],
            }
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="ALLOW",
                rule=self._rule_name(decision),
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            return _structured_result(view, text=json.dumps(view, indent=2))
        patterns = list(decision.get("patterns") or [])
        if decision.get("winner") and not patterns:
            patterns = list(decision["winner"].get("paths") or [])
        timeout = decision.get("exec_timeout") or 30
        payload = self._dispatch_endpoint(
            principal=principal,
            client_id=client["id"],
            endpoint_object_id=ep["id"],
            capability=name,
            arguments=arguments,
            patterns=patterns,
            timeout=int(timeout),
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        op_result = payload.get("result") or "ALLOW"
        self.plane.record_ai_activity(
            principal=principal["name"],
            endpoint=endpoint,
            capability=name,
            result=op_result,
            rule=self._rule_name(decision),
            operand=operand,
            duration_ms=duration_ms,
        )
        safe = dict(payload)
        if name not in ("read_file", "download_file"):
            safe.pop("content_b64", None)
        is_error = op_result not in ("ALLOW",)
        # Prefer structuredContent for coherent object payloads; never embed secrets.
        if name in ("get_system_info", "list_processes", "read_file", "download_file") and not is_error:
            return _structured_result(safe, text=json.dumps(safe, indent=2), is_error=is_error)
        return _text_result(json.dumps(safe, indent=2), is_error=is_error)

    def _dispatch_endpoint(self, *, principal, client_id, endpoint_object_id, capability, arguments, patterns, timeout):
        """Dispatch through the client AI agent job path, not a local MCP server."""
        with self._lock:
            job_id = self.plane.enqueue_ai_job(
                principal_id=principal["id"],
                endpoint_object_id=endpoint_object_id,
                client_id=client_id,
                capability=capability,
                arguments=arguments,
                patterns=patterns,
                timeout=timeout,
            )
        if client_id in self._agents:
            wait_for = max(2.0, float(timeout) + 2.0)
        else:
            wait_for = max(2.0, float(timeout) + 5.0)
            # Hermetic tests without in-process agents: keep a bounded wait so
            # real mgmt/bearer workers can claim, without a 30s+ hang on TIMEOUT.
            if os.environ.get("DRLINK_TEST_ROOT") and os.environ.get("DRLINK_AI_TEST_LOCAL_EXEC") != "1":
                wait_for = min(wait_for, 5.0)
        deadline = time.monotonic() + wait_for
        while time.monotonic() < deadline:
            with self._lock:
                if job_id in self._job_results:
                    return self._job_results.pop(job_id)
            job = self.plane.get_ai_job(job_id)
            if job and job.get("status") == "done":
                with self._lock:
                    if job_id in self._job_results:
                        return self._job_results.pop(job_id)
                consumed = self.plane.consume_ai_job_result(job_id)
                if consumed is not None:
                    return consumed
            if job and job.get("status") in (
                "timeout",
                "cancelled",
                "expired",
                "recovery_required",
            ):
                result = (job.get("result") or {}) if isinstance(job.get("result"), dict) else {}
                return {
                    "result": str(job.get("status") or "TIMEOUT").upper(),
                    "error": result.get("error") or "agent did not complete the job",
                }
            time.sleep(0.05)
        with self._lock:
            if job_id in self._job_results:
                return self._job_results.pop(job_id)
        job = self.plane.get_ai_job(job_id)
        if job and job.get("status") == "done":
            consumed = self.plane.consume_ai_job_result(job_id)
            if consumed is not None:
                return consumed
        # Unmistakable hermetic-test seam only. Production service config must
        # never set both DRLINK_AI_TEST_LOCAL_EXEC=1 and DRLINK_TEST_ROOT.
        if os.environ.get("DRLINK_AI_TEST_LOCAL_EXEC") == "1" and os.environ.get("DRLINK_TEST_ROOT"):
            try:
                claimed = self.plane.claim_ai_jobs(client_id, limit=64)
            except ControlPlaneError:
                claimed = []
            match = next((item for item in claimed if item.get("id") == job_id), None)
            if match is None:
                self.plane.terminalize_ai_job(job_id, "timeout")
                return {"result": "TIMEOUT", "error": "agent did not complete the job"}
            try:
                payload = execute_local(capability, arguments, patterns=patterns, timeout=timeout)
            except ControlPlaneError as exc:
                payload = {"result": "DENY", "error": str(exc)}
            with self._lock:
                self._job_results[job_id] = payload
                try:
                    self.plane.complete_ai_job(
                        job_id,
                        client_id,
                        payload,
                        claim_token=match.get("claim_token"),
                        attempt_id=match.get("attempt_id"),
                    )
                except ControlPlaneError:
                    pass
            return payload
        self.plane.terminalize_ai_job(job_id, "timeout")
        return {"result": "TIMEOUT", "error": "agent did not complete the job"}


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_handler(bridge: MCPBridge):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _send(self, code, payload, extra_headers=None, raw=None):
            if raw is None:
                raw = b"" if payload == {} and code == 202 else json.dumps(payload).encode("utf-8")
            self.send_response(code)
            if raw:
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
            else:
                self.send_header("Content-Length", "0")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def _public_cors(self):
            # Public metadata may be read cross-origin; credentials are never included.
            return {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name",
                "Access-Control-Max-Age": "600",
            }

        def _client_addr(self):
            try:
                return self.client_address[0]
            except Exception:
                return "unknown"

        def _trusted_oauth_source(self) -> str:
            return trusted_oauth_source(self._client_addr(), self.headers)

        def _rate_limited(
            self, bucket: str, *, limit: int = 60, window_s: int = 60, source: Optional[str] = None
        ) -> bool:
            if source is None:
                source = public_rate_source(self._client_addr(), self.headers)
            key = "%s:%s" % (bucket, source)
            now = time.time()
            with bridge._lock:
                hits = getattr(bridge, "_rate_hits", None)
                if hits is None:
                    bridge._rate_hits = {}
                    hits = bridge._rate_hits
                window = hits.get(key)
                if not window or now - window[0] >= window_s:
                    hits[key] = [now, 1]
                    return False
                window[1] += 1
                return window[1] > limit

        def _origin_denied(self):
            bad = bridge.validate_origin(self.headers)
            if bad:
                self._send(403, {"error": "invalid origin"})
                return True
            return False

        def _www_auth(self):
            return bridge.www_authenticate_value()

        def do_GET(self):
            if self._origin_denied():
                return
            parsed = urlparse(self.path)
            if parsed.path in ("/healthz", "/health"):
                st = bridge.plane.status()
                mcp = "Healthy" if st.get("mcp_configured") else "Not configured"
                self._send(200, {"status": mcp, "revision": st["revision"]})
                return
            if parsed.path in (
                "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-protected-resource/mcp",
            ):
                self._send(200, bridge.oauth_metadata(self.headers), extra_headers=self._public_cors())
                return
            if parsed.path == "/.well-known/oauth-authorization-server":
                self._send(200, bridge.as_metadata(self.headers), extra_headers=self._public_cors())
                return
            if parsed.path == "/oauth/authorize":
                source = self._trusted_oauth_source()
                if not source:
                    self._send(
                        503,
                        {
                            "error": "temporarily_unavailable",
                            "error_description": "authorization source unavailable",
                        },
                    )
                    return
                if self._rate_limited(
                    "authorize",
                    limit=OAUTH_AUTHORIZE_RATE_LIMIT,
                    window_s=OAUTH_AUTHORIZE_RATE_WINDOW_S,
                    source=source,
                ):
                    self._send(
                        429,
                        {
                            "error": "temporarily_unavailable",
                            "error_description": "authorization rate limit exceeded; retry later",
                        },
                    )
                    return
                qs = parse_qs(parsed.query)
                fields = {k: (v[0] if v else "") for k, v in qs.items()}
                if str(fields.get("code_challenge_method") or "S256") != "S256":
                    self._send(400, {"error": "invalid_request", "error_description": "code_challenge_method must be S256"})
                    return
                try:
                    resource = bridge._require_canonical_resource(str(fields.get("resource") or ""))
                    pending = bridge.plane.create_oauth_pending(
                        client_id=str(fields.get("client_id") or ""),
                        redirect_uri=str(fields.get("redirect_uri") or ""),
                        code_challenge=str(fields.get("code_challenge") or ""),
                        resource=resource,
                        state=str(fields.get("state") or ""),
                        source=source,
                    )
                except OAuthPendingCapacityError as exc:
                    self._send(
                        503,
                        {"error": exc.oauth_error, "error_description": str(exc)},
                    )
                    return
                except ControlPlaneError as exc:
                    self._send(400, {"error": "invalid_request", "error_description": str(exc)})
                    return
                auto = os.environ.get("DRLINK_OAUTH_AUTO_APPROVE") == "1" and bridge.listen_host in (
                    "127.0.0.1",
                    "localhost",
                    "::1",
                )
                if auto and not pending.get("unbound"):
                    try:
                        approved = bridge.plane.approve_oauth_pending(
                            pending["id"], retain_for_browser=False
                        )
                    except ControlPlaneError as exc:
                        self._send(400, {"error": "access_denied", "error_description": str(exc)})
                        return
                    loc = approved["redirect_uri"]
                    sep = "&" if "?" in loc else "?"
                    query = {"code": approved["code"], "iss": bridge.canonical_public_base()}
                    if approved.get("state"):
                        query["state"] = approved["state"]
                    loc = "%s%s%s" % (loc, sep, urlencode(query))
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if pending.get("unbound"):
                    hint = (
                        "system credential approve-oauth %s &lt;AI-IDENTITY&gt;" % pending["id"]
                    )
                else:
                    hint = "system credential approve-oauth %s" % pending["id"]
                continue_path = "/oauth/continue?%s" % urlencode({"t": pending["completion_token"]})
                page = (
                    "<!doctype html><html><head><meta charset='utf-8'>"
                    "<meta http-equiv='refresh' content='2;url=%s'>"
                    "<title>MCP OAuth consent</title></head><body>"
                    "<p>Approve this MCP OAuth request as operator:</p>"
                    "<pre>%s</pre>"
                    "<p>After approval this browser continues automatically to the registered redirect.</p>"
                    "<p><a href='%s'>Continue after approval</a></p>"
                    "<p>This is a consent page, not a management UI.</p>"
                    "<script>setTimeout(function(){location.replace(%s);},2000);</script>"
                    "</body></html>"
                ) % (
                    continue_path,
                    hint,
                    continue_path,
                    json.dumps(continue_path),
                )
                raw = page.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if parsed.path == "/oauth/continue":
                qs = parse_qs(parsed.query)
                token = (qs.get("t") or [""])[0]
                try:
                    result = bridge.plane.complete_oauth_pending_browser(token)
                except ControlPlaneError as exc:
                    self._send(400, {"error": "invalid_request", "error_description": str(exc)})
                    return
                status = result.get("status")
                if status == "pending":
                    continue_path = "/oauth/continue?%s" % urlencode({"t": token})
                    page = (
                        "<!doctype html><html><head><meta charset='utf-8'>"
                        "<meta http-equiv='refresh' content='2;url=%s'>"
                        "<title>Waiting for approval</title></head><body>"
                        "<p>Waiting for operator approval…</p>"
                        "<p><a href='%s'>Retry</a></p>"
                        "<script>setTimeout(function(){location.replace(%s);},2000);</script>"
                        "</body></html>"
                    ) % (continue_path, continue_path, json.dumps(continue_path))
                    raw = page.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                loc = str(result.get("redirect_uri") or "")
                if not loc:
                    self._send(400, {"error": "invalid_request", "error_description": "missing redirect_uri"})
                    return
                sep = "&" if "?" in loc else "?"
                if status == "denied":
                    query = {
                        "error": result.get("error") or "access_denied",
                        "error_description": result.get("error_description") or "denied",
                        "iss": bridge.canonical_public_base(),
                    }
                    if result.get("state"):
                        query["state"] = result["state"]
                elif status == "approved":
                    query = {"code": result["code"], "iss": bridge.canonical_public_base()}
                    if result.get("state"):
                        query["state"] = result["state"]
                else:
                    self._send(400, {"error": "invalid_request", "error_description": "unexpected status"})
                    return
                loc = "%s%s%s" % (loc, sep, urlencode(query))
                self.send_response(302)
                self.send_header("Location", loc)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(404, {"error": "not found"})

        def do_DELETE(self):
            # 2026-07-28 removed protocol-level sessions; DELETE is not a session
            # terminator. Answer 405 so official SDKs fail closed rather than hang.
            self.send_response(405)
            self.send_header("Allow", "GET, POST")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_OPTIONS(self):
            parsed = urlparse(self.path)
            if parsed.path.startswith("/.well-known/") or parsed.path.startswith("/oauth/") or parsed.path in (
                "/register",
                "/mcp",
            ):
                self._send(204, {}, extra_headers=self._public_cors())
                return
            self.send_response(204)
            self.send_header("Allow", "GET, POST")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            if self._origin_denied():
                return
            parsed = urlparse(self.path)
            # Agent claim/complete polls ~20Hz per Managed Host. Those POSTs must
            # not share the public 120/min budget with MCP clients, or official
            # SDK sessions 429 within a few seconds of bridge start.
            if not parsed.path.startswith("/agent/v1/") and self._rate_limited(
                "post", limit=120, window_s=60
            ):
                self._send(429, {"error": "rate_limited"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 2_000_000:
                self._send(413, _jsonrpc_error(None, -32700, "payload too large"))
                return
            raw = self.rfile.read(length) if length else b"{}"
            if parsed.path in ("/oauth/register", "/register"):
                if self._rate_limited("register", limit=20, window_s=60):
                    self._send(429, {"error": "rate_limited"})
                    return
                try:
                    meta = json.loads(raw.decode("utf-8") or "{}")
                except Exception:
                    self._send(400, {"error": "invalid_client_metadata"})
                    return
                try:
                    with bridge._lock:
                        registered = bridge.register_oauth_client(meta if isinstance(meta, dict) else {})
                except ControlPlaneError as exc:
                    self._send(400, {"error": "invalid_client_metadata", "error_description": str(exc)})
                    return
                self._send(201, registered, extra_headers=self._public_cors())
                return
            if parsed.path == "/oauth/revoke":
                fields = {}
                if self.headers.get("Content-Type", "").startswith("application/json"):
                    try:
                        fields = json.loads(raw.decode("utf-8") or "{}")
                    except Exception:
                        fields = {}
                else:
                    qs = parse_qs(raw.decode("utf-8"))
                    fields = {k: (v[0] if v else "") for k, v in qs.items()}
                token = str(fields.get("token") or "")
                with bridge._lock:
                    bridge.revoke_oauth_credential(token)
                # RFC 7009: always return 200 whether or not the token existed.
                self._send(200, {}, extra_headers=self._public_cors())
                return
            if parsed.path == "/oauth/token":
                if self._rate_limited("token", limit=60, window_s=60):
                    self._send(429, {"error": "rate_limited"})
                    return
                fields = {}
                if self.headers.get("Content-Type", "").startswith("application/json"):
                    try:
                        fields = json.loads(raw.decode("utf-8") or "{}")
                    except Exception:
                        self._send(400, {"error": "invalid_request"})
                        return
                else:
                    qs = parse_qs(raw.decode("utf-8"))
                    fields = {k: (v[0] if v else "") for k, v in qs.items()}
                auth = _header(self.headers, "Authorization")
                if auth.lower().startswith("basic "):
                    import base64

                    try:
                        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
                        cid, secret = decoded.split(":", 1)
                        fields.setdefault("client_id", cid)
                        fields.setdefault("client_secret", secret)
                    except Exception:
                        pass
                try:
                    issued = bridge.issue_oauth_token(fields, self.headers)
                except ControlPlaneError as exc:
                    self._send(400, {"error": "invalid_request", "error_description": str(exc)})
                    return
                if issued is None:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", self._www_auth())
                    body = json.dumps({"error": "invalid_client"}).encode("utf-8")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    for k, v in self._public_cors().items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._send(200, issued, extra_headers=self._public_cors())
                return
            if parsed.path in ("/agent/v1/claim", "/agent/v1/complete"):
                client_id = bridge.authenticate_agent(self.headers)
                if client_id is None:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Bearer realm="drlink-agent"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                try:
                    body = json.loads(raw.decode("utf-8") or "{}")
                except Exception:
                    self._send(400, {"error": "parse error"})
                    return
                try:
                    if parsed.path.endswith("/claim"):
                        with bridge._lock:
                            jobs = bridge.plane.claim_ai_jobs(client_id, int(body.get("limit") or 4))
                        self._send(200, {"jobs": jobs})
                        return
                    full = body.get("result") or {}
                    with bridge._lock:
                        bridge._job_results[str(body.get("id") or "")] = full
                        bridge.plane.complete_ai_job(
                            str(body.get("id") or ""),
                            client_id,
                            full,
                            claim_token=body.get("claim_token"),
                            attempt_id=body.get("attempt_id"),
                        )
                    self._send(200, {"ok": True})
                    return
                except ControlPlaneError as exc:
                    self._send(403, {"error": str(exc)})
                    return
            if parsed.path != "/mcp":
                self._send(404, {"error": "not found"})
                return
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                self._send(400, _jsonrpc_error(None, -32700, "parse error"))
                return
            principal = bridge.authenticate(self.headers)
            if principal is None:
                if self._rate_limited("authfail", limit=30, window_s=60):
                    self._send(429, {"error": "rate_limited"})
                    return
                err = _jsonrpc_error(body.get("id"), -32001, "unauthorized")
                err["error"]["data"] = {"_meta": bridge.www_authenticate_meta()}
                err["_meta"] = bridge.www_authenticate_meta()
                payload = json.dumps(err).encode("utf-8")
                self.send_response(401)
                self.send_header("WWW-Authenticate", self._www_auth())
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            code, result = bridge.handle_rpc(body, self.headers, principal)
            extra = {}
            if code == 200:
                extra["Cache-Control"] = "no-store"
            self._send(code, result, extra_headers=extra)

    return Handler


def serve(host=DEFAULT_LISTEN, port=DEFAULT_PORT, root=None):
    # Production bridge never starts Server-local Managed Host impersonation loops.
    bridge = MCPBridge(root=root, auto_agents=False)
    bridge.listen_host = host
    bridge.listen_port = int(port)
    httpd = ThreadingHTTPServer((host, int(port)), make_handler(bridge))
    httpd.serve_forever()


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Data Relay Link MCP Bridge")
    parser.add_argument("--listen", default=os.environ.get("DRLINK_MCP_LISTEN", DEFAULT_LISTEN))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DRLINK_MCP_PORT", DEFAULT_PORT)))
    args = parser.parse_args(argv)
    serve(args.listen, args.port)


if __name__ == "__main__":
    main()
