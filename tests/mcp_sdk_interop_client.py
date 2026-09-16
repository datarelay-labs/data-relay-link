#!/usr/bin/env python3
"""Official MCP Python SDK Streamable HTTP client used for protocol interop."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


async def run(url: str, token: str, endpoint: str, path: str, ca: str = "") -> dict:
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    import httpx2

    headers = {"Authorization": "Bearer %s" % token}
    kwargs = {"headers": headers, "timeout": httpx2.Timeout(30.0, read=60.0)}
    if ca:
        kwargs["verify"] = ca
    out = {"protocol": None, "tools": [], "list_hosts": None, "system": None, "read": None, "denied": None}
    async with httpx2.AsyncClient(**kwargs) as http:
        async with streamable_http_client(url, http_client=http, terminate_on_close=False) as streams:
            read_stream, write_stream = streams[0], streams[1]
            async with ClientSession(read_stream, write_stream) as session:
                discovered = await session.discover()
                out["protocol"] = str(getattr(discovered, "protocolVersion", None) or session.protocol_version)
                tools = await session.list_tools()
                out["tools"] = [t.name for t in tools.tools]
                hosts = await session.call_tool("list_hosts", {})
                out["list_hosts"] = _text(hosts)
                info = await session.call_tool("get_system_info", {"endpoint": endpoint})
                out["system"] = _text(info)
                read = await session.call_tool("read_file", {"endpoint": endpoint, "path": path})
                out["read"] = _text(read)
                denied = await session.call_tool("exec", {"endpoint": endpoint, "command": "id"})
                out["denied"] = _text(denied)
    return out


def _text(result) -> str:
    chunks = []
    content = getattr(result, "content", None) or []
    for item in content:
        chunks.append(getattr(item, "text", None) or str(item))
    if not chunks:
        return str(result)
    return "\n".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--ca", default="")
    args = parser.parse_args()
    result = asyncio.run(run(args.url, args.token, args.endpoint, args.path, args.ca))
    sys.stdout.write(json.dumps(result) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
