#!/usr/bin/env python3
"""A tiny FAKE MCP tool server, for testing ProvProxy without needing a
real MCP server (which usually means installing Node.js and using `npx`).

WHAT THIS DOES (plain language): a real MCP tool server would actually
read files, make network calls, etc. This one just pretends — it has a
small built-in dictionary of "fake files" (including one fake secret), so
you can genuinely test whether ProvProxy catches an attempt to read a
sensitive file and then leak its content, without needing any real
filesystem or network access.

HOW TO USE IT: point ProvProxy's `--` argument at this script:

    python -m provproxy --policy test_policy.json \\
                           --server-id test-server \\
                           -- python test_server/fake_mcp_server.py

Then, in that same terminal, paste JSON lines to simulate what a real AI
host would send. See README's "Try it yourself" section for a full
step-by-step walkthrough.
"""
from __future__ import annotations

import json
import sys

# Pretend files this fake server "has" — read_file calls for these paths
# return this exact content; anything else returns a generic placeholder.
FAKE_FILES = {
    "/home/user/.ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "FAKEKEYCONTENT1234567890ABCDEFGHIJKLMNOP\n"
        "-----END OPENSSH PRIVATE KEY-----"
    ),
    "/home/user/project/README.md": "# Demo project\nJust a normal, non-sensitive readme file.",
}


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        request_id = request.get("id")

        if method == "initialize":
            reply = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "fake-mcp-server"}},
            }
        elif method == "tools/list":
            reply = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": [{"name": "read_file"}, {"name": "http_request"}]},
            }
        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "unknown")
            args = params.get("arguments", {})

            if tool_name == "read_file":
                path = args.get("path", "")
                content = FAKE_FILES.get(path, f"[fake content for unknown path: {path}]")
                reply = {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": content}]}}
            else:
                reply = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": f"[fake result] pretended to run '{tool_name}'"}]},
                }
        else:
            reply = {"jsonrpc": "2.0", "id": request_id, "result": {}}

        print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
