import json
import subprocess
import threading
import queue
import sys
import time

SANDBOX = r"C:\Users\Nafeesa\Desktop\provproxy_mcp_sandbox"

def read_stdout(proc, q):
    for line in proc.stdout:
        line = line.strip()
        if line:
            q.put(line)

def send(proc, message):
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()

def wait_for_id(q, request_id, timeout=15):
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            line = q.get(timeout=0.5)
        except queue.Empty:
            continue

        print("SERVER:", line)

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        if obj.get("id") == request_id:
            return obj

    raise TimeoutError(f"No response for request id {request_id}")

def main():
    print("=" * 70)
    print("REAL MCP FILESYSTEM SMOKE TEST")
    print("=" * 70)

    proc = subprocess.Popen(
        [
            "cmd",
            "/c",
            "npx",
            "-y",
            "@modelcontextprotocol/server-filesystem",
            SANDBOX,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )

    q = queue.Queue()

    thread = threading.Thread(
        target=read_stdout,
        args=(proc, q),
        daemon=True,
    )
    thread.start()

    try:
        # 1. MCP initialize
        send(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "provproxy-external-validator",
                    "version": "0.1.0"
                }
            }
        })

        init_response = wait_for_id(q, 1)

        if "error" in init_response:
            print("\n[FAIL] MCP initialize returned an error:")
            print(init_response["error"])
            return 1

        print("\n[PASS] MCP initialize succeeded.")

        # MCP initialized notification
        send(proc, {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        })

        # 2. Request actual tools from external server
        send(proc, {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })

        tools_response = wait_for_id(q, 2)

        if "error" in tools_response:
            print("\n[FAIL] tools/list returned an error:")
            print(tools_response["error"])
            return 1

        tools = tools_response.get("result", {}).get("tools", [])

        print("\n[PASS] tools/list succeeded.")
        print(f"External MCP tools discovered: {len(tools)}")

        for tool in tools:
            print(f"  - {tool.get('name', '<unnamed>')}")

        if not tools:
            print("\n[FAIL] Server returned zero tools.")
            return 1

        print("\n" + "=" * 70)
        print("REAL MCP HANDSHAKE VERIFIED")
        print("=" * 70)
        return 0

    finally:
        proc.terminate()

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        stderr = proc.stderr.read().strip()

        if stderr:
            print("\nServer stderr:")
            print(stderr)

if __name__ == "__main__":
    sys.exit(main())