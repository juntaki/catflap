"""E2E driver: speaks MCP stdio to `catflap mcp --cap-file` and prints results.

Usage: python3 mcp_test.py <cap-file>
The cap file may be a bare token or `grant --out` output.
"""
import json
import subprocess
import sys

cap_file = sys.argv[1]
p = subprocess.Popen(
    ["./bin/catflap", "mcp", "--cap-file", cap_file],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
    cwd=".",
)


def send(obj):
    p.stdin.write(json.dumps(obj) + "\n")
    p.stdin.flush()


def recv():
    line = p.stdout.readline()
    assert line, "EOF from mcp server"
    return json.loads(line)


rid = 0


def call(method, params=None):
    global rid
    rid += 1
    msg = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    send(msg)
    return recv()


def tool(name, args):
    return call("tools/call", {"name": name, "arguments": args})


print("== initialize ==")
print(json.dumps(call("initialize", {"protocolVersion": "2024-11-05"}))[:160])
print("== tools/list ==")
print(json.dumps(call("tools/list"))[:260])
print("== exec allowed (echo) ==")
print(json.dumps(tool("remote_exec", {"command": "echo", "args": ["hello-catflap"]}))[:300])
print("== exec denied (rm) ==")
print(json.dumps(tool("remote_exec", {"command": "rm", "args": ["-rf", "/"]}))[:200])
print("== exec denied (absolute /bin/rm) ==")
print(json.dumps(tool("remote_exec", {"command": "/bin/rm", "args": ["x"]}))[:200])
print("== exec inert: metachars as argv ==")
r = tool("remote_exec", {"command": "echo", "args": ["x; touch testdata/e2e/PWNED"]})
print(json.dumps(r)[:300])
print("== read allowed ==")
print(json.dumps(tool("remote_read", {"path": "./testdata/hello.txt"}))[:260])
print("== read denied (/etc/passwd) ==")
print(json.dumps(tool("remote_read", {"path": "/etc/passwd"}))[:200])
print("== stat allowed ==")
print(json.dumps(tool("remote_stat", {"path": "./testdata/hello.txt"}))[:260])

p.stdin.close()
p.wait(timeout=10)
print("MCP_EXIT:", p.returncode)

import os
print("PWNED_EXISTS:", os.path.exists("testdata/e2e/PWNED"))
