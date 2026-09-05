"""E2E driver: speaks MCP stdio to `catflap mcp` and prints results."""
import json
import subprocess
import sys

cap_path = sys.argv[1]
with open(cap_path) as f:
    text = f.read()
cap = None
for line in text.splitlines():
    line = line.strip()
    if line.startswith("agc1_"):
        cap = line
        break
assert cap, "no capability found"

p = subprocess.Popen(
    ["./bin/catflap", "mcp", cap],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
    cwd=".",
)


def send(obj):
    line = json.dumps(obj)
    p.stdin.write(line + "\n")
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


print("== initialize ==")
print(json.dumps(call("initialize", {"protocolVersion": "2024-11-05"}))[:200])
print("== tools/list ==")
res = call("tools/list")
print(json.dumps(res)[:400])
print("== remote_exec allowed (echo) ==")
res = call("tools/call", {"name": "remote_exec", "arguments": {"command": "echo hello-catflap"}})
print(json.dumps(res)[:500])
print("== remote_exec denied (rm) ==")
res = call("tools/call", {"name": "remote_exec", "arguments": {"command": "rm -rf /"}})
print(json.dumps(res)[:500])
print("== remote_read allowed ==")
res = call("tools/call", {"name": "remote_read", "arguments": {"path": "./testdata/hello.txt"}})
print(json.dumps(res)[:500])
print("== remote_read denied (/etc/passwd) ==")
res = call("tools/call", {"name": "remote_read", "arguments": {"path": "/etc/passwd"}})
print(json.dumps(res)[:500])
print("== remote_stat allowed ==")
res = call("tools/call", {"name": "remote_stat", "arguments": {"path": "./testdata/hello.txt"}})
print(json.dumps(res)[:500])

p.stdin.close()
p.wait(timeout=10)
print("MCP_EXIT:", p.returncode)
