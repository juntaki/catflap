"""Minimal live-Tailcat probe: initialize + tools/list + one exec."""
import json
import subprocess
import sys

cap = None
for line in open(sys.argv[1]):
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
)


def rpc(method, params, rid):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n")
    p.stdin.flush()
    line = p.stdout.readline()
    assert line, "EOF from mcp server"
    return json.loads(line)


print("== initialize ==", flush=True)
print(json.dumps(rpc("initialize", {"protocolVersion": "2024-11-05"}, 1))[:200], flush=True)
print("== tools/list ==", flush=True)
print(json.dumps(rpc("tools/list", {}, 2))[:300], flush=True)
print("== remote_exec echo ==", flush=True)
print(json.dumps(rpc("tools/call", {"name": "remote_exec", "arguments": {"command": "echo via-tailcat"}}, 3))[:400], flush=True)
p.stdin.close()
p.wait(timeout=30)
print("MCP_EXIT:", p.returncode, flush=True)
