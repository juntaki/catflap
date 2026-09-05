"""Minimal live-Tailcat probe: initialize + tools/list + one exec (argv form)."""
import json
import subprocess
import sys

p = subprocess.Popen(
    ["./bin/catflap", "mcp", "--cap-file", sys.argv[1]],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)


def rpc_call(method, params, rid):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n")
    p.stdin.flush()
    line = p.stdout.readline()
    assert line, "EOF from mcp server"
    return json.loads(line)


print("== initialize ==", flush=True)
print(json.dumps(rpc_call("initialize", {"protocolVersion": "2024-11-05"}, 1))[:160], flush=True)
print("== tools/list ==", flush=True)
print(json.dumps(rpc_call("tools/list", {}, 2))[:260], flush=True)
print("== remote_exec echo ==", flush=True)
r = rpc_call("tools/call", {"name": "remote_exec", "arguments": {"command": "echo", "args": ["via-tailcat"]}}, 3)
print(json.dumps(r)[:300], flush=True)
print("== remote_exec denied ==", flush=True)
r = rpc_call("tools/call", {"name": "remote_exec", "arguments": {"command": "rm", "args": ["x"]}}, 4)
print(json.dumps(r)[:200], flush=True)
p.stdin.close()
p.wait(timeout=30)
print("MCP_EXIT:", p.returncode, flush=True)
