"""Adversarial E2E sweep (v0.2-F): real serve + MCP stdio, hostile inputs.

Starts its own `serve` (local transport), so it must run alone:
  python3 testdata/e2e/adversarial.py
Exits non-zero on any failure. All artifacts stay under ./testdata/e2e/.
"""
import json
import os
import subprocess
import sys
import threading
import time

BIN = "./bin/catflap"
STATE = "./testdata/e2e/adv-state.json"
AUDIT = "./testdata/e2e/adv-audit"
CAP = "./testdata/e2e/adv.cap"
POLICY = "./testdata/e2e/adversarial-policy.yaml"
WORK = "./testdata/e2e/work"

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail, flush=True)
    if not cond:
        failures.append(name)


class Mcp:
    def __init__(self, capfile):
        self.p = subprocess.Popen(
            [BIN, "mcp", "--cap-file", capfile],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1,
        )
        self.rid = 0
        self.lock = threading.Lock()
        # Spec handshake first: tools/call before initialize is rejected.
        self._raw({"jsonrpc": "2.0", "id": "init", "method": "initialize",
                   "params": {"protocolVersion": "2024-11-05",
                              "capabilities": {},
                              "clientInfo": {"name": "adversarial", "version": "0"}}})
        self._raw({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _raw(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()
        if "id" in obj:
            while True:
                r = json.loads(self.p.stdout.readline())
                if r.get("id") == obj["id"]:
                    return r
        return None

    def call(self, name, args):
        with self.lock:
            self.rid += 1
            rid = self.rid
            self.p.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                 "params": {"name": name, "arguments": args}}) + "\n")
            self.p.stdin.flush()
            return json.loads(self.p.stdout.readline())

    def close(self):
        try:
            self.p.stdin.close()
        except BrokenPipeError:
            pass
        self.p.wait(timeout=15)


def inner_text(resp):
    """Decoded stdout/text of a successful tool result, else None."""
    try:
        content = resp["result"]["content"][0]["text"]
        if resp["result"].get("isError"):
            return None
        return json.loads(content)
    except (KeyError, ValueError, TypeError):
        return None


def main():
    os.makedirs(WORK, exist_ok=True)
    for f in (STATE, CAP):
        if os.path.exists(f):
            os.remove(f)
    subprocess.run(["rm", "-rf", AUDIT], check=False)

    srv = subprocess.Popen(
        [BIN, "serve", "--transport", "local", "--policy", POLICY,
         "--ttl", "10m", "--state", STATE, "--audit", AUDIT,
         "--out", CAP, "--force"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        task = None
        for _ in range(100):
            line = srv.stdout.readline()
            if line.startswith("Task:"):
                task = line.split()[1]
                break
        assert task, "serve did not print a task"
        print("task:", task, flush=True)

        # --- protocol hygiene: tools/call before initialize is rejected ---
        raw = subprocess.Popen(
            [BIN, "mcp", "--cap-file", CAP],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1)
        raw.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "remote_exec",
                        "arguments": {"command": "echo", "args": ["x"]}}}) + "\n")
        raw.stdin.flush()
        first = json.loads(raw.stdout.readline())
        raw.stdin.close()
        raw.wait(timeout=15)
        check("pre-handshake call rejected",
              "error" in first and "initializ" in json.dumps(first))

        m = Mcp(CAP)

        # --- transport framing: oversized and newline-less floods die fast ---
        import base64
        import socket
        cap = json.loads(base64.urlsafe_b64decode(
            open(CAP).read().strip()[5:] + "=="))
        host, port = cap["endpoint"].rsplit(":", 1)
        frame = json.dumps({"task": cap["task"], "secret": cap["task_secret"],
                            "id": 1, "tool": "remote_exec",
                            "args": {"command": "echo", "args": ["x" * (2 * 1024 * 1024)]}})
        s = socket.create_connection((host, int(port)), timeout=10)
        s.sendall((frame + "\n").encode())
        s.settimeout(10)
        try:
            data = s.recv(4096)
        except (socket.timeout, ConnectionResetError):
            data = b""
        # Oversized frame: server closes the connection with no response.
        check("oversized frame killed", data == b"", "got %d bytes" % len(data))
        s.close()
        s = socket.create_connection((host, int(port)), timeout=10)
        try:
            s.sendall(b"z" * (4 * 1024 * 1024))  # no newline: must not balloon memory
        except BrokenPipeError:
            pass  # server already hung up at the bound: ideal outcome
        s.settimeout(10)
        try:
            data = s.recv(4096)
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            data = b""
        s.close()
        check("newline-less flood killed", data == b"", "got %d bytes" % len(data))

        # --- shell metacharacters are inert data ---
        # NOTE: compare decoded stdout, not the JSON dump (Go escapes &,<,>).
        for payload in ["a; touch " + WORK + "/p1", "a && touch " + WORK + "/p2",
                        "$(touch " + WORK + "/p3)", "`touch " + WORK + "/p4`",
                        "a\ntouch " + WORK + "/p5", "a|touch " + WORK + "/p6"]:
            r = m.call("remote_exec", {"command": "echo", "args": [payload]})
            body = inner_text(r)
            check("inert:" + payload[:8].replace("\n", "\\n"),
                  body is not None and body.get("stdout") == payload + "\n"
                  and body.get("exit_code") == 0, json.dumps(r)[:120])
        check("no payload files",
              not any(os.path.exists(os.path.join(WORK, "p%d" % i)) for i in range(1, 7)))

        # --- argv shape attacks ---
        r = m.call("remote_exec", {"command": "rm", "args": ["-rf", "/"]})
        check("unknown command denied", r["result"].get("isError") is True)
        r = m.call("remote_exec", {"command": "/bin/sleep", "args": ["5", "extra"]})
        check("extra argv denied", r["result"].get("isError") is True)
        r = m.call("remote_exec", {"command": "/bin/sleep", "args": []})
        check("empty argv denied", r["result"].get("isError") is True)
        r = m.call("remote_exec", {"command": "/bin/sleep", "args": ["999"]})
        check("integer range denied", r["result"].get("isError") is True)
        r = m.call("remote_exec", {"command": "echo", "args": ["x" * 5000]})
        check("very long argv denied", r["result"].get("isError") is True)
        r = m.call("no_such_tool", {})
        # Unregistered tools die at SDK routing (protocol error), never
        # reaching the gateway — also a deny.
        check("unknown tool denied",
              (r.get("result") or {}).get("isError") is True or "unknown tool" in json.dumps(r))

        # --- path attacks ---
        for bad in ["/etc/passwd", "./testdata/../README.md",
                    "./testdata/e2e/work/../../README.md"]:
            r = m.call("remote_read", {"path": bad})
            check("read denied:" + bad[-20:], r["result"].get("isError") is True)
        r = m.call("remote_write", {"path": "./testdata/hello.txt", "content": "x"})
        check("write outside grant denied", r["result"].get("isError") is True)
        r = m.call("remote_write", {"path": WORK + "/big.txt", "content": "x" * 5000})
        check("oversize write denied", r["result"].get("isError") is True)

        # --- write roundtrip inside grant ---
        r = m.call("remote_write", {"path": WORK + "/adv.txt", "content": "adv"})
        check("write allowed", inner_text(r) is not None, json.dumps(r)[:160])
        r = m.call("remote_read", {"path": WORK + "/adv.txt"})
        body = inner_text(r)
        check("readback", body is not None and body.get("content") == "adv",
              json.dumps(r)[:160])

        # --- modern protocol: server/discover + new-protocol calls ---
        # Spec 2026-07-28 surface, no legacy handshake involved.
        mp = subprocess.Popen(
            [BIN, "mcp", "--cap-file", CAP],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1)
        meta = {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}}}

        def modern(i, method, params):
            p = dict(params)
            p.update(meta)
            mp.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": i, "method": method,
                 "params": p}) + "\n")
            mp.stdin.flush()
            return json.loads(mp.stdout.readline())

        r = modern(101, "server/discover", {})
        check("discover versions",
              "2026-07-28" in json.dumps(r.get("result", {}).get("supportedVersions", [])),
              json.dumps(r)[:160])
        r = modern(102, "tools/list", {})
        names = [t.get("name") for t in r.get("result", {}).get("tools", [])]
        check("modern tools/list", "remote_exec" in names, str(names))
        check("modern list includes granted write", "remote_write" in names)
        r = modern(103, "tools/call",
                   {"name": "remote_exec",
                    "arguments": {"command": "echo", "args": ["modern-ok"]}})
        check("modern call ok", "modern-ok" in json.dumps(r), json.dumps(r)[:160])
        mp.stdin.close()
        mp.wait(timeout=15)

        # --- concurrency exhaustion (max 2) ---
        # One MCP stdio adapter serves requests sequentially, so parallel
        # pressure needs one adapter process per caller (same capability).
        results = []
        def slow(i):
            mm = Mcp(CAP)
            try:
                results.append(mm.call("remote_exec", {"command": "/bin/sleep", "args": ["4"]}))
            finally:
                mm.close()
        threads = [threading.Thread(target=slow, args=(i,)) for i in range(4)]
        t0 = time.time()
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=30)
        dt = time.time() - t0
        denied = sum(1 for r in results
                     if r["result"].get("isError") is True and "concurrency" in json.dumps(r))
        check("concurrency exhausted fast", denied >= 1 and dt < 20, "denied=%d dt=%.1fs" % (denied, dt))

        # --- revoke race: in-flight sleep must die revoked ---
        outcome = {}
        def doomed():
            outcome["r"] = m.call("remote_exec", {"command": "/bin/sleep", "args": ["30"]})
        th = threading.Thread(target=doomed)
        th.start()
        time.sleep(1.0)
        rv = subprocess.run([BIN, "revoke", "--state", STATE, task],
                            capture_output=True, text=True)
        check("revoke ok", rv.returncode == 0 and "revoked" in rv.stdout, rv.stdout.strip())
        th.join(timeout=20)
        check("in-flight killed revoked",
              not th.is_alive() and "task revoked" in json.dumps(outcome.get("r", {})),
              json.dumps(outcome.get("r", {}))[:120])
        r = m.call("remote_exec", {"command": "echo", "args": ["hi"]})
        check("post-revoke call fails", r["result"].get("isError") is True,
              json.dumps(r)[:120])
        m.close()
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
    for f in (STATE, CAP):
        if os.path.exists(f):
            os.remove(f)
    subprocess.run(["rm", "-rf", AUDIT,
                    WORK + "/adv.txt", WORK + "/big.txt"], check=False)

    print("FAILURES: %d" % len(failures), flush=True)
    sys.exit(1 if failures else 0)


main()
