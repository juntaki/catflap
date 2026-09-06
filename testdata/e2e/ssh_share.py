"""SSH-share E2E sweep: real `catflap share` (embedded SSH server) +
`catflap mcp` (Claude-side stdio adapter), exercised as real subprocess
boundaries — pairing, exec, disconnect, revoke (SIGTERM), TTL expiry,
and the audit hash-chain.

Catflap's product is now just this: one lease per process, pair once,
exec over real SSH, Ctrl-C/TTL is the only way to end it. There is no
admin API, no grant/revoke/tasks command, no capability file — so
unlike the old adversarial/pairing/approval scripts, this one drives
everything purely through `share`'s stdout and the `mcp` stdio tools.

Starts its own `share` processes, so it must run alone:
  python3 testdata/e2e/ssh_share.py
Exits non-zero on any failure. All artifacts stay under ./testdata/e2e/.
"""
import glob
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time

BIN = "./bin/catflap"
WORK = "./testdata/e2e/ssh-share-work"

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail, flush=True)
    if not cond:
        failures.append(name)


class Mcp:
    """One `catflap mcp` process (unpaired by default), speaking stdio
    JSON-RPC. A dedicated reader thread demuxes stdout by JSON-RPC id
    so a tools/list_changed notification (fired by AddTool/RemoveTools
    as a side effect of pair/disconnect) is never mistaken for that
    call's own response."""

    def __init__(self):
        self.p = subprocess.Popen(
            [BIN, "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        self.rid = 0
        self.write_lock = threading.Lock()
        self.pending_lock = threading.Lock()
        self.pending = {}
        self.notifications = []
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

        self._request({"jsonrpc": "2.0", "id": "init", "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18",
                                   "capabilities": {},
                                   "clientInfo": {"name": "ssh-share-e2e", "version": "0"}}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read_loop(self):
        while True:
            line = self.p.stdout.readline()
            if not line:
                return
            try:
                r = json.loads(line)
            except ValueError:
                continue
            rid = r.get("id")
            if rid is None:
                with self.pending_lock:
                    self.notifications.append(r)
                continue
            with self.pending_lock:
                q = self.pending.get(rid)
            if q is not None:
                q.put(r)

    def _send(self, obj):
        with self.write_lock:
            self.p.stdin.write(json.dumps(obj) + "\n")
            self.p.stdin.flush()

    def _request(self, obj, timeout=20):
        rid = obj["id"]
        q = queue.Queue()
        with self.pending_lock:
            self.pending[rid] = q
        try:
            self._send(obj)
            try:
                return q.get(timeout=timeout)
            except queue.Empty:
                return {"error": "timeout"}
        finally:
            with self.pending_lock:
                self.pending.pop(rid, None)

    def _next_id(self):
        with self.write_lock:
            self.rid += 1
            return self.rid

    def call(self, name, args, timeout=20):
        rid = self._next_id()
        return self._request({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                               "params": {"name": name, "arguments": args}}, timeout=timeout)

    def tools_list(self):
        rid = self._next_id()
        return self._request({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})

    def close(self):
        try:
            self.p.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self.p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.p.kill()


def inner_text(resp):
    """Decoded JSON body of a successful tool result, else None."""
    try:
        content = resp["result"]["content"][0]["text"]
        if resp["result"].get("isError"):
            return None
        return json.loads(content)
    except (KeyError, ValueError, TypeError):
        return None


def is_error(resp):
    try:
        return resp["result"].get("isError") is True
    except (KeyError, TypeError):
        return True  # eof / malformed frame: treat as denied, never as success


def tool_names(resp):
    try:
        return [t.get("name") for t in resp["result"]["tools"]]
    except (KeyError, TypeError):
        return []


def start_share(ttl="30s", pairing_ttl="25s", audit_dir=None):
    """Starts `catflap share --transport local`, reading its stdout
    (in a background thread — the process keeps running after it
    prints the pairing code) until the pairing code and Expires line
    are seen. Returns (process, pairing_code, stdout_lines)."""
    args = [BIN, "share", "--transport", "local", "--ttl", ttl,
            "--pairing-ttl", pairing_ttl]
    if audit_dir is not None:
        args += ["--audit", audit_dir]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, bufsize=1)
    lines = []
    code_box = {}

    def reader():
        for line in iter(p.stdout.readline, ""):
            lines.append(line)
            stripped = line.strip()
            if stripped.startswith("CAT-") and "code" not in code_box:
                code_box["code"] = stripped
            if stripped.startswith("Expires:"):
                code_box["done"] = True

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    deadline = time.time() + 20
    while time.time() < deadline and "done" not in code_box:
        time.sleep(0.05)
    return p, code_box.get("code"), lines


def stop(p, timeout=10, sig="terminate"):
    if p.poll() is not None:
        return
    if sig == "terminate":
        p.terminate()
    else:
        p.kill()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass


def main():
    if os.path.exists(WORK):
        shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)
    audit_golden = os.path.join(WORK, "audit-golden")
    audit_revoke = os.path.join(WORK, "audit-revoke")
    audit_ttl = os.path.join(WORK, "audit-ttl")

    share_golden = share_revoke = share_ttl = None
    m_golden = m_reuse = m_noauth = m_revoke = m_ttl = None

    try:
        # ============================= GOLDEN PATH =============================
        share_golden, code_golden, lines_golden = start_share(
            ttl="30s", pairing_ttl="25s", audit_dir=audit_golden)
        check("share printed a pairing code", bool(code_golden) and code_golden.startswith("CAT-"),
              str(code_golden))
        check("share printed the sharing banner",
              any(l.startswith("Sharing this machine for") for l in lines_golden), str(lines_golden))

        m_golden = Mcp()
        unpaired = tool_names(m_golden.tools_list())
        check("unpaired tools/list is exactly {pair,status}",
              sorted(unpaired) == ["pair", "status"], str(unpaired))

        r = m_golden.call("pair", {"code": code_golden})
        check("pair succeeds", not is_error(r), json.dumps(r)[:200])

        paired_tools = tool_names(m_golden.tools_list())
        check("paired tools/list includes exec and disconnect",
              "exec" in paired_tools and "disconnect" in paired_tools, str(paired_tools))

        r = m_golden.call("exec", {"command": "echo one && echo two 1>&2 && exit 3"})
        body = inner_text(r)
        check("golden exec ran without a tool error", body is not None, json.dumps(r)[:200])
        if body is not None:
            check("golden exec stdout", body.get("stdout") == "one\n", repr(body.get("stdout")))
            check("golden exec stderr", body.get("stderr") == "two\n", repr(body.get("stderr")))
            check("golden exec exit_code", body.get("exit_code") == 3, repr(body.get("exit_code")))

        r = m_golden.call("status", {})
        body = inner_text(r)
        check("status reports paired", body is not None and body.get("paired") is True,
              json.dumps(r)[:160])

        # --- pairing code reuse: a SECOND fresh mcp claiming the SAME
        # already-claimed code must fail (one-shot pairing server) ---
        m_reuse = Mcp()
        r = m_reuse.call("pair", {"code": code_golden})
        check("reused pairing code rejected", is_error(r), json.dumps(r)[:200])

        # --- exec before pairing: a fresh mcp instance calling exec
        # before pair must fail ---
        m_noauth = Mcp()
        r = m_noauth.call("exec", {"command": "echo hi"})
        check("exec before pairing rejected", is_error(r), json.dumps(r)[:200])

        # --- disconnect: ends only this adapter's connection, not the
        # task/process. Prove the task is still alive by checking the
        # `share` process itself (which is what actually owns the
        # task's lifetime) is still running, untouched by disconnect. ---
        r = m_golden.call("disconnect", {})
        body = inner_text(r)
        check("disconnect succeeds", body is not None and body.get("disconnected") is True,
              json.dumps(r)[:160])

        r = m_golden.call("exec", {"command": "echo should-fail"})
        check("exec after disconnect rejected", is_error(r), json.dumps(r)[:200])

        check("share process still running after disconnect (task not revoked)",
              share_golden.poll() is None, "returncode=%s" % share_golden.poll())

        after = tool_names(m_golden.tools_list())
        check("tools/list returns to unpaired shape after disconnect",
              sorted(after) == ["pair", "status"], str(after))

        # ============================= REVOKE (SIGTERM) =============================
        share_revoke, code_revoke, _ = start_share(
            ttl="30s", pairing_ttl="25s", audit_dir=audit_revoke)
        check("revoke-test share printed a pairing code",
              bool(code_revoke) and code_revoke.startswith("CAT-"), str(code_revoke))

        m_revoke = Mcp()
        r = m_revoke.call("pair", {"code": code_revoke})
        check("revoke-test pair succeeds", not is_error(r), json.dumps(r)[:200])
        r = m_revoke.call("exec", {"command": "echo alive"})
        check("revoke-test exec succeeds before SIGTERM", "alive" in json.dumps(r), json.dumps(r)[:160])

        share_revoke.terminate()
        try:
            share_revoke.wait(timeout=10)
        except subprocess.TimeoutExpired:
            share_revoke.kill()
            share_revoke.wait(timeout=10)
        check("share process exits after SIGTERM", share_revoke.poll() is not None,
              str(share_revoke.poll()))

        r = m_revoke.call("exec", {"command": "echo should-fail"}, timeout=30)
        check("exec after SIGTERM revoke fails (SSH connection severed)",
              is_error(r), json.dumps(r)[:200])

        # ============================= TTL EXPIRY =============================
        share_ttl, code_ttl, _ = start_share(ttl="2s", pairing_ttl="2s", audit_dir=audit_ttl)
        check("ttl-test share printed a pairing code",
              bool(code_ttl) and code_ttl.startswith("CAT-"), str(code_ttl))

        m_ttl = Mcp()
        r = m_ttl.call("pair", {"code": code_ttl})
        check("ttl-test pair succeeds", not is_error(r), json.dumps(r)[:200])
        r = m_ttl.call("exec", {"command": "echo alive"})
        check("ttl-test exec succeeds near the start", "alive" in json.dumps(r), json.dumps(r)[:160])

        time.sleep(3)
        r = m_ttl.call("exec", {"command": "echo should-fail"}, timeout=30)
        check("exec after TTL expiry fails", is_error(r), json.dumps(r)[:200])

        # ============================= BAD PAIRING CODE =============================
        # Garbage/checksum-bad code: rejected purely by local decode,
        # no share process involved at all.
        m_bad = Mcp()
        try:
            r = m_bad.call("pair", {"code": "CAT-0000-0000-0000-0000-0000-0000-0000-0000-0000-XXX"})
            check("garbage/checksum-bad pairing code rejected", is_error(r), json.dumps(r)[:200])
        finally:
            m_bad.close()

    finally:
        for p in (share_golden, share_revoke, share_ttl):
            if p is not None:
                stop(p)
        for m in (m_golden, m_reuse, m_noauth, m_revoke, m_ttl):
            if m is not None:
                m.close()

    # ============================= AUDIT TRAIL =============================
    # By now share_golden has exited (stopped in the finally above);
    # its per-task JSONL log should verify cleanly and show both a
    # create record and a terminal record.
    audit_files = glob.glob(os.path.join(audit_golden, "*.jsonl"))
    check("exactly one audit file for the golden-path task", len(audit_files) == 1, str(audit_files))
    if audit_files:
        rv = subprocess.run([BIN, "audit", "verify", audit_files[0]],
                             capture_output=True, text=True)
        check("audit verify exits 0", rv.returncode == 0, rv.stdout + rv.stderr)
        check("audit verify reports a create event", "create event: present" in rv.stdout, rv.stdout)
        check("audit verify reports a terminal event",
              "terminal event: none" not in rv.stdout and "terminal event:" in rv.stdout, rv.stdout)

    shutil.rmtree(WORK, ignore_errors=True)

    print("FAILURES: %d" % len(failures), flush=True)
    sys.exit(1 if failures else 0)


main()
