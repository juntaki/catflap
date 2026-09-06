"""Adversarial E2E sweep for the approval engine (approval-v03, Phase D):
real serve (with a pty-backed interactive terminal approver) + MCP stdio.

Starts its own `serve`, so it must run alone:
  python3 testdata/e2e/approval.py
Exits non-zero on any failure. All artifacts stay under ./testdata/e2e/.
"""
import json
import os
import pty
import queue
import re
import subprocess
import sys
import threading
import time

BIN = "./bin/catflap"
STATE = "./testdata/e2e/approval-state.json"
AUDIT = "./testdata/e2e/approval-audit"
CAP = "./testdata/e2e/approval.cap"
POLICY = "./testdata/e2e/approval-policy.yaml"
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
        self._raw({"jsonrpc": "2.0", "id": "init", "method": "initialize",
                   "params": {"protocolVersion": "2024-11-05",
                              "capabilities": {},
                              "clientInfo": {"name": "approval-e2e", "version": "0"}}})
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
    try:
        content = resp["result"]["content"][0]["text"]
        if resp["result"].get("isError"):
            return None
        return json.loads(content)
    except (KeyError, ValueError, TypeError):
        return None


def call_async(m, name, args):
    """Runs m.call in a background thread; returns a function that
    blocks (with timeout) for the result."""
    box = {}
    done = threading.Event()

    def run():
        box["r"] = m.call(name, args)
        done.set()

    threading.Thread(target=run, daemon=True).start()

    def wait(timeout):
        if not done.wait(timeout):
            return None
        return box["r"]
    return wait, done


TOKEN_RE = re.compile(r"type\s+(\S+)\s+to approve")


class Approver:
    """Drives serve's interactive TerminalApprover over a pty-backed
    stdin. A pty is required, not a plain pipe: isInteractiveTerminal
    only attaches an approver at all when stdin looks like a real
    terminal (os.ModeCharDevice) — see internal/cli/approve.go and
    serve.go's RunGateway. A plain subprocess.PIPE is not a character
    device, so serve would mint no approver and every approval-gated
    call would fail closed instantly, never exercising this code path.
    """

    def __init__(self, srv, master_fd):
        self.srv = srv
        self.master_fd = master_fd
        self.lines = queue.Queue()
        self.buf = ""
        t = threading.Thread(target=self._read_loop, daemon=True)
        t.start()

    def _read_loop(self):
        while True:
            line = self.srv.stderr.readline()
            if line == "":
                return
            self.lines.put(line)

    def wait_for_token(self, timeout=10):
        """Blocks for the next NEW prompt's token. Each Approve() call
        mints a fresh, never-repeated counter token (see
        internal/cli/approve.go) — this drains the queue until a line
        matching the prompt marker appears, returning that token."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self.lines.get(timeout=max(0.05, deadline - time.time()))
            except queue.Empty:
                break
            m = TOKEN_RE.search(line)
            if m:
                return m.group(1)
        return None

    def answer(self, token, yes):
        # The token ALONE approves; the token plus anything else denies
        # (see internal/cli/approve.go's parseApprovalAnswer).
        os.write(self.master_fd, (token + ("\n" if yes else " n\n")).encode())

    def approve_next(self, timeout=10):
        tok = self.wait_for_token(timeout)
        if tok is None:
            return False
        self.answer(tok, True)
        return True

    def deny_next(self, timeout=10):
        tok = self.wait_for_token(timeout)
        if tok is None:
            return False
        self.answer(tok, False)
        return True

    def no_prompt_within(self, seconds):
        """True if no NEW prompt token appears within `seconds` — used
        to prove `approval: once` served a call from cache without
        re-prompting."""
        return self.wait_for_token(timeout=seconds) is None


def main():
    os.makedirs(WORK, exist_ok=True)
    for f in (STATE, CAP):
        if os.path.exists(f):
            os.remove(f)
    subprocess.run(["rm", "-rf", AUDIT], check=False)

    master_fd, slave_fd = pty.openpty()
    srv = subprocess.Popen(
        [BIN, "serve", "--transport", "local", "--policy", POLICY,
         "--ttl", "10m", "--state", STATE, "--audit", AUDIT,
         "--out", CAP, "--force"],
        stdin=slave_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1)
    os.close(slave_fd)
    ap = Approver(srv, master_fd)
    try:
        task = None
        for _ in range(100):
            line = srv.stdout.readline()
            if line.startswith("Task:"):
                task = line.split()[1]
                break
        assert task, "serve did not print a task"
        print("task:", task, flush=True)

        m = Mcp(CAP)

        # --- approve: exec gated `approval: always` succeeds once granted ---
        wait, _ = call_async(m, "remote_exec", {"command": "echo", "args": ["hi1"]})
        check("approve: prompt appeared", ap.approve_next())
        r = wait(10)
        check("approve: exec succeeded", r is not None and inner_text(r) is not None,
              json.dumps(r)[:160] if r else "timeout")

        # --- deny: same tool, operator says no ---
        wait, _ = call_async(m, "remote_exec", {"command": "echo", "args": ["hi2"]})
        check("deny: prompt appeared", ap.deny_next())
        r = wait(10)
        check("deny: exec denied",
              r is not None and r["result"].get("isError") is True
              and "approval denied" in json.dumps(r), json.dumps(r)[:160] if r else "timeout")

        # --- always: identical argv still re-prompts every call ---
        wait, _ = call_async(m, "remote_exec", {"command": "echo", "args": ["hi1"]})
        check("always: re-prompts on identical argv", ap.approve_next())
        r = wait(10)
        check("always: second identical call still succeeded",
              r is not None and inner_text(r) is not None, json.dumps(r)[:160] if r else "timeout")

        # --- once: first sleep call prompts; identical second call must
        #     NOT prompt again, served straight from the once-cache ---
        wait1, _ = call_async(m, "remote_exec", {"command": "/bin/sleep", "args": ["1"]})
        check("once: first call prompts", ap.approve_next())
        r1 = wait1(10)
        check("once: first call succeeded", r1 is not None and inner_text(r1) is not None,
              json.dumps(r1)[:160] if r1 else "timeout")

        wait2, _ = call_async(m, "remote_exec", {"command": "/bin/sleep", "args": ["1"]})
        no_reprompt = ap.no_prompt_within(2)
        r2 = wait2(10)
        check("once: identical second call not re-prompted", no_reprompt)
        check("once: identical second call succeeded",
              r2 is not None and inner_text(r2) is not None, json.dumps(r2)[:160] if r2 else "timeout")

        # --- once: DIFFERENT argv (mutated operation) requires a fresh
        #     approval — proves the once-cache is keyed by the exact
        #     normalized operation, not just "this tool" ---
        wait3, _ = call_async(m, "remote_exec", {"command": "/bin/sleep", "args": ["2"]})
        check("once: mutated argv re-prompts", ap.approve_next())
        r3 = wait3(10)
        check("once: mutated argv call succeeded",
              r3 is not None and inner_text(r3) is not None, json.dumps(r3)[:160] if r3 else "timeout")

        # --- write: once, then mutated CONTENT at the same path requires
        #     reapproval — proves the write hash binds content, not just
        #     path ---
        path = WORK + "/approval.txt"
        wait4, _ = call_async(m, "remote_write", {"path": path, "content": "v1"})
        check("write once: first write prompts", ap.approve_next())
        r4 = wait4(10)
        check("write once: first write succeeded", r4 is not None and inner_text(r4) is not None,
              json.dumps(r4)[:160] if r4 else "timeout")

        wait5, _ = call_async(m, "remote_write", {"path": path, "content": "v1"})
        no_reprompt_write = ap.no_prompt_within(2)
        r5 = wait5(10)
        check("write once: identical rewrite not re-prompted", no_reprompt_write)
        check("write once: identical rewrite succeeded",
              r5 is not None and inner_text(r5) is not None, json.dumps(r5)[:160] if r5 else "timeout")

        wait6, _ = call_async(m, "remote_write", {"path": path, "content": "v2"})
        check("write once: mutated content re-prompts", ap.approve_next())
        r6 = wait6(10)
        check("write once: mutated content write succeeded",
              r6 is not None and inner_text(r6) is not None, json.dumps(r6)[:160] if r6 else "timeout")

        # --- revoke while an approval prompt is pending: the call must
        #     resolve denied promptly (task death kills the pending
        #     prompt), never hang until the 5-minute approval timeout ---
        wait7, done7 = call_async(m, "remote_exec", {"command": "echo", "args": ["pending-revoke"]})
        tok = ap.wait_for_token(10)
        check("revoke: prompt appeared before revoke", tok is not None)
        t0 = time.time()
        rv = subprocess.run([BIN, "revoke", "--state", STATE, task],
                             capture_output=True, text=True)
        check("revoke ok", rv.returncode == 0 and "revoked" in rv.stdout, rv.stdout.strip())
        r7 = wait7(20)
        dt = time.time() - t0
        check("revoke: pending prompt resolved promptly, denied",
              r7 is not None and r7["result"].get("isError") is True and dt < 15,
              "dt=%.1fs %s" % (dt, json.dumps(r7)[:160] if r7 else "timeout"))

        m.close()
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
        try:
            os.close(master_fd)
        except OSError:
            pass
    for f in (STATE, CAP):
        if os.path.exists(f):
            os.remove(f)
    subprocess.run(["rm", "-rf", AUDIT, WORK + "/approval.txt"], check=False)

    # --- expiry while an approval prompt is pending: a separate, short-TTL
    #     task's approval-gated call must resolve denied around expiry —
    #     task death (this time via TTL, not revoke) must kill a pending
    #     prompt the exact same way. Fresh serve instance so the earlier,
    #     already-revoked task can't interfere. ---
    exp_state = "./testdata/e2e/approval-exp-state.json"
    exp_audit = "./testdata/e2e/approval-exp-audit"
    exp_cap = "./testdata/e2e/approval-exp.cap"
    for f in (exp_state, exp_cap):
        if os.path.exists(f):
            os.remove(f)
    subprocess.run(["rm", "-rf", exp_audit], check=False)

    exp_master_fd, exp_slave_fd = pty.openpty()
    exp_srv = subprocess.Popen(
        [BIN, "serve", "--transport", "local", "--policy", POLICY,
         "--ttl", "3s", "--state", exp_state, "--audit", exp_audit,
         "--out", exp_cap, "--force"],
        stdin=exp_slave_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1)
    os.close(exp_slave_fd)
    exp_ap = Approver(exp_srv, exp_master_fd)
    try:
        exp_task = None
        for _ in range(100):
            line = exp_srv.stdout.readline()
            if line.startswith("Task:"):
                exp_task = line.split()[1]
                break
        assert exp_task, "expiry serve did not print a task"

        exp_m = Mcp(exp_cap)
        wait8, _ = call_async(exp_m, "remote_exec", {"command": "echo", "args": ["pending-expiry"]})
        tok = exp_ap.wait_for_token(10)
        check("expiry: prompt appeared before expiry", tok is not None)
        t0 = time.time()
        # Never answer it — let the 3s TTL expire the task out from under
        # the pending prompt.
        r8 = wait8(20)
        dt = time.time() - t0
        check("expiry: pending prompt resolved around TTL expiry, denied",
              r8 is not None and r8["result"].get("isError") is True and dt < 15,
              "dt=%.1fs %s" % (dt, json.dumps(r8)[:160] if r8 else "timeout"))
        exp_m.close()
    finally:
        exp_srv.terminate()
        try:
            exp_srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            exp_srv.kill()
        try:
            os.close(exp_master_fd)
        except OSError:
            pass
    for f in (exp_state, exp_cap):
        if os.path.exists(f):
            os.remove(f)
    subprocess.run(["rm", "-rf", exp_audit], check=False)

    print("FAILURES: %d" % len(failures), flush=True)
    sys.exit(1 if failures else 0)


main()
