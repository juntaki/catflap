"""Pairing golden + adversarial E2E (Phase 4): real `share`/`mcp`
binaries over subprocess + stdio JSON-RPC, pairing directly over a
temporary Tailcat/local pair server — no HTTP rendezvous of any kind.
Complements the unit tests in internal/pair and internal/mcp, which
cover the crypto/logic edge cases in isolation — this script exercises
the same paths across real process boundaries, the way an actual agent
and operator would.

Starts its own `share`, so it must run alone:
  python3 testdata/e2e/pairing.py
Exits non-zero on any failure. All artifacts stay under ./testdata/e2e/.
"""
import glob
import json
import os
import queue
import subprocess
import sys
import threading
import time

BIN = "./bin/catflap"
WORK = "./testdata/e2e/pairing-work"
STATE = "./testdata/e2e/pairing-state.json"
AUDIT = "./testdata/e2e/pairing-audit"

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail, flush=True)
    if not cond:
        failures.append(name)


class Mcp:
    """One `catflap mcp` process (unpaired by default), speaking stdio
    JSON-RPC.

    A dedicated reader thread demuxes stdout by JSON-RPC id, so that:
      - a notification (no "id" — e.g. notifications/tools/list_changed,
        fired by AddTool/RemoveTools as a side effect of the very call
        being awaited) is never mistaken for a request's response, and
      - two calls' requests can genuinely both be in flight on the wire
        at once (each blocks only on ITS OWN id's response, not on
        holding a lock across the whole write+read).
    """

    def __init__(self, extra_env=None):
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        self.p = subprocess.Popen(
            [BIN, "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env,
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
                                   "clientInfo": {"name": "pairing-e2e", "version": "0"}}})
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

    def call(self, name, args):
        rid = self._next_id()
        return self._request({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                               "params": {"name": name, "arguments": args}})

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


def start_share(ttl="10m", pairing_ttl=None, extra_args=None):
    """Starts `catflap share`, returns (process, pairing_code, machine_name)."""
    args = [BIN, "share", "--transport", "local", "--admin", "127.0.0.1:0",
            "--audit", AUDIT, "--state", STATE, "--ttl", ttl]
    if pairing_ttl:
        args += ["--pairing-ttl", pairing_ttl]
    if extra_args:
        args += extra_args
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    code = None
    machine = None
    lines = []
    for _ in range(200):
        line = p.stdout.readline()
        if not line:
            break
        lines.append(line)
        stripped = line.strip()
        if stripped.startswith("Sharing ") and machine is None:
            # "Sharing <machine> for <ttl>"
            machine = stripped.split()[1]
        elif stripped.startswith("CAT-") and code is None:
            code = stripped
        elif stripped.startswith("Expires:"):
            break
    return p, code, machine


def stop(p, timeout=10):
    if p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()


def main():
    os.makedirs(WORK, exist_ok=True)
    for f in (STATE,):
        if os.path.exists(f):
            os.remove(f)
    subprocess.run(["rm", "-rf", AUDIT], check=False)

    try:
        # ============================= GOLDEN PATH =============================
        share, code, machine = start_share()
        try:
            check("share printed a pairing code", bool(code) and code.startswith("CAT-"), str(code))
            check("share printed a machine name", bool(machine), str(machine))

            m = Mcp()
            unpaired = tool_names(m.tools_list())
            check("unpaired tools/list is exactly {pair,status}",
                  sorted(unpaired) == ["pair", "status"], str(unpaired))

            r = m.call("pair", {"code": code})
            check("pair succeeds", not is_error(r), json.dumps(r)[:200])

            paired_tools = tool_names(m.tools_list())
            check("paired tools/list includes remote_exec and disconnect",
                  "remote_exec" in paired_tools and "disconnect" in paired_tools,
                  str(paired_tools))
            check("paired tools/list still hides remote_write (readonly-debug policy)",
                  "remote_write" not in paired_tools, str(paired_tools))

            r = m.call("remote_exec", {"command": "echo", "args": ["golden-ok"]})
            check("allowed operation succeeds", "golden-ok" in json.dumps(r), json.dumps(r)[:160])

            r = m.call("remote_exec", {"command": "rm", "args": ["-rf", "/"]})
            check("denied operation (policy) is an error", is_error(r), json.dumps(r)[:160])

            r = m.call("status", {})
            body = inner_text(r)
            check("status reports paired with the right machine name",
                  body is not None and body.get("paired") is True and body.get("name") == machine,
                  json.dumps(r)[:160])
            check("status never includes the task secret",
                  "task_secret" not in json.dumps(r) and "client_priv" not in json.dumps(r),
                  json.dumps(r)[:160])

            r = m.call("disconnect", {})
            body = inner_text(r)
            check("disconnect confirms revoked",
                  body is not None and body.get("disconnected") is True and body.get("status") == "revoked",
                  json.dumps(r)[:160])

            after = tool_names(m.tools_list())
            check("tools/list returns to unpaired shape after disconnect",
                  sorted(after) == ["pair", "status"], str(after))
            m.close()

            # Endpoint unusable: the task itself — not just this MCP
            # process's view of it — must be gone server-side too
            # (revoke_self -> Stop -> onStop -> live/store detach +
            # server close), confirmed independently via the admin API
            # `catflap tasks` talks to.
            time.sleep(0.3)
            rv = subprocess.run([BIN, "tasks", "--state", STATE], capture_output=True, text=True)
            check("revoked task no longer appears in `tasks`",
                  rv.returncode == 0 and machine not in rv.stdout, rv.stdout.strip())

            # Audit finalized: the terminal record for this task's chain
            # must show the revoke, not just create/allow/deny entries.
            audit_files = glob.glob(AUDIT + "/*.jsonl")
            check("exactly one audit file", len(audit_files) == 1, str(audit_files))
            if audit_files:
                lines_ = open(audit_files[0]).read().strip().splitlines()
                terminal = [json.loads(l) for l in lines_ if '"task.stop"' in l]
                check("audit chain has a terminal task.stop record", len(terminal) == 1, str(terminal))
                if terminal:
                    check("terminal record's decision is revoked",
                          terminal[0].get("decision") == "revoked", json.dumps(terminal[0]))
        finally:
            stop(share)

        # =========================== ADVERSARIAL ===========================

        # --- wrong checksum: must fail locally, no dial attempt at all ---
        m = Mcp()
        r = m.call("pair", {"code": "CAT-0000-0000-0000-0000-0000-0000-0000-0000-0000-XXX"})
        check("adv: garbage/checksum-bad code rejected", is_error(r), json.dumps(r)[:160])
        m.close()

        # --- pair twice: second attempt on an already-paired server denied ---
        share2, code2, _ = start_share()
        try:
            m = Mcp()
            r = m.call("pair", {"code": code2})
            check("adv: first pair of a fresh server succeeds", not is_error(r), json.dumps(r)[:160])
            share3, code3, _ = start_share()
            try:
                r = m.call("pair", {"code": code3})
                check("adv: pairing twice on one MCP server is denied", is_error(r), json.dumps(r)[:160])
            finally:
                stop(share3)
            m.close()
        finally:
            stop(share2)

        # --- concurrent pair: two simultaneous pair calls, exactly one wins ---
        share4, code4, _ = start_share()
        try:
            m = Mcp()
            results = [None, None]

            def try_pair(i):
                results[i] = m.call("pair", {"code": code4})

            threads = [threading.Thread(target=try_pair, args=(i,)) for i in range(2)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=20)
            wins = sum(1 for r in results if r and not is_error(r))
            check("adv: concurrent pair on the same server has exactly one winner",
                  wins == 1, str([json.dumps(r)[:120] for r in results]))
            m.close()
        finally:
            stop(share4)

        # --- pair against an already-revoked task: revoke tears the pair
        # server down along with the task, so the still-unclaimed code
        # must fail too, not just the (already-gone) task itself ---
        share5, code5, machine5 = start_share()
        try:
            rv = subprocess.run([BIN, "revoke", "--state", STATE, machine5],
                                 capture_output=True, text=True)
            check("adv setup: revoke before pairing succeeds", rv.returncode == 0, rv.stdout.strip())
            m = Mcp()
            r = m.call("pair", {"code": code5})
            check("adv: pairing against an already-revoked task fails", is_error(r), json.dumps(r)[:160])
            m.close()
        finally:
            stop(share5)

        # --- expired pairing code (pair server TTL, not task TTL) ---
        share6, code6, _ = start_share(pairing_ttl="1s")
        try:
            time.sleep(2)
            m = Mcp()
            r = m.call("pair", {"code": code6})
            check("adv: expired pairing code (pair server TTL) is rejected", is_error(r), json.dumps(r)[:160])
            m.close()
        finally:
            stop(share6)

        # --- consumed pairing code: claimed once already ---
        share7, code7, _ = start_share()
        try:
            m1 = Mcp()
            r1 = m1.call("pair", {"code": code7})
            check("adv setup: first claim of the code succeeds", not is_error(r1), json.dumps(r1)[:160])
            m2 = Mcp()
            r2 = m2.call("pair", {"code": code7})
            check("adv: a second server can't re-claim an already-consumed code",
                  is_error(r2), json.dumps(r2)[:160])
            m1.close()
            m2.close()
        finally:
            stop(share7)

        # --- pair server gone before any claim: killing share tears the
        # pair server down along with the task, so pairing against a
        # code whose share process already died must fail cleanly (no
        # hang, no crash), not hang waiting for a dial that will never
        # complete ---
        share8, code8, _ = start_share()
        stop(share8)
        m = Mcp()
        r = m.call("pair", {"code": code8})
        check("adv: pair server gone before any claim fails cleanly (no hang, no crash)",
              is_error(r), json.dumps(r)[:160])
        m.close()

        # --- disconnect target unreachable: task's process is gone ---
        share9, code9, _ = start_share()
        m = Mcp()
        r = m.call("pair", {"code": code9})
        check("adv setup: pair before killing the target succeeds", not is_error(r), json.dumps(r)[:160])
        stop(share9)  # kill the target out from under the still-paired client
        time.sleep(0.3)
        r = m.call("disconnect", {})
        check("adv: disconnect against an unreachable target does not claim revoked",
              is_error(r), json.dumps(r)[:160])
        still_paired = tool_names(m.tools_list())
        check("adv: local pairing state is KEPT when disconnect can't confirm",
              "remote_exec" in still_paired, str(still_paired))
        m.close()

    finally:
        for f in (STATE,):
            if os.path.exists(f):
                os.remove(f)
        subprocess.run(["rm", "-rf", AUDIT, WORK], check=False)

    print("FAILURES: %d" % len(failures), flush=True)
    sys.exit(1 if failures else 0)


main()
