"""Golden-path E2E (§17): share -> pair -> operate -> disconnect -> dead.

Spawns its own rendezvous + share/serve processes (local transport), so it
must run alone. All artifacts stay under ./testdata/e2e/.
Exit non-zero on any failure.
"""
import json
import os
import re
import subprocess
import sys
import time

BIN = "./bin/catflap"
E2E = "./testdata/e2e"
RDV = "http://127.0.0.1:8479"

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail, flush=True)
    if not cond:
        failures.append(name)


class Mcp:
    def __init__(self, extra_env=None):
        env = dict(os.environ)
        env["CATFLAP_RENDEZVOUS"] = RDV
        if extra_env:
            env.update(extra_env)
        self.p = subprocess.Popen(
            [BIN, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1, env=env)
        self.rid = 0

    def call(self, name, args):
        self.rid += 1
        rid = self.rid
        self.p.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
             "params": {"name": name, "arguments": args}}) + "\n")
        self.p.stdin.flush()
        while True:
            r = json.loads(self.p.stdout.readline())
            if r.get("id") == rid:
                return r

    def list_tools(self):
        self.rid += 1
        rid = self.rid
        self.p.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": rid, "method": "tools/list"}) + "\n")
        self.p.stdin.flush()
        while True:
            r = json.loads(self.p.stdout.readline())
            if r.get("id") == rid:
                return [t["name"] for t in r["result"]["tools"]]

    def close(self):
        try:
            self.p.stdin.close()
        except BrokenPipeError:
            pass
        self.p.wait(timeout=15)


def text_of(resp):
    try:
        if resp["result"].get("isError"):
            return None
        return resp["result"]["content"][0]["text"]
    except (KeyError, TypeError):
        return None


def is_error(resp):
    try:
        return resp["result"].get("isError") is True
    except (KeyError, TypeError):
        return True


def start_rdv():
    log = open(E2E + "/golden-rdv.log", "w")
    p = subprocess.Popen([BIN, "rendezvous", "--listen", "127.0.0.1:8479"],
                         stdout=log, stderr=subprocess.STDOUT)
    for _ in range(50):
        time.sleep(0.1)
        try:
            import urllib.request
            import urllib.error
            try:
                urllib.request.urlopen(RDV + "/v1/envelopes/00", timeout=1)
            except urllib.error.HTTPError:
                pass  # 404 from a live server means ready
            return p
        except Exception:
            pass
    raise RuntimeError("rendezvous did not start")


def start_share(extra, out_prefix):
    out = open(E2E + "/" + out_prefix + ".out", "w")
    err = open(E2E + "/" + out_prefix + ".err", "w")
    p = subprocess.Popen(
        [BIN, "share", "--transport", "local", "--ttl", "10m",
         "--state", E2E + "/" + out_prefix + "-state.json",
         "--audit", E2E + "/" + out_prefix + "-audit",
         "--rendezvous", RDV] + extra,
        stdout=out, stderr=err)
    code = None
    for _ in range(100):
        time.sleep(0.1)
        with open(E2E + "/" + out_prefix + ".out") as f:
            m = re.search(r"CAT-[A-Z2-7\- ]+", f.read())
            if m:
                code = m.group(0).strip()
                break
    assert code, "share did not print a pairing code"
    return p, code


def main():
    rdv = start_rdv()
    procs = [rdv]
    try:
        # ---- Flow A: short code golden path ----
        share, code = start_share([], "golden-share")
        procs.append(share)
        check("code format", code.startswith("CAT-"), code[:20] + "…")
        m = Mcp()
        check("pre-pair tools", m.list_tools() == ["pair", "status"])
        r = m.call("pair", {"code": code})
        t = text_of(r)
        check("pair connected", t is not None and "Connected." in t, (t or "")[:60])
        tools = m.list_tools()
        for want in ("pair", "status", "disconnect", "run_command", "read_file", "stat_file"):
            check("tool listed:" + want, want in tools)
        check("write hidden (no grant)", "write_file" not in tools)
        r = m.call("run_command", {"command": "echo", "args": ["golden-ok"]})
        t = text_of(r)
        check("allowed op", t is not None and "golden-ok" in t)
        r = m.call("run_command", {"command": "rm", "args": []})
        check("denied op", is_error(r))
        r = m.call("status", {})
        t = text_of(r)
        check("status paired", t is not None and "Connected." in t)
        r = m.call("disconnect", {})
        check("disconnect", text_of(r) is not None and "isError" not in json.dumps(r))
        check("post-disconnect tools", m.list_tools() == ["pair", "status"])
        r = m.call("run_command", {"command": "echo", "args": ["x"]})
        check("post-disconnect call fails", is_error(r))
        m.close()

        # ---- Negatives: reuse / wrong / expired codes ----
        m2 = Mcp()
        r = m2.call("pair", {"code": code})
        check("code reuse denied", is_error(r), json.dumps(r)[:100])
        r = m2.call("pair", {"code": "CAT-AAAA-BBBB-CCCC"})
        check("wrong code denied", is_error(r))
        r = m2.call("pair", {"code": "not-a-code"})
        check("garbage denied", is_error(r))
        m2.close()

        share2, code2 = start_share(
            ["--pairing-ttl", "2s", "--name", "short-pair"], "golden-expire")
        procs.append(share2)
        time.sleep(3)
        m3 = Mcp()
        r = m3.call("pair", {"code": code2})
        check("expired code denied", is_error(r), json.dumps(r)[:100])
        m3.close()

        # ---- Flow B: revoked-task pair denied (paste flow via serve) ----
        st = E2E + "/golden-rev-state.json"
        capf = E2E + "/golden-rev.cap"
        au = E2E + "/golden-rev-audit"
        for f in (st, capf):
            if os.path.exists(f):
                os.remove(f)
        subprocess.run(["rm", "-rf", au], check=False)
        srv = subprocess.Popen(
            [BIN, "serve", "--transport", "local", "--ttl", "10m",
             "--state", st, "--audit", au, "--out", capf, "--force"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(srv)
        cap = None
        for _ in range(100):
            time.sleep(0.1)
            if os.path.exists(capf):
                cap = open(capf).read().strip()
                break
        assert cap, "serve did not write capability"
        m4 = Mcp()
        r = m4.call("pair", {"code": cap})
        check("paste pair connected", text_of(r) is not None)
        m4.close()
        # Revoke via CLI using the serve state, then pair must fail.
        import base64
        raw = open(capf).read().strip()
        task_id = json.loads(base64.urlsafe_b64decode(raw[5:] + "=="))["task"]
        rv = subprocess.run([BIN, "revoke", "--state", st, task_id],
                            capture_output=True, text=True)
        check("revoke ok", rv.returncode == 0 and "revoked" in rv.stdout)
        m5 = Mcp()
        r = m5.call("pair", {"code": cap})
        check("revoked-task pair denied", is_error(r), json.dumps(r)[:120])
        m5.close()
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        for f in ("golden-share.out", "golden-share.err", "golden-share-state.json",
                  "golden-expire.out", "golden-expire.err", "golden-expire-state.json",
                  "golden-rev-state.json", "golden-rev.cap", "golden-rdv.log"):
            try:
                os.remove(E2E + "/" + f)
            except OSError:
                pass
        subprocess.run(["rm", "-rf", E2E + "/golden-share-audit",
                        E2E + "/golden-expire-audit", E2E + "/golden-rev-audit"],
                       check=False)
    print("FAILURES: %d" % len(failures), flush=True)
    sys.exit(1 if failures else 0)


main()
