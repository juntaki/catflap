# catflap

> **Give an AI agent access to a machine, not a credential. The access dies with the task.**

catflap is an **ephemeral capability gateway**: it lends the capabilities of a
real machine to an AI agent, per task, with a TTL — then destroys both the
network reachability and the permission at once. No long-lived SSH keys, no
open ports, no reachable network left behind.

```text
Claude Code / Codex / Cursor
          │  MCP stdio
          ▼
┌──────────────────────────────┐
│ catflap mcp --cap-file t.cap │  agent-side adapter (ephemeral client key)
└──────────────┬───────────────┘
               │ Tailcat / WireGuard (no account, no root, userspace only)
               ▼
┌──────────────────────────────┐
│ task A: own Tailcat server   │  server key A + PSK A + address A
│  policy snapshot: lab-gpu   │  remote_exec / remote_read / remote_stat
│  expires +15m → server.Close │
└──────────────┬───────────────┘
               │  localhost/LAN
               ▼  GPU / DB / Robot
```

One task = one ephemeral network identity + one policy snapshot + one audit
chain. Expiry closes the task's own server, so the WireGuard identity, the
PSK, the address, and the RPC authorization all die together.

## Why not "SSH over MCP"?

Existing SSH-MCP tools wrap **long-lived credentials** to reach **always-on
networks**. catflap inverts that: starting from *no credential and no
reachable network*, it mints a **single-task encrypted route and permission
together**, and both vanish on expiry:

```text
CREATE (task id, ephemeral server+client keys, frozen policy, own address)
  → ACTIVE (MCP calls, each allow/deny audited)
    → EXPIRE (server.Close: identity, PSK, address, and auth die together)
```

## Status: v0.1.2 (security semantics)

- [x] 1 task = 1 Tailcat server (per-task key, PSK, address; expiry = Close)
- [x] Endpoint↔task binding: a secret stolen from task B is useless at A's endpoint
- [x] Expiry cancels in-flight execs, killing whole process trees (unix pgid,
  SIGKILL lands at cancel time via `Cmd.Cancel` — no reap window);
  ordered teardown: stop-accepting → cancel(cause) → bounded drain →
  terminal `task.stop` audit event → server close → audit close.
  Kill reasons propagate (`expired`/`revoked`/`shutdown`), ready for
  structured error codes.
- [x] Structured argv exec — no shell anywhere (`;`, `&&`, `$()` are inert)
- [x] Symlink/root-escape rejection on file tools
- [x] Ephemeral capabilities (`agc1_…`), TTL, `serve` / `grant` / `mcp`
- [x] `--cap-file` / `--out` flows: no symlinks, no silent overwrite
  (`--force`), atomic 0600 writes — tokens avoid argv and shell history
- [x] Hash-chained JSONL audit incl. terminal lifecycle events
- [x] CI: golangci-lint (correctness/security/context/resource boundary,
  Tailcat quarantine via depguard) + `go test -race` + `go build` + govulncheck
- [ ] Human approval, network restrictions, specialized adapters (roadmap)

## Quickstart

```bash
go build -o bin/catflap ./cmd/catflap

# 1. target: each task gets its OWN Tailcat address
./bin/catflap serve --policy ./examples/policies/readonly-debug.yaml --ttl 15m \
  --out ./task.cap
# Task: agt_…
# Capability: (written to ./task.cap)

# 2. (optional) mint more tasks while serve runs — each a new address
./bin/catflap grant --policy ./examples/policies/readonly-debug.yaml \
  --ttl 15m --out ./task2.cap

# 3. agent side: register as an MCP server (file, not argv)
./bin/catflap mcp --cap-file ./task.cap
```

Claude Code (`claude mcp add`):

```json
{
  "mcpServers": {
    "target": {
      "command": "/path/to/catflap",
      "args": ["mcp", "--cap-file", "/home/you/.catflap/tasks/xxx.cap"]
    }
  }
}
```

After the TTL, the task's server is closed: handshakes fail and calls fail
with `capability expired`. The agent sees only three tools: `remote_exec`
(command + argv, no shell), `remote_read`, `remote_stat`.

`--transport local` runs the same stack over loopback (tests, LAN demos).

## Policy

```yaml
name: staging-db-debug
ttl: 15m
tools:
  exec:
    allow:
      - command: systemctl
        args: [status, { match: "*" }]
      - command: journalctl
        args: ["-u", { any: true }, "-n", { integer: { max: 1000 } }]
      - command: docker
        args: [ps]
  file:
    read:
      roots:
        - /var/log/myapp
```

Arg matchers: exact string, `{any:true}`, `{integer:{min,max}}`,
`{choice:[…]}`, `{match:"glob"}`; `rest: any` permits trailing argv (only
for commands that cannot reach files — never for `cat`-likes). Arity is
exact otherwise. Commands resolve via `PATH` at call time (operator's PATH,
never the agent's) or as absolute paths. The v0.1 shell-string allowlist
(`exec.commands`) is rejected at load: it cannot be made shell-safe.

File access is confined to roots **after** symlink resolution: final-component
symlinks are denied, intermediate-symlink escapes (`root/outside -> /etc`)
are denied, files open with `O_NOFOLLOW`. Anything else is denied **and**
logged as denied. See [`examples/policies/`](examples/policies/).

## Audit

One hash-chained JSONL file per task (`~/.catflap/audit/<task>.jsonl`):

```json
{"task":"agt_…","seq":17,"time":"…","agent_key":"nodekey:abc…",
 "tool":"remote_exec","args_hash":"sha256:…","decision":"allow",
 "result_hash":"sha256:…","duration_ms":83,"prev":"sha256:…","hash":"sha256:…"}
```

`prev` links entries and args/results are stored as hashes only. This is a
hash-chained log, not tamper-proof against whole-file rewrites — a
`catflap audit verify` command plus an external head anchor is roadmap work.

## Security model — read this

**`Tailcat ≠ our security boundary.`** Tailcat's own
[`SECURITY.md`](https://github.com/tailscale/tailcat/blob/main/SECURITY.md)
states its wrapper was designed for *one person operating both ends* and its
threat model has not historically included mutually distrusting parties. Its
Go API/CLI/wire format also carry **no stability promises**.

So catflap draws the responsibility line explicitly:

```text
Tailcat = encrypted reachability transport
catflap = identity lifecycle + capability policy + TTL
          + process containment + resource restrictions + audit
```

Concretely, v0.1.1 assumes the **agent is untrusted but the operator running
`serve` is trusted**, and enforces:

```text
                 Catflap capability
                         │
            ┌────────────┴────────────┐
            │                         │
       network identity          application policy
       Tailcat node key          structured argv tools
       PSK                       filesystem roots
       unique address            TTL
            │                         │
            └────────────┬────────────┘
                         │
                      Task
                         │
                       expire
                         │
             ┌───────────┴───────────┐
             ↓                       ↓
        server.Close()          policy deleted
             ↓                       ↓
       unreachable               unauthorized
```

- `exec` is structured argv with no shell in the path: exact arity, typed
  matchers, narrowed environment, timeouts, output caps.
- File tools reject symlinks and resolve-then-contain every path.
- Every task owns a Tailcat server: fresh key + PSK, `AllowedClients`
  containing only that task's client key, single RPC port in
  `ServedTCPPorts`, `Close()` on expiry deleting the address itself.
  The handler is bound to the task id, so network credential A +
  RPC credential B denies: cross-endpoint secret replay fails.
- Task expiry cancels in-flight operations first (task-scoped context),
  then closes the server and audit: no process outlives its TTL. On unix
  the child runs in its own process group, so grandchildren die too —
  lifecycle containment, not a hostile-code sandbox.
- Every decision (allow/deny/expired/error) is hash-chained to JSONL.
- Bearer tokens travel via files (`--out` / `--cap-file`), not argv.

Known gaps: no human approval yet, no network egress policy yet, no resource
limits yet, symlink defense is check-then-open rather than `openat`-chained
(the residual window needs a concurrent local writer, which the agent is
not), audit chain has no external anchor yet.

## Layout (Tailcat is quarantined)

```text
cmd/catflap/            CLI: serve | grant | mcp
internal/
  transport/            seam: Server/Client interfaces (no Tailcat types leak out)
    transport.go
    tailcat/            ONLY package that imports github.com/tailscale/tailcat
    local/              loopback transport (tests/demos)
  capability/           agc1_… bearer tokens (task, endpoint, client key, secret, expiry)
  policy/               structured argv policy + symlink-aware file roots
  gateway/              per-task auth, TTL, enforcement (no shell), Stop/GC
  rpc/                  JSONL request/response frames
  audit/                hash-chained JSONL logger
  mcp/                  MCP stdio bridge (initialize/tools/list/tools/call)
  cli/                  serve (per-task servers+admin API) / grant / mcp wiring
examples/policies/      readonly-debug, lab-gpu
testdata/               e2e drivers (local + live-Tailcat probes) + adversarial tests
```

## Roadmap

```text
v0.1   Tailcat transport, ephemeral credentials, TTL, exec/read/stat, JSONL audit ✓
v0.1.1 security semantics: structured argv, symlink封じ, 1 task = 1 server, Close, cap-file ✓
v0.1.2 endpoint↔task binding, TTL cancels trees, ordered teardown, hardened --out, CI ✓
v0.2   human approval, read/write distinction, network restrictions, resource limits
v0.3   audit verify + external anchor, specialized adapters: PostgreSQL, Docker, GPU, serial/robot
v0.4   remote task issuance: GitHub Actions / Claude Code / Codex integration
```

## License

MIT — see [LICENSE](LICENSE). Tailcat itself is BSD-3-Clause and is used as a
library; no Tailscale account is required.
