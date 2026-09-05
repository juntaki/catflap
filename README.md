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
    → EXPIRE / REVOKE / SHUTDOWN (server.Close: identity, PSK, address, and auth die together)
```

Tasks move CREATING → ACTIVE → STOPPING → STOPPED; only ACTIVE tasks
accept operations, and every termination path funnels through one ordered
teardown (stop-accepting → cancel with cause → bounded drain → terminal
`task.stop` audit event → server close → audit close).

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
- [x] CI: golangci-lint (incl. Tailcat quarantine via depguard) +
  `go test -race` + `go build` + govulncheck + adversarial E2E job
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

# 2b. (optional) revoke a task early: same teardown as expiry —
# in-flight ops cancelled, endpoint closed, secrets deleted (idempotent)
./bin/catflap revoke --state <state-file> agt_…

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
with `capability expired` (or `task revoked` / `task shutdown` when killed
that way). The agent sees at most four tools: `remote_exec` (command +
argv, no shell), `remote_read`, `remote_stat`, and — only with an explicit
`file.write` grant — `remote_write`.

`--transport local` runs the same stack over loopback (tests, LAN demos).

## MCP protocol

The agent adapter is built on the official MCP Go SDK (pinned in
`go.mod`), speaking spec `2026-07-28` by default (`server/discover`,
stateless requests) while negotiating older spec versions with older
clients — no handwritten protocol parsing remains. The adapter waits up
to the task's max exec duration (carried in the capability) plus margin,
so long permitted operations are never cut off early; cancellation of
in-flight remote operations from the MCP side is future work (expiry and
revoke kill server-side meanwhile).

Gateway RPC frames are bounded at 2MiB, enforced incrementally on receipt
and checked before send. All policy-controlled content limits are capped
so even fully-adversarial bytes (worst-case 6x JSON escaping) fit one
frame. Argument vectors are unbounded by policy (use tight argv shapes) —
content limits, not argv, carry the frame guarantee.

## Policy

Policies are schema v1 (`version: 1` required; unknown versions and unknown
fields fail closed). The capability carries a short prefix of the policy's
canonical hash — equal authorization semantics hash equal, regardless of
YAML formatting.

```yaml
version: 1
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

Resource bounds live in `limits:` and always apply — omitted fields take
hard built-in defaults, never zero. Content ceilings honor the transport
contract (worst-case JSON escaping still fits one 2MiB frame):

```yaml
limits:
  max_concurrent_calls: 4   # per-task concurrent operations (fail fast)
  max_exec_duration: 60s    # clamps per-call timeouts
  max_stdout_bytes: 262144  # max 256KiB
  max_stderr_bytes: 65536   # max 64KiB
  max_read_bytes: 262144    # max 256KiB
```

`serve` additionally caps live tasks (`--max-tasks`, default 16): further
grants fail instead of allocating unboundedly.

`tools/list` exposes only the tools the task's policy can authorize
(`remote_exec` iff exec rules exist, `remote_read`/`remote_stat` iff read
roots exist, `remote_write` iff a write grant exists); the gateway
re-enforces every call regardless.

File access is confined to roots **after** symlink resolution: final-component
symlinks are denied, intermediate-symlink escapes (`root/outside -> /etc`)
are denied, files open with `O_NOFOLLOW`. Anything else is denied **and**
logged as denied. See [`examples/policies/`](examples/policies/).

All file access goes through the SafeFS layer (`internal/safefs`): every
open starts from a directory fd for the root and walks components with
`O_NOFOLLOW`; on Linux the final component additionally uses `openat2`
(`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`). Writes exist only through
`remote_write` with a separate `file.write` grant:

```yaml
  file:
    write:
      roots:
        - /workspace/work
      max_file_size: 262144
      create: true      # allow new files (parent must exist)
      overwrite: false  # allow replacing existing files
      atomic: true      # temp + fsync + rename (link for create-only); preserves mode on replace
```

Reads and writes are independent grants; without `file.write` the write
tool denies everything (default deny). New files are `0600`. Concurrent
create-only writes to the same path resolve atomically: exactly one wins,
the rest are denied (link-based publication, no rename race).

## Audit

One hash-chained JSONL file per task (`~/.catflap/audit/<task>.jsonl`),
schema v1 (`"v": 1` covered by the chain hash):

```json
{"v":1,"task":"agt_…","seq":17,"time":"…","agent_key":"nodekey:abc…",
 "tool":"remote_exec","args_hash":"sha256:…","decision":"allow",
 "result_hash":"sha256:…","duration_ms":83,"prev":"sha256:…","hash":"sha256:…"}
```

Every chain opens with `task.create` (binding the canonical policy hash)
and closes with `task.stop`; the terminal record seals the logger, so the
runtime itself cannot append after it. `prev` links entries and
args/results are stored as hashes only. Verify offline:

```bash
catflap audit verify <task>.jsonl [--expect-head sha256:…]
catflap audit anchor [--out anchor.log] <task>.jsonl
```

A valid chain alone is not proof against whole-file replacement — pair
verification with an external head anchor. A degraded sink (write errors)
is sticky and reported to the operator, never silent.

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
- The admin API binds loopback only; the state file (admin bearer token)
  gets the same secure-file semantics as capabilities.

Known gaps: no human approval yet, no network egress policy yet, SafeFS is
dirfd-walk (not full `openat2`-only) with a residual rename race against
concurrent local writers (which the agent is not), audit chain has no
external anchor yet.

## Layout (Tailcat is quarantined)

```text
cmd/catflap/            CLI: serve | grant | mcp
internal/
  transport/            seam: Server/Client interfaces (no Tailcat types leak out)
    transport.go
    tailcat/            ONLY package that imports github.com/tailscale/tailcat
    local/              loopback transport (tests/demos)
  capability/           agc1_… bearer tokens (task, endpoint, client key, secret, expiry)
  policy/               structured argv policy + file grants (schema v1)
  safefs/               dedicated filesystem layer (dirfd walk, openat2)
  gateway/              per-task auth, TTL, enforcement (no shell), Stop/GC
  rpc/                  JSONL request/response frames (2MiB bound, enforced incrementally)
  audit/                hash-chained JSONL logger (v1 records, verify, anchors)
  mcp/                  MCP adapter on the official Go SDK (spec 2026-07-28 baseline, older clients negotiated)
  cli/                  serve (per-task servers+admin API) / grant / mcp wiring
examples/policies/      readonly-debug, lab-gpu
testdata/               e2e drivers (local + live-Tailcat probes) + adversarial tests
```

## Roadmap

```text
v0.1   Tailcat transport, ephemeral credentials, TTL, exec/read/stat, JSONL audit ✓
v0.1.1 security semantics: structured argv, symlink封じ, 1 task = 1 server, Close, cap-file ✓
v0.1.2 endpoint↔task binding, TTL cancels trees, ordered teardown, hardened --out, CI ✓
v0.2-A policy schema v1 (version required, strict decode, canonical hash) ✓
v0.2-B revoke + lifecycle CREATING/ACTIVE/STOPPING/STOPPED ✓
v0.2-C SafeFS (dirfd walk, Linux openat2) ✓
v0.2-D remote_write on SafeFS (read/write split, default deny) ✓
v0.2-E limits (tasks, concurrency, timeouts, byte caps) + policy-normalized tools/list ✓
v0.2-F adversarial E2E (25 checks green), 0.2.0 ✓
v0.3   human approval, audit verify + external anchor, specialized adapters
```

## License

MIT — see [LICENSE](LICENSE). Tailcat itself is BSD-3-Clause and is used as a
library; no Tailscale account is required.
