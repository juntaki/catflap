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
│ catflap mcp (paired via      │  agent-side adapter (ephemeral client key)
│ pair: code or pasted token)  │
└──────────────┬───────────────┘
               │ Tailcat / WireGuard (no account, no root, userspace only)
               ▼
┌──────────────────────────────┐
│ task A: own Tailcat server   │  server key A + PSK A + address A
│  policy snapshot: lab-gpu   │  run_command / read_file / stat_file
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

## Status

- [x] 1 task = 1 Tailcat server (per-task key, PSK, address; expiry = Close)
- [x] Endpoint↔task binding, TTL cancels trees, ordered teardown
- [x] Structured argv exec (no shell), SafeFS, `remote_write` split grant
- [x] Policy schema v1 + canonical hash, limits, revoke, lifecycle states
- [x] Audit schema v1, `audit verify`, head anchors
- [x] Agent UX: `share` → pairing code → `pair` in normal Claude session
- [x] Pairing rendezvous (one-time encrypted envelopes, rate-limited)
- [x] CI: golangci-lint + `go test -race` + `go build` + govulncheck
- [ ] Human approval, network restrictions, specialized adapters (roadmap)

## Quickstart (golden path)

On the machine you want Claude to access:

```bash
go install github.com/juntaki/catflap/cmd/catflap@latest
catflap share
```

```text
Catflap access ready.

Pairing code:
  CAT-7KQ9-M2PV-…

Access:
  readonly-debug

Expires:
  15m
```

One-time setup on your own machine, then never again:

```bash
catflap setup claude
```

Afterwards, just start Claude normally and give it the code:

```text
> Connect with Catflap. CAT-7KQ9-M2PV-…
```

The agent pairs over an ephemeral P2P connection, sees only the granted
tools (`run_command`, `read_file`, `stat_file`), and the access disappears
when the task expires or is revoked. Say `disconnect`, or run
`catflap revoke <name>`, to kill it early.

Manage tasks on the target:

```bash
catflap tasks
# NAME              ACCESS           EXPIRES   STATE
# calm-panda        readonly-debug   11m       active

catflap revoke calm-panda
catflap revoke --all
```

`share` profiles and shortcuts (all compile to Policy v1 — there is no
second authorization implementation):

```bash
catflap share --profile workspace-edit
catflap share --read /var/log/myapp --ttl 20m
catflap share --write ./src --name investigate-prod
```

## Pairing security

The short code carries a random id plus a random wrap key — never the task
secret, which travels only inside the sealed envelope. Envelopes are
XChaCha20-Poly1305 sealed, single-use (fetch burns), short-lived (default
5 minutes, server-enforced), and the rendezvous sees ciphertext only. Ids
are rate-limited per IP; pairing a revoked task fails closed at connect;
every pair is audited on the target. The rendezvous relays introductions
only — task traffic is always P2P over Tailcat.

Without a rendezvous, `share` prints a paste-ready capability instead, and
`pair` accepts pasted `agc1_…` tokens directly.

## Advanced (automation)

```bash
catflap serve --policy p.yaml --ttl 15m --out task.cap  # raw gateway
catflap grant --policy p.yaml --ttl 15m                 # extra tasks
catflap mcp --cap-file task.cap                         # pre-paired adapter
catflap mcp                                             # unpaired adapter
catflap audit verify <task>.jsonl                       # chain check
catflap audit anchor [--out anchor.log] <task>.jsonl    # head attestation
catflap rendezvous --listen 127.0.0.1:8471              # pairing server
```

`--transport local` runs the same stack over loopback (tests, LAN demos).

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
hard built-in defaults, never zero:

```yaml
limits:
  max_concurrent_calls: 4   # per-task concurrent operations (fail fast)
  max_exec_duration: 60s    # clamps per-call timeouts
  max_stdout_bytes: 262144
  max_stderr_bytes: 65536
  max_read_bytes: 1048576
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
      max_file_size: 1048576
      create: true      # allow new files (parent must exist)
      overwrite: false  # allow replacing existing files
      atomic: true      # temp + fsync + rename; preserves mode on replace
```

Reads and writes are independent grants; without `file.write` the write
tool denies everything (default deny). New files are `0600`.

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
limits yet, SafeFS is dirfd-walk (not full `openat2`-only) with a residual
rename race against concurrent local writers (which the agent is not),
audit chain has no external anchor yet.

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
v0.2-A policy schema v1 (version required, strict decode, canonical hash) ✓
v0.2-B revoke + lifecycle CREATING/ACTIVE/STOPPING/STOPPED ✓
v0.2-C SafeFS (dirfd walk, Linux openat2) ✓
v0.2-D remote_write on SafeFS (read/write split, default deny) ✓
v0.2-E limits (tasks, concurrency, timeouts, byte caps) + policy-normalized tools/list ✓
v0.2-F adversarial E2E (25 checks green), 0.2.0 ✓
v0.3-A audit schema v1, verify, anchors, task.create ✓
UX agent path: share/profiles, pair/status/disconnect, renamed tools,
rendezvous, setup claude, tasks, golden E2E ✓
v0.3-B human approval (never/once/always)
v0.4   specialized adapters: PostgreSQL, Docker, GPU, serial/robot
```

## License

MIT — see [LICENSE](LICENSE). Tailcat itself is BSD-3-Clause and is used as a
library; no Tailscale account is required.
