# catflap

> **Give an AI agent access to a machine, not a credential. The access dies with the task.**

catflap is an **ephemeral capability gateway**: it lends the capabilities of a
real machine to an AI agent, per task, with a TTL — then destroys both the
network reachability and the permission at once. No long-lived SSH keys, no
open ports, no reachable network left behind, and no capability blob to
copy-paste.

```text
operator                                            agent side
--------                                             ----------
catflap share --policy p.yaml                        catflap setup claude
  → mints task, its own Tailcat server                 (registers unpaired MCP server)
  → starts a temporary PAIR server                    claude
    (own Tailcat identity, open to                      → MCP `pair` tool + code
     any client, claims one connection)                 → dials the pair server DIRECTLY
  → prints one-time code: CAT-XXXX-XXXX                   over Tailcat/WireGuard
                    │                                    → fetches capability, pair server dies
                    └── Tailcat/WireGuard ────────────────┐  → tools/list_changed: remote_* appear
                        (userspace, no account, no root)  │
                                                            ▼
                                                    task's own server
                                                    policy snapshot
                                                    expires → Close
```

No rendezvous, no hosted infrastructure of any kind: the agent connects
straight to a throwaway pair server over the same encrypted Tailcat tunnel
the task itself uses, fetches the capability once, and the pair server
destroys itself immediately after — whether or not that delivery even
succeeded. One task = one ephemeral network identity + one policy snapshot
+ one audit chain. Expiry closes the task's own server (and any still-open
pair server for it), so the WireGuard identity, the PSK, the address, and
the RPC authorization all die together.

## Why not "SSH over MCP"?

Existing SSH-MCP tools wrap **long-lived credentials** to reach **always-on
networks**. catflap inverts that: starting from *no credential and no
reachable network*, it mints a **single-task encrypted route and permission
together**, and both vanish on expiry:

```text
CREATE (task id, ephemeral server+client keys, frozen policy, own address)
  → ACTIVE (MCP calls, each allow/deny audited, some gated by human approval)
    → EXPIRE / REVOKE / SHUTDOWN (server.Close: identity, PSK, address, and auth die together)
```

Tasks move CREATING → ACTIVE → STOPPING → STOPPED; only ACTIVE tasks
accept operations, and every termination path funnels through one ordered
teardown (stop-accepting → cancel with cause → bounded drain → terminal
`task.stop` audit event → server close → audit close). Task death also kills
any approval prompt still pending for that task.

## Golden path

Install:

```bash
brew install juntaki/catflap/catflap
```

Operator (the machine being lent out — run from the project you want Claude
to work in):

```bash
catflap share
```

```text
Sharing calm-panda for 15m0s

Access
  Read   .
  Write  none
  Run    date, echo, pwd, uname, whoami

Pairing code (valid 5m0s):
  CAT-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX

Tell Claude:
  Connect to Catflap using CAT-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX

Expires: 2026-…
```

That's the built-in read-only-current-directory policy; pass `--policy
p.yaml` for anything else (see [Policy](#policy) below).

Agent side (Claude Code, once — registers the *unpaired* server at user scope):

```bash
catflap setup claude
claude
```

Paste the `Tell Claude:` line from `share`'s output into the `claude` session.
Nothing is copy-pasted by hand except that one pairing code: it encodes only
the address of a temporary pair server — a throwaway Tailcat (or local, for
tests) identity that accepts one connection, hands over the capability, and
destroys itself right after. No rendezvous, no third party ever sees the
capability or any task traffic — the agent dials the pair server directly
over the same encrypted tunnel the task itself uses. Once paired, the SDK
advertises the granted `remote_*` tools via `tools/list_changed` — no
reconnect needed. Pairing codes are single-use (a second claim gets nothing)
and their TTL is always clamped to the task's own remaining TTL.

```bash
catflap tasks                    # list live tasks on the running share/serve
catflap share-code <task|name>   # Claude restarted and the old code is used up?
                                  # reissue a fresh code for the SAME still-live task
catflap revoke <task|name>       # destroy a task early: same teardown as expiry
catflap doctor                   # Claude Code / MCP registration / audit — all in one check
```

Once paired, the agent sees `disconnect` (revoke its own access) alongside
whatever the policy grants: `remote_exec` (command + argv, no shell),
`remote_read`, `remote_stat`, and — only with an explicit `file.write`
grant — `remote_write`. After the TTL, the task's server is closed: calls
fail with `capability expired` (or `task revoked` / `task shutdown` when
killed that way).

### Advanced / legacy: build from source, manual capability file

```bash
go build -o bin/catflap ./cmd/catflap
```

Before pairing, catflap issued a capability blob directly. This path still
works — for scripting, tests, or headless automation — but is no longer the
default:

```bash
./bin/catflap serve --policy ./examples/policies/readonly-debug.yaml --ttl 15m --out ./task.cap
./bin/catflap grant --policy ./examples/policies/readonly-debug.yaml --ttl 15m --out ./task2.cap
./bin/catflap mcp --cap-file ./task.cap
```

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

`--transport local` runs the same stack over loopback (tests, LAN demos).

## MCP protocol

The agent adapter is built on the official MCP Go SDK (pinned in
`go.mod`), speaking spec `2026-07-28` by default (`server/discover`,
stateless requests) while negotiating older spec versions with older
clients — no handwritten protocol parsing remains. Unpaired, the server
exposes only `pair` / `status`; after pairing it advertises the
policy-granted `remote_*` tools via `tools/list_changed`. The adapter waits
up to the task's max exec duration (carried in the capability) plus margin,
so long permitted operations are never cut off early; cancellation of
in-flight remote operations from the MCP side is future work (expiry,
revoke, and approval denial kill server-side meanwhile).

Gateway RPC frames are bounded at 2MiB, enforced incrementally on receipt
and checked before send. All policy-controlled content limits are capped
so even fully-adversarial bytes (worst-case 6x JSON escaping) fit one
frame. Argv is capped independently (64 args, 4096 bytes each) and content
limits are capped separately — together they carry the frame guarantee.

## Policy

Policies are schema v1 (`version: 1` required; unknown versions and unknown
fields fail closed). The capability carries a short prefix of the policy's
canonical hash, independent of YAML formatting (key order, quoting,
whitespace); the hash also covers `name` and `ttl`, so two policies with
identical rules but a different name or TTL hash differently.

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
        approval: once
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
(`exec.commands`) is rejected at load: it cannot be made shell-safe. Argv
itself is bounded too: at most 64 arguments, each at most 4096 bytes.

### Human approval

Approval is an **additional** restriction, never an authorization source: a
policy deny can never be overridden by approval, and approval only ever
narrows what an already-allowed rule may do. Each `exec` rule and the
`file.write` grant carry an `approval` mode:

```yaml
approval: never    # default — the policy decision is final, no prompt
approval: once      # first exact normalized operation this task prompts;
                     # cached for the rest of the task only, never inherited
                     # by another task; any change to argv/path/content is a
                     # different operation and prompts again
approval: always   # every call prompts, no caching
```

The approved hash binds exactly to what executes (resolved path, argv, or
write content) — mutating any of it after approval requires re-approval.
Approval is checked against a terminal-attached `Approver`: `share` and
`serve` attach one automatically when stdin is an interactive terminal
(control bytes in prompts are escaped, concurrent prompts are serialized,
each prompt carries a unique reply token). Without an interactive terminal,
any operation requiring approval fails closed — never blocks forever, never
auto-approves. A task's death (expiry, revoke, shutdown) immediately kills
any approval prompt still pending for it.

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

`share`/`serve` additionally cap live tasks (`--max-tasks`, default 16):
further grants fail instead of allocating unboundedly.

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
      atomic: true       # temp + fsync + rename (link for create-only); preserves mode on replace
      approval: once
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
args/results are stored as hashes only. Approval decisions are logged
through the same fail-closed audit path as every other call — an audit
write failure denies the operation rather than silently proceeding. Verify
offline:

```bash
catflap audit verify [--expect-head sha256:…] <task>.jsonl
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
catflap = identity lifecycle + capability policy + TTL + human approval
          + process containment + resource restrictions + audit
```

Concretely, catflap assumes the **agent is untrusted but the operator
running `share`/`serve` is trusted**, and enforces:

```text
                 Catflap capability
                         │
            ┌────────────┴────────────┐
            │                         │
       network identity          application policy
       Tailcat node key          structured argv tools
       PSK                       filesystem roots
       unique address            TTL + approval mode
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
- Approval is layered strictly on top of policy: it can only add friction to
  an already-allowed operation, never grant one a deny would otherwise
  block, and it binds to the exact resolved argv/path/content that executes.
- Every decision (allow/deny/expired/approved/denied/error) is
  hash-chained to JSONL.
- Pairing codes are one-time, short-lived, and typo-safe (CRC-16 checked
  locally before any network round trip). They carry only a pair server's
  own transport+address — nothing else needs encrypting on top, since a
  Tailcat address already embeds a random WireGuard pre-shared key: knowing
  it is what lets a client complete the handshake at all. The pair server
  is its own Tailcat identity, separate from the task's, claims exactly one
  connection, and self-destructs immediately after (whether or not delivery
  succeeded) or after its own TTL — always clamped to the task's remaining
  TTL, so a code can never outlive its task. No rendezvous, no third party,
  no hosted infrastructure of any kind sees the capability or any task
  traffic. The legacy manual flow's bearer token is best carried via
  `--out` / `--cap-file` (0600 files); it also accepts `--cap` or an env
  var, both discouraged (`--cap` visibly leaks the token into argv/shell
  history) — prefer the pairing flow, or at minimum `--cap-file`.
- The admin API binds loopback only; the state file (admin bearer token)
  gets the same secure-file semantics as capabilities.

Known gaps: no network egress policy yet, SafeFS is dirfd-walk (not full
`openat2`-only on non-Linux) with a residual rename race against concurrent
local writers (which the agent is not), audit chain has an internal hash
chain and an external anchor command but no automated anchoring service yet.

## Layout (Tailcat is quarantined)

```text
cmd/catflap/            CLI entry point
internal/
  transport/            seam: Server/Client interfaces (no Tailcat types leak out)
    transport.go
    tailcat/            ONLY package that imports github.com/tailscale/tailcat
    local/              loopback transport (tests/demos)
  capability/           agc1_… bearer tokens (task, endpoint, client key, secret, expiry)
  pair/                 pairing codes (encode/decode only, no crypto) + the one-shot pair server/client
  policy/               structured argv policy + file grants + approval modes (schema v1)
  safefs/               dedicated filesystem layer (dirfd walk, openat2)
  gateway/              per-task auth, TTL, approval engine, enforcement (no shell), Stop/GC
  rpc/                  JSONL request/response frames (2MiB bound, enforced incrementally)
  audit/                hash-chained JSONL logger (v1 records, verify, anchors)
  mcp/                  MCP adapter on the official Go SDK (spec 2026-07-28 baseline, older clients negotiated)
  cli/                  share/serve (per-task servers+admin API) / grant / mcp / setup / audit / tasks / revoke wiring
examples/policies/      readonly-debug, lab-gpu
testdata/               e2e drivers (local + live-Tailcat probes) + adversarial + pairing + approval tests
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
v0.3-A pairing: rendezvous server, sealed envelopes, `share`/`setup claude`/pair MCP flow ✓
v0.3-B human approval engine: never/once/always, hash-bound, fail-closed, terminal UX ✓
v0.3   release hardening: cross-platform CI, signed releases, README/golden-path parity ✓
v0.3.1 UX pass: effective-permissions share output, share-code re-pair, catflap doctor ✓
v0.3.2 pairing rewrite: direct Tailcat pair servers, no HTTP rendezvous, no hosted infra ✓
v0.4   network egress policy, specialized adapters
```

## License

MIT — see [LICENSE](LICENSE). Tailcat itself is BSD-3-Clause and is used as a
library; no Tailscale account is required.
