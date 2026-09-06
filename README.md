# catflap

> **No pre-existing network reachability, no persistent credential — a temporary SSH login that dies with the task.**

catflap grants an AI agent a real SSH login to a real machine, for a fixed
TTL, then destroys the endpoint, the route to it, and the credential that
authenticated against it — all three at once. There is no command
allowlist, no filesystem policy, and no approval flow: SSH already is a
general-purpose remote-access protocol, and the OS account `catflap share`
runs as is what defines what an agent can do, exactly like a normal SSH
login. What catflap adds is that none of it outlives the task.

```text
Host                                       Agent side

catflap share
  │
  ├─ ephemeral Tailcat identity
  ├─ ephemeral SSH host key
  ├─ embedded SSH server (in-process — no sshd, no authorized_keys)
  ├─ TTL
  └─ one-shot pair server
             │
             │ CAT-XXXX-XXXX-...
             ▼
                                        catflap setup claude
                                        claude
                                          │
                                          ├─ generate ephemeral Ed25519 key
                                          │    private → stays on this side
                                          │    public  ─────────────────────┐
                                          │                                 │
             ◀────────────────────────────┘                                │
  register that exact key as the                                          │
  task's one allowed SSH identity;                                        │
  pair server dies (one-shot)                                             │
             │                                                            │
             └═══════════════════ SSH over Tailcat/WireGuard ═════════════┘

TTL / Ctrl-C / SIGTERM
  → SSH server closes (severs any already-open session, not just future ones)
  → every ordinary in-flight command's process GROUP is killed
  → Tailcat identity dies
  → the one allowed key stops meaning anything — network route and credential are both gone
```

No Catflap-operated rendezvous, no Catflap-hosted service of any kind: the
agent dials the pair server directly over the same Tailcat tunnel the task
itself will use, exchanges keys, and the pair server destroys itself right
after — whether or not the exchange even succeeded. (Tailcat itself may
still use Tailscale's DERP relays to bootstrap and, when a direct path
isn't possible, as a fallback relay — see
[Security model](#security-model--read-this) — but no Catflap component of
any kind sits in that path.)

## Why not just run sshd?

Because the two things that make handing someone SSH access uncomfortable
— a long-lived key you have to remember to revoke, and a machine that has
to already be reachable on some network — are exactly what catflap removes:

```text
CREATE  → ephemeral Tailcat identity (network reachability, previously none)
        → ephemeral SSH host key (in memory only, never written to disk)
        → the ONE client key pairing delivers (in-memory allowlist, no authorized_keys)
ACTIVE  → ordinary SSH: real shell, real pipes, whatever the OS account can do
EXPIRE / REVOKE / SHUTDOWN → SSH server closes: identity, route, and the one
                              allowed key all stop existing at once
```

Nothing about *what a command is allowed to do* is Catflap's job anymore —
that boundary already exists, and it's the one your OS account has always
had. Catflap's job is narrower and sharper: the machine is unreachable
until you run `share`, and the access it grants cannot outlive the process
that granted it.

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
Sharing this machine for 30m0s

Pairing code:
  CAT-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX

Tell Claude:
  Connect to Catflap using CAT-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX

Expires: 21:42
```

Agent side (Claude Code, once — registers the *unpaired* server at user
scope):

```bash
catflap setup claude
claude
```

Paste the `Tell Claude:` line into the `claude` session. Nothing is
copy-pasted by hand except that one pairing code: it encodes only the
address of a temporary pair server — a throwaway Tailcat (or local, for
tests) identity that accepts one connection, exchanges keys, and destroys
itself right after. No Catflap-operated rendezvous or third party ever
sees either side's key in the clear — the exchange happens only inside the
Tailcat/WireGuard tunnel.

Once paired, the SDK advertises `exec` and `disconnect` via
`tools/list_changed` — no reconnect needed. Pairing codes are single-use (a
second claim gets nothing) and their TTL is always clamped to the task's
own remaining TTL.

```bash
catflap doctor   # Claude Code / MCP registration / audit — all in one check
```

There is no `grant`, `revoke`, `tasks`, or `share-code` command: one
`share` process is one lease. Ending it (Ctrl-C, SIGTERM, or its own TTL)
is the only way to end access, and it ends all of it at once. Once paired,
the agent sees:

- `exec` — run a shell command line on the paired machine, through its
  login shell. Pipes, `&&`, redirection, quoting all work normally, exactly
  like a real `ssh` client — there is no argv allowlist. Result is
  `{"stdout", "stderr", "exit_code"}`; a non-zero remote exit is a normal
  result, not a tool error.
- `disconnect` — ends this adapter's own connection. It does **not** revoke
  the task; only the operator's `share` process ending does that.

## MCP protocol

The agent adapter is built on the official MCP Go SDK (pinned in
`go.mod`), speaking spec `2026-07-28` by default (`server/discover`,
stateless requests) while negotiating older spec versions with older
clients. Unpaired, the server exposes only `pair` / `status`; after
pairing it advertises `exec` / `disconnect` via `tools/list_changed`.

## Audit

One hash-chained JSONL file per task (`~/.catflap/audit/<task>.jsonl`),
schema v1 (`"v": 1` covered by the chain hash). Unlike the RPC-era gateway,
there is no structured per-tool decision to log — the audit record here is
coarser, one line per SSH session's command shape and outcome, never its
output:

```json
{"v":1,"task":"agt_…","seq":2,"time":"…",
 "tool":"ssh_exec","args_hash":"sha256:…","decision":"allow",
 "result_hash":"sha256:…","duration_ms":83,"prev":"sha256:…","hash":"sha256:…"}
```

Every chain opens with `task.create` and closes with a terminal event
(`expired` / `revoked` / `shutdown`); the terminal record seals the
logger, so the runtime itself cannot append after it. `prev` links entries
and args/results are stored as hashes only. Verify offline:

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
SSH     = the actual access protocol and its own well-understood auth model
catflap = making the endpoint, the route, and the SSH credential ephemeral
```

Concretely, catflap assumes the **agent (or whoever holds the pairing
code) is untrusted but the operator running `share` is trusted**, and
enforces:

- **No pre-existing reachability.** Nothing about this machine is
  dialable before `share` runs. The task's Tailcat identity — fresh key,
  fresh PSK, one address — exists only for the task's lifetime; `Close()`
  on expiry/revoke deletes the address itself, not just the auth on top
  of it.
- **No persistent credential.** The SSH host key is generated in memory
  per task and never touches disk. The one client key allowed to
  authenticate is whatever pairing delivered — there is no
  `authorized_keys` file, no way to add a second key, and it means
  nothing once the task is gone.
- **Host key pinning, not blind SSH trust-on-first-use.** The pairing
  exchange (itself carried over an independently-authenticated Tailcat
  tunnel — a Tailcat address embeds a random WireGuard pre-shared key, so
  knowing it is what lets a client complete the handshake at all) hands
  the client the task's exact host key fingerprint. The client's SSH
  `HostKeyCallback` rejects anything else, so a network-level impersonator
  that somehow answers on the right address still can't pass as the real
  task.
- **Revoke actually severs live sessions.** The embedded SSH server is one
  shared instance per task, not one per connection — closing it (TTL,
  Ctrl-C, SIGTERM) closes every currently-open connection, not just future
  ones. An idle interactive session gets disconnected outright.
- **Ordinary in-flight commands are killed as a process group, not just
  their direct shell.** Catflap terminates the process group of an
  ordinary in-flight SSH command on task death — a build's worker
  processes, a test runner's children, all die with it. This is
  lifecycle cleanup, not containment: code running with the OS account's
  own privileges can deliberately detach a process (`setsid`, a
  cron/launchd/systemd unit it installs) to survive outside that process
  group on purpose. A task-scoped SSH login and a sandbox that can roll
  back every side effect an untrusted process makes on the host are two
  different products; catflap is the former.
- **Pairing codes are one-time, short-lived, and typo-safe** (CRC-16
  checked locally before any network round trip). They carry only a pair
  server's own transport+address — nothing else needs encrypting on top.
  The pair server is its own Tailcat identity, separate from the task's,
  claims exactly one connection, and self-destructs immediately after
  (whether or not the exchange succeeded) or after its own TTL — always
  clamped to the task's remaining TTL and to a fixed 10-minute ceiling
  regardless of how long the task itself runs, so a code can never outlive
  its task or become a long-lived bootstrap secret on its own.
- **Every SSH session is audited** (command shape, duration, exit code —
  never output) through the same hash-chained, fail-closed log every prior
  version used.

**What catflap explicitly does NOT do**, on purpose: it does not decide
what commands are safe to run, does not sandbox or contain a running
process beyond killing it at task death, and does not restrict network
egress from the paired session. Those are the OS account's job now, the
same as they are for anyone you'd hand a real SSH login to. If you need
narrower guarantees than "whatever this OS account can do," don't run
`share` as that account — create one scoped to exactly what you're willing
to lend out.

A pairing code is a bearer secret for the duration it's claimable: whoever
connects to the pair server first with it wins, first-come-first-served —
this is normal for one-shot device pairing, but it means a leaked code
(shared over chat, screenshotted) can be claimed by someone other than the
intended agent if they're faster. Keep the window (`--pairing-ttl`) tight
if that risk matters to you.

## Layout (Tailcat is quarantined)

```text
cmd/catflap/            CLI entry point
internal/
  transport/            seam: Server/Client interfaces (no Tailcat types leak out)
    transport.go
    tailcat/            ONLY package that imports github.com/tailscale/tailcat; also owns Tailcat's own security contract (allowlist, port restriction, per-Serve identity)
    local/              loopback transport (tests/demos)
    transporttest/        shared behavioral contract every transport (local, tailcat, future ones) must satisfy
  sshhost/              the embedded SSH server bound to one task (host key, allowed client key, TTL/revoke, exec/PTY sessions)
  sshmcp/               the Claude-side MCP adapter: pair (host-key-pinned SSH dial) / exec / disconnect / status
  pair/                 pairing codes (encode/decode, no crypto) + the one-shot pair server/client exchanging SSH keys
  audit/                hash-chained JSONL logger (v1 records, verify, anchors)
  cli/                  share / mcp / setup / audit / doctor wiring
testdata/               e2e driver: real share + real mcp stdio, golden path + adversarial pairing/revoke/TTL cases
```

## License

MIT — see [LICENSE](LICENSE). Tailcat itself is BSD-3-Clause and is used as a
library; no Tailscale account is required.
