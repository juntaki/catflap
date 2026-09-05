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
┌─────────────────────┐
│ catflap mcp agc1_…  │  agent-side adapter (ephemeral client key)
└──────────┬──────────┘
           │ Tailcat / WireGuard (no account, no root, userspace only)
           ▼
┌──────────────────────────┐
│ catflap serve (target)   │
│  task: agt_…  expires +15m
│  policy snapshot: lab-gpu│
│  MCP tools: remote_exec / remote_read / remote_stat
└───────────┬──────────────┘
            │  localhost/LAN
            ▼  GPU / DB / Robot
```

One task = one ephemeral identity + one policy snapshot + one network
capability + one audit chain.

## Why not "SSH over MCP"?

Existing SSH-MCP tools wrap **long-lived credentials** to reach **always-on
networks**. catflap inverts that: starting from *no credential and no
reachable network*, it mints a **single-task encrypted route and permission
together**, and both vanish on expiry:

```text
CREATE (task id, ephemeral server+client keys, frozen policy)
  → ACTIVE (MCP calls, each allow/deny audited)
    → EXPIRE / CLOSE (keys destroyed, capability dead)
```

## Status: v0.1

- [x] Tailcat transport (ephemeral server key + PSK, `AllowedClients` per grant)
- [x] Ephemeral capabilities (`agc1_…`), TTL, `serve` / `grant` / `mcp`
- [x] `remote_exec` / `remote_read` / `remote_stat` with policy enforcement
- [x] JSONL audit with hash chain
- [ ] YAML policy allowlists/roots are minimal (v0.2 hardens them)
- [ ] Human approval, read/write split, specialized adapters (roadmap below)

## Quickstart

```bash
go build -o bin/catflap ./cmd/catflap

# 1. target: serve (prints one capability immediately)
./bin/catflap serve --policy ./examples/policies/readonly-debug.yaml --ttl 15m
# Task: agt_…
# Capability:
# agc1_xxxxxxxxxxxxxxxxx
# Expires: …

# 2. (optional) mint more tasks while serve runs
./bin/catflap grant --policy ./examples/policies/readonly-debug.yaml --ttl 15m

# 3. agent side: register as an MCP server
./bin/catflap mcp agc1_xxxxxxxxxxxxxxxxx
```

Claude Code (`claude mcp add`):

```json
{
  "mcpServers": {
    "target": {
      "command": "/path/to/catflap",
      "args": ["mcp", "agc1_xxxxxxxxxxxxxxxxx"]
    }
  }
}
```

After the TTL, every call fails with `capability expired` — the server key,
client key, and policy binding are gone. The agent sees only three tools:
`remote_exec`, `remote_read`, `remote_stat`.

`--transport local` runs the same stack over loopback (tests, LAN demos).

## Policy

```yaml
name: staging-db-debug
ttl: 15m
tools:
  exec:
    commands:
      - systemctl status '*'
      - journalctl '*'
      - docker ps
  file:
    read:
      roots:
        - /var/log/myapp
```

Command patterns match the whole command line (quote-insensitive glob, `*`
spans `/`). File access is confined to the listed roots. Anything else is
denied **and** logged as denied. See [`examples/policies/`](examples/policies/).

## Audit

One JSONL file per task (`~/.catflap/audit/<task>.jsonl`, `--audit` to change):

```json
{"task":"agt_…","seq":17,"time":"…","agent_key":"nodekey:abc…",
 "tool":"remote_exec","args_hash":"sha256:…","decision":"allow",
 "result_hash":"sha256:…","duration_ms":83,"prev":"sha256:…","hash":"sha256:…"}
```

`prev` chains entries; args/results are stored as hashes only.

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

Concretely, v0.1 assumes the **agent is untrusted but the operator running
`serve` is trusted**, and still:

- `exec` is never a general shell: default-deny allowlist, `sh -c` with a
  narrowed environment, timeouts, and output caps.
- File access is root-confined; directories can't be exfiltrated via `read`.
- Tailcat layer is locked down: fresh ephemeral server key + PSK per `serve`
  run, `AllowedClients` limited to granted client keys, single RPC port in
  `ServedTCPPorts`.
- Every decision (allow/deny/expired/error) is hash-chained to JSONL.

Known gaps for later milestones: no human approval yet, no write/network
policy enforcement yet, command allowlists are glob-based (v0.2+ moves toward
structured argv matching), no resource limits (v0.2+).

## Layout (Tailcat is quarantined)

```text
cmd/catflap/            CLI: serve | grant | mcp
internal/
  transport/            seam: Server/Client interfaces (no Tailcat types leak out)
    transport.go
    tailcat/            ONLY package that imports github.com/tailscale/tailcat
    local/              loopback transport (tests/demos)
  capability/           agc1_… bearer tokens (task, endpoint, client key, secret, expiry)
  policy/               YAML policy: exec allowlist, file roots
  gateway/              per-task auth, TTL, enforcement, dispatch
  rpc/                  JSONL request/response frames
  audit/                hash-chained JSONL logger
  mcp/                  MCP stdio bridge (initialize/tools/list/tools/call)
  cli/                  serve (gateway+admin API) / grant / mcp wiring
examples/policies/      readonly-debug, lab-gpu
testdata/               e2e drivers (local + live-Tailcat probes)
```

## Roadmap

```text
v0.1  Tailcat transport, ephemeral credentials, TTL, exec/read/stat, JSONL audit ✓
v0.2  YAML policy hardening, command argv matching, filesystem roots, network restrictions
v0.3  human approval, read/write distinction, audit hash-chain verification cmd
v0.4  specialized adapters: PostgreSQL, Docker, GPU, serial/robot
v0.5  remote task issuance: GitHub Actions / Claude Code / Codex integration
```

## License

MIT — see [LICENSE](LICENSE). Tailcat itself is BSD-3-Clause and is used as a
library; no Tailscale account is required.
