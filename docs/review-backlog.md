# Review backlog

Non-blocking findings from Codex merge-gate reviews. P2/P3 only — P0/P1
findings are fixed before a phase's gate passes and never land here.

## Phase 0 (termination ownership unification) — codex review, 2026-09-05

- **P2 — `TestRevokeSelfVsExpiryOwnershipMatchesWinner` doesn't force
  contention.** The test ignores the revoke_self RPC's response and can
  pass even when expiry wins the arbiter before revoke_self's RPC ever
  reaches `beginControlOp`/`TryRequestStop` — i.e. it may be exercising
  "expiry alone" rather than a genuine race between the two paths. Tighten
  with explicit synchronization (e.g. block one path until the other has
  reached a checkpoint) so both sides are provably contesting the same
  task. (`internal/cli/lifecycle_test.go`)
- **P3 — minor** — none currently outstanding from this phase; the two
  stale-comment findings from this review round were fixed in-phase
  (root-context comment in `RunGateway`, ownership-test comment
  referencing the removed `lt.stopping` field).
