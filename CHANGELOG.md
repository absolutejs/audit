# Changelog

All notable changes to `@absolutejs/audit` are recorded here.

## [0.0.4] — 2026-07-14

- Integrity-wrapped sinks now always expose `flush()` and `close()`, even when
  the underlying immediate sink has no lifecycle methods. This makes the
  append-tail drain guarantee uniform across memory, Postgres, console, and
  buffered sinks.

## [0.0.3] — 2026-07-14

- `withIntegrity()` now waits for its serialized append chain before
  delegating `flush()` or `close()` to the wrapped sink. Fire-and-forget audit
  producers can therefore rely on the documented graceful-shutdown contract
  without losing an integrity-protected tail event.
- No API changes.

## [0.0.1] — 2026-05-29

Initial preview. Cross-surface audit-event substrate addressing the gap the
deep-research audit flagged: every package in the AbsoluteJS substrate
emitted a different "something happened" shape; SOC2 V1 + every enterprise
tenant needed one unified append-only log spanning the whole tenant
lifecycle.

### Core

- **`createAudit({ sinks, onError })`** — factory. Fans out every append
  to every sink concurrently; one sink throwing doesn't cancel the others.
- **`AuditEvent`** with open-ended `kind: string` so any package can emit
  any event type without modifying audit.
- **`audit.metrics()`** — cumulative `appended` / `appendErrors` +
  per-sink `sinkErrors` counters.
- **`audit.flush()` / `audit.close()`** — graceful shutdown contract.
- **`AuditClosedError`** thrown by `append()` after `close()`.

### Bundled sinks

- **`memorySink({ max })`** — in-process FIFO tail with filterable `list()`,
  `prune()`, and `flush`/`close` no-ops.
- **`consoleSink({ stream, stringify })`** — JSON-per-line to stdout or
  stderr; rides the host's existing log pipeline.

### Hash-chain integrity

- **`withIntegrity(sink, { secret, writerId, loadWriterHead })`** — decorator
  that adds tamper-evidence to any sink. Stores `(previousHash, hash, writerId)`
  in `metadata.__integrity` so any storage (memory, jsonb, S3 JSON)
  round-trips it without schema changes. Concurrent appends serialize within
  a writer so they don't race on `lastHash`.
- **`verifyChain(events, secret?)`** — forensic verifier. Returns
  `{ ok: true }` or `{ ok: false, brokenAt: <index> }`. Per-writer sub-chains
  verified independently.
- **HMAC mode** (with `secret`) prevents forgery even by writers; SHA-256
  mode (no secret) detects modification.
- **Stable JSON** for hashing — survives jsonb / JSON round-trips that
  reorder object keys.

### Live-wire helpers

Each returns a callback the host wires into the SOURCE package's existing
listener API:

- **`recordRuntimeTransition(audit)`** → `runtime.<type>` events keyed on
  tenant. Wires into `createRuntime({ onTransition })`.
- **`recordQueueError(audit)`** → `queue.error` with job context. Wires into
  `createQueueWorker({ onError })`.
- **`recordSecretRotation(audit)`** → `secrets.rotated` with name +
  fingerprint (never the value). Wires into `broker.onRotate(name, ...)`.
- **`recordSyncActivity(audit)`** → `sync.change.<op>` / `sync.mutation.<status>`
  / `sync.batch.<status>` / `sync.retry`. Wires into `engine.onActivity(...)`.

### Tests

34 across 3 files: core fan-out + sink composition + integrity (clean
chain, modification, removal, reordering, HMAC, concurrent writers,
preserved metadata, genesis hash, JSON round-trip, 50-concurrent
serialization) + adapter shape + integration (three-source single-chain).
