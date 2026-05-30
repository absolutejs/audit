# @absolutejs/audit

Cross-surface audit-event substrate for the AbsoluteJS ecosystem.

One append-only log spanning sync mutations + queue jobs + runtime exits +
secret rotations + auth events + anything else the host wants to record.
Pluggable sinks, optional hash-chain tamper-evidence, live-wire helpers that
attach to the substrate packages' existing listener APIs.

## Install

```sh
bun add @absolutejs/audit
```

## The 30-second tour

```ts
import {
  createAudit,
  memorySink,
  consoleSink,
  withIntegrity,
  verifyChain,
  recordRuntimeTransition,
  recordQueueError,
  recordSecretRotation,
  recordSyncActivity,
} from '@absolutejs/audit';

// One sink to hold a tail in memory, one to ship JSON lines to your
// existing log pipeline.
const audit = createAudit({
  sinks: [
    withIntegrity(memorySink({ max: 10_000 }), { secret: process.env.AUDIT_SECRET }),
    consoleSink(),
  ],
});

// Live-wire the substrate packages' lifecycle hooks.
const runtime = createRuntime({
  onTransition: recordRuntimeTransition(audit),
  // ...
});
const worker = createQueueWorker({
  onError: recordQueueError(audit),
  // ...
});
broker.onRotate('STRIPE_KEY', recordSecretRotation(audit));
engine.onActivity(recordSyncActivity(audit));

// Or emit directly for anything not covered by a helper.
await audit.append({
  kind: 'billing.invoice.created',
  actor: 'system',
  target: invoice.id,
  metadata: { amountCents: invoice.amountCents },
});

// Forensics later: detect any modification / removal / reordering.
const events = await sink.list?.({ since: someTimestamp });
const result = await verifyChain(events, process.env.AUDIT_SECRET);
if (!result.ok) console.error(`Chain broken at index ${result.brokenAt}`);
```

## Design

### Open-ended event shape

```ts
type AuditEvent = {
  at: number;
  kind: string;             // open: "auth.login", "sync.insert", "runtime.exit", ...
  actor?: string;           // userId, system component, etc.
  target?: string;          // resourceId, tenantId, table name, etc.
  metadata?: Record<string, unknown>;
};
```

`kind` is a free-form namespaced identifier. No closed union — any package
(yours included) can emit any event type without modifying audit.

### Sinks are pluggable + composable

Bundled:

- **`memorySink({ max })`** — in-process FIFO tail. Useful in tests and small
  deployments. Pair with a durable sink for production.
- **`consoleSink({ stream, stringify })`** — one JSON line per event to
  stdout (default) or stderr. Rides the host's existing log pipeline.

Vendor-specific sinks (Postgres, SQS, SIEM forwarders) live as siblings in
`@absolutejs/audit-adapters/*`.

The sink contract is intentionally minimal:

```ts
type AuditSink = {
  append: (event: AuditEvent) => Promise<void> | void;
  list?: (filter?: AuditEventFilter) => Promise<AuditEvent[]> | AuditEvent[];
  prune?: (before: number) => Promise<number> | number;
  flush?: () => Promise<void> | void;
  close?: () => Promise<void> | void;
  readonly name?: string;
};
```

`append` is required; the rest is optional. A SIEM forwarder doesn't implement
`list`; a memory tail does. `createAudit` fans out to every sink — a sink
that throws bumps `audit.metrics().sinkErrors[name]` but doesn't block the
others.

### Hash-chain integrity is a decorator

```ts
const sink = withIntegrity(memorySink(), { secret: 'shared-key' });
// Every appended event carries metadata.__integrity = { hash, previousHash, writerId }.

// Later:
const events = await sink.list?.();
const result = await verifyChain(events, 'shared-key');
// { ok: true } or { ok: false, brokenAt: <index> }
```

- **Concurrent appends are serialized within a writer.** The chain is the
  correctness contract, not a perf optimization — `withIntegrity` queues
  appends so concurrent callers don't race on `lastHash`.
- **Per-writer sub-chains** let multiple instances or a single instance
  across restarts each own a self-contained chain. Default: random
  `writerId` per `withIntegrity` call. Pass a stable `writerId` to resume
  one chain across restarts (seeded by scanning the sink, or supply
  `loadWriterHead` for a scan-free seed).
- **HMAC mode** (when you provide `secret`) means an attacker with write
  access still can't forge a valid chain. Without a secret, the chain uses
  SHA-256 — modification is detectable but a writer can forge new chains.
- The integrity link rides in `metadata.__integrity`, so any sink (memory,
  jsonb, S3 JSON) preserves it through serialization round-trips.

### Live-wire helpers

Each helper returns a callback the host wires into the SOURCE package's
existing listener API. Audit doesn't reach into the runtime's lifecycle.

| Helper | Wires into | Emits |
|---|---|---|
| `recordRuntimeTransition(audit)` | `createRuntime({ onTransition })` | `runtime.<type>` |
| `recordQueueError(audit)` | `createQueueWorker({ onError })` | `queue.error` |
| `recordSecretRotation(audit)` | `broker.onRotate(name, ...)` | `secrets.rotated` |
| `recordSyncActivity(audit)` | `engine.onActivity(...)` | `sync.change.<op>` / `sync.mutation.<status>` / `sync.batch.<status>` / `sync.retry` |

For events not covered by a helper (your own app's billing / impersonation /
deletion etc.), call `audit.append({ kind, ... })` directly.

### Metrics

```ts
audit.metrics();
// {
//   appended: 1234,     // successful appends (all sinks succeeded)
//   appendErrors: 2,    // appends where at least one sink threw
//   sinkErrors: { memory: 0, console: 0, postgres: 2 }
// }
```

Scrape on a 30s interval; alert on `appendErrors` climbing.

## License

[BSL-1.1](./LICENSE) with a Tier-A carveout: you can't use this to operate
a hosted audit-trail / compliance-log SaaS that competes with Datadog Audit
Trail, Splunk Enterprise Audit, Cribl Stream, Vanta, Drata, Sumo Logic, or
AWS CloudTrail's hosted equivalents. You CAN use it as one piece of your
own application (including your own SaaS). The license auto-converts to
Apache 2.0 on 2030-05-29.
