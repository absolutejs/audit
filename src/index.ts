/**
 * @absolutejs/audit — cross-surface audit-event substrate.
 *
 * The problem the deep-research audit flagged: every package in the
 * AbsoluteJS substrate emits a different "something happened" shape. Auth
 * has typed `AuditEvent`s, sync has `LoggedChange`s, queue has
 * `worker.onJobEvent`, runtime has `onTransition`, secrets has
 * `onRotate`. SOC2 + every enterprise tenant wants ONE append-only log
 * spanning the whole tenant lifecycle. This package is that log.
 *
 * Design choices:
 *
 * 1. **Open-ended event shape.** `kind: string` is a free-form
 *    namespaced identifier (`"sync.insert"`, `"runtime.exit"`,
 *    `"secrets.rotated"`, `"queue.job.completed"`). NO closed union, so
 *    any package — including ones we haven't shipped yet — can emit
 *    without modifying `@absolutejs/audit`. The structured fields
 *    (`actor` / `target` / `metadata`) cover the common cross-surface
 *    questions ("who did this", "what was it done to", "any extra
 *    context").
 *
 * 2. **Sinks are pluggable + composable.** Bundled: `memorySink()`
 *    (in-process tail; useful in tests and small deployments) and
 *    `consoleSink()` (stdout JSON; useful with the runtime's
 *    `redactStream` for stdout-shipped audit forwarding). Postgres /
 *    SQS / SIEM-vendor sinks live as siblings in
 *    `@absolutejs/audit-adapters/*`. The sink contract is intentionally
 *    minimal — `append` is required; `list` and `prune` are optional
 *    (a forwarder doesn't need either).
 *
 * 3. **Hash-chain integrity is a decorator.** `withIntegrity(sink, ...)`
 *    wraps any sink; it stores the `(previousHash, hash)` link inside
 *    `metadata.__integrity`, so every existing sink (memory, file,
 *    Postgres jsonb, S3 JSON) round-trips it with no schema change.
 *    `verifyChain(events, secret?)` is the forensic verifier. Per-writer
 *    sub-chains let multiple instances or a redeploying single instance
 *    keep their chains separate.
 *
 * 4. **Live-wire helpers, not subscriptions.** Each adapter
 *    (`recordRuntimeTransition`, `recordQueueEvent`, etc.) returns a
 *    plain callback the host wires into the SOURCE package's existing
 *    listener API. Audit doesn't reach into the runtime's lifecycle —
 *    the host stays in control of what gets logged and from which
 *    source.
 *
 * 5. **Cumulative metrics, like the rest of the substrate.**
 *    `audit.metrics()` returns `appended`/`appendErrors`. Scrape on a
 *    30s interval; alert on errors climbing.
 */

const INTEGRITY_KEY = '__integrity';
const GENESIS = '';

const encoder = new TextEncoder();

/**
 * A single audit event. `kind` is a namespaced string (`"sync.insert"`,
 * `"auth.login"`, etc.) — open-ended on purpose so any package can emit
 * any event type without coordinating with `@absolutejs/audit`. The
 * structured fields cover the cross-surface essentials; everything else
 * goes in `metadata`.
 */
export type AuditEvent = {
	/** Wall-clock at emission (`Date.now()`). */
	at: number;
	/**
	 * Namespaced event identifier. Convention: `"<source>.<event>"`,
	 * e.g. `"runtime.spawn"`, `"sync.delete"`, `"queue.job.failed"`.
	 * Free-form — no enforced enum.
	 */
	kind: string;
	/**
	 * Who caused the event — `userId`, system component, or omitted
	 * for events with no semantic actor (`"runtime.observation"`).
	 */
	actor?: string;
	/**
	 * What the event was done TO — `resourceId`, `tenantId`, table
	 * name, etc.
	 */
	target?: string;
	/** Free-form extra context. Avoid stuffing secrets here — pair with
	 * `@absolutejs/secrets` `redact()` first. */
	metadata?: Record<string, unknown>;
};

/** Filter for {@link AuditSink.list}. Stores may implement additional filters. */
export type AuditEventFilter = {
	/** Max events to return. */
	limit?: number;
	/**
	 * Substring match against `kind` (`"runtime."` returns every runtime
	 * event). Exact match if the implementation supports it; substring is
	 * the lowest-common-denominator contract.
	 */
	kind?: string;
	/** Exact match on `actor`. */
	actor?: string;
	/** Events with `at >= since`. */
	since?: number;
	/** Events with `at <= until`. */
	until?: number;
};

/**
 * Append-only sink. The contract:
 *
 * - `append` MUST be append-only. Replaying a sink onto another sink
 *   must produce equivalent state (modulo `metadata.__integrity` if
 *   the source used `withIntegrity`).
 * - `list` is optional. Forwarders (SIEM pipelines, console, fire-and-
 *   forget HTTP) don't implement it; stores (memory, Postgres, SQLite)
 *   do.
 * - `prune` is optional. Implementations enforcing a retention window
 *   return the count removed. Note that pruning drops tamper-evidence
 *   for the pruned tail — `verifyChain` can only run forward of the
 *   oldest retained event per writer.
 */
export type AuditSink = {
	append: (event: AuditEvent) => Promise<void> | void;
	list?: (filter?: AuditEventFilter) => Promise<AuditEvent[]> | AuditEvent[];
	prune?: (before: number) => Promise<number> | number;
	/** Optional flush — let the sink batch and write under back-pressure. */
	flush?: () => Promise<void> | void;
	/** Optional close — used by `audit.close()`. */
	close?: () => Promise<void> | void;
	/** Optional name for diagnostics (shown in `audit.metrics()` errors). */
	readonly name?: string;
};

/** Cumulative operator metrics from {@link Audit.metrics}. */
export type AuditMetrics = {
	/** Successful `audit.append()` calls (broadcast to every sink, all succeeded). */
	appended: number;
	/** `audit.append()` calls where at least one sink threw. */
	appendErrors: number;
	/** Per-sink error counts, keyed by sink `name` (or `"sink-<index>"`). */
	sinkErrors: Record<string, number>;
};

export type AuditOptions = {
	/**
	 * One or more sinks. Every `audit.append()` call writes to every
	 * sink concurrently; sink errors don't block other sinks. A sink
	 * that throws bumps `metrics().sinkErrors[name]`.
	 */
	sinks: AuditSink[];
	/**
	 * Per-sink error handler. Defaults to `console.warn`. Useful to
	 * route sink failures to a separate auditing stream (`audit.append`
	 * itself would loop; the host wires a side-channel).
	 */
	onError?: (error: unknown, sinkName: string, event: AuditEvent) => void;
	/** Override `Date.now()` for tests. */
	clock?: () => number;
};

/**
 * The audit handle. Construct with {@link createAudit}.
 */
export type Audit = {
	/**
	 * Emit an audit event. Synthesizes `at` from `clock()` if absent.
	 * Fan-out to every sink is concurrent; one sink throwing doesn't
	 * cancel the others — its error goes to `onError` and the per-sink
	 * counter, the others still receive the event.
	 */
	append: (event: Omit<AuditEvent, 'at'> & { at?: number }) => Promise<void>;
	/** Operator-shaped cumulative counters. */
	metrics: () => AuditMetrics;
	/** Flush every sink that implements `flush()`. */
	flush: () => Promise<void>;
	/** Flush + close every sink. After close(), append() throws. */
	close: () => Promise<void>;
};

export class AuditClosedError extends Error {
	constructor() {
		super('[audit] append() called after close()');
		this.name = 'AuditClosedError';
	}
}

export const createAudit = (options: AuditOptions): Audit => {
	const clock = options.clock ?? Date.now;
	const onError =
		options.onError ??
		((error, sinkName) =>
			console.warn(`[audit] sink "${sinkName}" threw:`, error));
	const sinks = [...options.sinks];
	const sinkName = (sink: AuditSink, index: number): string =>
		sink.name ?? `sink-${index}`;
	let closed = false;
	let appended = 0;
	let appendErrors = 0;
	const sinkErrors: Record<string, number> = {};
	for (let i = 0; i < sinks.length; i++) {
		sinkErrors[sinkName(sinks[i]!, i)] = 0;
	}

	return {
		append: async (partial) => {
			if (closed) throw new AuditClosedError();
			const event: AuditEvent = {
				at: partial.at ?? clock(),
				kind: partial.kind,
				...(partial.actor !== undefined ? { actor: partial.actor } : {}),
				...(partial.target !== undefined
					? { target: partial.target }
					: {}),
				...(partial.metadata !== undefined
					? { metadata: partial.metadata }
					: {})
			};
			const results = await Promise.allSettled(
				sinks.map(async (sink, index) => {
					try {
						await sink.append(event);
					} catch (error) {
						const name = sinkName(sink, index);
						sinkErrors[name] = (sinkErrors[name] ?? 0) + 1;
						onError(error, name, event);
						throw error;
					}
				})
			);
			const anyFailed = results.some(
				(result) => result.status === 'rejected'
			);
			if (anyFailed) appendErrors += 1;
			else appended += 1;
		},
		flush: async () => {
			await Promise.allSettled(
				sinks.map(async (sink, index) => {
					if (sink.flush === undefined) return;
					try {
						await sink.flush();
					} catch (error) {
						onError(error, sinkName(sink, index), {
							at: clock(),
							kind: 'audit.flush.error'
						});
					}
				})
			);
		},
		close: async () => {
			if (closed) return;
			closed = true;
			await Promise.allSettled(
				sinks.map(async (sink, index) => {
					if (sink.flush !== undefined) {
						try {
							await sink.flush();
						} catch (error) {
							onError(error, sinkName(sink, index), {
								at: clock(),
								kind: 'audit.close.flush.error'
							});
						}
					}
					if (sink.close !== undefined) {
						try {
							await sink.close();
						} catch (error) {
							onError(error, sinkName(sink, index), {
								at: clock(),
								kind: 'audit.close.error'
							});
						}
					}
				})
			);
		},
		metrics: () => ({
			appendErrors,
			appended,
			sinkErrors: { ...sinkErrors }
		})
	};
};

// -----------------------------------------------------------------------------
// Bundled sinks
// -----------------------------------------------------------------------------

export type MemorySinkOptions = {
	/** Max events retained. Older events are dropped FIFO when exceeded. */
	max?: number;
};

/**
 * In-process tail of recent events. Useful in tests and small
 * deployments. Drops oldest events FIFO when `max` is reached.
 *
 * NOT durable across restarts. For production, pair this with a
 * durable sink (Postgres, SQS, etc.) — `createAudit({ sinks: [memory,
 * postgres] })` writes to both; queries hit memory, durability hits
 * Postgres.
 */
export const memorySink = (options: MemorySinkOptions = {}): AuditSink => {
	const max = options.max ?? 10_000;
	const events: AuditEvent[] = [];
	return {
		append: (event) => {
			events.push(event);
			while (events.length > max) events.shift();
		},
		list: (filter) => {
			let out = events;
			if (filter?.kind !== undefined) {
				const needle = filter.kind;
				out = out.filter((event) => event.kind.includes(needle));
			}
			if (filter?.actor !== undefined) {
				const actor = filter.actor;
				out = out.filter((event) => event.actor === actor);
			}
			if (filter?.since !== undefined) {
				const since = filter.since;
				out = out.filter((event) => event.at >= since);
			}
			if (filter?.until !== undefined) {
				const until = filter.until;
				out = out.filter((event) => event.at <= until);
			}
			if (filter?.limit !== undefined) {
				out = out.slice(0, filter.limit);
			}
			return [...out];
		},
		name: 'memory',
		prune: (before) => {
			const dropped = events.filter((event) => event.at < before).length;
			let i = 0;
			while (i < events.length && events[i]!.at < before) i++;
			events.splice(0, i);
			return dropped;
		}
	};
};

export type ConsoleSinkOptions = {
	/** `console.log` (default) | `console.error`. */
	stream?: 'log' | 'error';
	/** Override the JSON serializer for redaction or canonicalization. */
	stringify?: (event: AuditEvent) => string;
};

/**
 * Emit one JSON line per event to stdout (default) or stderr. Useful
 * when the host already ships container logs to a SIEM and audit
 * events should ride that pipeline. Pair with
 * `@absolutejs/secrets`'s `redactStream()` upstream so secrets never
 * appear in the JSON.
 */
export const consoleSink = (options: ConsoleSinkOptions = {}): AuditSink => {
	const stream = options.stream ?? 'log';
	const stringify = options.stringify ?? ((event) => JSON.stringify(event));
	return {
		append: (event) => {
			if (stream === 'error') console.error(stringify(event));
			else console.log(stringify(event));
		},
		name: 'console'
	};
};

// -----------------------------------------------------------------------------
// Hash-chain integrity
// -----------------------------------------------------------------------------

const toHex = (buffer: ArrayBuffer): string =>
	[...new Uint8Array(buffer)]
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');

const sha256Hex = async (message: string): Promise<string> =>
	toHex(await crypto.subtle.digest('SHA-256', encoder.encode(message)));

const hmacSha256Hex = async (
	secret: string,
	message: string
): Promise<string> => {
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secret),
		{ hash: 'SHA-256', name: 'HMAC' },
		false,
		['sign']
	);
	return toHex(
		await crypto.subtle.sign('HMAC', key, encoder.encode(message))
	);
};

const sortKeys = (value: unknown): unknown =>
	value === null || typeof value !== 'object' || Array.isArray(value)
		? value
		: Object.fromEntries(
				Object.entries(value as Record<string, unknown>).sort(
					(left, right) => left[0].localeCompare(right[0])
				)
			);

/** Deterministic JSON: object keys sorted at every level. */
const stableStringify = (value: unknown): string =>
	JSON.stringify(value, (_key, val) => sortKeys(val));

const cleanMetadata = (
	metadata?: Record<string, unknown>
): Record<string, unknown> | undefined => {
	if (metadata === undefined) return undefined;
	const result: Record<string, unknown> = {};
	for (const [key, val] of Object.entries(metadata)) {
		if (key !== INTEGRITY_KEY) result[key] = val;
	}
	return Object.keys(result).length === 0 ? undefined : result;
};

const readIntegrity = (event: AuditEvent): AuditIntegrity | undefined => {
	const raw = event.metadata?.[INTEGRITY_KEY];
	if (raw === undefined) return undefined;
	return raw as AuditIntegrity;
};

export type AuditIntegrity = {
	hash: string;
	previousHash: string;
	writerId?: string;
};

export type WithIntegrityOptions = {
	/**
	 * Optional HMAC secret. Without it, the chain uses SHA-256 — a
	 * reader can still detect modification but an attacker with write
	 * access could forge a new chain. With a secret, only a holder of
	 * the secret can produce a valid chain.
	 */
	secret?: string;
	/**
	 * Stable id for this writer. Defaults to a random UUID per
	 * `withIntegrity()` call, so concurrent writers / redeploys each
	 * own a self-contained sub-chain. Pass a stable value to resume a
	 * single writer's chain across restarts.
	 */
	writerId?: string;
	/**
	 * If `writerId` is stable AND the sink supports `list`, the chain
	 * seeds from the most recent event matching this writer. Override
	 * with `loadWriterHead` to skip the scan (e.g. read a single row
	 * keyed by `writerId`).
	 */
	loadWriterHead?: (
		writerId: string
	) => Promise<string | undefined> | string | undefined;
	/** Max events scanned to find the writer's head. Default 1000. */
	seedScanLimit?: number;
};

/**
 * Wrap any sink with per-writer hash-chain integrity. Each appended
 * event carries a `metadata.__integrity = { hash, previousHash,
 * writerId }` link so {@link verifyChain} can detect modification,
 * removal, or reordering. The wrapper preserves `list` / `prune` /
 * `flush` / `close` from the underlying sink.
 */
export const withIntegrity = (
	sink: AuditSink,
	options: WithIntegrityOptions = {}
): AuditSink => {
	const writerId = options.writerId ?? crypto.randomUUID();
	const isResuming = options.writerId !== undefined;
	const secret = options.secret;
	const seedScanLimit = options.seedScanLimit ?? 1000;
	let lastHash: string | undefined;
	let seeded = false;
	// Serialize appends within a writer so concurrent `audit.append`
	// calls don't race on `lastHash`. Without this, two callers can both
	// read the same `previousHash`, then the second's hash links to the
	// pre-first state — `verifyChain` reports brokenAt. The serial chain
	// is the chain's correctness contract, not a perf optimization.
	let appendChain: Promise<void> = Promise.resolve();

	const seed = async (): Promise<void> => {
		if (seeded) return;
		seeded = true;
		if (!isResuming) {
			lastHash = GENESIS;
			return;
		}
		if (options.loadWriterHead) {
			lastHash = (await options.loadWriterHead(writerId)) ?? GENESIS;
			return;
		}
		const recent = (await sink.list?.({ limit: seedScanLimit })) ?? [];
		const head = recent.find(
			(event) => readIntegrity(event)?.writerId === writerId
		);
		lastHash = head ? (readIntegrity(head)?.hash ?? GENESIS) : GENESIS;
	};

	const doAppend = async (event: AuditEvent): Promise<void> => {
		await seed();
		const previousHash = lastHash ?? GENESIS;
		const hash = await hashAuditEvent(event, previousHash, secret);
		lastHash = hash;
		const integrity: AuditIntegrity = {
			hash,
			previousHash,
			writerId
		};
		await sink.append({
			...event,
			metadata: { ...event.metadata, [INTEGRITY_KEY]: integrity }
		});
	};

	return {
		append: (event) => {
			// Chain onto the previous append. A throw doesn't poison the
			// chain — the .catch absorbs it so the NEXT append still
			// runs. The original promise propagates to the caller.
			const next = appendChain.then(() => doAppend(event));
			appendChain = next.catch(() => {});
			return next;
		},
		close: sink.close?.bind(sink),
		flush: sink.flush?.bind(sink),
		list: sink.list?.bind(sink),
		name: sink.name ? `${sink.name}+integrity` : 'integrity',
		prune: sink.prune?.bind(sink)
	};
};

/**
 * Hash a single event into the chain. Excludes the integrity link
 * itself so verification round-trips through any storage that might
 * re-order or normalize JSON.
 */
export const hashAuditEvent = (
	event: AuditEvent,
	previousHash: string,
	secret?: string
): Promise<string> => {
	const message = `${previousHash}.${stableStringify({
		...event,
		metadata: cleanMetadata(event.metadata)
	})}`;
	return secret === undefined
		? sha256Hex(message)
		: hmacSha256Hex(secret, message);
};

export type ChainVerificationResult = {
	ok: boolean;
	/** Index in the input array of the first event whose link is missing or broken. */
	brokenAt?: number;
};

/**
 * Verify a chain. Pass events oldest-first. Each writer's sub-chain
 * is verified independently (events without a `writerId` share one
 * chain — matches the simple single-writer case). Returns `{ ok: true }`
 * or `{ ok: false, brokenAt: <index> }`.
 */
export const verifyChain = async (
	events: AuditEvent[],
	secret?: string
): Promise<ChainVerificationResult> => {
	const heads = new Map<string, string>();
	for (let index = 0; index < events.length; index += 1) {
		const event = events[index];
		if (event === undefined) return { brokenAt: index, ok: false };
		const integrity = readIntegrity(event);
		const chain = integrity?.writerId ?? GENESIS;
		const previousHash = heads.get(chain) ?? GENESIS;
		const expected = await hashAuditEvent(event, previousHash, secret);
		if (
			integrity === undefined ||
			integrity.previousHash !== previousHash ||
			integrity.hash !== expected
		) {
			return { brokenAt: index, ok: false };
		}
		heads.set(chain, integrity.hash);
	}
	return { ok: true };
};

// -----------------------------------------------------------------------------
// Live-wire recording helpers
// -----------------------------------------------------------------------------
//
// These return plain callbacks the host wires into the SOURCE package's
// existing listener API. Audit doesn't reach into the runtime's
// lifecycle; the host stays in control. Each helper has a narrow
// duck-typed input so we don't take peer-deps on every substrate
// package — the substrate packages already export the shapes; we accept
// the minimal subset we need to emit a useful event.

/** Shape of `@absolutejs/runtime`'s `RuntimeTransitionEvent`. */
export type RuntimeTransitionLike = {
	type: string;
	key: string;
	pid?: number;
	port?: number;
	reason?: string;
	exitCode?: number | null;
	durationMs?: number;
};

/**
 * Returns an `onTransition` callback that emits `"runtime.<type>"`
 * events. Wire into `createRuntime({ onTransition: ... })`.
 */
export const recordRuntimeTransition =
	(audit: Audit) =>
	(event: RuntimeTransitionLike): void => {
		void audit.append({
			kind: `runtime.${event.type}`,
			metadata: {
				...(event.pid !== undefined ? { pid: event.pid } : {}),
				...(event.port !== undefined ? { port: event.port } : {}),
				...(event.reason !== undefined ? { reason: event.reason } : {}),
				...(event.exitCode !== undefined
					? { exitCode: event.exitCode }
					: {}),
				...(event.durationMs !== undefined
					? { durationMs: event.durationMs }
					: {})
			},
			target: event.key
		});
	};

/** Shape of a `@absolutejs/queue` `Job` — minimal subset we use. */
export type JobLike = {
	id: string;
	kind: string | number | symbol;
	attempts?: number;
	maxAttempts?: number;
};

/**
 * Returns an `onError` callback for `@absolutejs/queue`'s
 * `createQueueWorker({ onError })`. Emits
 * `"queue.error"` events with the job context.
 */
export const recordQueueError =
	(audit: Audit) =>
	(error: unknown, job?: JobLike): void => {
		void audit.append({
			kind: 'queue.error',
			metadata: {
				...(job?.kind !== undefined
					? { jobKind: String(job.kind) }
					: {}),
				...(job?.attempts !== undefined
					? { attempts: job.attempts }
					: {}),
				...(job?.maxAttempts !== undefined
					? { maxAttempts: job.maxAttempts }
					: {}),
				error: error instanceof Error ? error.message : String(error)
			},
			...(job?.id !== undefined ? { target: job.id } : {})
		});
	};

/** Shape of `@absolutejs/secrets`'s `RotationListener` event. */
export type SecretRotationLike = {
	name: string;
	fingerprint: string;
	at: number;
	value?: string;
};

/**
 * Returns a `RotationListener` for
 * `@absolutejs/secrets`'s `broker.onRotate(name, listener)`. Emits
 * `"secrets.rotated"` events keyed on the secret name. The value
 * itself is NOT recorded — only the fingerprint, which is safe-for-log.
 */
export const recordSecretRotation =
	(audit: Audit) =>
	(event: SecretRotationLike): void => {
		void audit.append({
			at: event.at,
			kind: 'secrets.rotated',
			metadata: { fingerprint: event.fingerprint },
			target: event.name
		});
	};

/** Shape of `@absolutejs/sync`'s `EngineActivity` events — minimal. */
export type EngineActivityLike =
	| { type: 'change'; at?: number; table: string; op: string; version: number }
	| {
			type: 'mutation';
			at?: number;
			name: string;
			status: 'ok' | 'error';
	  }
	| {
			type: 'mutationBatch';
			at?: number;
			names: string[];
			status: 'ok' | 'error';
	  }
	| {
			type: 'mutationRetry';
			at?: number;
			name: string;
			attempt: number;
			delayMs: number;
			errorName?: string;
			errorMessage?: string;
	  };

/**
 * Returns a listener for `@absolutejs/sync`'s `engine.onActivity`.
 * Maps each activity type to a corresponding audit event:
 *   - `change` → `"sync.change.<op>"`
 *   - `mutation` → `"sync.mutation.<status>"`
 *   - `mutationBatch` → `"sync.batch.<status>"`
 *   - `mutationRetry` → `"sync.retry"`
 *
 * Wire with: `engine.onActivity(recordSyncActivity(audit))`. The
 * engine's change shape carries a `version` already; the helper keeps
 * it in metadata so the audit log can pair with the engine's
 * `LoggedChange` for forensics.
 */
export const recordSyncActivity =
	(audit: Audit) =>
	(event: EngineActivityLike): void => {
		switch (event.type) {
			case 'change':
				void audit.append({
					...(event.at !== undefined ? { at: event.at } : {}),
					kind: `sync.change.${event.op}`,
					metadata: { version: event.version },
					target: event.table
				});
				return;
			case 'mutation':
				void audit.append({
					...(event.at !== undefined ? { at: event.at } : {}),
					kind: `sync.mutation.${event.status}`,
					target: event.name
				});
				return;
			case 'mutationBatch':
				void audit.append({
					...(event.at !== undefined ? { at: event.at } : {}),
					kind: `sync.batch.${event.status}`,
					metadata: { names: event.names }
				});
				return;
			case 'mutationRetry':
				void audit.append({
					...(event.at !== undefined ? { at: event.at } : {}),
					kind: 'sync.retry',
					metadata: {
						attempt: event.attempt,
						delayMs: event.delayMs,
						...(event.errorName !== undefined
							? { errorName: event.errorName }
							: {}),
						...(event.errorMessage !== undefined
							? { errorMessage: event.errorMessage }
							: {})
					},
					target: event.name
				});
				return;
		}
	};
