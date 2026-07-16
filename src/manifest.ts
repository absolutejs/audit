import {
	defineImplementation,
	defineManifest,
	toolFactory
} from '@absolutejs/manifest';
import { Type } from '@sinclair/typebox';
import { verifyChain } from './index';
import type {
	Audit,
	AuditOptions,
	AuditSink,
	ConsoleSinkOptions,
	MemorySinkOptions
} from './index';

/**
 * The runtime hosts bind for audit tools. The `Audit` handle is append-only
 * by design (queries live on sinks), so query-shaped tools additionally need
 * a queryable sink: bind `{ audit, store }` where `store` is a sink that
 * implements `list` (memory, Postgres). Tools degrade gracefully when
 * `store` is absent or write-only.
 */
export type AuditToolRuntime = {
	audit: Audit;
	store?: AuditSink;
};

const tool = toolFactory<AuditToolRuntime>();

/* AuditOptions has no serializable keys: `sinks` is instance-valued → the
 * `sink` slot; `onError` / `clock` are function-valued → wiring concerns. */
export const manifest = defineManifest<AuditOptions, AuditToolRuntime>()({
	contract: 1,
	identity: {
		accent: '#8b5cf6',
		category: 'compliance',
		description:
			'Cross-surface audit-event substrate: one append-only log with pluggable sinks (memory, console, Postgres, S3 via `@absolutejs/audit-*`), optional hash-chain tamper-evidence (`withIntegrity` + `verifyChain`), and privacy-safe live-wire helpers for agent runs, sync mutations, queue jobs, runtime exits, and secret rotations.',
		docsUrl: 'https://github.com/absolutejs/audit',
		name: '@absolutejs/audit',
		tagline:
			'Keep a tamper-evident record of everything that happens in your app.'
	},
	implements: [
		defineImplementation<MemorySinkOptions>()({
			contract: 'audit/sink',
			factory: 'memorySink',
			from: '@absolutejs/audit',
			settings: Type.Object({
				max: Type.Optional(
					Type.Integer({
						default: 10000,
						description:
							'The oldest events are dropped once the in-memory tail exceeds this many.',
						minimum: 1,
						title: 'Events kept in memory'
					})
				)
			}),
			title: 'In memory (queryable tail — pair with a durable sink for production)',
			wiring: {
				code: 'memorySink(${settings})',
				imports: [{ from: '@absolutejs/audit', names: ['memorySink'] }]
			}
		}),
		defineImplementation<ConsoleSinkOptions>()({
			contract: 'audit/sink',
			factory: 'consoleSink',
			from: '@absolutejs/audit',
			settings: Type.Object({
				stream: Type.Optional(
					Type.Union([Type.Literal('log'), Type.Literal('error')], {
						default: 'log',
						description:
							'Which console stream each JSON event line is written to.',
						title: 'Output stream'
					})
				)
			}),
			title: 'Server logs (one JSON line per event — rides your existing log shipping)',
			wiring: {
				code: 'consoleSink(${settings})',
				imports: [{ from: '@absolutejs/audit', names: ['consoleSink'] }]
			}
		})
	],
	settings: Type.Object({}),
	slots: {
		sink: {
			configPath: 'sinks',
			contract: 'audit/sink',
			description: 'Where audit events are stored',
			known: [
				'@absolutejs/audit#memory',
				'@absolutejs/audit#console',
				'@absolutejs/audit-postgres',
				'@absolutejs/audit-s3'
			],
			required: true
		}
	},
	tools: {
		audit_stats: tool.runtime({
			annotations: { readOnlyHint: true },
			description:
				'Cumulative audit counters since the server started: successful appends, appends where a sink failed, and per-sink error counts.',
			handler: (_input, runtime) => JSON.stringify(runtime.audit.metrics()),
			input: Type.Object({})
		}),
		list_audit_events: tool.runtime({
			annotations: { readOnlyHint: true },
			description:
				'List recent audit events, optionally filtered by kind substring (e.g. "auth."), exact actor, or time range (ms epochs). Requires a queryable store (memory or Postgres sink).',
			handler: async (input, runtime) => {
				if (runtime.store?.list === undefined) {
					return 'the bound audit store does not support queries (write-only sink)';
				}
				const events = await runtime.store.list(input);

				return events.length === 0
					? 'no audit events matched'
					: JSON.stringify(events);
			},
			input: Type.Object({
				actor: Type.Optional(Type.String()),
				kind: Type.Optional(Type.String()),
				limit: Type.Optional(
					Type.Integer({ maximum: 1000, minimum: 1 })
				),
				since: Type.Optional(Type.Number()),
				until: Type.Optional(Type.Number())
			})
		}),
		record_audit_event: tool.runtime({
			description:
				'Append one audit event to the log — e.g. an operator note during an incident. `kind` is a namespaced identifier like "ops.note". Events are append-only: they cannot be edited or removed afterwards.',
			handler: async ({ actor, kind, metadata, target }, runtime) => {
				await runtime.audit.append({
					kind,
					...(actor !== undefined ? { actor } : {}),
					...(target !== undefined ? { target } : {}),
					...(metadata !== undefined ? { metadata } : {})
				});

				return `appended "${kind}"`;
			},
			input: Type.Object({
				actor: Type.Optional(Type.String()),
				kind: Type.String({ minLength: 1 }),
				metadata: Type.Optional(
					Type.Record(Type.String(), Type.Unknown())
				),
				target: Type.Optional(Type.String())
			})
		}),
		verify_audit_chain: tool.runtime({
			annotations: { readOnlyHint: true },
			description:
				'Verify the tamper-evidence hash chain over recent events. Only meaningful when events were written through withIntegrity() and the bound store supports queries. HMAC-secured chains cannot be verified here — the chain secret never passes through tools.',
			handler: async ({ limit }, runtime) => {
				if (runtime.store?.list === undefined) {
					return 'the bound audit store does not support queries (write-only sink)';
				}
				const events = [
					...(await runtime.store.list({ limit: limit ?? 1000 }))
				].sort((left, right) => left.at - right.at);
				if (events.length === 0) return 'no events to verify';
				const result = await verifyChain(events);
				if (result.ok) {
					return `chain intact across ${events.length} events`;
				}
				const broken = events[result.brokenAt ?? 0];

				return `chain BROKEN at index ${result.brokenAt} of ${events.length} (event kind "${broken?.kind ?? 'unknown'}")`;
			},
			input: Type.Object({
				limit: Type.Optional(
					Type.Integer({ maximum: 10000, minimum: 1 })
				)
			})
		})
	},
	wiring: [
		{
			id: 'default',
			server: {
				code: 'const audit = createAudit({ sinks: [${slot.sink}] });',
				imports: [{ from: '@absolutejs/audit', names: ['createAudit'] }],
				placement: 'module-scope'
			},
			title: 'Create the audit log'
		},
		{
			description:
				'Every event carries a hash link to the previous one, so any edit, removal, or reorder is detectable with verifyChain().',
			id: 'tamper-evident',
			server: {
				code: 'const audit = createAudit({ sinks: [withIntegrity(${slot.sink})] });',
				imports: [
					{
						from: '@absolutejs/audit',
						names: ['createAudit', 'withIntegrity']
					}
				],
				placement: 'module-scope'
			},
			title: 'Tamper-evident audit log (hash chain)'
		}
	]
});
