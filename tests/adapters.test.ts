import { describe, expect, test } from 'bun:test';
import {
	createAudit,
	memorySink,
	recordQueueError,
	recordAgentRunEvent,
	recordRuntimeTransition,
	recordSecretRotation,
	recordSyncActivity
} from '../src';

describe('recordAgentRunEvent() — 0.1.0', () => {
	test('records identity and budgets without prompts, payloads, or user PII', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordAgentRunEvent(audit);
		handler({
			type: 'step.appended',
			run: {
				id: 'run-1',
				status: 'running',
				actor: { tenantId: 'tenant-1', userId: 'private-user', agentId: 'agent-1' },
				agent: { descriptorId: 'https://agent.example', descriptorVersion: '1', descriptorDigest: 'sha256:abc' },
				usage: { actions: 1, costMicros: 2, inputTokens: 3, outputTokens: 4, spendMinor: 5, wallTimeMs: 6 }
			},
			step: { id: 'step-1', sequence: 1, kind: 'effect.requested', name: 'wallet.pay' }
		});
		await new Promise((resolve) => setTimeout(resolve, 0));
		const event = (await sink.list?.())?.[0];
		expect(event?.kind).toBe('agent.step.effect.requested');
		expect(event?.target).toBe('run-1');
		expect(event?.metadata?.descriptorDigest).toBe('sha256:abc');
		expect(JSON.stringify(event)).not.toContain('private-user');
	});
});

describe('recordRuntimeTransition() — 0.0.1', () => {
	test('emits runtime.<type> events keyed on the tenant', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordRuntimeTransition(audit);
		handler({ key: 'tenant-A', pid: 1234, port: 9001, type: 'spawn' });
		handler({
			exitCode: 0,
			key: 'tenant-A',
			pid: 1234,
			reason: 'idle-killed',
			type: 'exit'
		});
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events).toHaveLength(2);
		expect(events[0]!.kind).toBe('runtime.spawn');
		expect(events[0]!.target).toBe('tenant-A');
		expect(events[0]!.metadata).toMatchObject({ pid: 1234, port: 9001 });
		expect(events[1]!.kind).toBe('runtime.exit');
		expect(events[1]!.metadata).toMatchObject({
			exitCode: 0,
			reason: 'idle-killed'
		});
	});
});

describe('recordQueueError() — 0.0.1', () => {
	test('emits queue.error with the job context', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordQueueError(audit);
		handler(new Error('boom'), {
			attempts: 2,
			id: 'job-1',
			kind: 'email.send',
			maxAttempts: 5
		});
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events).toHaveLength(1);
		expect(events[0]!.kind).toBe('queue.error');
		expect(events[0]!.target).toBe('job-1');
		expect(events[0]!.metadata).toMatchObject({
			attempts: 2,
			error: 'boom',
			jobKind: 'email.send',
			maxAttempts: 5
		});
	});

	test('handles errors with no job context (worker-level failure)', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordQueueError(audit);
		handler(new Error('worker tick failed'));
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events).toHaveLength(1);
		expect(events[0]!.target).toBeUndefined();
		expect(events[0]!.metadata?.error).toBe('worker tick failed');
	});
});

describe('recordSecretRotation() — 0.0.1', () => {
	test('emits secrets.rotated with name + fingerprint, NEVER the value', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordSecretRotation(audit);
		handler({
			at: 5000,
			fingerprint: 'abc12345',
			name: 'STRIPE_KEY',
			value: 'sk_live_secret_value_NEVER_LOG'
		});
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events).toHaveLength(1);
		expect(events[0]!.kind).toBe('secrets.rotated');
		expect(events[0]!.target).toBe('STRIPE_KEY');
		expect(events[0]!.metadata).toEqual({ fingerprint: 'abc12345' });
		// The value MUST NOT appear anywhere in the recorded event.
		const serialized = JSON.stringify(events[0]);
		expect(serialized).not.toContain('sk_live_secret_value_NEVER_LOG');
	});
});

describe('recordSyncActivity() — 0.0.1', () => {
	test('maps change events to sync.change.<op>', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordSyncActivity(audit);
		handler({
			at: 1,
			op: 'insert',
			table: 'tasks',
			type: 'change',
			version: 5
		});
		handler({
			at: 2,
			op: 'delete',
			table: 'tasks',
			type: 'change',
			version: 6
		});
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events.map((e) => e.kind)).toEqual([
			'sync.change.insert',
			'sync.change.delete'
		]);
		expect(events[0]!.target).toBe('tasks');
		expect(events[0]!.metadata).toEqual({ version: 5 });
	});

	test('maps mutation events to sync.mutation.<status>', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordSyncActivity(audit);
		handler({ at: 1, name: 'createIssue', status: 'ok', type: 'mutation' });
		handler({
			at: 2,
			name: 'createIssue',
			status: 'error',
			type: 'mutation'
		});
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events.map((e) => e.kind)).toEqual([
			'sync.mutation.ok',
			'sync.mutation.error'
		]);
	});

	test('maps mutationRetry to sync.retry with attempt details', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordSyncActivity(audit);
		handler({
			at: 1,
			attempt: 2,
			delayMs: 100,
			errorMessage: 'serialization failure',
			errorName: 'SerializationError',
			name: 'updateTask',
			type: 'mutationRetry'
		});
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events[0]!.kind).toBe('sync.retry');
		expect(events[0]!.metadata).toMatchObject({
			attempt: 2,
			delayMs: 100,
			errorMessage: 'serialization failure',
			errorName: 'SerializationError'
		});
	});

	test('maps mutationBatch to sync.batch.<status>', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		const handler = recordSyncActivity(audit);
		handler({
			at: 1,
			names: ['a', 'b', 'c'],
			status: 'ok',
			type: 'mutationBatch'
		});
		await new Promise((resolve) => setTimeout(resolve, 5));
		const events = (await sink.list?.()) ?? [];
		expect(events[0]!.kind).toBe('sync.batch.ok');
		expect(events[0]!.metadata?.names).toEqual(['a', 'b', 'c']);
	});
});

describe('integration: tamper-evident multi-source audit', () => {
	test('events from three sources form one chain', async () => {
		const base = memorySink();
		const { withIntegrity, verifyChain } = await import('../src');
		const sink = withIntegrity(base, { secret: 'k' });
		const audit = createAudit({ sinks: [sink] });

		const onTransition = recordRuntimeTransition(audit);
		const onError = recordQueueError(audit);
		const onRotate = recordSecretRotation(audit);

		// Simulate the host wiring all three.
		onTransition({ key: 'tenant-A', pid: 1, type: 'spawn' });
		onRotate({
			at: 1000,
			fingerprint: 'abc',
			name: 'API_KEY'
		});
		onError(new Error('queue boom'), { id: 'job-1', kind: 'email' });
		// Let microtasks drain.
		await new Promise((resolve) => setTimeout(resolve, 10));

		const events = (await base.list?.()) ?? [];
		expect(events).toHaveLength(3);
		const result = await verifyChain(events, 'k');
		expect(result.ok).toBe(true);
		// Mix of sources in one chain — that's the whole point.
		const kinds = events.map((e) => e.kind);
		expect(kinds).toContain('runtime.spawn');
		expect(kinds).toContain('secrets.rotated');
		expect(kinds).toContain('queue.error');
	});
});
