import { describe, expect, test } from 'bun:test';
import {
	createAudit,
	hashAuditEvent,
	memorySink,
	verifyChain,
	withIntegrity,
	type AuditSink
} from '../src';

describe('withIntegrity() + verifyChain() — 0.0.1', () => {
	test('chain verifies after a clean append run', async () => {
		const base = memorySink();
		const sink = withIntegrity(base);
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'a' });
		await audit.append({ kind: 'b' });
		await audit.append({ kind: 'c' });
		const events = (await base.list?.()) ?? [];
		expect(events).toHaveLength(3);
		const result = await verifyChain(events);
		expect(result.ok).toBe(true);
	});

	test('detects a modified event', async () => {
		const base = memorySink();
		const sink = withIntegrity(base);
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'a' });
		await audit.append({ kind: 'b' });
		await audit.append({ kind: 'c' });
		const events = (await base.list?.()) ?? [];
		// tamper: change middle event's kind without recomputing hash
		events[1] = { ...events[1]!, kind: 'tampered' };
		const result = await verifyChain(events);
		expect(result.ok).toBe(false);
		expect(result.brokenAt).toBe(1);
	});

	test('detects a removed event', async () => {
		const base = memorySink();
		const sink = withIntegrity(base);
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'a' });
		await audit.append({ kind: 'b' });
		await audit.append({ kind: 'c' });
		const events = (await base.list?.()) ?? [];
		events.splice(1, 1); // drop the middle event
		const result = await verifyChain(events);
		expect(result.ok).toBe(false);
		expect(result.brokenAt).toBe(1);
	});

	test('detects reordering', async () => {
		const base = memorySink();
		const sink = withIntegrity(base);
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'a' });
		await audit.append({ kind: 'b' });
		const events = (await base.list?.()) ?? [];
		const swapped = [events[1]!, events[0]!];
		const result = await verifyChain(swapped);
		expect(result.ok).toBe(false);
	});

	test('HMAC mode requires the same secret to verify', async () => {
		const base = memorySink();
		const sink = withIntegrity(base, { secret: 'top-secret' });
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'a' });
		await audit.append({ kind: 'b' });
		const events = (await base.list?.()) ?? [];
		const okSame = await verifyChain(events, 'top-secret');
		expect(okSame.ok).toBe(true);
		const okWrong = await verifyChain(events, 'wrong-secret');
		expect(okWrong.ok).toBe(false);
	});

	test('concurrent writers each get their own sub-chain', async () => {
		const base = memorySink();
		const sinkA = withIntegrity(base, { writerId: 'writer-A' });
		const sinkB = withIntegrity(base, { writerId: 'writer-B' });
		await sinkA.append({ at: 1, kind: 'a1' });
		await sinkB.append({ at: 2, kind: 'b1' });
		await sinkA.append({ at: 3, kind: 'a2' });
		await sinkB.append({ at: 4, kind: 'b2' });
		const events = (await base.list?.()) ?? [];
		expect(events).toHaveLength(4);
		const result = await verifyChain(events);
		expect(result.ok).toBe(true);
	});

	test('integrity preserves existing metadata', async () => {
		const base = memorySink();
		const sink = withIntegrity(base);
		await sink.append({
			at: 1,
			kind: 'evt',
			metadata: { user: 'alice', custom: 42 }
		});
		const events = (await base.list?.()) ?? [];
		const meta = events[0]!.metadata!;
		expect(meta.user).toBe('alice');
		expect(meta.custom).toBe(42);
		expect(meta.__integrity).toBeDefined();
	});

	test('chain genesis hash is computed from empty previousHash', async () => {
		const event = { at: 1, kind: 'genesis' };
		const expected = await hashAuditEvent(event, '');
		const base = memorySink();
		const sink = withIntegrity(base);
		await sink.append(event);
		const stored = (await base.list?.()) ?? [];
		const integrity = stored[0]!.metadata!.__integrity as {
			hash: string;
			previousHash: string;
		};
		expect(integrity.previousHash).toBe('');
		expect(integrity.hash).toBe(expected);
	});

	test('concurrent appends within a writer chain correctly (serialized)', async () => {
		// 1.20.0-style fan-out: 50 concurrent appends. Without serialization
		// the chain would break — they'd all read the same lastHash before
		// any wrote. With it, the chain is intact end-to-end.
		const base = memorySink();
		const sink = withIntegrity(base, { secret: 'k' });
		const audit = createAudit({ sinks: [sink] });
		const promises = Array.from({ length: 50 }, (_, i) =>
			audit.append({ kind: `evt-${i}` })
		);
		await Promise.all(promises);
		const events = (await base.list?.()) ?? [];
		expect(events).toHaveLength(50);
		const result = await verifyChain(events, 'k');
		expect(result.ok).toBe(true);
	});

	test('flush and close wait for the serialized append tail', async () => {
		let releaseAppend!: () => void;
		const appendBlocked = new Promise<void>((resolve) => {
			releaseAppend = resolve;
		});
		const lifecycle: string[] = [];
		const base: AuditSink = {
			append: async () => {
				await appendBlocked;
				lifecycle.push('append');
			},
			close: () => {
				lifecycle.push('close');
			},
			flush: () => {
				lifecycle.push('flush');
			}
		};
		const sink = withIntegrity(base, { secret: 'k' });
		void sink.append({ at: 1, kind: 'tail' });
		const flush = sink.flush?.();
		const close = sink.close?.();

		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(lifecycle).toEqual([]);
		releaseAppend();
		await Promise.all([flush, close]);
		expect(lifecycle[0]).toBe('append');
		expect(lifecycle.slice(1).sort()).toEqual(['close', 'flush']);
	});

	test('adds drain lifecycle methods to immediate sinks', async () => {
		let appended = false;
		const sink = withIntegrity({
			append: async () => {
				await new Promise((resolve) => setTimeout(resolve, 1));
				appended = true;
			}
		});
		void sink.append({ at: 1, kind: 'tail' });
		expect(sink.flush).toBeFunction();
		expect(sink.close).toBeFunction();
		await sink.flush?.();
		expect(appended).toBe(true);
	});

	test('stable writers resume from the newest event in the scan window', async () => {
		const base = memorySink();
		const first = withIntegrity(base, {
			secret: 'k',
			seedScanLimit: 3,
			writerId: 'stable-writer'
		});
		for (let index = 0; index < 5; index++) {
			await first.append({ at: index, kind: `before-${index}` });
		}
		const resumed = withIntegrity(base, {
			secret: 'k',
			seedScanLimit: 3,
			writerId: 'stable-writer'
		});
		await resumed.append({ at: 6, kind: 'after-restart' });
		const events = (await base.list?.()) ?? [];
		expect(await verifyChain(events, 'k')).toEqual({ ok: true });
	});

	test('JSON serialization round-trip preserves chain validity', async () => {
		// Simulates the chain surviving a database (jsonb) round-trip
		// that may reorder object keys.
		const base = memorySink();
		const sink = withIntegrity(base, { secret: 'k' });
		const audit = createAudit({ sinks: [sink] });
		await audit.append({
			kind: 'evt',
			metadata: { z: 1, a: 2, m: 3 }
		});
		await audit.append({ kind: 'evt2' });
		const events = (await base.list?.()) ?? [];
		// Round-trip through JSON.
		const roundtripped = events.map(
			(event) => JSON.parse(JSON.stringify(event)) as typeof event
		);
		const result = await verifyChain(roundtripped, 'k');
		expect(result.ok).toBe(true);
	});
});
