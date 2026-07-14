import { describe, expect, test } from 'bun:test';
import {
	AuditClosedError,
	consoleSink,
	createAudit,
	memorySink,
	type AuditEvent,
	type AuditSink
} from '../src';

const fixedClock = () => {
	let t = 1_000_000;
	return () => {
		t += 1;
		return t;
	};
};

describe('createAudit() — 0.0.1', () => {
	test('appends to a memory sink and lists them back', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink], clock: fixedClock() });
		await audit.append({ kind: 'auth.login', actor: 'user-1' });
		await audit.append({ kind: 'auth.logout', actor: 'user-1' });
		const events = (await sink.list?.()) ?? [];
		expect(events).toHaveLength(2);
		expect(events[0]!.kind).toBe('auth.login');
		expect(events[0]!.at).toBeGreaterThan(0);
	});

	test('synthesizes `at` from the clock when omitted', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink], clock: () => 42 });
		await audit.append({ kind: 'system.startup' });
		const events = (await sink.list?.()) ?? [];
		expect(events[0]!.at).toBe(42);
	});

	test('passes `at` through when provided', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'historical', at: 1000 });
		const events = (await sink.list?.()) ?? [];
		expect(events[0]!.at).toBe(1000);
	});

	test('fans out to every sink concurrently', async () => {
		const a = memorySink();
		const b = memorySink();
		const audit = createAudit({ sinks: [a, b] });
		await audit.append({ kind: 'broadcast' });
		expect((await a.list?.())?.length).toBe(1);
		expect((await b.list?.())?.length).toBe(1);
	});

	test('one sink throwing does not prevent the others receiving', async () => {
		const flakySink: AuditSink = {
			append: () => {
				throw new Error('flaky');
			},
			name: 'flaky'
		};
		const memory = memorySink();
		const errors: { name: string; event: AuditEvent }[] = [];
		const audit = createAudit({
			onError: (_error, name, event) => {
				errors.push({ event, name });
			},
			sinks: [flakySink, memory]
		});
		await audit.append({ kind: 'event' });
		expect(((await memory.list?.()) ?? []).length).toBe(1);
		expect(errors).toHaveLength(1);
		expect(errors[0]!.name).toBe('flaky');
		expect(audit.metrics().appendErrors).toBe(1);
		expect(audit.metrics().sinkErrors.flaky).toBe(1);
		expect(audit.metrics().appended).toBe(0);
	});

	test('close() prevents further appends', async () => {
		const audit = createAudit({ sinks: [memorySink()] });
		await audit.close();
		await expect(
			audit.append({ kind: 'after-close' })
		).rejects.toBeInstanceOf(AuditClosedError);
	});

	test('close() calls flush + close on every sink', async () => {
		const flushes: string[] = [];
		const closes: string[] = [];
		const sink: AuditSink = {
			append: () => {},
			close: () => {
				closes.push('done');
			},
			flush: () => {
				flushes.push('done');
			},
			name: 'spy'
		};
		const audit = createAudit({ sinks: [sink] });
		await audit.close();
		expect(flushes).toEqual(['done']);
		expect(closes).toEqual(['done']);
	});

	test('metrics() counters increment correctly', async () => {
		const audit = createAudit({ sinks: [memorySink()] });
		await audit.append({ kind: 'a' });
		await audit.append({ kind: 'b' });
		await audit.append({ kind: 'c' });
		expect(audit.metrics().appended).toBe(3);
		expect(audit.metrics().appendErrors).toBe(0);
	});
});

describe('memorySink() — 0.0.1', () => {
	test('list filters by kind substring', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'auth.login' });
		await audit.append({ kind: 'auth.logout' });
		await audit.append({ kind: 'sync.insert' });
		const auth = (await sink.list?.({ kind: 'auth' })) ?? [];
		expect(auth).toHaveLength(2);
	});

	test('list filters by actor exact match', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'evt', actor: 'alice' });
		await audit.append({ kind: 'evt', actor: 'bob' });
		await audit.append({ kind: 'evt', actor: 'alice' });
		const alice = (await sink.list?.({ actor: 'alice' })) ?? [];
		expect(alice).toHaveLength(2);
	});

	test('drops oldest events FIFO when max is reached', async () => {
		const sink = memorySink({ max: 2 });
		const audit = createAudit({ sinks: [sink] });
		await audit.append({ kind: 'first' });
		await audit.append({ kind: 'second' });
		await audit.append({ kind: 'third' });
		const events = (await sink.list?.()) ?? [];
		expect(events).toHaveLength(2);
		expect(events.map((e) => e.kind)).toEqual(['second', 'third']);
	});

	test('prune() removes events older than the cutoff', async () => {
		const sink = memorySink();
		const audit = createAudit({ sinks: [sink], clock: () => 0 });
		// inject events directly so we can control `at`
		await sink.append({ at: 100, kind: 'old' });
		await sink.append({ at: 200, kind: 'old2' });
		await sink.append({ at: 300, kind: 'new' });
		const dropped = await sink.prune?.(250);
		expect(dropped).toBe(2);
		const remaining = (await sink.list?.()) ?? [];
		expect(remaining).toHaveLength(1);
		expect(remaining[0]!.kind).toBe('new');
	});

	test('list since/until window', async () => {
		const sink = memorySink();
		await sink.append({ at: 100, kind: 'a' });
		await sink.append({ at: 200, kind: 'b' });
		await sink.append({ at: 300, kind: 'c' });
		const window = (await sink.list?.({ since: 150, until: 250 })) ?? [];
		expect(window).toHaveLength(1);
		expect(window[0]!.kind).toBe('b');
	});

	test('list limit returns the most recent events oldest-first', async () => {
		const sink = memorySink();
		for (let index = 0; index < 5; index++) {
			await sink.append({ at: index, kind: `event-${index}` });
		}
		const events = (await sink.list?.({ limit: 2 })) ?? [];
		expect(events.map((event) => event.kind)).toEqual([
			'event-3',
			'event-4'
		]);
	});
});

describe('consoleSink() — 0.0.1', () => {
	test('logs JSON to stdout by default', async () => {
		const captured: string[] = [];
		const originalLog = console.log;
		console.log = (msg: string) => captured.push(msg);
		try {
			const sink = consoleSink();
			const audit = createAudit({ sinks: [sink] });
			await audit.append({ kind: 'visible', actor: 'tester' });
		} finally {
			console.log = originalLog;
		}
		expect(captured).toHaveLength(1);
		const parsed = JSON.parse(captured[0]!);
		expect(parsed.kind).toBe('visible');
		expect(parsed.actor).toBe('tester');
	});

	test('respects custom stringify (e.g. for redaction)', async () => {
		const captured: string[] = [];
		const originalLog = console.log;
		console.log = (msg: string) => captured.push(msg);
		try {
			const sink = consoleSink({
				stringify: (event) =>
					JSON.stringify({ ...event, REDACTED: true })
			});
			const audit = createAudit({ sinks: [sink] });
			await audit.append({ kind: 'evt' });
		} finally {
			console.log = originalLog;
		}
		expect(JSON.parse(captured[0]!).REDACTED).toBe(true);
	});
});
