import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, mkdirSync} from 'node:fs';
import {resolve, join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';
import {decodeTraceRequest, mapTraceRequest, OTLP_BATCH_FORMAT, OTLP_MAPPING_VERSION} from '../src/otlp.mjs';

function fixture(t, mutate = config => config) {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/otlp-ingest-')), config = mutate(initialize(dir));
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8')});
  t.after(() => s.store.close());
  const principal = (kind, tenant = 'alpha') => config.principals.find(p => p.tenant === tenant && (p.kind === kind || p.role === kind));
  const batch = (events, extra = {}) => JSON.stringify({format: OTLP_BATCH_FORMAT, mapping: OTLP_MAPPING_VERSION, events, ...extra});
  const ingest = (body, p = principal('otlp')) => s.handle('POST', new URL('http://localhost/api/ingest/otlp'), {authorization: `Bearer ${p.token}`}, body);
  return {s, config, principal, batch, ingest};
}
const traceEvents = () => mapTraceRequest(decodeTraceRequest(readFileSync(new URL('./fixtures/otlp/sdk-genai.json', import.meta.url)), 'json')).events;

test('vault OTLP batch route: one transaction, duplicates, conflicts and per-event re-validation', async t => {
  const {s, batch, ingest, principal} = fixture(t);
  const events = traceEvents(), ledger = () => s.store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n, before = ledger();
  const first = await ingest(batch(events));
  assert.deepEqual({accepted: first.accepted, duplicates: first.duplicates, rejected: first.rejected}, {accepted: 4, duplicates: 0, rejected: 0});
  assert.equal(first.durability, 'sqlite_full_commit');
  assert.equal(ledger() - before, 8); // 4 events + 4 receipts, committed together
  const replay = await ingest(batch([...events, events[0]]));
  assert.deepEqual({accepted: replay.accepted, duplicates: replay.duplicates, rejected: replay.rejected}, {accepted: 0, duplicates: 5, rejected: 0});
  const changed = structuredClone(events[1]); changed.status = 'success';
  const forged = structuredClone(events[0]); forged.id = 'otel:custom-id';
  const wrongKind = {...structuredClone(events[1]), kind: 'execution'};
  const result = await ingest(batch([changed, forged, wrongKind, {}, 'x']));
  assert.equal(result.accepted, 0); assert.deepEqual(result.reasons, {id_conflict: 1, invalid_event: 4});
  // Envelope problems reject the whole request.
  for (const body of ['nope', '[]', batch(events, {extra: 1}), JSON.stringify({format: OTLP_BATCH_FORMAT, mapping: 'otel-genai-map-0', events: []}),
    batch(Array(2049).fill(events[0]))])
    await assert.rejects(ingest(body), e => [400, 413].includes(e.status));
  // Only OTLP sources may use the route, and the OTLP credential cannot use other source routes.
  for (const kind of ['agent', 'telemetry', 'auditor']) await assert.rejects(ingest(batch([]), principal(kind)), e => e.status === 403, kind);
  const p = principal('otlp'), body = JSON.stringify(events[0]), ts = String(Date.now()), nonce = randomUUID();
  await assert.rejects(s.handle('POST', new URL('http://localhost/api/ingest'), {authorization: `Bearer ${p.token}`, 'x-evid-timestamp': ts,
    'x-evid-nonce': nonce, 'x-evid-signature': mac('x', ts, nonce, body)}, body), e => e.status === 401);
  const integrity = await s.handle('GET', new URL('http://localhost/api/integrity'), {authorization: `Bearer ${principal('auditor').token}`});
  assert.equal(integrity.valid, true, integrity.error);
  const stored = await s.handle('GET', new URL('http://localhost/api/events?limit=10'), {authorization: `Bearer ${principal('auditor').token}`});
  assert.equal(stored.total, 4); assert.ok(stored.items.every(e => e.assurance === 'authenticated_telemetry_report'));
});

test('OTLP principals are bearer-only sources', t => {
  assert.throws(() => fixture(t, config => { config.principals.find(p => p.kind === 'otlp').hmacSecret = 'x'.repeat(43); return config; }),
    /Invalid credential configuration/);
  assert.throws(() => fixture(t, config => { config.principals.find(p => p.kind === 'otlp').role = 'auditor'; return config; }),
    /Invalid credential configuration/);
  const config = initialize(mkdtempSync(resolve('.test-runs/otlp-init-')));
  const otlp = config.principals.filter(p => p.kind === 'otlp');
  assert.deepEqual(otlp.map(p => p.id).sort(), ['alpha-otlp', 'beta-otlp']);
  assert.ok(otlp.every(p => p.role === 'source' && p.hmacSecret === undefined && p.token.length >= 32));
});

test('analysis backlog gate is per tenant on the HMAC ingest route as well (audit S7)', async t => {
  const {ingest, batch, principal, s} = fixture(t);
  const signed = (p, raw) => { const body = JSON.stringify(raw), ts = String(Date.now()), nonce = randomUUID();
    return s.handle('POST', new URL('http://localhost/api/ingest'), {authorization: `Bearer ${p.token}`, 'x-evid-timestamp': ts, 'x-evid-nonce': nonce,
      'x-evid-signature': mac(p.hmacSecret, ts, nonce, body)}, body); };
  const event = (id, kind = 'self_report') => ({id, actionId: id, traceId: 'trace-s7', kind, occurredAt: new Date().toISOString()});
  process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT = '2';
  t.after(() => { delete process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT; });
  for (const id of ['a1', 'a2', 'a3']) await signed(principal('agent'), event(id));
  await assert.rejects(signed(principal('agent'), event('a4')), e => e.status === 503);
  await assert.rejects(ingest(batch(traceEvents())), e => e.status === 503);
  assert.equal((await signed(principal('agent', 'beta'), event('b1'))).accepted, true);
  // A batch is gated on the backlog it would leave: beta's own backlog 1 + 3 new actions > 2, while alpha's never counts.
  await assert.rejects(ingest(batch(traceEvents()), principal('otlp', 'beta')), e => e.status === 503);
  assert.equal((await ingest(batch(traceEvents().filter(e => e.kind === 'notice')), principal('otlp', 'beta'))).accepted, 2);
});

test('OTLP batches are gated on the backlog they would leave, not only on the backlog before them', async t => {
  const {ingest, batch, principal, s} = fixture(t);
  process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT = '3';
  t.after(() => { delete process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT; });
  const start = String(BigInt(Date.now() - 60000) * 1000000n);
  const attributes = [{key: 'gen_ai.operation.name', value: {stringValue: 'execute_tool'}}];
  const tools = (trace, ids) => mapTraceRequest(decodeTraceRequest(JSON.stringify({resourceSpans: [{scopeSpans: [{spans: ids.map(i => ({traceId: trace,
    spanId: i.toString(16).padStart(16, '0'), startTimeUnixNano: start, attributes}))}]}]}), 'json')).events;
  const backlog = tenant => s.store.db.prepare('SELECT COUNT(*) n FROM actions WHERE tenant=? AND analyzed<version').get(tenant).n;
  const beta = principal('otlp', 'beta'), trace = 'b7'.repeat(16);
  assert.equal((await ingest(batch(tools(trace, [1])), beta)).accepted, 1); assert.equal(backlog('beta'), 1);
  // 1 pending + 3 new actions > 3: refused whole (retryable), although the backlog before the batch was below the limit.
  await assert.rejects(ingest(batch(tools(trace, [2, 3, 4])), beta), e => e.status === 503);
  assert.equal(backlog('beta'), 1);
  assert.equal((await ingest(batch(tools(trace, [2, 3])), beta)).accepted, 2); assert.equal(backlog('beta'), 3);
  // Duplicates and events of already pending actions add nothing; any new action now would exceed the limit.
  const replay = await ingest(batch(tools(trace, [1, 2, 3])), beta);
  assert.deepEqual([replay.accepted, replay.duplicates], [0, 3]);
  await assert.rejects(ingest(batch(tools(trace, [5])), beta), e => e.status === 503);
  assert.equal(backlog('beta'), 3);
  // An empty backlog still admits one batch larger than the limit, or such a batch could never be stored.
  const big = await ingest(batch(tools('a7'.repeat(16), [1, 2, 3, 4, 5])));
  assert.equal(big.accepted, 5); assert.equal(backlog('alpha'), 5);
  await assert.rejects(ingest(batch(tools('a7'.repeat(16), [6]))), e => e.status === 503);
  // Duplicates and conflicts inside one batch are classified before the gate and the appends.
  const [x] = tools('a8'.repeat(16), [1]), conflict = {...structuredClone(x), status: 'failure'};
  process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT = '100';
  const mixed = await ingest(batch([x, x, conflict]));
  assert.deepEqual([mixed.accepted, mixed.duplicates, mixed.reasons], [1, 1, {id_conflict: 1}]);
});
