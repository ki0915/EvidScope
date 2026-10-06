import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import zlib from 'node:zlib';
import {randomUUID} from 'node:crypto';
import {harness} from './harness.mjs';
import {mac} from '../src/crypto.mjs';

const fixture = name => readFileSync(new URL(`./fixtures/otlp/${name}`, import.meta.url));
const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
const CANARIES = ['Weather in Paris', 'weather API timed out', 'Plans trips', 'Get current weather', '123-45-6789', 'sk-live', 'secret prompt'];

async function send(base, body, {type = 'application/json', encoding, token, headers = {}, path = '/v1/traces', method = 'POST'} = {}) {
  const response = await fetch(base + path, {method, body: method === 'GET' ? undefined : body,
    headers: {'content-type': type, ...(encoding ? {'content-encoding': encoding} : {}), ...(token === null ? {} : {authorization: `Bearer ${token}`}), ...headers}});
  const raw = Buffer.from(await response.arrayBuffer());
  const contentType = response.headers.get('content-type');
  return {status: response.status, type: contentType, raw, retryAfter: response.headers.get('retry-after'), json: contentType === 'application/json' && raw.length ? JSON.parse(raw) : undefined};
}
const otlpJson = (spans, service = 'unit-svc') => JSON.stringify({resourceSpans: [{resource: {attributes: [{key: 'service.name', value: {stringValue: service}}]}, scopeSpans: [{scope: {name: 'unit'}, spans}]}]});
const span = (spanId, attributes, extra = {}) => ({traceId: extra.traceId || 'a1'.repeat(16), spanId, name: `span ${spanId} secret prompt`, kind: 3, startTimeUnixNano: String(BigInt(Date.now() - 60000) * 1000000n),
  attributes: Object.entries(attributes).map(([key, value]) => ({key, value: typeof value === 'number' ? {intValue: String(value)} : {stringValue: value}})), status: {}, ...extra});
const events = async (h, query = '') => (await h.api(`/api/events?limit=500${query}`)).body;

test('OTLP/HTTP receiver: encodings, responses, idempotency, auth and gateway boundaries', async t => {
  const h = await harness(); t.after(() => h.close());
  const token = h.principal('otlp').token, ingress = h.ingress.url;

  // OTLP/JSON from the JS SDK: full success is 200 + {} in the request's Content-Type.
  const json = await send(ingress, fixture('sdk-genai.json'), {token});
  assert.equal(json.status, 200); assert.equal(json.type, 'application/json'); assert.deepEqual(json.json, {});
  let stored = await events(h, `&traceId=${TRACE}`);
  assert.equal(stored.total, 4);
  for (const e of stored.items) { assert.equal(e.source, 'alpha-otlp'); assert.equal(e.sourceKind, 'otlp'); assert.equal(e.assurance, 'authenticated_telemetry_report'); }
  assert.deepEqual(stored.items.map(e => e.kind).sort(), ['notice', 'notice', 'self_report', 'self_report']);

  // Same trace as gzip/zstd/deflate protobuf from the Collector: duplicates, empty protobuf success body.
  for (const [name, encoding] of [['sdk-genai.pb.gz', 'gzip'], ['collector-genai.pb.zst', 'zstd'], ['collector-genai.pb.deflate', 'deflate']]) {
    const proto = await send(ingress, fixture(name), {token, type: 'application/x-protobuf', encoding});
    assert.equal(proto.status, 200, name); assert.equal(proto.type, 'application/x-protobuf'); assert.equal(proto.raw.length, 0);
  }
  assert.equal((await send(ingress, fixture('collector-genai.pb'), {token, type: 'application/x-protobuf; charset=binary'})).status, 200);
  assert.equal((await events(h, `&traceId=${TRACE}`)).total, 4);

  // Partial success: one stored, one non-GenAI, one invalid span context. Clients must not retry.
  const mixed = otlpJson([span('b1'.repeat(8), {'gen_ai.operation.name': 'chat', 'gen_ai.provider.name': 'anthropic', 'gen_ai.request.model': 'claude-unit'}),
    span('b2'.repeat(8), {'http.request.method': 'GET'}), span('0'.repeat(16), {'gen_ai.operation.name': 'chat'})]);
  const partial = await send(ingress, mixed, {token});
  assert.equal(partial.status, 200); assert.equal(partial.json.partialSuccess.rejectedSpans, '2');
  assert.match(partial.json.partialSuccess.errorMessage, /^2 spans not stored: invalid_span_context=1, not_genai=1; non-GenAI/);
  const partialPb = await send(ingress, zlib.gzipSync(Buffer.from(mixed)), {token, encoding: 'gzip'});
  assert.equal(partialPb.status, 200); assert.equal(partialPb.json.partialSuccess.rejectedSpans, '2');
  // Same span id with different content is a per-span conflict, never an overwrite.
  // JSON bytes declared as protobuf are undecodable: 400, which exporters do not retry.
  assert.equal((await send(ingress, mixed, {token, type: 'application/x-protobuf'})).status, 400);
  const conflictJson = await send(ingress, otlpJson([span('b1'.repeat(8), {'gen_ai.operation.name': 'chat', 'gen_ai.provider.name': 'openai', 'gen_ai.request.model': 'other-model'})]), {token});
  assert.equal(conflictJson.status, 200); assert.equal(conflictJson.json.partialSuccess.rejectedSpans, '1'); assert.match(conflictJson.json.partialSuccess.errorMessage, /id_conflict=1/);
  const stillOriginal = (await events(h, `&traceId=${'a1'.repeat(16)}`)).items;
  assert.equal(stillOriginal.length, 1); assert.equal(stillOriginal[0].model, 'claude-unit');

  // Undecodable protobuf: 400 with a protobuf google.rpc.Status body (code=3, message).
  const badPb = await send(ingress, Buffer.from([0x0b]), {token, type: 'application/x-protobuf'});
  assert.equal(badPb.status, 400); assert.equal(badPb.type, 'application/x-protobuf'); assert.equal(badPb.raw.subarray(0, 3).toString('hex'), '080312');

  // Authentication and authorization: Status bodies in the request encoding, never success.
  for (const [credential, status] of [[null, 401], ['wrong-token-'.repeat(4), 401], [h.principal('agent').token, 403], [h.principal('auditor').token, 403], [h.principal('telemetry').token, 403]]) {
    const denied = await send(ingress, fixture('collector-genai.pb'), {token: credential, type: 'application/x-protobuf'});
    assert.equal(denied.status, status, String(status)); assert.equal(denied.type, 'application/x-protobuf');
  }
  const deniedJson = await send(ingress, fixture('sdk-genai.json'), {token: 'nope'.repeat(10)});
  assert.equal(deniedJson.status, 401); assert.equal(deniedJson.json.code, 16); assert.equal(typeof deniedJson.json.message, 'string');
  // The OTLP bearer token is useless on HMAC and human routes.
  const ts = String(Date.now()), nonce = randomUUID(), hmacBody = JSON.stringify({id: 'x', kind: 'notice', occurredAt: new Date().toISOString(), traceId: 'x', actionId: 'x'});
  assert.equal((await send(ingress, hmacBody, {token, path: '/api/ingest', headers: {'x-evid-timestamp': ts, 'x-evid-nonce': nonce, 'x-evid-signature': mac('guess', ts, nonce, hmacBody)}})).status, 401);
  assert.equal((await h.api('/api/events', {role: 'otlp'})).status, 403);

  // Media type, encoding and method errors.
  assert.equal((await send(ingress, 'x', {token, type: 'text/plain'})).status, 415);
  assert.equal((await send(ingress, fixture('sdk-genai.json'), {token, encoding: 'br'})).status, 415);
  const get = await send(ingress, undefined, {token, method: 'GET'});
  assert.equal(get.status, 405); assert.equal(get.json.code, 12);
  assert.equal((await send(ingress, zlib.gzipSync(Buffer.from('{}')).subarray(0, 10), {token, encoding: 'gzip'})).status, 400);
  assert.equal((await send(ingress, '{"resourceSpans":', {token})).status, 400);
  assert.equal((await send(ingress, '{}', {token})).status, 200); // empty request is a success

  // Gateway boundaries: the vault batch route is never public, the audit gateway never ingests.
  assert.equal((await send(ingress, '{"format":"evidscope-otlp-batch-v1","mapping":"otel-genai-map-1","events":[]}', {token, path: '/api/ingest/otlp'})).status, 403);
  assert.equal((await send(h.audit.url, fixture('sdk-genai.json'), {token, path: '/api/ingest/otlp'})).status, 403);
  assert.equal((await send(h.audit.url, fixture('sdk-genai.json'), {token})).status, 403);
  assert.equal((await send(ingress, fixture('sdk-genai.json'), {token, headers: {origin: 'https://evil.example'}})).status, 403);

  // Minimization: no content attribute, span name or status message is retrievable anywhere.
  const exported = JSON.stringify((await h.api('/api/export')).body), listed = JSON.stringify(await events(h));
  for (const canary of CANARIES) { assert.ok(!exported.includes(canary), canary); assert.ok(!listed.includes(canary), canary); }
  const integrity = await h.api('/api/integrity'); assert.equal(integrity.body.valid, true, JSON.stringify(integrity.body.error));
  assert.equal((await events(h)).total, 5); assert.equal((await h.api('/api/events', {tenant: 'beta'})).body.total, 0);
});

test('OTLP views: AI visibility, agents, overview and monitoring show OTLP-sourced activity', async t => {
  const h = await harness(); t.after(() => h.close());
  const token = h.principal('otlp').token;
  assert.equal((await send(h.ingress.url, fixture('collector-genai.pb'), {token, type: 'application/x-protobuf'})).status, 200);
  for (let i = 0; i < 4; i++) await h.analyze();
  const visible = (await h.api('/api/ai-visibility?range=24h')).body;
  const asset = visible.assets.find(a => a.id === 'otel-service:travel-agent');
  assert.ok(asset, JSON.stringify(visible.assets.map(a => a.id)));
  assert.equal(asset.registered, false); assert.equal(asset.observationCount, 2); assert.deepEqual(asset.providers, ['openai']); assert.deepEqual(asset.models, ['gpt-4o-2024-08-06']);
  assert.deepEqual(asset.collectors, ['evidscope-otlp-receiver']); assert.ok(asset.attention.some(a => a.code === 'AI_UNREGISTERED_ASSET'));
  const agents = (await h.api('/api/agents')).body;
  const agent = agents.items.find(a => a.source === 'alpha-otlp' && a.actor === 'travel-planner');
  assert.ok(agent, JSON.stringify(agents.items.map(a => [a.source, a.actor])));
  assert.equal(agent.actions, 2); assert.deepEqual([...agent.models].sort(), ['gpt-4o', 'gpt-4o-2024-08-06']);
  assert.equal(agent.counts.compliant, 0); // self-telemetry alone never proves compliance
  assert.equal(agents.unattributedActions, 0);
  const overview = (await h.api('/api/overview')).body;
  assert.equal(overview.sources.find(s => s.id === 'alpha-otlp').status, 'receiving');
  const monitor = (await h.api('/api/monitoring?range=1h')).body;
  assert.equal(monitor.points.reduce((n, p) => n + p.received, 0), 4); assert.equal(monitor.points.reduce((n, p) => n + p.telemetryFailures, 0), 1);
  assert.equal(monitor.points.reduce((n, p) => n + p.failure, 0), 0); // not mixed with independent tool results
  const investigation = (await h.api(`/api/events?traceId=${TRACE}`)).body;
  assert.equal(investigation.total, 4);
  const betaAgents = (await h.api('/api/agents', {tenant: 'beta'})).body;
  assert.equal(betaAgents.items.filter(a => a.source.startsWith('alpha')).length, 0);
});

test('OTLP limits: compressed, decompressed and declared sizes are 413; vault-only mode serves /v1/traces', async t => {
  const h = await harness({vaultOnly: true}); t.after(() => h.close());
  const token = h.principal('otlp').token;
  const direct = await send(h.vault.url, fixture('sdk-genai.pb'), {token, type: 'application/x-protobuf'});
  assert.equal(direct.status, 200); assert.equal(direct.raw.length, 0);
  const small = await h.start('ingress', {VAULT_URL: h.vault.url, OTLP_MAX_BODY_BYTES: '4096', OTLP_MAX_DECODED_BYTES: '6000', OTLP_MAX_SPANS: '4'});
  assert.equal((await send(small.url, fixture('collector-genai.pb'), {token, type: 'application/x-protobuf'})).status, 200);
  assert.equal((await send(small.url, fixture('sdk-genai.json'), {token})).status, 413);
  const bomb = zlib.gzipSync(Buffer.alloc(1024 * 1024, 0x20));
  assert.ok(bomb.length < 4096);
  const decompressed = await send(small.url, bomb, {token, encoding: 'gzip'});
  assert.equal(decompressed.status, 413); assert.equal(decompressed.json.code, 8);
  assert.equal((await send(small.url, Buffer.alloc(5000, 0x20), {token})).status, 413);
  assert.equal((await send(small.url, otlpJson([1, 2, 3, 4, 5].map(i => span(`c${i}`.repeat(8), {'gen_ai.operation.name': 'chat'}))), {token})).status, 413);
  // A chunked body without Content-Length is bounded while streaming.
  const stream = new ReadableStream({start(controller) { for (let i = 0; i < 5; i++) controller.enqueue(new Uint8Array(1024).fill(0x20)); controller.close(); }});
  const chunked = await fetch(small.url + '/v1/traces', {method: 'POST', body: stream, duplex: 'half', headers: {'content-type': 'application/json', authorization: `Bearer ${token}`}});
  assert.equal(chunked.status, 413); await chunked.arrayBuffer();
});

test('per-tenant analysis backlog answers 503 + Retry-After for that tenant only', async t => {
  process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT = '2';
  let h;
  try { h = await harness(); } finally { delete process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT; }
  t.after(() => h.close());
  const tools = traceId => otlpJson([1, 2, 3].map(i => span(`d${i}`.repeat(8), {'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': `tool-${i}`}, {traceId})));
  const alpha = h.principal('otlp').token, beta = h.principal('otlp', 'beta').token;
  assert.equal((await send(h.ingress.url, tools('e1'.repeat(16)), {token: alpha})).status, 200); // 3 pending actions > limit 2
  const busy = await send(h.ingress.url, tools('e2'.repeat(16)), {token: alpha, type: 'application/json'});
  assert.equal(busy.status, 503); assert.equal(busy.retryAfter, '5'); assert.equal(busy.json.code, 14);
  const busyPb = await send(h.ingress.url, fixture('collector-genai.pb'), {token: alpha, type: 'application/x-protobuf', encoding: undefined});
  assert.equal(busyPb.status, 503); assert.equal(busyPb.type, 'application/x-protobuf');
  // Another tenant is not refused because alpha is busy (audit S7).
  assert.equal((await send(h.ingress.url, tools('e3'.repeat(16)), {token: beta})).status, 200);
  // The retried batch succeeds once the analysis worker drains alpha's backlog.
  await h.analyze();
  const retried = await send(h.ingress.url, tools('e2'.repeat(16)), {token: alpha});
  assert.equal(retried.status, 200); assert.deepEqual(retried.json, {});
  assert.equal((await events(h, `&traceId=${'e2'.repeat(16)}`)).total, 3);
});

test('replay client posts saved OTLP exports; the stdin collector no longer accepts OTLP', async t => {
  const h = await harness(); t.after(() => h.close());
  const dir = mkdtempSync(join(h.dir, 'replay-')), lines = join(dir, 'spans.jsonl'), gz = join(dir, 'trace.pb.gz');
  writeFileSync(lines, [otlpJson([span('f1'.repeat(8), {'gen_ai.operation.name': 'chat'})]), otlpJson([span('f2'.repeat(8), {'http.request.method': 'GET'})])].join('\n'));
  writeFileSync(gz, zlib.gzipSync(fixture('collector-genai.pb')));
  const replay = (files, env) => spawnSync(process.execPath, ['scripts/replay-otlp.mjs', `${h.ingress.url}/v1/traces`, ...files], {env: {...process.env, ...env}, encoding: 'utf8'});
  const ok = replay([new URL('./fixtures/otlp/sdk-genai.json', import.meta.url).pathname, lines, gz], {EVIDSCOPE_OTLP_TOKEN: h.principal('otlp').token});
  assert.equal(ok.status, 0, ok.stderr);
  assert.deepEqual(JSON.parse(ok.stdout), {requests: 4, delivered: 4, rejectedSpans: 1, failed: 0, statuses: {200: 4}});
  assert.equal((await events(h)).total, 5);
  const denied = replay([lines], {EVIDSCOPE_OTLP_TOKEN: h.principal('agent').token});
  assert.equal(denied.status, 1); assert.deepEqual(JSON.parse(denied.stdout).statuses, {403: 2}); assert.ok(!denied.stdout.includes(h.principal('agent').token));
  assert.equal(replay([lines], {EVIDSCOPE_OTLP_TOKEN: ''}).status, 2);
  const retired = spawnSync(process.execPath, ['scripts/collect-ai-observations.mjs', 'otlp'], {input: fixture('sdk-genai.json'), encoding: 'utf8'});
  assert.equal(retired.status, 2); assert.equal(retired.stdout, ''); assert.match(retired.stderr, /retired/);
});
