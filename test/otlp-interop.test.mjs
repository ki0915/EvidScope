// Interop with the real OpenTelemetry Collector and JS SDK. Gated: set EVIDSCOPE_OTELCOL_BIN to an otelcol
// (core distribution >= 0.140) binary and EVIDSCOPE_OTEL_JS_DIR to a directory whose node_modules contains
// @opentelemetry/{api,sdk-trace-base,resources,exporter-trace-otlp-http,exporter-trace-otlp-proto}.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {existsSync, readFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {join} from 'node:path';
import {harness} from './harness.mjs';

const otelcol = process.env.EVIDSCOPE_OTELCOL_BIN, jsDir = process.env.EVIDSCOPE_OTEL_JS_DIR;
const collectorSkip = !otelcol ? 'EVIDSCOPE_OTELCOL_BIN not set' : !existsSync(otelcol) ? 'EVIDSCOPE_OTELCOL_BIN does not exist' : false;
const sdkSkip = !jsDir ? 'EVIDSCOPE_OTEL_JS_DIR not set' : !existsSync(join(jsDir, 'node_modules', '@opentelemetry', 'exporter-trace-otlp-proto')) ? 'EVIDSCOPE_OTEL_JS_DIR lacks OTel exporters' : false;
const config = new URL('../deploy/otel-collector/evidscope-collector.yaml', import.meta.url).pathname;
const sender = new URL('./fixtures/otlp/send-genai-trace.cjs', import.meta.url).pathname;
const fixture = name => readFileSync(new URL(`./fixtures/otlp/${name}`, import.meta.url));
const CANARIES = ['CANARY', 'Weather in Paris', 'weather API timed out', 'Plans trips', 'Get current weather', '123-45-6789', 'sk-live', 'secret'];

const freePort = () => new Promise((resolve, reject) => { const s = createServer(); s.once('error', reject); s.listen(0, '127.0.0.1', () => { const {port} = s.address(); s.close(() => resolve(port)); }); });
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(check, timeoutMs = 20000, label = 'condition') {
  const end = Date.now() + timeoutMs;
  for (;;) { const value = await check(); if (value) return value; if (Date.now() > end) throw Error(`timed out waiting for ${label}`); await sleep(200); }
}
async function startCollector(t, h, token) {
  const [http, grpc, health] = [await freePort(), await freePort(), await freePort()];
  const env = {...process.env, EVIDSCOPE_OTLP_ENDPOINT: `${h.ingress.url}/v1/traces`, EVIDSCOPE_OTLP_TOKEN: token, OTELCOL_OTLP_HTTP_ENDPOINT: `127.0.0.1:${http}`,
    OTELCOL_OTLP_GRPC_ENDPOINT: `127.0.0.1:${grpc}`, OTELCOL_HEALTH_ENDPOINT: `127.0.0.1:${health}`, OTELCOL_METRICS_LEVEL: 'none'};
  const child = spawn(otelcol, ['--config', config], {env, stdio: ['ignore', 'pipe', 'pipe']});
  let log = ''; child.stdout.on('data', b => { log += b; }); child.stderr.on('data', b => { log += b; });
  t.after(() => new Promise(r => { if (child.exitCode !== null) return r(); child.once('exit', r); child.kill('SIGTERM'); setTimeout(() => { child.kill('SIGKILL'); r(); }, 5000).unref(); }));
  await until(async () => { try { return (await fetch(`http://127.0.0.1:${health}/`)).status === 200; } catch { return false; } }, 20000, `collector health: ${log}`);
  const post = async (body, type) => (await fetch(`http://127.0.0.1:${http}/v1/traces`, {method: 'POST', headers: {'content-type': type}, body})).status;
  return {post, log: () => log};
}
const traceEvents = async (h, traceId) => (await h.api(`/api/events?limit=100&traceId=${traceId}`)).body;

test('real Collector (core distribution) minimizes and forwards GenAI spans with the shipped config', {skip: collectorSkip}, async t => {
  const validate = spawnSync(otelcol, ['validate', '--config', config], {env: {...process.env, EVIDSCOPE_OTLP_ENDPOINT: 'https://evidscope.example/v1/traces', EVIDSCOPE_OTLP_TOKEN: 'x'}, encoding: 'utf8'});
  assert.equal(validate.status, 0, validate.stderr);
  const h = await harness(); t.after(() => h.close());
  const collector = await startCollector(t, h, h.principal('otlp').token);
  // Apps post OTLP/JSON and OTLP/protobuf to the Collector; it forwards gzip protobuf with the bearer header.
  assert.equal(await collector.post(fixture('sdk-genai.json'), 'application/json'), 200);
  assert.equal(await collector.post(fixture('legacy-content.json'), 'application/json'), 200);
  assert.equal(await collector.post(fixture('collector-genai.pb'), 'application/x-protobuf'), 200); // same trace again: duplicates
  const travel = await until(async () => { const v = await traceEvents(h, '4bf92f3577b34da6a3ce929d0e0e4736'); return v.total === 4 && v; }, 20000, 'travel trace');
  const legacy = await until(async () => { const v = await traceEvents(h, '5b8efff798038103d269b633813fc60c'); return v.total === 1 && v; }, 20000, 'legacy trace');
  await sleep(2500); // let the duplicate batch arrive too
  assert.equal((await traceEvents(h, '4bf92f3577b34da6a3ce929d0e0e4736')).total, 4);
  const stored = JSON.stringify([travel, legacy, (await h.api('/api/export')).body]);
  for (const canary of CANARIES) assert.ok(!stored.includes(canary), canary);
  assert.equal(legacy.items[0].aiObservation.provider, 'openai'); assert.equal(legacy.items[0].status, 'failure');
  for (let i = 0; i < 4; i++) await h.analyze();
  const visible = (await h.api('/api/ai-visibility?range=24h')).body;
  assert.deepEqual(visible.assets.map(a => a.id).filter(id => id.startsWith('otel-service:')).sort(), ['otel-service:legacy-agent', 'otel-service:travel-agent']);
  assert.equal(visible.summary.totalObservations, 3);
  const agents = (await h.api('/api/agents')).body.items.filter(a => a.source === 'alpha-otlp');
  assert.deepEqual(agents.map(a => a.actor).sort(), ['service:legacy-agent', 'travel-planner']);
  assert.equal((await h.api('/api/integrity')).body.valid, true);
  assert.doesNotMatch(collector.log(), /Dropping data|Partial success|not retryable/i);
  t.diagnostic(`collector: ${JSON.stringify({travel: travel.total, legacy: legacy.total, assets: visible.summary.assets, observations: visible.summary.totalObservations, agents: agents.map(a => `${a.actor}:${a.actions}:${a.models.join('+')}`)})}`);
});

test('real Collector retries EvidScope 503 + Retry-After and delivers once the tenant backlog drains', {skip: collectorSkip}, async t => {
  process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT = '1';
  let h;
  try { h = await harness(); } finally { delete process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT; }
  t.after(() => h.close());
  const collector = await startCollector(t, h, h.principal('otlp').token);
  assert.equal(await collector.post(fixture('sdk-genai.json'), 'application/json'), 200);
  await until(async () => (await traceEvents(h, '4bf92f3577b34da6a3ce929d0e0e4736')).total === 4, 20000, 'first trace');
  assert.equal(await collector.post(fixture('legacy-content.json'), 'application/json'), 200); // 3 pending actions > 1: vault answers 503
  await until(() => /503|Throttle|retry/i.test(collector.log()), 15000, 'collector retry log');
  assert.equal((await traceEvents(h, '5b8efff798038103d269b633813fc60c')).total, 0);
  await h.analyze();
  await until(async () => (await traceEvents(h, '5b8efff798038103d269b633813fc60c')).total === 1, 30000, 'retried delivery');
  assert.doesNotMatch(collector.log(), /Dropping data/i);
  const retries = collector.log().split('\n').filter(l => /Will retry/.test(l)).map(l => [/"error": "(Throttle \(\d+s\)).*?Status Code (\d+)/.exec(l)?.slice(1).join(' '), /"interval": "([^"]+)"/.exec(l)?.[1]]);
  assert.ok(retries.length >= 1 && retries.every(([error]) => /^Throttle \(5s\) 503$/.test(error || '')), JSON.stringify(retries));
  t.diagnostic(`collector retries: ${JSON.stringify(retries)}`);
});

test('real OpenTelemetry JS SDK exporters (http/json and http/protobuf) deliver to the ingress', {skip: sdkSkip}, async t => {
  const h = await harness(); t.after(() => h.close());
  const url = `${h.ingress.url}/v1/traces`, start = String(Date.now() - 60000);
  const run = (encoding, compression, traceId, flag) => {
    const result = spawnSync(process.execPath, [sender, encoding, url, compression, traceId, start, ...(flag ? [flag] : [])],
      {env: {...process.env, EVIDSCOPE_OTEL_JS_DIR: jsDir, EVIDSCOPE_OTLP_TOKEN: h.principal('otlp').token}, encoding: 'utf8', timeout: 30000});
    assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /sent/);
    return result.stdout + result.stderr;
  };
  const traceA = 'aa'.repeat(16), traceB = 'bb'.repeat(16);
  const jsonOut = run('json', 'gzip', traceA);
  assert.doesNotMatch(jsonOut, /Export failed|Partial Success|error/i);
  assert.equal((await traceEvents(h, traceA)).total, 3);
  const protoOut = run('proto', 'none', traceA); // same spans over protobuf: idempotent duplicates
  assert.doesNotMatch(protoOut, /Export failed|Partial Success|error/i);
  const a = await traceEvents(h, traceA); assert.equal(a.total, 3);
  // A non-GenAI span is reported as a partial success; the SDK logs it and does not retry.
  const partialOut = run('proto', 'gzip', traceB, '--with-http-span');
  assert.match(partialOut, /Partial Success/i); assert.match(partialOut, /not_genai=1/);
  const b = await traceEvents(h, traceB); assert.equal(b.total, 3);
  const stored = JSON.stringify([a, b]);
  for (const canary of CANARIES) assert.ok(!stored.includes(canary), canary);
  for (let i = 0; i < 3; i++) await h.analyze();
  const visible = (await h.api('/api/ai-visibility?range=24h')).body.assets.find(x => x.id === 'otel-service:travel-agent');
  assert.equal(visible.observationCount, 2); assert.deepEqual(visible.models, ['gpt-4o-2024-08-06']);
  const agent = (await h.api('/api/agents')).body.items.find(x => x.source === 'alpha-otlp' && x.actor === 'travel-planner');
  assert.equal(agent.actions, 4); assert.deepEqual([...agent.models].sort(), ['gpt-4o', 'gpt-4o-2024-08-06']);
  t.diagnostic(`sdk: ${JSON.stringify({traceA: a.total, traceB: b.total, observations: visible.observationCount, agent: `${agent.actor}:${agent.actions}:${agent.models.join('+')}`})}`);
});
