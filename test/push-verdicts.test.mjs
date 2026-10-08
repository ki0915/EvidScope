// scripts/push-verdicts.mjs (docs/observability-integration.md): EvidScope verdicts as Langfuse scores and Phoenix annotations.
// Local mock servers check the documented request shapes (Langfuse public API 4.54 OpenAPI: POST /api/public/ingestion
// score-create, DELETE /api/public/scores/{id}; Phoenix 20.19 OpenAPI: POST /v1/trace_annotations and /v1/span_annotations).
// No real Langfuse or Phoenix service is contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {promisify} from 'node:util';
import {generateKeyPairSync} from 'node:crypto';
import {harness} from './harness.mjs';
import {tempDir} from './temp-dir.mjs';
import {submit} from '../src/client.mjs';
import {run, serviceBase, request, redact, UsageError} from '../scripts/push-verdicts.mjs';
import {actionVerdicts, assessExport, langfuseScores, phoenixAnnotations, stableId, NAMES} from '../src/observability-export.mjs';

const exec = promisify(execFile);
const TRACE = 'c0ffee'.padEnd(32, '1'), SPAN_CHAT = '1111111111111111', SPAN_TOOL = '2222222222222222', UNKNOWN_SPAN = '3333333333333333';
const CANARIES = ['CANARY-ACTOR-a1', 'CANARY-RESOURCE-b2', 'CANARY-DEST.example', 'CANARY-NOTE-c3', 'CANARY-AGENT-d4', 'CANARY-TOOL-e5',
  'CANARY-SERVICE', 'CANARY-PURPOSE-f6', 'CANARY-MODEL-g7'];
const SECRETS = {LANGFUSE_PUBLIC_KEY: 'pk-lf-CANARY-public-0123456789', LANGFUSE_SECRET_KEY: 'sk-lf-CANARY-secret-0123456789',
  PHOENIX_API_KEY: 'phx-CANARY-api-key-0123456789'};
const json = (res, status, body) => { res.statusCode = status; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(body)); };
const readBody = req => new Promise(r => {
  const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', () => r(Buffer.concat(chunks).toString('utf8')));
});
const listen = async server => { await new Promise(r => server.listen(0, '127.0.0.1', r)); return `http://127.0.0.1:${server.address().port}/`; };
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/, HEX32 = /^[a-f0-9]{32}$/, HEX16 = /^[a-f0-9]{16}$/;

// Langfuse: Basic auth; a score is replaced when id, name and the date of its timestamp all match (docs: "Preventing Duplicate Scores").
async function mockLangfuse() {
  const requests = [], scores = new Map(), problems = [];
  const server = createServer(async (req, res) => {
    const raw = await readBody(req), url = new URL(req.url, 'http://x');
    requests.push({method: req.method, path: url.pathname, headers: req.headers, raw});
    if (req.headers.authorization !== `Basic ${Buffer.from(`${SECRETS.LANGFUSE_PUBLIC_KEY}:${SECRETS.LANGFUSE_SECRET_KEY}`).toString('base64')}`)
      return json(res, 401, {message: 'Invalid credentials'});
    const deleted = /^\/api\/public\/scores\/([^/]+)$/.exec(url.pathname);
    if (req.method === 'DELETE' && deleted) {
      const keys = [...scores.keys()].filter(k => k.startsWith(`${decodeURIComponent(deleted[1])}|`));
      keys.forEach(k => scores.delete(k)); res.statusCode = keys.length ? 204 : 404; return res.end();
    }
    if (req.method !== 'POST' || url.pathname !== '/api/public/ingestion') return json(res, 404, {message: 'not found'});
    const body = JSON.parse(raw), successes = [], errors = [];
    if (!Array.isArray(body.batch) || Object.keys(body).some(k => !['batch', 'metadata'].includes(k))) return json(res, 400, {message: 'bad envelope'});
    for (const event of body.batch) {
      const s = event.body, bad = [];
      if (event.type !== 'score-create' || typeof event.id !== 'string' || !ISO.test(event.timestamp)) bad.push('envelope');
      if (typeof s?.id !== 'string' || !HEX32.test(s.traceId) || typeof s.name !== 'string') bad.push('ids');
      if (s?.observationId !== undefined && !HEX16.test(s.observationId)) bad.push('observationId');
      if (!['CATEGORICAL', 'NUMERIC', 'BOOLEAN'].includes(s?.dataType)) bad.push('dataType');
      if (s?.dataType === 'CATEGORICAL' ? typeof s.value !== 'string' : typeof s?.value !== 'number') bad.push('value');
      const allowed = ['id', 'traceId', 'observationId', 'name', 'value', 'dataType', 'comment', 'metadata', 'environment'];
      if (Object.keys(s || {}).some(k => !allowed.includes(k))) bad.push('field');
      if (bad.length) { problems.push(bad); errors.push({id: event.id, status: 400, message: bad.join(',')}); continue; }
      scores.set(`${s.id}|${s.name}|${event.timestamp.slice(0, 10)}`, {...s, timestamp: event.timestamp});
      successes.push({id: event.id, status: 201});
    }
    json(res, 207, {successes, errors});
  });
  return {url: await listen(server), requests, scores, problems, close: () => new Promise(r => server.close(r))};
}
// Phoenix: Bearer API key; annotations upsert on (name, trace or span, identifier); sync=true answers 404 for unknown targets.
async function mockPhoenix({traces = [TRACE], spans = [SPAN_CHAT, SPAN_TOOL]} = {}) {
  const requests = [], annotations = new Map(), problems = [];
  const server = createServer(async (req, res) => {
    const raw = await readBody(req), url = new URL(req.url, 'http://x');
    requests.push({method: req.method, path: url.pathname, query: url.search, headers: req.headers, raw});
    if (req.headers.authorization !== `Bearer ${SECRETS.PHOENIX_API_KEY}`) { res.statusCode = 401; return res.end('Unauthorized'); }
    const kind = {'/v1/trace_annotations': 'trace_id', '/v1/span_annotations': 'span_id'}[url.pathname];
    if (req.method !== 'POST' || !kind || url.searchParams.get('sync') !== 'true') return json(res, 404, {detail: 'not found'});
    const {data} = JSON.parse(raw), known = kind === 'trace_id' ? traces : spans;
    for (const d of data) {
      const allowed = ['name', 'annotator_kind', 'result', 'metadata', 'identifier', kind];
      if (Object.keys(d).some(k => !allowed.includes(k)) || d.annotator_kind !== 'CODE' || typeof d.identifier !== 'string' || !d.identifier
        || !(kind === 'trace_id' ? HEX32 : HEX16).test(d[kind]) || typeof d.result?.label !== 'string'
        || !(d.result.score === null || typeof d.result.score === 'number') || typeof d.result.explanation !== 'string') problems.push(d);
    }
    const missing = data.filter(d => !known.includes(d[kind]));
    if (missing.length) { res.statusCode = 404; return res.end(`Spans with IDs ${missing.map(d => d[kind]).join(', ')} do not exist.`); }
    for (const d of data) annotations.set(`${kind}|${d[kind]}|${d.name}|${d.identifier}`, d);
    json(res, 200, {data: data.map((_, i) => ({id: `SpanAnnotation:${i}`}))});
  });
  return {url: await listen(server), requests, annotations, problems, close: () => new Promise(r => server.close(r))};
}

const span = (spanId, attributes, now) => ({traceId: TRACE, spanId, name: 'chat secret prompt', kind: 3,
  startTimeUnixNano: String(BigInt(now - 60000) * 1000000n),
  endTimeUnixNano: String(BigInt(now - 59000) * 1000000n), status: {},
  attributes: Object.entries(attributes).map(([key, value]) => ({key, value: {stringValue: value}}))});
async function scenario(h) {
  const now = Date.now(), when = offset => new Date(now + offset).toISOString();
  const common = {actionId: 'pay-run-1', traceId: TRACE, actor: CANARIES[0], tool: 'payments-api', action: 'write', resource: CANARIES[1],
    destination: CANARIES[2], occurredAt: when(-1000), purpose: CANARIES[7]};
  for (const [kind, event] of [['agent', {...common, id: 'e1', kind: 'intent', note: CANARIES[3]}],
    ['tool', {...common, id: 'e2', kind: 'execution', status: 'started'}]])
    assert.equal((await submit(h.ingress.url, h.principal(kind), event)).status, 202);
  const chat = {'gen_ai.operation.name': 'chat', 'gen_ai.provider.name': 'openai', 'gen_ai.request.model': CANARIES[8], 'gen_ai.agent.name': CANARIES[4]};
  const spans = [span(SPAN_CHAT, chat, now), span(SPAN_TOOL, {'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': CANARIES[5]}, now)];
  const resource = {attributes: [{key: 'service.name', value: {stringValue: CANARIES[6]}}]};
  const body = JSON.stringify({resourceSpans: [{resource, scopeSpans: [{scope: {name: 'u'}, spans}]}]});
  const headers = {authorization: `Bearer ${h.principal('otlp').token}`, 'content-type': 'application/json'};
  const r = await fetch(h.ingress.url + '/v1/traces', {method: 'POST', headers, body});
  assert.equal(r.status, 200);
  for (let i = 0; i < 4; i++) await h.analyze();
  return {common, when};
}
const sent = (...mocks) => mocks.flatMap(m => m.requests.map(r => r.raw)).join('\n');
const env = (h, extra = {}) => ({EVIDSCOPE_TOKEN: h.principal('auditor').token, ...SECRETS, ...extra});

test('push-verdicts: mapping, preview default, idempotent update, canaries, tampering, credentials, HTTPS and redirects', async t => {
  const h = await harness(); t.after(() => h.close());
  const langfuse = await mockLangfuse(), phoenix = await mockPhoenix(); t.after(() => Promise.all([langfuse.close(), phoenix.close()]));
  const {common, when} = await scenario(h), dir = tempDir('evidscope-push-'), key = join(h.dir, 'trust-anchor.pem');
  const base = ['--evidscope', `${h.audit.url}/`, '--key', key, '--link-base', 'https://audit.example/', '--langfuse', langfuse.url, '--phoenix', phoenix.url];
  const exportFile = join(dir, 'export.json'), exported = (await h.api('/api/export')).body;
  writeFileSync(exportFile, JSON.stringify(exported));
  for (const canary of CANARIES) assert.ok(readFileSync(exportFile, 'utf8').includes(canary) || canary === CANARIES[8], `export holds ${canary}`);

  await t.test('preview is the default: verdicts and the exact requests, nothing sent', async () => {
    const {code, output} = await run(base, env(h));
    assert.equal(code, 0); assert.equal(output.mode, 'preview'); assert.equal(output.export.verdict, 'verified');
    assert.equal(langfuse.requests.length + phoenix.requests.length, 0);
    assert.ok(output.langfuse.events.length > 0 && output.phoenix.traceAnnotations.length > 0);
    const actions = output.verdicts.map(v => v.actionId).sort();
    assert.deepEqual(actions, ['otel-trace:' + TRACE, `otel:${TRACE}:${SPAN_TOOL}`, 'pay-run-1'].sort());
    assert.ok(output.verdicts.every(v => v.traceId === TRACE && v.verdict === 'verified'));
  });

  await t.test('send: documented request shapes, trace and span links, deep link back', async () => {
    const {code, output} = await run([...base, '--send'], env(h));
    assert.equal(code, 0, JSON.stringify(output)); assert.equal(output.mode, 'sent');
    assert.deepEqual(langfuse.problems, []); assert.deepEqual(phoenix.problems, []);
    assert.equal(output.langfuse.errors.length, 0); assert.equal(output.phoenix.errors.length, 0); assert.equal(output.phoenix.notFound, 0);
    const pay = [...langfuse.scores.values()].filter(s => s.metadata.evidscope.actionId === 'pay-run-1');
    const verdict = pay.find(s => s.name === NAMES.verified), findings = pay.find(s => s.name === NAMES.findings);
    assert.equal(verdict.value, 'verified'); assert.equal(verdict.dataType, 'CATEGORICAL'); assert.equal(verdict.traceId, TRACE);
    assert.equal(verdict.observationId, undefined);
    assert.equal(findings.dataType, 'NUMERIC'); assert.equal(findings.value, 4);
    assert.ok(findings.metadata.evidscope.findings.codes.includes('AUTHORITY_MISSING'));
    assert.ok(verdict.comment.includes('https://audit.example/#action=pay-run-1'), verdict.comment);
    assert.equal(verdict.metadata.evidscope.witness, 'none');
    const ledger = verdict.metadata.evidscope.ledger;
    const evaluationRow = exported.records.filter(r => r.type === 'evaluation' && r.payload.actionId === 'pay-run-1').at(-1);
    assert.deepEqual([ledger.seq, ledger.hash], [evaluationRow.seq, evaluationRow.hash]);
    assert.equal(verdict.metadata.evidscope.receipt.record, `/api/receipts/record?seq=${evaluationRow.seq}`);
    assert.match(verdict.metadata.evidscope.receipt.exportSha256, /^[a-f0-9]{64}$/);
    const spanScores = [...langfuse.scores.values()].filter(s => s.name === NAMES.recorded);
    assert.deepEqual(spanScores.map(s => s.observationId).sort(), [SPAN_CHAT, SPAN_TOOL]);
    const chatRow = exported.records.find(r => r.type === 'event' && r.seq === spanScores.find(s => s.observationId === SPAN_CHAT).metadata.evidscope.span.seq);
    assert.ok(chatRow, 'span score names the ledger row of the span');
    const traceNotes = [...phoenix.annotations.values()].filter(a => a.trace_id === TRACE && a.metadata.evidscope.actionId === 'pay-run-1');
    assert.deepEqual(traceNotes.map(a => a.name).sort(), [NAMES.findings, NAMES.verified, NAMES.witness].sort());
    const phxVerdict = traceNotes.find(a => a.name === NAMES.verified);
    assert.deepEqual([phxVerdict.result.label, phxVerdict.result.score], ['verified', 1]);
    assert.ok(phxVerdict.result.explanation.includes('https://audit.example/#action=pay-run-1'));
    assert.deepEqual([...phoenix.annotations.values()].filter(a => a.span_id).map(a => a.span_id).sort(), [SPAN_CHAT, SPAN_TOOL]);
    assert.ok(phoenix.requests.every(r => r.query === '?sync=true'));
  });

  await t.test('no payload or body field leaves EvidScope (canaries)', () => {
    const outbound = sent(langfuse, phoenix);
    assert.ok(outbound.length > 1000);
    for (const canary of [...CANARIES, 'secret prompt']) assert.ok(!outbound.includes(canary), canary);
    for (const message of exported.records.filter(r => r.type === 'evaluation').flatMap(r => r.payload.findings.map(f => f.message)))
      assert.ok(!outbound.includes(message), 'finding messages stay in EvidScope');
  });

  await t.test('re-push is idempotent; a later finding updates the same score and annotation', async () => {
    const before = new Map(langfuse.scores), phx = phoenix.annotations.size;
    assert.equal((await run([...base, '--send'], env(h))).code, 0);
    assert.deepEqual([...langfuse.scores.keys()].sort(), [...before.keys()].sort());
    assert.equal(phoenix.annotations.size, phx);
    // A tool result contradicting the agent's own success report arrives later: a new finding on the same action.
    const later = [['agent', {...common, id: 'e3', kind: 'self_report', status: 'success', occurredAt: when(-500)}],
      ['tool', {...common, id: 'e4', kind: 'result', status: 'failure', occurredAt: when(-400)}]];
    for (const [kind, event] of later) assert.equal((await submit(h.ingress.url, h.principal(kind), event)).status, 202);
    for (let i = 0; i < 3; i++) await h.analyze();
    assert.equal((await run([...base, '--send'], env(h))).code, 0);
    assert.deepEqual([...langfuse.scores.keys()].sort(), [...before.keys()].sort(), 'same ids, names and dates: replaced, not duplicated');
    assert.equal(phoenix.annotations.size, phx);
    const id = stableId('langfuse', 'alpha', 'pay-run-1', TRACE, NAMES.findings, '');
    const old = [...before.values()].find(s => s.id === id), updated = [...langfuse.scores.values()].find(s => s.id === id);
    assert.ok(updated.value > old.value, `${old.value} -> ${updated.value}`);
    assert.ok(updated.metadata.evidscope.ledger.seq > old.metadata.evidscope.ledger.seq);
    const phxFindings = [...phoenix.annotations.values()].find(a => a.name === NAMES.findings && a.metadata.evidscope.actionId === 'pay-run-1');
    assert.equal(phxFindings.result.score, updated.value);
  });

  await t.test('tampered, rolled back or foreign-key exports are pushed as such, never as verified', async () => {
    const latest = (await h.api('/api/export')).body, tampered = structuredClone(latest);
    const evaluation = tampered.records.filter(r => r.type === 'evaluation' && r.payload.actionId === 'pay-run-1').at(-1);
    evaluation.payload.findings = [];
    writeFileSync(exportFile, JSON.stringify(tampered));
    const fileArgs = ['--export', exportFile, '--key', key, '--langfuse', langfuse.url, '--phoenix', phoenix.url, '--send'];
    const marker = langfuse.requests.length;
    const result = await run(fileArgs, env(h));
    assert.equal(result.code, 1); assert.equal(result.output.export.verdict, 'tampered');
    assert.deepEqual(result.output.export.reasons, ['ledger_altered']);
    const pushed = langfuse.requests.slice(marker).filter(r => r.method === 'POST').flatMap(r => JSON.parse(r.raw).batch.map(e => e.body));
    assert.ok(pushed.length > 0 && pushed.every(s => (s.name === NAMES.witness ? s.value === 'none' : s.value === 'tampered')),
      JSON.stringify(pushed.map(s => [s.name, s.value])));
    assert.ok(!pushed.some(s => s.name === NAMES.findings), 'no findings count from a tampered export');
    assert.ok(langfuse.requests.slice(marker).some(r => r.method === 'DELETE'), 'stale findings scores are removed');
    assert.ok(![...langfuse.scores.values()].some(s => s.name === NAMES.findings && s.metadata.evidscope.actionId === 'pay-run-1'));
    assert.equal([...langfuse.scores.values()].find(s => s.name === NAMES.verified && s.metadata.evidscope.actionId === 'pay-run-1').value, 'tampered');
    const phx = [...phoenix.annotations.values()].filter(a => a.metadata.evidscope.actionId === 'pay-run-1');
    assert.ok(phx.every(a => a.result.label !== 'verified' && a.result.score !== 1));
    assert.equal(phx.find(a => a.name === NAMES.findings).result.label, 'unavailable');
    // Another key: the signature cannot be attributed, so `unverified`, not `tampered`.
    const other = join(dir, 'other.pem');
    writeFileSync(other, generateKeyPairSync('ed25519').publicKey.export({type: 'spki', format: 'pem'}));
    writeFileSync(exportFile, JSON.stringify(latest));
    const foreign = await run(['--export', exportFile, '--key', other, '--langfuse', langfuse.url], env(h));
    assert.equal(foreign.code, 1); assert.equal(foreign.output.export.verdict, 'unverified');
    assert.deepEqual(foreign.output.export.reasons, ['checkpoint_signature_invalid']);
    assert.ok(foreign.output.langfuse.events.every(e => e.body.value !== 'verified'));
    // The export's own checkpoint pinned out of band: verified, and the witness level says how rollback was excluded.
    const current = join(dir, 'current-checkpoint.json');
    writeFileSync(current, JSON.stringify(latest.checkpoint));
    const pinnedRun = await run(['--export', exportFile, '--key', key, '--checkpoint', current, '--langfuse', langfuse.url], env(h));
    assert.deepEqual([pinnedRun.code, pinnedRun.output.export.verdict, pinnedRun.output.export.witness], [0, 'verified', 'pinned_checkpoint']);
    assert.ok(pinnedRun.output.langfuse.events.some(e => e.body.name === NAMES.witness && e.body.value === 'pinned_checkpoint'));
    // A pinned checkpoint the export does not match: possible rollback.
    const pinned = join(dir, 'checkpoint.json');
    writeFileSync(pinned, JSON.stringify(exported.checkpoint));
    const rolled = await run(['--export', exportFile, '--key', key, '--checkpoint', pinned], env(h));
    assert.deepEqual([rolled.code, rolled.output.export.verdict, rolled.output.export.reasons], [1, 'tampered', ['rollback_detected']]);
    // Restore the verified state for the following subtests.
    assert.equal((await run([...base, '--send'], env(h))).code, 0);
  });

  await t.test('credentials come from the environment and are never printed', async () => {
    const script = join(process.cwd(), 'scripts/push-verdicts.mjs');
    const child = await exec(process.execPath, [script, ...base, '--send'], {env: {...process.env, ...env(h)}});
    const sentBasic = langfuse.requests.at(-1).headers.authorization;
    for (const secret of [...Object.values(SECRETS), h.principal('auditor').token, sentBasic.slice(6)])
      assert.ok(!child.stdout.includes(secret) && !child.stderr.includes(secret), 'secret printed');
    // A failing push names the URL and status only.
    const failing = await exec(process.execPath, [script, ...base.slice(0, -4), '--langfuse', langfuse.url, '--send'],
      {env: {...process.env, ...env(h), LANGFUSE_SECRET_KEY: 'sk-lf-CANARY-wrong-0123456789'}}).catch(error => error);
    assert.equal(failing.code, 1);
    assert.ok(!`${failing.stdout}${failing.stderr}`.includes('CANARY-wrong'));
    // Missing keys stop before anything is read or sent.
    const count = langfuse.requests.length;
    const missing = await exec(process.execPath, [script, ...base, '--send'], {env: {...process.env, EVIDSCOPE_TOKEN: 'x'}}).catch(error => error);
    assert.equal(missing.code, 2); assert.match(missing.stderr, /LANGFUSE_PUBLIC_KEY/); assert.equal(langfuse.requests.length, count);
    assert.equal(redact(`a ${SECRETS.PHOENIX_API_KEY} b`, SECRETS), 'a [REDACTED] b');
  });

  await t.test('HTTPS only, no redirects, bounded retries', async () => {
    for (const bad of ['http://langfuse.example.com/', 'ftp://x/', 'https://user:pw@langfuse.example.com/', 'https://x/?q=1', 'not a url'])
      assert.throws(() => serviceBase(bad, '--langfuse'), UsageError, bad);
    assert.equal(serviceBase('https://phoenix.example/s/team', '--phoenix').href, 'https://phoenix.example/s/team/');
    await assert.rejects(run([...base.slice(0, 6), '--langfuse', 'http://langfuse.example.com/', '--send'], env(h)), UsageError);
    await assert.rejects(run(['--evidscope', `${h.audit.url}/api/`, '--key', key], env(h)), UsageError);
    // A redirect is refused, never followed: the second server sees nothing and no credential travels.
    const target = await mockLangfuse(), hops = [];
    const redirector = createServer((req, res) => {
      hops.push(req.url); res.statusCode = 307; res.setHeader('location', `${target.url}api/public/ingestion`); res.end();
    });
    const redirectUrl = await listen(redirector);
    t.after(() => Promise.all([target.close(), new Promise(r => redirector.close(r))]));
    const redirected = await run([...base.slice(0, 6), '--langfuse', redirectUrl, '--send'], env(h));
    assert.equal(redirected.code, 1); assert.match(redirected.output.langfuse.error, /redirect/);
    assert.equal(target.requests.length, 0); assert.equal(hops.length, 1);
    // 503 is retried a bounded number of times; 4xx is not retried.
    let calls = 0;
    const flaky = createServer((req, res) => { calls++; res.statusCode = req.url === '/bad' ? 400 : 503; res.setHeader('retry-after', '0'); res.end('{}'); });
    const flakyUrl = await listen(flaky); t.after(() => new Promise(r => flaky.close(r)));
    assert.equal((await request(new URL('x', flakyUrl), {method: 'POST', body: '{}'})).status, 503); assert.equal(calls, 3);
    calls = 0; assert.equal((await request(new URL('/bad', flakyUrl), {method: 'POST', body: '{}'})).status, 400); assert.equal(calls, 1);
    // Oversized responses are cut off.
    const big = createServer((req, res) => res.end('x'.repeat(2 * 1024 * 1024))), bigUrl = await listen(big); t.after(() => new Promise(r => big.close(r)));
    await assert.rejects(request(new URL('x', bigUrl)), /exceeds/);
  });

  await t.test('Phoenix: unknown traces and spans are counted, not failed; mapping helpers are pure', async () => {
    const partial = await mockPhoenix({spans: [SPAN_CHAT]}); t.after(() => partial.close());
    const result = await run([...base.slice(0, 6), '--phoenix', partial.url, '--send'], env(h));
    assert.equal(result.code, 0, JSON.stringify(result.output.phoenix)); assert.equal(result.output.phoenix.notFound, 1);
    assert.ok([...partial.annotations.values()].some(a => a.span_id === SPAN_CHAT));
    const assessment = assessExport(readFileSync(exportFile), {publicKey: readFileSync(key, 'utf8')});
    const verdicts = actionVerdicts(assessment);
    assert.ok(verdicts.every(v => v.link === null && v.verdict === 'verified'));
    const a = langfuseScores(verdicts), b = langfuseScores(actionVerdicts(assessExport(readFileSync(exportFile), {publicKey: readFileSync(key, 'utf8')})));
    assert.deepEqual(a, b, 'same export, same events and ids');
    assert.deepEqual(phoenixAnnotations(verdicts), phoenixAnnotations(verdicts));
    assert.ok(!verdicts.some(v => v.spans.some(s => s.spanId === UNKNOWN_SPAN)));
    assert.deepEqual(actionVerdicts(assessExport(Buffer.from('not json'), {publicKey: readFileSync(key, 'utf8')})), []);
    // A forged export: only negative verdicts, and only identifier-shaped action ids and tenants leave.
    const event = (actionId, n) => ({seq: n, type: 'event', recordedAt: new Date().toISOString(), payload: {actionId, traceId: TRACE, id: `x${n}`}});
    const forged = {checkpoint: {format: 'evidscope-checkpoint-v1', tenant: 'CANARY tenant <b>', count: 2, head: 'f'.repeat(64), signature: 'AAAA'},
      records: [event('CANARY action with spaces', 1), event('ok-action', 2)]};
    const forgedAssessment = assessExport(Buffer.from(JSON.stringify(forged)), {publicKey: readFileSync(key, 'utf8')});
    const negative = actionVerdicts(forgedAssessment, {linkBase: 'https://a.example/'});
    assert.deepEqual(negative.map(v => [v.actionId, v.tenant, v.verdict, v.reasons[0], v.analysis]),
      [['ok-action', null, 'unverified', 'checkpoint_signature_invalid', 'unknown']]);
  });
});
