// Kill switch end to end (docs/kill-switch.md): a one-person stop order with the suspension in its commit and a four-eyes lift,
// pull distribution of the OPA bundle and the DSSE deny-list through the ingress gateway (ETag/304, tenant isolation, refused
// credentials), OPA status intake with allowlisting, propagation in the registry API, the two new findings from analysis,
// export with offline verification and replay, and exports written before stop orders.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createPrivateKey, randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {digest, makeCheckpoint, verifyBundle} from '../src/crypto.mjs';
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V2, EVALUATION_ENGINE_V4} from '../src/model.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';
import {ed25519Verifier, openEnvelope} from '../src/dsse.mjs';
import {DENY_LIST_PAYLOAD_TYPE} from '../src/enforcement-bundle.mjs';

const secret = () => randomBytes(32).toString('base64url');
const gateway = {id: 'alpha-gateway', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const betaGateway = {id: 'beta-gateway', tenant: 'beta', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const second = {id: 'alpha-reviewer-2', tenant: 'alpha', role: 'reviewer', token: secret()};
const CANARY = 'CANARY-7f3a9c';
let h, revisionAtStop, stopId, toolStopId;
test.before(async () => {
  h = await harness({beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));
    config.principals.push(gateway, betaGateway, second);writeFileSync(file, JSON.stringify(config));
  }});
  h.config.principals.push(gateway, betaGateway, second);
});
test.after(async () => { await h?.close(); });

const call = (path, body, role = 'reviewer') => h.api(path, {body, role});
const asSecond = (path, body) => h.api(path, {body, role: 'reviewer', headers: {authorization: `Bearer ${second.token}`}});
const send = async (kind, event) => {
  const r = await submit(h.ingress.url, h.principal(kind), {occurredAt: new Date().toISOString(), traceId: 'ks-trace', ...event});
  assert.equal(r.status, 202, JSON.stringify(r.body));
};
const pull = (path, token, headers = {}, base = h.ingress.url) =>
  fetch(base + path, {headers: {...(token ? {authorization: `Bearer ${token}`} : {}), ...headers}});
const status = (report, token = gateway.token, path = '/api/enforcement/opa/status') => fetch(h.ingress.url + path,
  {method: 'POST', headers: {'content-type': 'application/json', authorization: `Bearer ${token}`}, body: JSON.stringify(report)});
async function analyzeAll() {for (let i = 0; i < 30; i++) {const r = (await h.analyze()).body;if (!r.backlog && !r.processed) return;}}
const latest = async actionId => (await call(`/api/actions/${encodeURIComponent(actionId)}`, undefined, 'auditor')).body.evaluations[0];
const codes = async actionId => (await latest(actionId)).findings.map(f => f.code);
function untar(gz) {
  const tar = gunzipSync(gz), files = new Map();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);if (header.every(b => b === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, ''), size = parseInt(header.subarray(124, 136).toString('utf8'), 8);
    files.set(name, tar.subarray(offset + 512, offset + 512 + size));offset += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}
const bundleData = async response => JSON.parse(untar(Buffer.from(await response.arrayBuffer())).get('/data.json')).evidscope;
const BUNDLE = '/api/enforcement/opa/bundles/evidscope';

test('an agent in production with a propagation window and a default enforcement point in the signed registry policy', async () => {
  const created = await call('/api/registry', {id: 'mail-agent', owner: 'ops', purpose: 'replies', sources: ['alpha-agent'], actors: ['mail-agent'],
    tools: [{name: 'lookup', enforcement: 'required'}]});
  assert.equal(created.status, 200, JSON.stringify(created.body));
  await call('/api/registry/mail-agent/transitions', {to: 'testing', reason: 'pilot'});
  const approved = await call('/api/registry/mail-agent/transitions', {to: 'approved', reason: 'pilot passed'});
  await asSecond(`/api/registry/transitions/${approved.body.transition.id}/approve`, {reason: 'ok'});
  const live = await call('/api/registry/mail-agent/transitions', {to: 'production', reason: 'go live'});
  assert.equal((await asSecond(`/api/registry/transitions/${live.body.transition.id}/approve`, {reason: 'ok'})).body.entry.state, 'production');
  assert.equal((await call('/api/registry/policy', {stopPropagation: {windowSeconds: 5}}, 'reviewer')).status, 403, 'policy is admin-only');
  assert.equal((await call('/api/registry/policy', {stopPropagation: {enforcementPoints: ['alpha-agent']}}, 'admin')).status, 400, 'not an enforcement point');
  const policy = await call('/api/registry/policy', {stopPropagation: {windowSeconds: 10, enforcementPoints: ['alpha-gateway']}}, 'admin');
  assert.deepEqual([policy.status, policy.body.stopPropagation], [200, {windowSeconds: 10, enforcementPoints: ['alpha-gateway']}]);
  assert.equal(policy.body.enforcement, 'off', 'other policy fields are kept');
});

test('enforcement points pull their own tenant through the ingress gateway; other credentials are refused', async () => {
  const first = await pull(BUNDLE, gateway.token);
  assert.equal(first.status, 200);assert.equal(first.headers.get('content-type'), 'application/gzip');
  const etag = first.headers.get('etag'), data = await bundleData(first);
  assert.match(etag, /^"\d+-[a-f0-9]{16}"$/);
  const mail = data.agents['mail-agent'];
  assert.deepEqual([data.tenant, mail.state, mail.stopped, data.actors['mail-agent']], ['alpha', 'production', false, 'mail-agent']);
  assert.equal(`"${data.revision}"`, etag, 'the ETag is the revision named in the manifest and the data');
  const again = await pull(BUNDLE, gateway.token, {'if-none-match': etag});
  assert.equal(again.status, 304);assert.equal(again.headers.get('etag'), etag);assert.equal((await again.arrayBuffer()).byteLength, 0);
  assert.equal((await pull(BUNDLE, gateway.token, {'if-none-match': '"1-0000000000000000"'})).status, 200, 'a stale ETag gets the bundle');
  assert.equal((await pull(BUNDLE, gateway.token, {}, h.vault.url)).status, 200, 'the vault serves the same route');
  assert.equal((await pull(BUNDLE, null)).status, 401);
  assert.equal((await pull(BUNDLE, 'not-a-token-' + secret())).status, 401);
  assert.equal((await pull(BUNDLE, h.principal('agent').token)).status, 403, 'another source kind');
  assert.equal((await pull(BUNDLE, h.principal('reviewer').token)).status, 403, 'a person');
  assert.equal((await pull(BUNDLE, gateway.token, {}, h.audit.url)).status, 403, 'not served through the audit gateway');
  assert.equal((await pull('/api/enforcement/opa/bundles/../x', gateway.token)).status, 404);
  const beta = await pull(BUNDLE, betaGateway.token), betaBytes = Buffer.from(await beta.clone().arrayBuffer());
  const betaData = await bundleData(beta);
  assert.deepEqual([betaData.tenant, betaData.agents, betaData.revision], ['beta', {}, '0-0000000000000000']);
  assert.ok(!gunzipSync(betaBytes).toString('latin1').includes('mail-agent'), 'no other tenant data');
  const deny = await pull('/api/enforcement/deny-list', gateway.token);
  assert.equal(deny.status, 200);assert.equal(deny.headers.get('etag'), etag);
  const list = JSON.parse(openEnvelope(await deny.json(), [ed25519Verifier(readFileSync(join(h.dir, 'trust-anchor.pem'), 'utf8'))],
    {payloadTypes: [DENY_LIST_PAYLOAD_TYPE]}).body);
  assert.deepEqual([list.tenant, list.revision, list.entries], ['alpha', data.revision, []]);
  assert.equal((await pull('/api/enforcement/deny-list', gateway.token, {'if-none-match': etag})).status, 304);
});

test('one reviewer stops the agent: the order and the suspension are one commit, and the bundle and deny-list change', async () => {
  const before = (await pull(BUNDLE, gateway.token)).headers.get('etag');
  assert.equal((await call('/api/registry/mail-agent/stop', {reason: 'x'}, 'auditor')).status, 403, 'auditors cannot stop');
  assert.equal((await call('/api/registry/mail-agent/stop', {reason: ' '})).status, 400, 'a reason is required');
  assert.equal((await call('/api/registry/mail-agent/stop', {reason: 'x', enforcementPoints: ['alpha-tool']})).status, 400);
  assert.equal((await call('/api/registry/mail-agent/stop', {reason: 'x', scope: 'tools'})).status, 400, 'tool stops name tools');
  const stop = await call('/api/registry/mail-agent/stop', {reason: 'prompt injection incident', evidence: [{type: 'external', ref: 'INC-7'}]});
  assert.equal(stop.status, 200, JSON.stringify(stop.body));
  stopId = stop.body.order.id;
  assert.deepEqual([stop.body.order.status, stop.body.order.issuedBy, stop.body.order.scope, stop.body.transition.status, stop.body.transition.stopOrderId,
    stop.body.entry.state], ['active', 'alpha-reviewer', 'agent', 'applied', stopId, 'suspended']);
  assert.deepEqual(stop.body.order.enforcementPoints, [{id: 'alpha-gateway', basis: ['policy']}]);
  assert.deepEqual(stop.body.order.propagation.windowSeconds, 10);
  const pulled = await pull(BUNDLE, gateway.token, {'if-none-match': before});
  assert.equal(pulled.status, 200);
  const data = await bundleData(pulled);revisionAtStop = data.revision;
  assert.deepEqual([data.agents['mail-agent'].state, data.agents['mail-agent'].stopped, data.agents['mail-agent'].stop_orders], ['suspended', true, [stopId]]);
  assert.deepEqual(Object.keys(data.stop_orders), [stopId]);
  assert.ok(!JSON.stringify(data).includes('prompt injection'), 'reasons and evidence are not distributed');
  const list = JSON.parse(Buffer.from((await (await pull('/api/enforcement/deny-list', gateway.token)).json()).payload, 'base64'));
  assert.deepEqual(list.entries.map(e => [e.agent, e.deny, e.stop_orders]), [['mail-agent', 'all', [stopId]]]);
  const resumeTooEarly = await call(`/api/registry/stops/${stopId}/lift`, {reason: 'fixed'});
  assert.equal(resumeTooEarly.status, 409, 'a suspended agent is lifted by the resume approval');
});

test('OPA status reports become allowlisted activation records; unknown and foreign revisions are ignored', async () => {
  const activatedAt = new Date().toISOString();
  const report = revision => ({labels: {id: 'opa-sidecar-1', version: '1.4.2', app: CANARY, secret: CANARY},
    bundles: {evidscope: {name: 'evidscope', active_revision: revision, last_successful_activation: activatedAt,
      last_request: new Date().toISOString(), message: CANARY, code: CANARY, errors: [CANARY], metrics: {[CANARY]: 1},
      http_code: 200, size: 1, type: 'snapshot'},
    authz: {name: CANARY, active_revision: CANARY, last_successful_activation: new Date().toISOString()}},
    plugins: {bundle: {state: 'OK', message: CANARY}}, decision_logs: {code: CANARY}, metrics: {prometheus: {[CANARY]: 1}}, discovery: {name: CANARY}});
  const accepted = await status(report(revisionAtStop));
  assert.equal(accepted.status, 200, await accepted.clone().text());
  assert.deepEqual(await accepted.json(),
    {accepted: 1, duplicates: 0, ignored: {foreign_bundle: 1}, instance: 'opa-sidecar-1', durability: 'sqlite_full_commit'});
  assert.deepEqual(await (await status(report(revisionAtStop), gateway.token, '/api/enforcement/opa/status/partition-a')).json(),
    {accepted: 0, duplicates: 1, ignored: {foreign_bundle: 1}, instance: 'opa-sidecar-1', durability: 'sqlite_full_commit'},
    'a repeated report is a duplicate');
  assert.deepEqual((await (await status(report('99999-0123456789abcdef'))).json()).ignored, {unknown_revision: 1, foreign_bundle: 1});
  assert.deepEqual((await (await status(report(revisionAtStop), betaGateway.token)).json()).ignored, {unknown_revision: 1, foreign_bundle: 1},
    'another tenant cannot report this tenant\'s revision');
  assert.equal((await status({bundles: {}})).status, 400, 'labels.id is required');
  assert.equal((await status(report(revisionAtStop), h.principal('agent').token)).status, 403);
  assert.equal((await status({labels: {id: 'opa-2'}, padding: 'x'.repeat(70 * 1024)})).status, 413);
  const stops = (await call('/api/registry/stops', undefined, 'auditor')).body.items;
  const view = stops.find(s => s.orderId === stopId), point = view.points.find(p => p.id === 'alpha-gateway');
  assert.deepEqual([view.propagation, point.covering, point.status, point.instances, point.firstActivation.revision],
    ['activated_in_window', true, 'activated_in_window', ['opa-sidecar-1'], revisionAtStop]);
  assert.ok(point.firstActivation.latencyMs >= 0 && point.firstActivation.latencyMs < 10000);
  const detail = (await call('/api/registry/mail-agent', undefined, 'auditor')).body;
  assert.equal(detail.stopOrders[0].orderId, stopId);
  assert.equal((await call('/api/registry', undefined, 'auditor')).body.items[0].activeStopOrders, 1);
  const events = (await call('/api/events?limit=200', undefined, 'auditor')).body;
  assert.ok(!JSON.stringify(events).includes(CANARY), 'no canary value reaches stored events');
});

test('analysis: execution after the activation does not hold the stop; activity past the window without activation is missing', async () => {
  await send('tool', {id: 'ks-exec', actionId: 'ks-exec', kind: 'execution', status: 'success', actor: 'mail-agent', tool: 'lookup'});
  // A second agent with a tool stop no enforcement point has activated; its activity past the 10 s window is reported.
  assert.equal((await call('/api/registry', {id: 'report-agent', owner: 'bi', purpose: 'reports', sources: ['alpha-otlp'], actors: ['report-agent'],
    tools: ['export']})).status, 200);
  const toolStop = await call('/api/registry/report-agent/stop', {scope: 'tools', tools: ['export'], reason: 'exfiltration suspected'});
  assert.equal(toolStop.status, 200, JSON.stringify(toolStop.body));toolStopId = toolStop.body.order.id;
  assert.equal(toolStop.body.transition, undefined, 'a tool stop changes no lifecycle state');
  const future = new Date(Date.parse(toolStop.body.order.issuedAt) + 60000).toISOString();
  await send('tool', {id: 'ks-report-late', actionId: 'ks-report-late', kind: 'execution', status: 'success', actor: 'report-agent', tool: 'export',
    occurredAt: future});
  await send('tool', {id: 'ks-report-now', actionId: 'ks-report-now', kind: 'execution', status: 'success', actor: 'report-agent', tool: 'export'});
  await send('tool', {id: 'ks-report-other', actionId: 'ks-report-other', kind: 'execution', status: 'success', actor: 'report-agent', tool: 'read',
    occurredAt: future});
  await analyzeAll();
  const exec = await codes('ks-exec');
  assert.ok(exec.includes('STOP_ORDER_NOT_HELD') && exec.includes('AGENT_SUSPENDED_ACTIVITY'), exec.join(','));
  assert.ok(!exec.includes('STOP_PROPAGATION_MISSING'), 'activated within the window');
  assert.equal((await latest('ks-exec')).replay.engine, EVALUATION_ENGINE_V4);
  assert.ok((await codes('ks-report-late')).includes('STOP_PROPAGATION_MISSING'));
  assert.ok(!(await codes('ks-report-now')).some(c => c.startsWith('STOP_')), 'inside the window');
  assert.ok(!(await codes('ks-report-other')).some(c => c.startsWith('STOP_')), 'a tool the order does not name');
});

test('lifting keeps four eyes: an independent lift approval, and the resume approval for a suspended agent; no promotion while stopped', async () => {
  assert.equal((await call(`/api/registry/stops/${toolStopId}/lift/approve`, {reason: 'x'})).status, 409, 'nothing requested');
  assert.equal((await call(`/api/registry/stops/${toolStopId}/lift`, {reason: 'contained'})).body.order.change, 'lift_requested');
  assert.equal((await call(`/api/registry/stops/${toolStopId}/lift`, {reason: 'again'})).status, 409);
  assert.equal((await call(`/api/registry/stops/${toolStopId}/lift/approve`, {reason: 'self'})).status, 403, 'the requester cannot approve');
  const lifted = await asSecond(`/api/registry/stops/${toolStopId}/lift/approve`, {reason: 'reviewed'});
  assert.deepEqual([lifted.body.order.status, lifted.body.order.lift.via, lifted.body.order.lift.approvedBy], ['lifted', 'approval', 'alpha-reviewer-2']);
  assert.equal((await call(`/api/registry/stops/${toolStopId}/lift`, {reason: 'x'})).status, 409, 'ended orders are final');
  // A whole-agent stop on a draft blocks promotion until lifted, and supersedes nothing it does not cover.
  const draftStop = await call('/api/registry/report-agent/stop', {reason: 'hold'});
  assert.equal(draftStop.body.transition, undefined);
  await call('/api/registry/report-agent/transitions', {to: 'testing', reason: 'tests may run while stopped'});
  assert.equal((await call('/api/registry/report-agent/transitions', {to: 'approved', reason: 'x'})).status, 409, 'no promotion while stopped');
  const narrower = await call('/api/registry/report-agent/stop', {scope: 'tools', tools: ['export'], reason: 'narrow'});
  const wider = await call('/api/registry/report-agent/stop', {reason: 'whole again'});
  assert.deepEqual(wider.body.superseded.sort(), [draftStop.body.order.id, narrower.body.order.id].sort(), 'a covering order supersedes');
  await call(`/api/registry/stops/${wider.body.order.id}/lift`, {reason: 'done'});
  await asSecond(`/api/registry/stops/${wider.body.order.id}/lift/approve`, {reason: 'done'});
  assert.equal((await call('/api/registry/report-agent/transitions', {to: 'approved', reason: 'x'})).body.transition.status, 'pending');
  // The suspended agent: the resume request needs another reviewer, and its approval lifts the whole-agent order.
  const resume = await call('/api/registry/mail-agent/transitions', {to: 'production', reason: 'fixed'}, 'admin');
  assert.equal((await call(`/api/registry/transitions/${resume.body.transition.id}/approve`, {reason: 'self'}, 'admin')).status, 403);
  const resumed = await asSecond(`/api/registry/transitions/${resume.body.transition.id}/approve`, {reason: 'fix verified'});
  assert.deepEqual([resumed.body.entry.state, resumed.body.liftedStopOrders], ['production', [stopId]]);
  const order = (await call(`/api/registry/stops/${stopId}`, undefined, 'auditor')).body;
  assert.deepEqual([order.order.status, order.order.lift.via, order.order.lift.transitionId, order.history.valid], ['lifted', 'transition',
    resume.body.transition.id, true]);
  assert.deepEqual(order.versions.map(v => v.change), ['issued', 'lifted']);
  const data = await bundleData(await pull(BUNDLE, gateway.token));
  assert.deepEqual([data.agents['mail-agent'].state, data.agents['mail-agent'].stopped, Object.keys(data.stop_orders)], ['production', false, []]);
});

const run = (script, args) => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL(`../scripts/${script}`, import.meta.url)), ...args], {encoding: 'utf8'});
  return {status: r.status, out: r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};
function resign(bundle, privateKey) {
  let previous = '0'.repeat(64);
  for (const row of bundle.records) {row.previous = previous;const {hash, ...record} = row;row.hash = digest(record);previous = row.hash;}
  bundle.checkpoint = makeCheckpoint(bundle.checkpoint.tenant, bundle.records.length, previous, privateKey);
  return bundle;
}

test('exports carry stop orders and activations; offline verification, propagation and replay pass and catch a forged lift', async t => {
  await analyzeAll();
  const bundle = (await call('/api/export', undefined, 'auditor')).body, key = join(h.dir, 'trust-anchor.pem');
  assert.ok(bundle.records.some(r => r.type === 'agent_stop_order'));
  assert.ok(!JSON.stringify(bundle).includes(CANARY), 'no canary value in the export');
  assert.equal(verifyBundle(bundle, readFileSync(key, 'utf8')).valid, true);
  const replay = replayEvaluations(bundle);
  assert.equal(replay.valid, true, JSON.stringify(replay.evaluations.filter(e => e.status === 'mismatch')));
  assert.ok(replay.evaluations.some(e => e.engine === EVALUATION_ENGINE_V4 && e.status === 'replayed'));
  const v2Only = replayEvaluations(bundle, {engines: [EVALUATION_ENGINE, EVALUATION_ENGINE_V2]});
  assert.equal(v2Only.valid, true, 'a verifier without v4 reports engine_unavailable, never a mismatch');
  assert.ok(v2Only.summary.notReplayableReasons.engine_unavailable > 0);
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-kill-switch-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json');writeFileSync(file, JSON.stringify(bundle));
  for (const [script, extra] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...extra, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);assert.equal(r.out.stopOrders.valid, true, JSON.stringify(r.out.stopOrders.problems));
    assert.equal(r.out.registry.valid, true);assert.equal(r.out.replay.valid, true);
    const first = r.out.stopOrders.propagation.find(p => p.orderId === stopId);
    assert.deepEqual([first.propagation, first.status, first.points[0].firstActivation.instance], ['activated_in_window', 'lifted', 'opa-sidecar-1']);
  }
  const forged = structuredClone(bundle), lift = forged.records.find(r => r.type === 'agent_stop_order' && r.payload.lift?.via === 'approval');
  lift.payload.lift.approvedBy = lift.payload.lift.requestedBy;lift.principal = lift.payload.lift.requestedBy;
  resign(forged, createPrivateKey(readFileSync(join(h.dir, 'signing-private.pem'))));writeFileSync(file, JSON.stringify(forged));
  const r = run('evidscope-verify.mjs', ['bundle', file, key]);
  assert.equal(r.status, 1);assert.equal(r.out.valid, true, 'chain and checkpoint alone accept it');
  assert.ok(r.out.stopOrders.problems.some(p => /four-eyes/.test(p.message)));
});

test('an export written with the registry before stop orders (ef18d23) verifies and replays exactly as before', t => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/registry-export-ef18d23.json', import.meta.url), 'utf8'));
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-registry-fixture-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(dir, 'key.pem');
  writeFileSync(file, JSON.stringify(fixture.exportBundle));writeFileSync(key, fixture.publicKeyPem);
  for (const [script, extra] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...extra, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);assert.equal(r.out.stopOrders, undefined, 'no stop-order section without stop orders');
    assert.equal(r.out.registry.valid, true);assert.equal(r.out.replay.valid, true);assert.equal(r.out.replay.summary.replayed, 4);
    assert.deepEqual(r.out.replay.evaluations.map(e => [e.engine, e.status]), [[EVALUATION_ENGINE, 'replayed'], [EVALUATION_ENGINE_V2, 'replayed'],
      [EVALUATION_ENGINE_V2, 'replayed'], [EVALUATION_ENGINE_V2, 'replayed']]);
  }
  const codes = fixture.exportBundle.records.filter(r => r.type === 'evaluation').flatMap(r => r.payload.findings.map(f => f.code));
  assert.ok(codes.includes('EXECUTION_AFTER_DENY') && codes.includes('AGENT_SUSPENDED_ACTIVITY'), 'the fixture exercises engine v2 rules');
});
