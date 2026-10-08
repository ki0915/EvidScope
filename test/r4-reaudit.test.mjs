// Round-4 re-audit regression tests (docs/kill-switch.md, docs/approval-queue.md). Each R4-n test is the proof of concept of one
// finding and failed on 503c185: R4-1 prototype-named entries and actors dropped from the bundle and deny-list, R4-2 a stopped
// entry's names taken out of distribution by an edit or a re-issued order, R4-3 the risk-override author approving alone, R4-4
// approval histories the API never writes accepted offline. The E2E tests run engines v3 and v4 in one tenant.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';
import {harness} from './harness.mjs';
import {ed25519Verifier, openEnvelope} from '../src/dsse.mjs';
import {DENY_LIST_PAYLOAD_TYPE, denyList, enforcementState, goCanonical} from '../src/enforcement-bundle.mjs';
import {requestApproval} from '../src/approval-client.mjs';
import {approvalEligibility, approvalPolicyOf, approvalRequestId, targetDigest, verifyApprovalHistory} from '../src/approvals.mjs';
import {riskBasis} from '../src/agent-registry.mjs';
import {verifyBundle} from '../src/crypto.mjs';
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V2, EVALUATION_ENGINE_V3, EVALUATION_ENGINE_V4} from '../src/model.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';
import {buildApprovalsStopsExport} from './fixtures/make-approvals-stops-export-fixture.mjs';

const secret = () => randomBytes(32).toString('base64url');
const gateway = {id: 'alpha-gateway', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const protoAgent = {id: 'alpha-proto-agent', tenant: 'alpha', role: 'source', kind: 'agent', token: secret(), hmacSecret: secret()};
const second = {id: 'alpha-reviewer-2', tenant: 'alpha', role: 'reviewer', token: secret()};
const extra = [gateway, protoAgent, second];
let h;
test.before(async () => {
  h = await harness({beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));
    config.principals.push(...extra);writeFileSync(file, JSON.stringify(config));
  }});
  h.config.principals.push(...extra);
});
test.after(async () => { await h?.close(); });

const call = (path, body, role = 'reviewer') => h.api(path, {body, role});
const pull = path => fetch(h.ingress.url + path, {headers: {authorization: `Bearer ${gateway.token}`}});
function untar(gz) {
  const tar = gunzipSync(gz), files = new Map();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);if (header.every(b => b === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, ''), size = parseInt(header.subarray(124, 136).toString('utf8'), 8);
    files.set(name, tar.subarray(offset + 512, offset + 512 + size));offset += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}
const bundle = async () => JSON.parse(untar(Buffer.from(await (await pull('/api/enforcement/opa/bundles/evidscope')).arrayBuffer())).get('/data.json'))
  .evidscope;
const denied = async () => JSON.parse(openEnvelope(await (await pull('/api/enforcement/deny-list')).json(),
  [ed25519Verifier(readFileSync(join(h.dir, 'trust-anchor.pem'), 'utf8'))], {payloadTypes: [DENY_LIST_PAYLOAD_TYPE]}).body).entries;
const own = (object, key) => Object.hasOwn(object, key);

test('R4-1: an entry id or actor name that is an Object.prototype key stays in the bundle and the deny-list', async () => {
  // A reviewer may register any identifier, including __proto__; actors are free text.
  const created = await call('/api/registry', {id: '__proto__', owner: 'ops', purpose: 'x', sources: ['alpha-proto-agent'], actors: ['constructor']});
  assert.equal(created.status, 200, JSON.stringify(created.body));
  const stop = await call('/api/registry/__proto__/stop', {reason: 'incident'});
  assert.equal(stop.status, 200, JSON.stringify(stop.body));
  const data = await bundle();
  assert.ok(own(data.agents, '__proto__'), 'the stopped agent is in the bundle');
  assert.deepEqual([data.agents.__proto__.stopped, data.agents.__proto__.stop_orders], [true, [stop.body.order.id]]);
  assert.ok(own(data.actors, 'constructor') && data.actors.constructor === '__proto__', 'the actor maps to its entry');
  assert.equal(data.sources['alpha-proto-agent'], '__proto__');
  const entries = await denied();
  assert.deepEqual(entries.map(e => [e.agent, e.deny]), [['__proto__', 'all']], 'the stopped agent is on the deny-list');
  // Pure builder: every prototype key survives as data.
  const state = enforcementState({tenant: 't', revision: '1-aaaaaaaaaaaaaaaa', orders: [],
    entries: [{id: 'toString', state: 'suspended', sources: ['hasOwnProperty'], actors: ['valueOf', '__proto__'], tools: []}]});
  const parsed = JSON.parse(goCanonical(state));
  assert.deepEqual([parsed.agents.toString.state, parsed.sources.hasOwnProperty, parsed.actors.valueOf, own(parsed.actors, '__proto__')],
    ['suspended', 'toString', 'toString', true]);
  assert.deepEqual(denyList(state).entries.map(e => e.agent), ['toString']);
});

test('R4-2: editing a stopped entry does not take its sources and actors out of distribution', async () => {
  const created = await call('/api/registry', {id: 'mail-agent', owner: 'ops', purpose: 'replies', sources: ['alpha-agent'], actors: ['mail-agent']});
  assert.equal(created.status, 200, JSON.stringify(created.body));
  const stop = await call('/api/registry/mail-agent/stop', {reason: 'incident'});
  assert.equal(stop.status, 200, JSON.stringify(stop.body));
  // The same reviewer, alone, empties the names the order stopped (allowed outside approved/production) and re-registers them.
  const edited = await call('/api/registry/mail-agent', {sources: [], actors: []});
  assert.equal(edited.status, 200, JSON.stringify(edited.body));
  assert.equal((await call('/api/registry', {id: 'mail-agent-2', owner: 'ops', purpose: 'x', sources: ['alpha-agent'], actors: ['mail-agent']})).status, 200);
  const entry = (await denied()).find(e => e.agent === 'mail-agent');
  assert.deepEqual([entry.deny, entry.sources, entry.actors], ['all', ['alpha-agent'], ['mail-agent']], 'the deny-list keeps the stopped names');
  const data = await bundle();
  assert.deepEqual([data.sources['alpha-agent'], data.actors['mail-agent']], ['mail-agent', 'mail-agent'], 'an active order keeps its names');
  assert.deepEqual([data.agents['mail-agent'].sources, data.agents['mail-agent'].actors], [['alpha-agent'], ['mail-agent']]);
  // A new whole-agent order by the same reviewer supersedes the first one; it inherits the names the first order stopped.
  const again = await call('/api/registry/mail-agent/stop', {reason: 'reissued'});
  assert.deepEqual([again.status, again.body.superseded], [200, [stop.body.order.id]]);
  assert.deepEqual([again.body.order.target.sources, again.body.order.target.actors], [['alpha-agent'], ['mail-agent']]);
  assert.deepEqual([(await bundle()).sources['alpha-agent'], (await denied()).find(e => e.agent === 'mail-agent').sources], ['mail-agent', ['alpha-agent']]);
  // Lifting with four eyes releases the names to the entry that holds them now.
  const order = again.body.order.id;
  await call(`/api/registry/stops/${order}/lift`, {reason: 'fixed'});
  const lifted = await h.api(`/api/registry/stops/${order}/lift/approve`, {body: {reason: 'ok'}, headers: {authorization: `Bearer ${second.token}`}});
  assert.equal(lifted.status, 200, JSON.stringify(lifted.body));
  const after = await bundle();
  assert.deepEqual([after.sources['alpha-agent'], after.agents['mail-agent'].sources], ['mail-agent-2', []]);
});

test('R4-3: a reviewer who lowered the risk tier cannot then approve the requests that tier governs alone', async () => {
  const asSecond = (path, body) => h.api(path, {body, headers: {authorization: `Bearer ${second.token}`}});
  const created = await call('/api/registry', {id: 'pay-agent', owner: 'payments', purpose: 'refunds', actors: ['pay-agent'], tools: ['payment_transfer']});
  assert.equal(created.body.risk.computed, 'high');
  // One reviewer who neither registered nor edited the agent lowers its tier: high needs two approvers, low needs one.
  const override = await asSecond('/api/registry/pay-agent/risk', {tier: 'low', reason: 'sandbox account'});
  assert.equal(override.status, 200, JSON.stringify(override.body));
  const opened = await requestApproval(h.ingress.url, gateway, {decisionId: 'r4-3', actionId: 'r4-3', enforcementPointId: 'gw-1',
    target: {actor: 'pay-agent', tool: 'payment_transfer', resource: 'acct-991'}, binding_message: 'refund 1,200,000 to 991'});
  assert.equal(opened.status, 200, JSON.stringify(opened.body));assert.deepEqual(opened.body.eligibility, {tier: 'low', approvers: 1});
  const id = opened.body.auth_req_id, detail = (await call(`/api/approvals/${id}`, undefined, 'auditor')).body.request;
  assert.equal(detail.eligibility.basis.overrideBy, 'alpha-reviewer-2', 'the override author is frozen into the request');
  const alone = await asSecond(`/api/approvals/${id}/approve`, {reason: 'ok', version: 1});
  assert.equal(alone.status, 403, 'the override author would otherwise approve alone: ' + JSON.stringify(alone.body));
  assert.equal((await asSecond(`/api/approvals/${id}`)).body.request.mayAnswer.allowed, false);
  const independent = await call(`/api/approvals/${id}/approve`, {reason: 'checked', version: 1}, 'admin');
  assert.deepEqual([independent.status, independent.body.status], [200, 'approved']);
});

test('R4-5: names with lone surrogates do not produce duplicate keys in the bundle data OPA hashes', () => {
  // Registry text may hold lone surrogates; Go (and so OPA) reads each as U+FFFD, so two such names are one key there.
  const state = enforcementState({tenant: 't', revision: '1-aaaaaaaaaaaaaaaa', orders: [], entries: [{id: 'e', state: 'production',
    sources: ['s\uD800', 's\uDC00'], actors: ['a\uD800', 'a\uDC00'], tools: [{name: 't\uD800'}, {name: 't\uDC00', enforcement: 'required'}]}]});
  const text = goCanonical(state);
  assert.equal(goCanonical(JSON.parse(text)), text, 'data.json is the canonical form of the value it parses to');
  const parsed = JSON.parse(text);
  assert.deepEqual([parsed.actors['a\uFFFD'], parsed.agents.e.tools['t\uFFFD'].enforcement], ['e', 'required'], 'a merged tool keeps required');
});

// A signed-history shape as the vault API writes it (rows without signatures: verifyApprovalHistory is the part under test).
const T0 = Date.parse('2026-10-07T10:00:00.000Z'), iso = ms => new Date(T0 + ms).toISOString();
function history({override, answeredBy = 'alpha-reviewer-3', change = v1 => v1, between = [], answerAt = 1000} = {}) {
  const entry = {id: 'pay-agent', version: 1, state: 'draft', change: 'created', actors: ['pay-agent'], sources: [], tools: [{name: 'payment_transfer',
    enforcement: 'not_required'}], dataCategories: [], destinations: [], registeredBy: 'alpha-reviewer', editedBy: 'alpha-reviewer', owner: 'ops'};
  if (override) entry.risk = {override: {tier: 'low', by: override, reason: 'x', at: iso(0), basisHash: riskBasis(entry)}};
  const target = {actor: 'pay-agent', tool: 'payment_transfer'};
  const v1 = change({id: approvalRequestId('alpha', 'alpha-gateway', 'd-1'), version: 1, change: 'requested', status: 'pending', requestedBy: 'alpha-gateway',
    enforcementPointId: 'gw-1', decisionId: 'd-1', actionId: 'a-1', target, targetDigest: targetDigest(target), bindingMessage: 'x', requestedAt: iso(0),
    expiresAt: iso(300000), intervalSeconds: 5, executionWindowSeconds: 300, eligibility: approvalEligibility(entry, approvalPolicyOf(null)), approvals: [],
    refusal: null, decidedAt: null, executionWindow: null});
  const by = {by: answeredBy, role: 'reviewer', at: iso(answerAt), reason: 'ok'}, done = v1.eligibility.approvers === 1;
  const v2 = {...v1, version: 2, change: done ? 'approved' : 'approval_added', status: done ? 'approved' : 'pending', approvals: [by],
    ...(done ? {decidedAt: by.at, executionWindow: {notBefore: by.at, notAfter: iso(answerAt + 300000)}} : {})};
  const row = (seq, type, principal, payload, at) => ({seq, tenant: 'alpha', type, principal, recordedAt: iso(at), payload});
  return [row(1, 'agent_registry', 'alpha-reviewer', entry, 0), row(2, 'approval_request', 'alpha-gateway', v1, 0),
    ...between.map((payload, i) => row(3 + i, 'agent_registry', payload.editedBy, payload, 500)), row(3 + between.length, 'approval_request', answeredBy, v2,
      answerAt)];
}
const problems = rows => verifyApprovalHistory(rows).problems.map(p => p.message);

test('R4-3 offline: the override author recorded in a request is excluded from answering it', () => {
  assert.deepEqual(problems(history({override: 'alpha-reviewer-2'})), [], 'an independent approver of a low-tier request');
  assert.deepEqual(history({override: 'alpha-reviewer-2'})[1].payload.eligibility.basis.overrideBy, 'alpha-reviewer-2');
  assert.ok(problems(history({override: 'alpha-reviewer-2', answeredBy: 'alpha-reviewer-2'})).some(m => /excluded/.test(m)));
  const renamed = history({override: 'alpha-reviewer-2', change: v1 => ({...v1, eligibility: {...v1.eligibility, basis: {...v1.eligibility.basis,
    overrideBy: 'someone-else'}}})});
  assert.ok(problems(renamed).some(m => /who may answer/.test(m)), 'a recorded override author must match the ledger');
  // A request opened before round 4 has no overrideBy and keeps verifying.
  const legacy = history({override: 'alpha-reviewer-2', change: v1 => {const {overrideBy, ...basis} = v1.eligibility.basis;
    return {...v1, eligibility: {...v1.eligibility, basis}};}});
  assert.deepEqual(problems(legacy), []);
});

test('R4-4: the offline check refuses request histories the vault API never writes', () => {
  assert.deepEqual(problems(history()), [], 'the first of two approvals, as the API writes it');
  // The agent's editor at the time of the answer (an edit after the request opened): the API refuses this answer with 403.
  const edited = {...history()[0].payload, version: 2, change: 'updated', editedBy: 'alpha-reviewer-3'};
  assert.ok(problems(history({between: [edited]})).some(m => /registrant or editor/.test(m)));
  // An answer dated before the request was opened.
  assert.ok(problems(history({answerAt: -60000})).some(m => /answer time/.test(m)));
  // A lifetime the policy never gives (default 300 s, no requested_expiry) and a poll interval other than the policy's.
  assert.ok(problems(history({change: v1 => ({...v1, expiresAt: iso(600000)})})).some(m => /lifetime/.test(m)));
  assert.ok(problems(history({change: v1 => ({...v1, requestedExpiry: 120})})).some(m => /lifetime/.test(m)));
  assert.deepEqual(problems(history({change: v1 => ({...v1, requestedExpiry: 120, expiresAt: iso(120000)})})), []);
  assert.deepEqual(problems(history({change: v1 => ({...v1, requestedExpiry: 5000, expiresAt: iso(900000)})})), [], 'capped at maxLifetimeSeconds');
  assert.ok(problems(history({change: v1 => ({...v1, intervalSeconds: 1})})).some(m => /interval/.test(m)));
});

// Engines v3 (approval requests) and v4 (stop orders) in one tenant: the current verifiers check and replay everything, and a
// verifier that knows fewer engines reports the newer evaluations as engine_unavailable, never as a snapshot mismatch.
const run = (script, args) => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL(`../scripts/${script}`, import.meta.url)), ...args], {encoding: 'utf8'});
  return {status: r.status, out: r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};
function verifiesAndReplays(t, exportBundle, publicKeyPem) {
  assert.equal(verifyBundle(exportBundle, publicKeyPem).valid, true);
  const evaluations = exportBundle.records.filter(r => r.type === 'evaluation');
  const engines = new Set(evaluations.map(r => r.payload.replay.engine));
  assert.deepEqual([...engines].sort(), [EVALUATION_ENGINE_V3, EVALUATION_ENGINE_V4]);
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-r4-e2e-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(dir, 'key.pem');writeFileSync(file, JSON.stringify(exportBundle));writeFileSync(key, publicKeyPem);
  for (const [script, args] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...args, file, key, '--replay']);
    assert.equal(r.status, 0, r.err || JSON.stringify(r.out).slice(0, 2000));
    assert.deepEqual([r.out.approvals.valid, r.out.stopOrders.valid, r.out.registry.valid, r.out.replay.valid], [true, true, true, true]);
    assert.equal(r.out.replay.summary.replayed, evaluations.length);
    assert.ok(r.out.replay.evaluations.every(e => e.status === 'replayed' && e.inputs.snapshotHash === 'matches_record'));
  }
  for (const known of [[EVALUATION_ENGINE, EVALUATION_ENGINE_V2, EVALUATION_ENGINE_V3], [EVALUATION_ENGINE, EVALUATION_ENGINE_V2]]) {
    const older = replayEvaluations(exportBundle, {engines: known});
    assert.equal(older.valid, true, JSON.stringify(older.evaluations.filter(e => !['replayed', 'not_replayable'].includes(e.status))));
    for (const e of older.evaluations)
      assert.equal(e.status, known.includes(e.engine) ? 'replayed' : 'not_replayable', `${e.engine} with ${known.join(',')}`);
    assert.equal(older.summary.notReplayableReasons.engine_unavailable, evaluations.filter(r => !known.includes(r.payload.replay.engine)).length);
  }
  const latest = new Map(evaluations.map(r => [r.payload.actionId, r.payload]));
  const codes = id => latest.get(id).findings.map(f => f.code);
  assert.ok(!codes('ap-1').some(c => /APPROVAL|STOP_/.test(c)), codes('ap-1').join());
  assert.ok(codes('ap-2').includes('EXECUTION_AFTER_APPROVAL_REFUSED'));
  assert.ok(codes('st-1').includes('STOP_ORDER_NOT_HELD') && codes('st-1').includes('EXECUTION_BEFORE_APPROVAL'), codes('st-1').join());
  const both = latest.get('st-1').replay;
  assert.deepEqual([both.engine, both.inputs.approvals.length, both.inputs.stopOrders.orders, both.inputs.stopOrders.activations.length],
    [EVALUATION_ENGINE_V4, 1, 1, 1]);
}

test('E2E: a tenant with approval requests and stop orders exports, verifies offline and replays (current code)', async t => {
  const {exportBundle, publicKeyPem} = await buildApprovalsStopsExport(fileURLToPath(new URL('..', import.meta.url)));
  verifiesAndReplays(t, exportBundle, publicKeyPem);
});

test('E2E: the same scenario exported by 503c185 verifies and replays exactly as before', t => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/approvals-stops-export-503c185.json', import.meta.url), 'utf8'));
  assert.equal(fixture.baseCommit, '503c185');
  verifiesAndReplays(t, fixture.exportBundle, fixture.publicKeyPem);
});
