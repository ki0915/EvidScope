// Agent registry API, lifecycle and evaluation end to end (docs/agent-registry.md): CRUD with history, four-eyes refusals,
// data-driven gates, risk tiers and overrides, candidates, point-in-time findings from analysis, policy-decision intake,
// export with offline verification and replay, and the old-export regression.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createPrivateKey, randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {digest, makeCheckpoint, verifyBundle} from '../src/crypto.mjs';
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V2} from '../src/model.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';

const secret = () => randomBytes(32).toString('base64url');
const enforcement = {id: 'alpha-enforcement', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const second = {id: 'alpha-reviewer-2', tenant: 'alpha', role: 'reviewer', token: secret()};
let h;
test.before(async () => {
  h = await harness({beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));
    config.principals.push(enforcement, second);writeFileSync(file, JSON.stringify(config));
  }});
  h.config.principals.push(enforcement, second);
});
test.after(async () => { await h?.close(); });

const call = (path, body, role = 'reviewer') => h.api(path, {body, role});
const asSecond = (path, body) => h.api(path, {body, role: 'reviewer', headers: {authorization: `Bearer ${second.token}`}});
const send = async (kind, event) => {
  const principal = kind === 'enforcement' ? enforcement : h.principal(kind);
  const r = await submit(h.ingress.url, principal, {occurredAt: new Date().toISOString(), ...event});
  assert.equal(r.status, 202, JSON.stringify(r.body));
};
async function analyzeAll() {for (let i = 0; i < 20; i++) {const r = (await h.analyze()).body;if (!r.backlog && !r.processed) return;}}
const latest = async actionId => (await call(`/api/actions/${encodeURIComponent(actionId)}`, undefined, 'auditor')).body.evaluations[0];
const findingCodes = async actionId => (await latest(actionId)).findings.map(f => f.code);
const pause = ms => new Promise(done => setTimeout(done, ms));
const mail = {id: 'mail-agent', name: 'Mail agent', owner: 'ops-team', purpose: 'customer replies', sources: ['alpha-agent'], actors: ['mail-agent'],
  tools: [{name: 'mailer', enforcement: 'required'}], dataCategories: ['customer'], destinations: ['smtp.vendor.example'],
  fingerprint: {codeCommit: 'abc1234'}};
let beforeSuspension;

test('registry entries are created as signed drafts with history; roles and links are enforced', async () => {
  assert.equal((await call('/api/registry', mail, 'auditor')).status, 403, 'auditors read only');
  const created = await call('/api/registry', mail);
  assert.equal(created.status, 200, JSON.stringify(created.body));
  assert.deepEqual([created.body.state, created.body.version, created.body.change, created.body.registeredBy], ['draft', 1, 'created', 'alpha-reviewer']);
  assert.equal(created.body.risk.computed, 'medium');
  assert.deepEqual(created.body.risk.reasons.map(r => r.rule).sort(), ['data-internal', 'destination-external']);
  assert.equal((await call('/api/registry', {...mail, id: 'other', input: 'x'})).status, 400, 'unknown field');
  assert.equal((await call('/api/registry', {...mail, id: 'other', sources: ['alpha-auditor']})).status, 400, 'not a source principal');
  assert.equal((await call('/api/registry', {...mail, id: 'other', assetIds: ['missing']})).status, 400, 'unknown asset');
  assert.equal((await call('/api/registry', {...mail, id: 'policy'})).status, 400, 'reserved id');
  assert.equal((await call('/api/registry', {...mail, state: 'production', id: 'other'})).status, 400, 'no direct production');
  assert.equal((await call('/api/registry', mail)).status, 409, 'duplicate id');
  assert.equal((await call('/api/registry', {id: 'other', actors: ['mail-agent']})).status, 409, 'one live entry per actor');
  const list = await call('/api/registry', undefined, 'auditor');
  assert.equal(list.status, 200);assert.deepEqual(list.body.items.map(i => i.id), ['mail-agent']);assert.equal(list.body.policy.source, 'built_in_default');
  const edited = await call('/api/registry/mail-agent', {owner: 'mail-team'});
  assert.deepEqual([edited.body.version, edited.body.change, edited.body.owner, edited.body.sources], [2, 'updated', 'mail-team', ['alpha-agent']]);
  const detail = (await call('/api/registry/mail-agent', undefined, 'auditor')).body;
  assert.deepEqual(detail.versions.map(v => [v.version, v.principal]), [[1, 'alpha-reviewer'], [2, 'alpha-reviewer']]);
  assert.equal(detail.lifecycle.valid, true);assert.deepEqual(detail.next.map(n => n.to), ['testing', 'retired']);
  assert.equal((await call('/api/registry/missing', undefined, 'auditor')).status, 404);
});

test('lifecycle: immediate transitions, four-eyes approvals, data-driven gates, stale and refused requests', async () => {
  const toTesting = await call('/api/registry/mail-agent/transitions', {to: 'testing', reason: 'start pilot'});
  assert.equal(toTesting.status, 200);assert.equal(toTesting.body.transition.status, 'applied');assert.equal(toTesting.body.entry.state, 'testing');
  assert.equal((await call('/api/registry/mail-agent/transitions', {to: 'production', reason: 'skip'})).status, 409, 'not allowed by the lifecycle');
  const request = await call('/api/registry/mail-agent/transitions', {to: 'approved', reason: 'pilot passed'}, 'admin');
  assert.equal(request.body.transition.status, 'pending');
  assert.deepEqual(request.body.gate.unmet, ['telemetry-in-testing', 'decision-log-received'], 'medium tier gates are checked at request time');
  assert.equal((await call('/api/registry/mail-agent/transitions', {to: 'approved', reason: 'again'}, 'admin')).status, 409, 'one pending request');
  const id = request.body.transition.id;
  assert.equal((await call(`/api/registry/transitions/${id}/approve`, {reason: 'self'})).status, 403, 'the registrant cannot approve');
  assert.equal((await call(`/api/registry/transitions/${id}/approve`, {reason: 'self'}, 'admin')).status, 403, 'the requester cannot approve');
  assert.equal((await call(`/api/registry/transitions/${id}/approve`, {reason: 'auditor'}, 'auditor')).status, 403);
  const unmet = await asSecond(`/api/registry/transitions/${id}/approve`, {reason: 'looks fine'});
  assert.equal(unmet.status, 409);assert.match(unmet.body.error, /telemetry-in-testing/);
  await send('agent', {id: 'mail-testing-intent', actionId: 'mail-testing', traceId: 'mail-trace', kind: 'intent', actor: 'mail-agent', tool: 'mailer'});
  await send('enforcement', {id: 'mail-testing-decision', actionId: 'mail-testing', traceId: 'mail-trace', kind: 'policy_decision', decision: 'allow',
    actor: 'mail-agent', tool: 'mailer', decisionId: 'dec-1', enforcementPointId: 'gw-1', engine: 'opa'});
  const approved = await asSecond(`/api/registry/transitions/${id}/approve`, {reason: 'pilot evidence present'});
  assert.equal(approved.status, 200, JSON.stringify(approved.body));
  assert.equal(approved.body.entry.state, 'approved');assert.equal(approved.body.transition.reviewedBy, 'alpha-reviewer-2');
  assert.equal(approved.body.gate.met, true);
  assert.equal((await call('/api/registry/mail-agent', {tools: [{name: 'shell'}]})).status, 409, 'configuration is frozen once approved');
  // A refused request leaves the state; an edit makes a pending request stale (superseded on the record).
  const refused = await call('/api/registry/mail-agent/transitions', {to: 'production', reason: 'go live'}, 'admin');
  assert.equal((await asSecond(`/api/registry/transitions/${refused.body.transition.id}/refuse`, {reason: 'not yet'})).body.transition.status, 'refused');
  const stale = await call('/api/registry/mail-agent/transitions', {to: 'production', reason: 'go live'}, 'admin');
  const mailAsset = {id: 'mail-asset', actor: 'mail-agent', tool: 'mailer', owner: 'ops', policyVersion: 'p1', approvalRequired: false};
  assert.equal((await call('/api/assets', mailAsset)).status, 200);
  assert.equal((await call('/api/registry/mail-agent', {assetIds: ['mail-asset']})).status, 200, 'links can change while approved');
  assert.equal((await asSecond(`/api/registry/transitions/${stale.body.transition.id}/approve`, {reason: 'ok'})).status, 409, 'stale request');
  const detail = (await call('/api/registry/mail-agent', undefined, 'auditor')).body;
  assert.equal(detail.transitions.find(t => t.id === stale.body.transition.id).status, 'superseded');
  const live = await call('/api/registry/mail-agent/transitions', {to: 'production', reason: 'go live', evidence: [{type: 'asset', ref: 'mail-asset'}]},
    'admin');
  assert.deepEqual(live.body.transition.evidence, [{type: 'asset', ref: 'mail-asset', verification: 'signed_object_at_request'}]);
  assert.equal((await call('/api/registry/mail-agent/transitions', {to: 'retired', reason: 'x', evidence: [{type: 'event', ref: 'alpha-agent/none'}]},
    'admin')).status, 400, 'event evidence must be a retained event');
  const production = await asSecond(`/api/registry/transitions/${live.body.transition.id}/approve`, {reason: 'assets linked'});
  assert.equal(production.status, 200, JSON.stringify(production.body));assert.equal(production.body.entry.state, 'production');
});

test('suspension applies at once; leaving suspended needs an independent approval; activity is judged at its time', async () => {
  await send('agent', {id: 'mail-before', actionId: 'mail-before', traceId: 'mail-trace', kind: 'intent', actor: 'mail-agent', tool: 'mailer'});
  beforeSuspension = Date.now();await pause(20);
  const suspended = await call('/api/registry/mail-agent/transitions', {to: 'suspended', reason: 'incident'}, 'admin');
  assert.equal(suspended.body.transition.status, 'applied');assert.equal(suspended.body.entry.state, 'suspended');
  await pause(20);
  await send('tool', {id: 'mail-during', actionId: 'mail-during', traceId: 'mail-trace', kind: 'execution', actor: 'mail-agent', tool: 'mailer', action: 'send',
    resource: 'ticket-1', status: 'success'});
  await analyzeAll();
  assert.ok((await findingCodes('mail-during')).includes('AGENT_SUSPENDED_ACTIVITY'));
  assert.ok(!(await findingCodes('mail-before')).includes('AGENT_SUSPENDED_ACTIVITY'), 'activity before the suspension');
  assert.equal((await latest('mail-during')).replay.engine, EVALUATION_ENGINE_V2);
  const resume = await call('/api/registry/mail-agent/transitions', {to: 'production', reason: 'fixed'}, 'admin');
  assert.equal(resume.body.transition.status, 'pending');
  assert.equal((await call(`/api/registry/transitions/${resume.body.transition.id}/approve`, {reason: 'self'})).status, 403);
  assert.equal((await asSecond(`/api/registry/transitions/${resume.body.transition.id}/approve`, {reason: 'reviewed fix'})).body.entry.state, 'production');
});

test('decision rules: execution after deny and a missing decision for an enforced tool', async () => {
  const target = {actor: 'mail-agent', tool: 'mailer', action: 'send', resource: 'ticket-2'};
  await send('enforcement', {id: 'deny-1', actionId: 'mail-denied', traceId: 'mail-trace', kind: 'policy_decision', decision: 'deny', decisionId: 'dec-deny-1',
    enforcementPointId: 'gw-1', engine: 'opa', ...target});
  await pause(5);
  await send('tool', {id: 'exec-denied', actionId: 'mail-denied', traceId: 'mail-trace', kind: 'execution', status: 'success', ...target});
  await send('tool', {id: 'exec-unchecked', actionId: 'mail-unchecked', traceId: 'mail-trace', kind: 'execution', status: 'success', ...target});
  await analyzeAll();
  assert.ok((await findingCodes('mail-denied')).includes('EXECUTION_AFTER_DENY'));
  assert.ok((await findingCodes('mail-unchecked')).includes('ENFORCEMENT_DECISION_MISSING'));
  assert.ok(!(await findingCodes('mail-denied')).includes('ENFORCEMENT_DECISION_MISSING'));
});

test('risk overrides are independent and bound to the configuration; retired agents and enforcement', async () => {
  const pay = await call('/api/registry', {id: 'pay-agent', owner: 'finance', purpose: 'refunds', actors: ['pay-agent'], tools: ['payment_transfer']});
  assert.equal(pay.body.risk.tier, 'high');
  assert.equal((await call('/api/registry/pay-agent/risk', {tier: 'medium', reason: 'sandbox only'})).status, 403, 'the registrant cannot lower its tier');
  const override = await asSecond('/api/registry/pay-agent/risk', {tier: 'medium', reason: 'sandbox account only'});
  assert.deepEqual([override.body.change, override.body.risk.tier, override.body.risk.override.by], ['risk_override', 'medium', 'alpha-reviewer-2']);
  const changed = await call('/api/registry/pay-agent', {tools: ['payment_transfer', 'refund_api']});
  assert.deepEqual([changed.body.risk.override, changed.body.risk.tier], [null, 'high'], 'a changed configuration drops the override');
  assert.equal((await call('/api/registry/pay-agent/transitions', {to: 'retired', reason: 'replaced'})).body.entry.state, 'retired');
  assert.equal((await call('/api/registry/pay-agent', {owner: 'x'})).status, 409, 'retired is terminal');
  await send('tool', {id: 'pay-after', actionId: 'pay-after', traceId: 'pay-trace', kind: 'execution', status: 'success', actor: 'pay-agent',
    tool: 'payment_transfer'});
  await send('tool', {id: 'shadow-1', actionId: 'shadow-1', traceId: 'shadow-trace', kind: 'execution', status: 'success', actor: 'shadow-agent', tool: 'crm'});
  assert.equal((await call('/api/registry/policy', {enforcement: 'unregistered_activity'})).status, 403, 'policy is admin-only');
  assert.equal((await call('/api/registry/policy', {gates: {high: {production: [{id: 'x', check: 'run_code'}]}}}, 'admin')).status, 400);
  const policy = await call('/api/registry/policy', {enforcement: 'unregistered_activity'}, 'admin');
  assert.deepEqual([policy.status, policy.body.version, policy.body.enforcement], [200, 1, 'unregistered_activity']);
  await pause(5);
  await send('tool', {id: 'shadow-2', actionId: 'shadow-2', traceId: 'shadow-trace', kind: 'execution', status: 'success', actor: 'shadow-agent', tool: 'crm'});
  await analyzeAll();
  assert.ok((await findingCodes('pay-after')).includes('AGENT_RETIRED_ACTIVITY'));
  assert.ok((await findingCodes('shadow-2')).includes('AGENT_UNREGISTERED_ACTIVITY'));
  assert.ok(!(await findingCodes('shadow-1')).includes('AGENT_UNREGISTERED_ACTIVITY'), 'activity before enforcement was configured');
  const candidates = (await call('/api/registry/candidates', undefined, 'auditor')).body;
  const shadow = candidates.items.find(c => c.actor === 'shadow-agent');
  assert.deepEqual([shadow.state, shadow.registered, shadow.suggestedId, shadow.events], ['discovered', false, 'shadow-agent', 2]);
  assert.ok(shadow.reasons.includes('UNREGISTERED_ASSET'));
  assert.ok(!candidates.items.some(c => c.actor === 'mail-agent'), 'registered agents are not candidates');
  assert.equal((await call('/api/registry', undefined, 'auditor')).body.items.length, 2, 'candidates are never registered automatically');
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

test('exports carry registry and decision records; offline verification, lifecycle check and replay pass and catch forgery', async t => {
  await analyzeAll();
  const bundle = (await call('/api/export', undefined, 'auditor')).body;
  const types = new Set(bundle.records.map(r => r.type));
  for (const type of ['agent_registry', 'agent_transition', 'agent_registry_policy']) assert.ok(types.has(type), type);
  assert.equal(verifyBundle(bundle, h.publicKey ?? readFileSync(join(h.dir, 'trust-anchor.pem'), 'utf8')).valid, true);
  const replay = replayEvaluations(bundle);
  assert.equal(replay.valid, true, JSON.stringify(replay.evaluations.filter(e => e.status !== 'replayed' && e.status !== 'not_replayable')));
  assert.ok(replay.evaluations.some(e => e.engine === EVALUATION_ENGINE_V2 && e.status === 'replayed'));
  const v1Only = replayEvaluations(bundle, {engine: EVALUATION_ENGINE});
  assert.equal(v1Only.valid, true, 'a v1-only verifier reports v2 evaluations as engine_unavailable, never as a mismatch');
  assert.ok(v1Only.summary.notReplayableReasons.engine_unavailable > 0);
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-registry-export-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(h.dir, 'trust-anchor.pem');writeFileSync(file, JSON.stringify(bundle));
  for (const [script, extra] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...extra, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);assert.equal(r.out.registry.valid, true);assert.ok(r.out.registry.entries >= 2);assert.equal(r.out.replay.valid, true);
  }
  // A re-signed history in which the requester approved its own production request passes the signature and fails the lifecycle.
  const forged = structuredClone(bundle), approval = forged.records.find(r => r.type === 'agent_transition' && r.payload.status === 'approved');
  approval.payload.reviewedBy = approval.payload.requestedBy;approval.principal = approval.payload.requestedBy;
  resign(forged, createPrivateKey(readFileSync(join(h.dir, 'signing-private.pem'))));
  writeFileSync(file, JSON.stringify(forged));
  const r = run('evidscope-verify.mjs', ['bundle', file, key]);
  assert.equal(r.status, 1);assert.equal(r.out.valid, true, 'chain and checkpoint alone accept it');
  assert.ok(r.out.registry.problems.some(p => /four-eyes/.test(p.message)));
});

test('an export written before the registry (9a15b5f) verifies and replays exactly as before', t => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/pre-registry-export-9a15b5f.json', import.meta.url), 'utf8'));
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-pre-registry-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(dir, 'key.pem');
  writeFileSync(file, JSON.stringify(fixture.exportBundle));writeFileSync(key, fixture.publicKeyPem);
  for (const [script, extra] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...extra, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);assert.equal(r.out.registry, undefined, 'no registry section for an export without registry records');
    assert.equal(r.out.replay.valid, true);assert.equal(r.out.replay.summary.replayed, 4);
    assert.ok(r.out.replay.evaluations.every(e => e.engine === EVALUATION_ENGINE && e.status === 'replayed'));
  }
  const findings = fixture.exportBundle.records.filter(r => r.type === 'evaluation').flatMap(r => r.payload.findings.map(f => f.code));
  assert.ok(findings.includes('DESTINATION_OUTSIDE_POLICY') && findings.includes('CUSTOM:external:v1'), 'the fixture exercises policies and rules');
});
