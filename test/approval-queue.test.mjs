// Approval queue end to end (docs/approval-queue.md): request validation, CIBA-style polling states and slow_down, expiry as
// refusal, who may answer (403) and stale answers (409), the DSSE answer verified offline, point-in-time findings from analysis,
// export with offline verification and replay, forged histories, tenant isolation, and the export written before the queue.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createPrivateKey, randomBytes, randomUUID} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {digest, mac, makeCheckpoint, verifyBundle} from '../src/crypto.mjs';
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V2, EVALUATION_ENGINE_V3} from '../src/model.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';
import {verifyApprovalAnswer} from '../src/approvals.mjs';
import {awaitApproval, pollApproval, requestApproval} from '../src/approval-client.mjs';

const secret = () => randomBytes(32).toString('base64url');
const gateway = {id: 'alpha-gateway', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const gateway2 = {id: 'alpha-gateway-2', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const betaGateway = {id: 'beta-gateway', tenant: 'beta', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const second = {id: 'alpha-reviewer-2', tenant: 'alpha', role: 'reviewer', token: secret()};
const extra = [gateway, gateway2, betaGateway, second];
let h;
test.before(async () => {
  h = await harness({beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));
    config.principals.push(...extra);writeFileSync(file, JSON.stringify(config));
  }});
  h.config.principals.push(...extra);
});
test.after(async () => { await h?.close(); });

const call = (path, body, role = 'reviewer', tenant = 'alpha') => h.api(path, {body, role, tenant});
const asSecond = (path, body) => h.api(path, {body, headers: {authorization: `Bearer ${second.token}`}});
const pause = ms => new Promise(done => setTimeout(done, ms));
const target = {actor: 'pay-agent', tool: 'payment_transfer', action: 'refund'};
const ask = (decisionId, extraFields = {}, principal = gateway) => requestApproval(h.ingress.url, principal, {decisionId, actionId: decisionId,
  enforcementPointId: 'gw-1', traceId: 'trace-' + decisionId, policyId: 'payments.refund', policyVersion: 'p1', target: {...target, resource: decisionId},
  binding_message: `refund ${decisionId}`, ...extraFields});
const poll = (id, principal = gateway) => pollApproval(h.ingress.url, principal, id);
const answer = (id, operation, body, as = 'admin') => as === 'second' ? asSecond(`/api/approvals/${id}/${operation}`, body)
  : call(`/api/approvals/${id}/${operation}`, body, as);
async function analyzeAll() {for (let i = 0; i < 20; i++) {const r = (await h.analyze()).body;if (!r.backlog && !r.processed) return;}}
const findingCodes = async actionId => (await call(`/api/actions/${encodeURIComponent(actionId)}`, undefined, 'auditor')).body.evaluations[0].findings
  .map(f => f.code);
const tool = (id, occurredAt = new Date().toISOString(), fields = {}) => submit(h.ingress.url, h.principal('tool'), {id: `x-${id}-${randomUUID()}`,
  kind: 'execution', status: 'success', actionId: id, traceId: 'trace-' + id, ...target, resource: id, policyVersion: 'p1', occurredAt, ...fields});
const decide = id => submit(h.ingress.url, gateway, {id: `d-${id}`, kind: 'policy_decision', actionId: id, traceId: 'trace-' + id, ...target, resource: id,
  decision: 'require_approval', engine: 'opa', decisionId: id, enforcementPointId: 'gw-1', occurredAt: new Date(Date.now() - 1000).toISOString()});
const requests = new Map();

test('setup: the agent is registered and the answer policy is signed data', async () => {
  const entry = await call('/api/registry', {id: 'pay-agent', owner: 'alpha-admin-owner', purpose: 'refunds', actors: ['pay-agent'],
    tools: [{name: 'payment_transfer', enforcement: 'required'}]});
  assert.equal(entry.status, 200, JSON.stringify(entry.body));assert.equal(entry.body.risk.computed, 'high');
  const bad = await call('/api/registry/policy', {approvals: {intervalSeconds: 1, answer: {high: {approvers: 2, roles: ['auditor']}}}}, 'admin');
  assert.equal(bad.status, 400, 'only reviewer and admin can answer');
  assert.equal((await call('/api/registry/policy', {approvals: {lifetime: 5}}, 'admin')).status, 400, 'unknown field');
  const policy = await call('/api/registry/policy', {approvals: {intervalSeconds: 1, executionWindowSeconds: 120, maxLifetimeSeconds: 600}}, 'admin');
  assert.equal(policy.status, 200, JSON.stringify(policy.body));
  assert.deepEqual([policy.body.approvals.answer.high.approvers, policy.body.approvals.intervalSeconds], [2, 1]);
});

test('requests: only enforcement credentials, HMAC-signed, target metadata only, retries find the same request', async () => {
  const body = {decisionId: 'v-1', actionId: 'v-1', enforcementPointId: 'gw-1', target, binding_message: 'refund 1'};
  assert.equal((await requestApproval(h.ingress.url, h.principal('tool'), body)).status, 403, 'wrong source kind');
  assert.equal((await requestApproval(h.ingress.url, {...h.principal('reviewer'), hmacSecret: 'x'}, body)).status, 403, 'people do not open requests');
  for (const [field, value] of [['arguments', {amount: 10}], ['payload', 'x'], ['callback', 'https://x']])
    assert.equal((await requestApproval(h.ingress.url, gateway, {...body, [field]: value})).status, 400, field);
  const payload = await requestApproval(h.ingress.url, gateway, {...body, body: '{"amount":1}'});
  assert.match(payload.body.error, /호출 본문/);
  assert.equal((await requestApproval(h.ingress.url, gateway, {...body, target: {...target, input: 'x'}})).status, 400, 'payload in the target');
  assert.equal((await requestApproval(h.ingress.url, gateway, {...body, binding_message: 'x'.repeat(201)})).status, 400, 'bounded summary');
  assert.equal((await requestApproval(h.ingress.url, gateway, {...body, binding_message: undefined})).status, 400, 'summary required');
  assert.equal((await requestApproval(h.ingress.url, gateway, {...body, target: {tool: 'x'}})).status, 400, 'actor required');
  assert.equal((await requestApproval(h.ingress.url, gateway, {...body, requested_expiry: 0})).status, 400);
  const text = JSON.stringify(body), stamp = String(Date.now()), nonce = randomUUID();
  const forged = await fetch(new URL('/api/approvals/requests', h.ingress.url), {method: 'POST', body: text, headers: {'content-type': 'application/json',
    authorization: `Bearer ${gateway.token}`, 'x-evid-timestamp': stamp, 'x-evid-nonce': nonce, 'x-evid-signature': mac(gateway2.hmacSecret, stamp,
      nonce, text)}});
  assert.equal(forged.status, 401, 'HMAC with another secret');
  const opened = await requestApproval(h.ingress.url, gateway, {...body, requested_expiry: 100000});
  assert.equal(opened.status, 200, JSON.stringify(opened.body));
  assert.match(opened.body.auth_req_id, /^apr_[A-Za-z0-9_-]{27}$/);
  assert.deepEqual([opened.body.interval, opened.body.status, opened.body.eligibility], [1, 'pending', {tier: 'high', approvers: 2}]);
  assert.ok(opened.body.expires_in <= 600 && opened.body.expires_in > 590, 'requested lifetime capped by the tenant policy');
  const again = await requestApproval(h.ingress.url, gateway, {...body, requested_expiry: 100000});
  assert.deepEqual([again.body.auth_req_id, again.body.duplicate], [opened.body.auth_req_id, true]);
  assert.equal((await requestApproval(h.ingress.url, gateway, {...body, target: {...target, resource: 'other'}})).status, 409, 'same decision, other target');
  const audit = await fetch(new URL('/api/approvals/requests', h.audit.url), {method: 'POST', headers: {'content-type': 'application/json'}, body: text});
  assert.equal(audit.status, 403, 'not served by the audit gateway');
  requests.set('v-1', opened.body.auth_req_id);
});

test('polling follows CIBA: pending, slow_down with a longer interval, invalid_grant for other credentials and tenants', async () => {
  const id = requests.get('v-1');
  const first = await poll(id);
  assert.deepEqual([first.status, first.body.error], [400, 'authorization_pending']);
  const early = await poll(id);
  assert.deepEqual([early.status, early.body.error, early.body.interval], [400, 'slow_down', 6]);
  assert.equal((await poll(id, gateway2)).body.error, 'invalid_grant', 'another credential of the tenant');
  assert.equal((await poll(id, betaGateway)).body.error, 'invalid_grant', 'another tenant');
  assert.equal((await poll('apr_' + 'A'.repeat(27))).body.error, 'invalid_grant', 'unknown request');
  const grant = await fetch(new URL('/api/approvals/token', h.ingress.url), {method: 'POST', headers: {'content-type': 'application/json',
    authorization: `Bearer ${gateway.token}`}, body: JSON.stringify({grant_type: 'client_credentials', auth_req_id: id})});
  assert.equal((await grant.json()).error, 'unsupported_grant_type');
  assert.equal((await pollApproval(h.ingress.url, h.principal('tool'), id)).status, 403);
  // Tenant isolation on the reviewer side too.
  assert.equal((await call(`/api/approvals/${id}`, undefined, 'reviewer', 'beta')).status, 404);
  assert.equal((await call('/api/approvals', undefined, 'auditor', 'beta')).body.total, 0);
});

test('who may answer: roles, policy exclusions, distinct approvers and stale versions', async () => {
  const opened = await ask('a-1');assert.equal(opened.status, 200);const id = opened.body.auth_req_id;requests.set('a-1', id);
  const queue = (await call('/api/approvals', undefined, 'auditor')).body;
  const item = queue.pending.find(r => r.id === id);
  assert.ok(item.remainingSeconds > 0 && item.approvalsNeeded === 2);assert.equal(item.mayAnswer.allowed, false, 'auditors read only');
  assert.equal((await answer(id, 'approve', {reason: 'ok', version: 1}, 'auditor')).status, 403);
  const registrant = await answer(id, 'approve', {reason: 'ok', version: 1}, 'reviewer');
  assert.equal(registrant.status, 403, 'the agent registrant is excluded by the policy');
  assert.equal((await answer(id, 'approve', {reason: '', version: 1}, 'second')).status, 400, 'reason required');
  assert.equal((await answer(id, 'approve', {reason: 'ok', version: 1, override: true}, 'second')).status, 400);
  const one = await answer(id, 'approve', {reason: 'amount checked', version: 1}, 'second');
  assert.deepEqual([one.status, one.body.status, one.body.version], [200, 'pending', 2]);
  assert.equal((await answer(id, 'approve', {reason: 'again', version: 2}, 'second')).status, 403, 'two distinct approvers');
  assert.equal((await answer(id, 'approve', {reason: 'ok', version: 1})).status, 409, 'stale version');
  const two = await answer(id, 'approve', {reason: 'second look', version: 2});
  assert.deepEqual([two.status, two.body.status, two.body.approvals.map(a => a.by)], [200, 'approved', ['alpha-reviewer-2', 'alpha-admin']]);
  assert.equal((await answer(id, 'refuse', {reason: 'late', version: 3}, 'second')).status, 409, 'final answer');
  const detail = (await call(`/api/approvals/${id}`, undefined, 'auditor')).body;
  assert.deepEqual(detail.history.map(v => [v.version, v.change, v.principal]),
    [[1, 'requested', 'alpha-gateway'], [2, 'approval_added', 'alpha-reviewer-2'], [3, 'approved', 'alpha-admin']]);
  assert.deepEqual([detail.registry.id, detail.registry.tier], ['pay-agent', 'high']);
});

test('the answer is a DSSE statement the gateway verifies offline; the CLI agrees; tampering is refused', async t => {
  const id = requests.get('a-1');await pause(1100);
  const r = await poll(id);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const expected = {auth_req_id: id, actionId: 'a-1', decisionId: 'a-1', tenant: 'alpha', target: {...target, resource: 'a-1'}};
  const result = verifyApprovalAnswer({envelope: r.body.answer, publicKey: h.publicKey, expected});
  assert.deepEqual([result.approved, result.answer.approvers.length, result.answer.ledger.seq], [true, 2, r.body.ledger.seq]);
  await pause(1100);
  assert.deepEqual((await poll(id)).body.answer, r.body.answer, 'the same signed bytes on every poll');
  assert.equal(verifyApprovalAnswer({envelope: r.body.answer, publicKey: h.publicKey, expected: {...expected, target}}).approved, false);
  const tampered = structuredClone(r.body.answer), statement = JSON.parse(Buffer.from(tampered.payload, 'base64').toString());
  statement.predicate.actionId = 'a-2';tampered.payload = Buffer.from(JSON.stringify(statement)).toString('base64');
  assert.throws(() => verifyApprovalAnswer({envelope: tampered, publicKey: h.publicKey, expected}), /signature verification failed/);
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-approval-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'answer.json'), key = join(dir, 'key.pem'), want = join(dir, 'target.json'), other = join(dir, 'other.json');
  writeFileSync(file, JSON.stringify(r.body));writeFileSync(key, h.publicKey);writeFileSync(want, JSON.stringify(expected.target));
  writeFileSync(other, JSON.stringify(target));
  const cli = args => spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/evidscope-verify.mjs', import.meta.url)), 'approval', ...args],
    {encoding: 'utf8'});
  const ok = cli([file, key, '--action-id', 'a-1', '--target', want, '--auth-req-id', id]);
  assert.equal(ok.status, 0, ok.stderr);assert.equal(JSON.parse(ok.stdout).approved, true);
  assert.equal(cli([file, key, '--action-id', 'a-1', '--target', other]).status, 1, 'another target');
  writeFileSync(file, JSON.stringify({answer: tampered}));
  assert.equal(cli([file, key, '--action-id', 'a-1', '--target', want]).status, 1, 'tampered');
});

test('refusals and expiry are answers the gateway must treat as refusal', async () => {
  const refused = (await ask('r-1')).body.auth_req_id;requests.set('r-1', refused);
  assert.equal((await answer(refused, 'refuse', {reason: 'amount too high', version: 1}, 'second')).body.status, 'refused');
  const denied = await poll(refused);
  assert.deepEqual([denied.status, denied.body.error, denied.body.decision], [400, 'access_denied', 'refused']);
  const verdict = verifyApprovalAnswer({envelope: denied.body.answer, publicKey: h.publicKey, expected: {actionId: 'r-1', target: {...target,
    resource: 'r-1'}}});
  assert.deepEqual([verdict.valid, verdict.approved, verdict.answer.refusedBy.principal], [true, false, 'alpha-reviewer-2']);
  const expiring = (await ask('e-1', {requested_expiry: 1})).body.auth_req_id;requests.set('e-1', expiring);
  await pause(1200);
  const expired = await poll(expiring);
  assert.deepEqual([expired.status, expired.body.error], [400, 'expired_token']);
  assert.equal((await answer(expiring, 'approve', {reason: 'late', version: 1}, 'second')).status, 409, 'an expired request cannot be answered');
  const queue = (await call('/api/approvals', undefined, 'auditor')).body;
  assert.equal(queue.recent.find(r => r.id === expiring).state, 'expired');
  assert.ok(!queue.pending.some(r => r.id === expiring || r.id === refused));
  // The client helper fails closed: a refusal and an unreachable vault are both refusals.
  const quick = {publicKey: h.publicKey, principal: gateway, sleep: () => pause(1100), deadlineMs: 10000};
  const helper = await awaitApproval({...quick, url: h.ingress.url, request: {decisionId: 'r-1', actionId: 'r-1', enforcementPointId: 'gw-1',
    traceId: 'trace-r-1', policyId: 'payments.refund', policyVersion: 'p1', target: {...target, resource: 'r-1'}, binding_message: 'refund r-1'}});
  assert.deepEqual([helper.approved, helper.reason], [false, 'access_denied']);
  const down = await awaitApproval({...quick, url: 'http://127.0.0.1:9', request: {}});
  assert.deepEqual([down.approved, down.reason], [false, 'evidscope_unreachable']);
});

test('analysis: in-vault answers decide the approval findings at the time of execution', async () => {
  for (const id of ['a-1', 'r-1', 'e-1']) assert.equal((await decide(id)).status, 202);
  assert.equal((await tool('a-1')).status, 202);
  assert.equal((await tool('r-1')).status, 202);
  assert.equal((await tool('e-1')).status, 202);
  // Approved, executed after the window (occurredAt may lie up to five minutes ahead), and on another target.
  const late = (await ask('w-1')).body.auth_req_id;await answer(late, 'approve', {reason: 'ok', version: 1}, 'second');
  const approved = await answer(late, 'approve', {reason: 'ok', version: 2});
  const afterWindow = new Date(Date.parse(approved.body.executionWindow.notAfter) + 60000).toISOString();
  assert.equal((await tool('w-1', afterWindow)).status, 202);
  const swap = (await ask('m-1')).body.auth_req_id;await answer(swap, 'approve', {reason: 'ok', version: 1}, 'second');
  await answer(swap, 'approve', {reason: 'ok', version: 2});
  assert.equal((await tool('m-1', undefined, {resource: 'someone-else'})).status, 202);
  await analyzeAll();
  const a1 = await findingCodes('a-1');
  assert.ok(!a1.some(c => /APPROVAL_(TARGET|WINDOW|ANSWERER|TIME)|EXECUTION_(BEFORE|AFTER)_APPROVAL|REQUIRED_APPROVAL/.test(c)), a1.join());
  assert.ok((await findingCodes('r-1')).includes('EXECUTION_AFTER_APPROVAL_REFUSED'));
  assert.ok((await findingCodes('e-1')).includes('EXECUTION_AFTER_APPROVAL_EXPIRED'));
  assert.ok((await findingCodes('w-1')).includes('APPROVAL_WINDOW_EXCEEDED'));
  assert.ok((await findingCodes('m-1')).includes('APPROVAL_TARGET_MISMATCH'));
  const evaluation = (await call('/api/actions/a-1', undefined, 'auditor')).body.evaluations[0];
  assert.equal(evaluation.replay.engine, EVALUATION_ENGINE_V3);assert.deepEqual(evaluation.replay.inputs.approvals.map(a => a.version), [3]);
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

test('exports carry every request version; offline verification, history check and replay pass and catch re-signed forgeries', async t => {
  const bundle = (await call('/api/export', undefined, 'auditor')).body, key = join(h.dir, 'trust-anchor.pem');
  const versions = bundle.records.filter(r => r.type === 'approval_request');
  assert.ok(versions.filter(r => r.payload.id === requests.get('a-1')).length === 3, 'every version is kept');
  assert.equal(verifyBundle(bundle, h.publicKey).valid, true);
  const replay = replayEvaluations(bundle);
  assert.equal(replay.valid, true, JSON.stringify(replay.evaluations.filter(e => !['replayed', 'not_replayable'].includes(e.status))));
  assert.ok(replay.evaluations.some(e => e.engine === EVALUATION_ENGINE_V3 && e.status === 'replayed'));
  const older = replayEvaluations(bundle, {engines: [EVALUATION_ENGINE, EVALUATION_ENGINE_V2]});
  assert.equal(older.valid, true, 'a v1/v2 verifier reports v3 evaluations as engine_unavailable, never as a mismatch');
  assert.ok(older.summary.notReplayableReasons.engine_unavailable > 0);
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-approval-export-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json');writeFileSync(file, JSON.stringify(bundle));
  for (const [script, args] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...args, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);assert.equal(r.out.approvals.valid, true);assert.ok(r.out.approvals.answered >= 4);assert.equal(r.out.replay.valid, true);
  }
  const signingKey = createPrivateKey(readFileSync(join(h.dir, 'signing-private.pem')));
  const forge = (mutate, pattern) => {
    const forged = structuredClone(bundle);mutate(forged.records);resign(forged, signingKey);writeFileSync(file, JSON.stringify(forged));
    const r = run('evidscope-verify.mjs', ['bundle', file, key]);
    assert.equal(r.status, 1);assert.equal(r.out.valid, true, 'chain and checkpoint alone accept it');
    assert.ok(r.out.approvals.problems.some(p => pattern.test(p.message)), JSON.stringify(r.out.approvals.problems));
  };
  // The registrant (excluded by the policy) re-signed as the second approver.
  forge(records => {
    const row = records.find(r => r.type === 'approval_request' && r.payload.id === requests.get('a-1') && r.payload.version === 3);
    row.payload.approvals[1].by = 'alpha-reviewer';row.principal = 'alpha-reviewer';
  }, /excluded/);
  // A request whose recorded answer rules were emptied when it was opened.
  forge(records => {
    for (const row of records.filter(r => r.type === 'approval_request' && r.payload.id === requests.get('a-1'))) row.payload.eligibility.excluded = [];
  }, /who may answer/);
  // An expired request approved afterwards.
  forge(records => {
    const at = records.findIndex(r => r.type === 'approval_request' && r.payload.id === requests.get('e-1'));
    const v = records[at].payload, late = new Date(Date.parse(v.expiresAt) + 1000).toISOString();
    records.push({...records[at], seq: records.length + 1, recordedAt: late, principal: 'alpha-reviewer-2', payload: {...v, version: 2, change: 'refused',
      status: 'refused', refusal: {by: 'alpha-reviewer-2', role: 'reviewer', at: late, reason: 'x'}, decidedAt: late}});
  }, /after the request expired/);
});

test('an export written before the approval queue (ef18d23) verifies and replays exactly as before', t => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/pre-approvals-export-ef18d23.json', import.meta.url), 'utf8'));
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-pre-approvals-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(dir, 'key.pem');
  writeFileSync(file, JSON.stringify(fixture.exportBundle));writeFileSync(key, fixture.publicKeyPem);
  const evaluations = fixture.exportBundle.records.filter(r => r.type === 'evaluation').length;
  for (const [script, args] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...args, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);assert.equal(r.out.approvals, undefined, 'no approvals section without approval records');
    assert.equal(r.out.registry.valid, true);assert.equal(r.out.replay.valid, true);assert.equal(r.out.replay.summary.replayed, evaluations);
    assert.ok(r.out.replay.evaluations.every(e => e.engine === EVALUATION_ENGINE_V2 && e.status === 'replayed' && e.inputs.snapshotHash === 'matches_record'));
  }
  const findings = fixture.exportBundle.records.filter(r => r.type === 'evaluation').flatMap(r => r.payload.findings.map(f => f.code));
  assert.ok(findings.includes('REQUIRED_APPROVAL_MISSING') && findings.includes('EXECUTION_AFTER_DENY'), 'the fixture exercises the decision rules');
});
