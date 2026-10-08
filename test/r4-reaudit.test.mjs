// Round-4 re-audit regression tests (docs/kill-switch.md, docs/approval-queue.md). Each test is the proof of concept of one
// finding and failed on 503c185: hostile entry and actor names dropped from the enforcement bundle and deny-list.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {gunzipSync} from 'node:zlib';
import {harness} from './harness.mjs';
import {ed25519Verifier, openEnvelope} from '../src/dsse.mjs';
import {DENY_LIST_PAYLOAD_TYPE, denyList, enforcementState, goCanonical} from '../src/enforcement-bundle.mjs';
import {requestApproval} from '../src/approval-client.mjs';
import {approvalEligibility, approvalPolicyOf, approvalRequestId, targetDigest, verifyApprovalHistory} from '../src/approvals.mjs';
import {riskBasis} from '../src/agent-registry.mjs';

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
