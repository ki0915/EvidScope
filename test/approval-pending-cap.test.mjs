// One enforcement credential cannot flood the approval queue (round-4 re-audit proposal P-2): unanswered, unexpired requests per
// source are capped by the signed policy field `approvals.maxPendingPerSource` (default 100), and other sources are unaffected.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import {requestApproval} from '../src/approval-client.mjs';

const secret = () => randomBytes(32).toString('base64url');
const gateway = {id: 'alpha-gateway', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const gateway2 = {id: 'alpha-gateway-2', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()};
const second = {id: 'alpha-reviewer-2', tenant: 'alpha', role: 'reviewer', token: secret()};
let h;
test.before(async () => {
  h = await harness({beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));
    config.principals.push(gateway, gateway2, second);writeFileSync(file, JSON.stringify(config));
  }});
  h.config.principals.push(gateway, gateway2, second);
});
test.after(async () => { await h?.close(); });

const ask = (id, principal = gateway) => requestApproval(h.ingress.url, principal, {decisionId: id, actionId: id, enforcementPointId: 'gw-1',
  policyId: 'payments.refund', policyVersion: 'p1', target: {actor: 'unregistered-agent', tool: 'payment_transfer', resource: id},
  binding_message: `refund ${id}`});

test('pending approval requests are capped per enforcement source, and answering one frees a slot', async () => {
  const bad = await h.api('/api/registry/policy', {role: 'admin', body: {approvals: {maxPendingPerSource: 0}}});
  assert.equal(bad.status, 400, 'the cap is at least 1');
  const policy = await h.api('/api/registry/policy', {role: 'admin', body: {approvals: {maxPendingPerSource: 2}}});
  assert.equal(policy.status, 200, JSON.stringify(policy.body));
  for (const id of ['cap-1', 'cap-2']) assert.equal((await ask(id)).status, 200);
  const third = await ask('cap-3');
  assert.equal(third.status, 429, JSON.stringify(third.body));
  assert.equal((await ask('cap-1')).body.duplicate, true, 'a retry of an open request is still idempotent at the cap');
  assert.equal((await ask('other-1', gateway2)).status, 200, 'another enforcement source has its own allowance');
  const opened = (await ask('cap-1')).body.auth_req_id;
  const refused = await h.api(`/api/approvals/${opened}/refuse`, {role: 'admin', body: {reason: 'not now', version: 1}});
  assert.equal(refused.body.status, 'refused', JSON.stringify(refused.body));
  assert.equal((await ask('cap-3')).status, 200, 'an answered request no longer counts');
});
