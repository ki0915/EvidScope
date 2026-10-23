// Approval poll pacing (src/approval-service.mjs): the in-memory pacing table is shared fairly between enforcement sources. One
// source holding every entry must not make every other source's first poll a slow_down, and eviction must not let the
// flooding source poll faster than its interval. The store is a stub: pacing is decided before and after one cached read.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createApprovals} from '../src/approval-service.mjs';
import {CIBA_GRANT_TYPE} from '../src/approvals.mjs';

const source = id => ({id, tenant: 'alpha', role: 'source', kind: 'enforcement'});
const requestId = (owner, n) => `apr_${`${owner}-${n}`.padEnd(27, '_')}`;
function service(options = {}) {
  const owners = new Map(), clock = {at: Date.parse('2026-10-08T00:00:00Z')};
  const store = {transaction: f => f(), cachedApprovals: (tenant, {id}) => ({values: owners.has(id) ? [{seq: 1, hash: 'h', body: {id,
    requestedBy: owners.get(id), status: 'pending', expiresAt: '2027-01-01T00:00:00.000Z', intervalSeconds: 5}}] : []})};
  const approvals = createApprovals({store, principals: [], policyObjects: () => new Map(), signer: null, now: () => clock.at, ...options});
  const poll = (p, id) => {
    owners.set(id, p.id);
    try { approvals.poll(p, JSON.stringify({grant_type: CIBA_GRANT_TYPE, auth_req_id: id})); } catch (error) { return error.code ?? error.message; }
    return 'answered';
  };
  return {poll, clock};
}

test('one source filling the pacing table does not slow every other source down', () => {
  const {poll} = service(), flooder = source('flooder'), other = source('other');
  for (let n = 0; n < 10000; n++) assert.equal(poll(flooder, requestId('f', n)), 'authorization_pending');
  assert.equal(poll(other, requestId('o', 0)), 'authorization_pending', 'another source still gets its first poll answered');
  assert.equal(poll(flooder, requestId('f', 'new')), 'slow_down', 'the source over its share gets slow_down for a new request');
});

test('eviction is fair and never lets the evicted source escape pacing', () => {
  const {poll, clock} = service({paceEntries: 4}), a = source('a'), b = source('b'), c = source('c');
  for (let n = 0; n < 4; n++) assert.equal(poll(a, requestId('a', n)), 'authorization_pending');
  assert.equal(poll(a, requestId('a', 4)), 'slow_down', 'alone and full: no room for more');
  assert.equal(poll(b, requestId('b', 0)), 'authorization_pending');
  assert.equal(poll(b, requestId('b', 1)), 'authorization_pending', 'b may hold half');
  assert.equal(poll(b, requestId('b', 2)), 'slow_down', 'but not more than its share');
  assert.equal(poll(c, requestId('c', 0)), 'authorization_pending', 'a third source evicts from the largest holder');
  // a lost its three oldest entries to b and c; polling them at once is still early, as is any new request of a until the evicted time.
  for (const id of [requestId('a', 0), requestId('a', 1), requestId('a', 9)]) assert.equal(poll(a, id), 'slow_down', id);
  assert.equal(poll(a, requestId('a', 3)), 'slow_down', 'a kept entry is paced as before');
  clock.at += 5000;
  assert.equal(poll(b, requestId('b', 0)), 'authorization_pending', 'on time');
  assert.equal(poll(a, requestId('a', 0)), 'slow_down', 'a is at its share (4 / 3 sources), so an evicted request gets no new entry');
  clock.at += 120000;
  assert.equal(poll(a, requestId('a', 0)), 'authorization_pending', 'expired entries are pruned when the table is full');
});
