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
