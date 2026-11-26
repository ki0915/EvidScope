// A request target the URL parser rejects (security review 2026-10-22, "//" is one): the vault answers 400 and keeps serving, also
// while it is saturated (100 requests in flight) or stopping, where src/server.mjs used to parse the target outside its error
// handling and the uncaught error ended the process, an unauthenticated way to stop collection.
import test from 'node:test';
import assert from 'node:assert/strict';
import {connect} from 'node:net';
import {harness} from './harness.mjs';

const host = process.env.EVIDSCOPE_TEST_HOST || '127.0.0.1';
// One raw request and its status line, on its own connection (fetch would normalise the target).
function rawRequest(port, target, {timeoutMs = 3000} = {}) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, host), timer = setTimeout(() => { socket.destroy(); reject(Error('no answer for ' + target)); }, timeoutMs);
    let data = '';
    socket.on('data', b => { data += b; });
    socket.on('error', e => { clearTimeout(timer); reject(e); });
    socket.on('close', () => { clearTimeout(timer); resolve(data); });
    socket.on('connect', () => socket.end(`GET ${target} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`));
  });
}
// A request whose body never arrives holds one slot of the server's in-flight count until its request timeout.
function hangingRequest(port) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, host);
    socket.on('error', reject);
    socket.on('connect', () => { socket.write(`POST /api/ingest HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n{`);
      setTimeout(() => resolve(socket), 20); });
  });
}
const status = answer => Number(/^HTTP\/1\.1 (\d{3})/.exec(answer)?.[1]);

test('an unparseable request target gets 400, whether the vault is idle or saturated, and the vault stays up', async t => {
  const h = await harness({vaultOnly: true});
  t.after(() => h.close());
  const port = h.vault.port;
  assert.equal(status(await rawRequest(port, '//')), 400);
  const sockets = [];
  try {
    for (let i = 0; i < 100; i++) sockets.push(await hangingRequest(port));
    const saturated = await rawRequest(port, '/healthz');
    assert.equal(status(saturated), 503, 'the hundred hanging requests saturate the vault: ' + saturated.split('\r\n')[0]);
    assert.equal(status(await rawRequest(port, '//')), 400, 'the saturated branch parses the target safely too');
    assert.equal(h.vault.child.exitCode, null, 'the vault process is still running');
  } finally { for (const s of sockets) s.destroy(); }
  const healthy = await fetch(h.vault.url + '/healthz');
  assert.equal(healthy.status, 200);
  assert.equal((await healthy.json()).status, 'ready');
});
