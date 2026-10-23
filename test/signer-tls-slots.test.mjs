// Round 3 re-audit: the TLS signer accepts TCP connections from anyone the network lets through, before any token check. One peer
// that opened maxConnections (64) sockets and never finished a TLS handshake held every slot for the default handshake timeout
// (120 s) and could reconnect at once, so the vault could not reach its signer. Each address now holds at most a few connections
// and a handshake must finish within a few seconds.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, randomBytes} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {connect} from 'node:net';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import * as T from '../src/tlog.mjs';
import {fileBackend} from '../src/signer-backends.mjs';
import {DEFAULT_LIMITS, initSignerState, startSignerServer} from '../src/signer.mjs';
import {createSignerClient} from '../src/signer-client.mjs';

const openssl = process.env.EVIDSCOPE_TEST_OPENSSL || 'openssl';
const hasOpenssl = spawnSync(openssl, ['version'], {encoding: 'utf8'}).status === 0;
// The attacker needs another source address than the vault; Linux routes all of 127/8 to loopback.
async function canUse(localAddress) {
  const socket = connect({host: '127.0.0.1', port: 9, localAddress});
  const [what] = await Promise.race([once(socket, 'error').catch(e => [e]), once(socket, 'connect').then(() => ['connect'])]);
  socket.destroy();
  return what === 'connect' || what?.code === 'ECONNREFUSED';
}
function tlsFiles(dir) {
  const run = args => assert.equal(spawnSync(openssl, args, {encoding: 'utf8'}).status, 0, args.join(' '));
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
  run(['req', '-x509', ...ec, '-days', '1', '-subj', '/CN=signer-test-ca', '-keyout', join(dir, 'ca.key'), '-out', join(dir, 'ca.pem')]);
  run(['req', ...ec, '-subj', '/CN=localhost', '-keyout', join(dir, 'server.key'), '-out', join(dir, 'server.csr')]);
  writeFileSync(join(dir, 'ext'), 'subjectAltName=IP:127.0.0.1\n');
  run(['x509', '-req', '-in', join(dir, 'server.csr'), '-CA', join(dir, 'ca.pem'), '-CAkey', join(dir, 'ca.key'), '-set_serial', '9', '-days', '1',
    '-extfile', join(dir, 'ext'), '-out', join(dir, 'server.pem')]);
  return {ca: readFileSync(join(dir, 'ca.pem')), cert: readFileSync(join(dir, 'server.pem')), key: readFileSync(join(dir, 'server.key'))};
}

test('an unauthenticated peer that never finishes a TLS handshake cannot hold every signer connection', async t => {
  if (!hasOpenssl) return t.skip('openssl is not available');
  if (!await canUse('127.0.0.2')) return t.skip('127.0.0.2 is not a usable source address here');
  const root = mkdtempSync(join(tmpdir(), 'evs-signer-slots-')), stateDir = join(root, 'state'), keyFile = join(root, 'signer.pem');
  t.after(() => rmSync(root, {recursive: true, force: true}));
  mkdirSync(join(root, 'tls'));
  writeFileSync(keyFile, generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  const backend = fileBackend({keyFile}), tls = tlsFiles(join(root, 'tls')), token = randomBytes(32).toString('hex');
  initSignerState(stateDir, backend.publicKey);
  const server = await startSignerServer({stateDir, backend, listen: {host: '127.0.0.1', port: 0}, token, log: () => {},
    tls: {cert: tls.cert, key: tls.key}, limits: {handshakeTimeoutMs: 600}});
  const sockets = [];
  t.after(async () => { for (const s of sockets) s.destroy(); await server.close(); });
  // The attacker opens as many sockets as the server takes in all and sends nothing.
  const port = Number(new URL(server.address).port);
  let closed = 0;
  for (let i = 0; i < 64; i++) {
    const s = connect({host: '127.0.0.1', port, localAddress: '127.0.0.2'});
    s.on('error', () => {}).on('close', () => { closed++; });
    sockets.push(s);
  }
  await Promise.all(sockets.map(s => once(s, 'connect').catch(() => {})));
  await delay(200);
  // The vault still reaches its signer, while the attacker keeps only a few of its sockets.
  const head = await createSignerClient({url: server.address, token, ca: tls.ca}).head(T.headsOrigin('vault.test/evidscope'));
  assert.deepEqual([head.httpStatus, head.body.known], [200, false]);
  assert.ok(closed >= 64 - DEFAULT_LIMITS.maxConnectionsPerAddress, `only ${closed} of 64 idle sockets were refused`);
  // And the handshake timeout closes the ones it kept.
  for (let i = 0; i < 50 && closed < 64; i++) await delay(50);
  assert.equal(closed, 64);
  // The defaults are what the signer runs with unless told otherwise.
  assert.ok(DEFAULT_LIMITS.handshakeTimeoutMs <= 10000 && DEFAULT_LIMITS.maxConnectionsPerAddress <= 16);
});
