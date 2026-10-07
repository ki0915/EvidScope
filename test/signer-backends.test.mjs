// Key backends of the heads signer and their startup conformance self-test: a file key, an ssh-agent key (the in-repo JS agent,
// a fake agent for refusals, and the Go x/crypto agent when EVIDSCOPE_SSH_TESTAGENT_BIN is set) and an external signing
// command standing in for a cloud KMS CLI. The self-test rejects a wrong key, a prehash variant and a canned signature.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash, generateKeyPairSync, randomBytes, verify} from 'node:crypto';
import {chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import net from 'node:net';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import * as T from '../src/tlog.mjs';
import {commandBackend, fileBackend, selfTest, SELF_TEST_VECTOR, sshAgentBackend, sshFingerprint} from '../src/signer-backends.mjs';
import {createAuthorization, initSignerState, startSignerServer} from '../src/signer.mjs';
import {createSignerClient} from '../src/signer-client.mjs';
import {startSshAgent} from './support/ssh-agent.mjs';

const FAKE = fileURLToPath(new URL('./support/fake-signer-command.mjs', import.meta.url));
const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
function keys(t) {
  const dir = mkdtempSync(join(tmpdir(), 'evs-backend-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const pair = (name, mode = 0o600) => {
    const {privateKey, publicKey} = generateKeyPairSync('ed25519');
    writeFileSync(join(dir, name + '.pem'), privateKey.export({format: 'pem', type: 'pkcs8'}), {mode});
    writeFileSync(join(dir, name + '.pub'), publicKey.export({format: 'pem', type: 'spki'}));
    return {key: join(dir, name + '.pem'), pub: join(dir, name + '.pub'), publicKey};
  };
  return {dir, pair};
}
const signs = async (backend, message = randomBytes(40)) => verify(null, message, backend.publicKey, await backend.sign(message));

test('file backend: PKCS#8 Ed25519 key, private permissions, self-test', async t => {
  const k = keys(t), good = k.pair('signer');
  const backend = fileBackend({keyFile: good.key});
  assert.equal(await selfTest(backend), true);
  assert.ok(await signs(backend));
  if (process.platform !== 'win32') {
    chmodSync(good.key, 0o644);
    assert.throws(() => fileBackend({keyFile: good.key}), /readable by other users/);
  }
  const rsa = generateKeyPairSync('rsa', {modulusLength: 2048}).privateKey, rsaFile = join(k.dir, 'rsa.pem');
  writeFileSync(rsaFile, rsa.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  assert.throws(() => fileBackend({keyFile: rsaFile}), /not an Ed25519 private key/);
});

test('ssh-agent backend: the key is chosen by SHA256 fingerprint and signs pure Ed25519 over the agent protocol', async t => {
  const k = keys(t), socket = join(k.dir, 'agent.sock'), agent = await startSshAgent(socket, SEED);
  t.after(() => agent.close());
  const backend = await sshAgentBackend({socket, fingerprint: agent.fingerprint});
  assert.equal(await selfTest(backend), true);
  assert.deepEqual(T.ed25519RawPublic(backend.publicKey), T.ed25519RawPublic(T.ed25519PrivateFromSeed(Buffer.from(SEED, 'hex'))));
  await assert.rejects(sshAgentBackend({socket, fingerprint: 'SHA256:' + 'A'.repeat(43)}), /holds no key with fingerprint/);
  await assert.rejects(sshAgentBackend({socket: join(k.dir, 'missing.sock'), fingerprint: agent.fingerprint}), /ssh-agent at .*ENOENT/);
  await assert.rejects(sshAgentBackend({socket, fingerprint: 'MD5:aa'}), /needs --fingerprint SHA256/);
});

// A misbehaving agent: lists an ssh-rsa key (or a FIDO sk-ssh-ed25519 key) under the requested fingerprint, or refuses to sign.
function fakeAgent(socket, {type = 'ssh-ed25519', sign = 'fail'}) {
  const str = b => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); };
  const blob = Buffer.concat([str(Buffer.from(type)), str(randomBytes(32))]);
  const server = net.createServer(c => c.on('data', d => {
    const kind = d[4];
    if (kind === 11) {
      const n = Buffer.alloc(4);
      n.writeUInt32BE(1);
      c.write(str(Buffer.concat([Buffer.from([12]), n, str(blob), str(Buffer.from('fake'))])));
    } else if (sign === 'fail') c.write(str(Buffer.from([5])));
    else c.write(str(Buffer.concat([Buffer.from([14]), str(Buffer.concat([str(Buffer.from('ssh-rsa')), str(randomBytes(64))]))])));
  }));
  return new Promise(r => server.listen(socket, () => r({fingerprint: sshFingerprint(blob), close: () => new Promise(d => server.close(d))})));
}
test('ssh-agent backend refuses other key types, a refused signature and a non-Ed25519 signature', async t => {
  const k = keys(t);
  for (const type of ['ssh-rsa', 'sk-ssh-ed25519@openssh.com']) {
    const agent = await fakeAgent(join(k.dir, type.length + '.sock'), {type});
    await assert.rejects(sshAgentBackend({socket: join(k.dir, type.length + '.sock'), fingerprint: agent.fingerprint}), /is not ssh-ed25519/);
    await agent.close();
  }
  const refusing = await fakeAgent(join(k.dir, 'r.sock'), {sign: 'fail'});
  t.after(() => refusing.close());
  // The listing is right (an ed25519 key) but every signature request fails: the self-test stops the signer from starting.
  const backend = await sshAgentBackend({socket: join(k.dir, 'r.sock'), fingerprint: refusing.fingerprint});
  await assert.rejects(selfTest(backend), /self-test failed: ssh-agent refused to sign/);
  const wrong = await fakeAgent(join(k.dir, 'w.sock'), {sign: 'rsa'});
  t.after(() => wrong.close());
  await assert.rejects((await sshAgentBackend({socket: join(k.dir, 'w.sock'), fingerprint: wrong.fingerprint})).sign(Buffer.from('x')), /ssh-rsa signature/);
});

// The Go agent sits next to litewitness in the interop toolchain (as witnessctl does), or is named explicitly.
const LW = process.env.EVIDSCOPE_LITEWITNESS_BIN, goAgent = process.env.EVIDSCOPE_SSH_TESTAGENT_BIN || (LW ? join(dirname(LW), 'testagent') : undefined);
const noGoAgent = goAgent && existsSync(goAgent) ? false : 'no Go testagent (EVIDSCOPE_SSH_TESTAGENT_BIN, or testagent beside litewitness)';
test('ssh-agent backend against the Go x/crypto/ssh/agent keyring', {skip: noGoAgent},
  async t => {
    const k = keys(t), socket = join(k.dir, 'go.sock'), child = spawn(goAgent, [socket, SEED], {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => child.kill());
    const fingerprint = await new Promise(r => child.stdout.once('data', d => r(String(d).trim())));
    for (let i = 0; i < 100 && !existsSync(socket); i++) await new Promise(r => setTimeout(r, 20));
    const backend = await sshAgentBackend({socket, fingerprint});
    assert.equal(await selfTest(backend), true);
    assert.ok(await signs(backend));
  });

test('command backend: message on stdin, raw or base64 signature; the self-test rejects prehash, wrong key and canned signatures', async t => {
  const k = keys(t), good = k.pair('kms'), other = k.pair('other');
  const command = (mode, extra = {}) => commandBackend({argv: [process.execPath, FAKE, mode, good.key], publicKeyFile: good.pub, ...extra});
  for (const mode of ['base64', 'raw']) assert.equal(await selfTest(command(mode)), true, mode);
  assert.ok(await signs(command('raw'), SELF_TEST_VECTOR));
  await assert.rejects(selfTest(command('prehash')), /does not verify as pure Ed25519 .*prehash variant/);
  await assert.rejects(selfTest(commandBackend({argv: [process.execPath, FAKE, 'base64', good.key], publicKeyFile: other.pub})), /wrong key/);
  // A canned signature passes the fixed vector but not the fresh challenge.
  assert.ok(verify(null, SELF_TEST_VECTOR, good.publicKey, await command('canned').sign(Buffer.from('anything'))));
  await assert.rejects(selfTest(command('canned')), /does not verify/);
  await assert.rejects(command('raw', {output: 'base64'}).sign(Buffer.from('m')), /neither a raw nor a base64 signature|-byte signature/);
  await assert.rejects(command('fail').sign(Buffer.from('m')), /signing command failed \(3\): AccessDeniedException/);
  await assert.rejects(command('slow', {timeoutMs: 300}).sign(Buffer.from('m')), /timed out after 300 ms/);
  assert.throws(() => commandBackend({argv: 'aws kms sign', publicKeyFile: good.pub}), /argv array/);
  assert.throws(() => commandBackend({argv: [process.execPath], publicKeyFile: undefined}), /needs --public-key/);
  // The argv is passed as is: shell metacharacters are just argument bytes.
  const literal = commandBackend({argv: [process.execPath, FAKE, 'base64', good.key, '; touch ' + join(k.dir, 'pwned')], publicKeyFile: good.pub});
  assert.ok(await signs(literal));
  assert.ok(!existsSync(join(k.dir, 'pwned')));
});

test('a signer served by the command backend signs heads checkpoints the vault can verify', async t => {
  const k = keys(t), good = k.pair('kms'), stateDir = join(k.dir, 'state'), origin = T.headsOrigin('vault.test/kms');
  const backend = commandBackend({argv: [process.execPath, FAKE, 'base64', good.key], publicKeyFile: good.pub});
  initSignerState(stateDir, backend.publicKey);
  createAuthorization(stateDir, {kind: 'genesis', origin, predecessor: null});
  await assert.rejects(startSignerServer({stateDir, backend: commandBackend({argv: [process.execPath, FAKE, 'prehash', good.key], publicKeyFile: good.pub}),
    listen: {socket: join(k.dir, 'x.sock')}, log: () => {}}), /self-test failed/);
  const server = await startSignerServer({stateDir, backend, listen: {socket: join(k.dir, 's.sock')}, log: () => {}});
  t.after(() => server.close());
  const root = createHash('sha256').update('alpha').digest('hex');
  const r = await createSignerClient({socket: join(k.dir, 's.sock')}).signHeads({origin, previous: {size: 0, root: T.EMPTY_ROOT.toString('hex')},
    leaf: {entries: [{log: `vault.test/kms/t/${T.tenantLogId('alpha')}`, size: 1, root}]}});
  assert.equal(r.body.status, 'signed', JSON.stringify(r.body));
  assert.equal(T.parseCheckpoint(T.openNote(r.body.note, [T.noteVerifier(T.logVkey(origin, good.publicKey))]).text).size, 1);
});
