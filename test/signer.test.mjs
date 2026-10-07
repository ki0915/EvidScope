// Heads signer policy, state and server (src/signer.mjs): it signs a heads leaf only when every tenant log of the previous leaf
// is still there and extends append-only, needs a single-use operator authorization for a new heads origin, survives restarts
// and torn writes, audits every signature and refusal, and enforces its transport limits.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, randomBytes} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import * as T from '../src/tlog.mjs';
import {fileBackend} from '../src/signer-backends.mjs';
import {
  assertSignerStateDir, createAuthorization, initSignerState, openSigner, readSignerState, revokeAuthorization, startSignerServer, verifyAuditLog,
} from '../src/signer.mjs';
import {createSignerClient} from '../src/signer-client.mjs';
import {epochAuthorization, handoverAuthorization} from '../scripts/signer.mjs';

const BASE = 'vault.test/evidscope', ORIGIN = T.headsOrigin(BASE), EMPTY = T.EMPTY_ROOT.toString('hex');
const id = name => T.tenantLogId(name), logOf = (name, base = BASE) => `${base}/t/${id(name)}`;
// A tenant log as a list of leaves; entry() and proof() give what the vault would send for it.
const tenant = n => Array.from({length: n}, () => T.leafHash(randomBytes(16)));
const entry = (name, leaves, base = BASE) => ({log: logOf(name, base), size: leaves.length, root: T.mth(leaves).toString('hex')});
const proof = (leaves, from) => ({from, hashes: T.consistencyProof(leaves, from).map(T.b64)});
const sorted = list => T.sortHeadsEntries(list);

function setup(t, {limits} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'evs-signer-')), stateDir = join(root, 'state'), keyFile = join(root, 'signer.pem');
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const {privateKey} = generateKeyPairSync('ed25519');
  writeFileSync(keyFile, privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  const backend = fileBackend({keyFile});
  initSignerState(stateDir, backend.publicKey);
  const open = () => openSigner({stateDir, backend, limits});
  return {root, stateDir, keyFile, backend, open, authorize: fields => createAuthorization(stateDir, fields)};
}
const audit = stateDir => readFileSync(join(stateDir, 'audit.log'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
const refused = async (promise, reason, pattern) => {
  const error = await promise.then(() => null, e => e);
  assert.ok(error, `expected a ${reason} refusal`);
  assert.equal(error.refusal, reason, error.message);
  if (pattern) assert.match(error.message, pattern);
  return error;
};
const verifyNote = (note, publicKey, origin = ORIGIN) => T.parseCheckpoint(T.openNote(note, [T.noteVerifier(T.logVkey(origin, publicKey))]).text);

test('the signer starts a heads origin only with an authorization and signs growth with consistency proofs', async t => {
  const s = setup(t), core = s.open();
  t.after(() => core.close());
  const a = tenant(3), b = tenant(2);
  const first = {origin: ORIGIN, previous: {size: 0, root: EMPTY}, leaf: {entries: sorted([entry('alpha', a)])}};
  const unauthorized = await refused(core.signHeads(first), 'unauthorized', /no authorization for the new heads origin/);
  assert.deepEqual(unauthorized.head, {origin: ORIGIN, known: false});
  const auth = s.authorize({kind: 'genesis', origin: ORIGIN, predecessor: null});
  const one = await core.signHeads(first);
  const c1 = verifyNote(one.note, s.backend.publicKey);
  assert.deepEqual([one.size, c1.size, c1.root.toString('hex')], [1, 1, one.root]);
  // The root is the signer's own: the leaf of these entries appended to an empty compact range.
  assert.equal(one.root, T.mth([T.headsLeafHash(T.headsLeafContent(first.leaf.entries))]).toString('hex'));
  a.push(...tenant(2));
  const two = await core.signHeads({origin: ORIGIN, previous: {size: 1, root: one.root}, leaf: {entries: sorted([entry('alpha', a), entry('beta', b)])},
    proofs: {[logOf('alpha')]: proof(a, 3)}});
  assert.equal(two.size, 2);
  const log = audit(s.stateDir).filter(e => e.event === 'signed');
  assert.deepEqual(log.map(e => [e.origin, e.oldSize, e.newSize, e.root]), [[ORIGIN, 0, 1, one.root], [ORIGIN, 1, 2, two.root]]);
  assert.deepEqual(log[0].authorization, {id: auth.id, kind: 'genesis'});
  assert.equal(audit(s.stateDir).find(e => e.event === 'refused').reason, 'unauthorized');
});

test('the signer refuses shrink, fork, tenant removal, growth without a valid proof and unchanged leaves, and audits each', async t => {
  const s = setup(t), core = s.open();
  t.after(() => core.close());
  s.authorize({kind: 'genesis', origin: ORIGIN, predecessor: null});
  const a = tenant(5), b = tenant(3);
  const one = await core.signHeads({origin: ORIGIN, previous: {size: 0, root: EMPTY}, leaf: {entries: sorted([entry('alpha', a), entry('beta', b)])}});
  const previous = {size: 1, root: one.root};
  const req = (entries, proofs = {}) => core.signHeads({origin: ORIGIN, previous, leaf: {entries: sorted(entries)}, proofs});
  await refused(req([entry('alpha', a.slice(0, 4)), entry('beta', b)]), 'rollback', /shrinks tenant log .* from 5 to 4 \(rollback\)/);
  await refused(req([entry('alpha', tenant(5)), entry('beta', b)]), 'fork', /changes tenant log .* at size 5 \(fork\)/);
  await refused(req([entry('alpha', a)]), 'tenant_removal', /drops tenant log .*beta|drops tenant log/);
  const grown = [...a, ...tenant(2)], forked = [...tenant(5), ...tenant(2)];
  await refused(req([entry('alpha', grown), entry('beta', b)]), 'fork', /without a valid consistency proof/);
  await refused(req([entry('alpha', forked), entry('beta', b)], {[logOf('alpha')]: proof(forked, 5)}), 'fork', /without a valid consistency proof/);
  await refused(req([entry('alpha', grown), entry('beta', b)], {[logOf('alpha')]: proof(grown, 4)}), 'fork');
  await refused(req([entry('alpha', a), entry('beta', b)]), 'unchanged');
  // A stale previous (the vault behind the signer) is out of sync and carries the signer's head to adopt.
  const stale = await refused(core.signHeads({origin: ORIGIN, previous: {size: 0, root: EMPTY}, leaf: {entries: [entry('alpha', a)]}}), 'out_of_sync');
  assert.deepEqual([stale.head.size, stale.head.root, stale.head.entries.length], [1, one.root, 2]);
  const ok = await req([entry('alpha', grown), entry('beta', b), entry('gamma', tenant(1))], {[logOf('alpha')]: proof(grown, 5)});
  assert.equal(ok.size, 2);
  const lines = audit(s.stateDir);
  assert.deepEqual(lines.filter(e => e.event === 'refused').map(e => e.reason),
    ['rollback', 'fork', 'tenant_removal', 'fork', 'fork', 'fork', 'unchanged', 'out_of_sync']);
  assert.ok(lines.filter(e => e.event === 'refused').every(e => e.origin === ORIGIN && e.oldSize === 1 && typeof e.time === 'string'));
  assert.deepEqual(verifyAuditLog(join(s.stateDir, 'audit.log')).lines, lines.length);
  // Malformed requests are rejected without an audit line or a signature.
  await refused(core.signHeads({origin: ORIGIN, previous: {size: 2, root: ok.root}, leaf: {entries: [{log: 'x', size: 1, root: EMPTY}]}}), 'invalid_request');
  const unsorted = [entry('alpha', grown), entry('beta', b)].sort((x, y) => (x.log < y.log ? 1 : -1));
  await refused(core.signHeads({origin: ORIGIN, previous: {size: 2, root: ok.root}, leaf: {entries: unsorted}}), 'invalid_request',
    /sorted/);
  assert.equal(audit(s.stateDir).length, lines.length);
});

test('signer state survives restarts, ignores torn temporary writes and refuses a corrupt or missing state', async t => {
  const s = setup(t);
  s.authorize({kind: 'genesis', origin: ORIGIN, predecessor: null});
  let core = s.open();
  const a = tenant(2);
  const one = await core.signHeads({origin: ORIGIN, previous: {size: 0, root: EMPTY}, leaf: {entries: [entry('alpha', a)]}});
  assert.throws(() => s.open(), /already open in this process/);
  core.close();
  // A crash while writing the next state leaves a temporary file; the committed state is untouched.
  writeFileSync(join(s.stateDir, `state.json.${process.pid}.deadbeef0000.tmp`), '{"format":"evidscope-signer-sta');
  // A crash while appending to the audit log leaves a torn line; it was never acknowledged.
  const torn = '{"format":"evidscope-signer-audit-v1","se';
  writeFileSync(join(s.stateDir, 'audit.log'), readFileSync(join(s.stateDir, 'audit.log'), 'utf8') + torn);
  core = s.open();
  assert.ok(!readdirSync(s.stateDir).some(n => n.endsWith('.tmp')));
  assert.equal(audit(s.stateDir).find(e => e.event === 'audit_recovered').droppedBytes, torn.length);
  assert.equal(verifyAuditLog(join(s.stateDir, 'audit.log')).lines, audit(s.stateDir).length);
  a.push(...tenant(3));
  const two = await core.signHeads({origin: ORIGIN, previous: {size: 1, root: one.root}, leaf: {entries: [entry('alpha', a)]},
    proofs: {[logOf('alpha')]: proof(a, 2)}});
  assert.equal(two.size, 2);
  core.close();
  assert.equal(readSignerState(s.stateDir).origins[ORIGIN].size, 2);
  const state = join(s.stateDir, 'state.json'), saved = readFileSync(state);
  // A state whose stored leaf no longer folds to its root, or that is cut short, is refused instead of starting over.
  const tampered = JSON.parse(saved);
  tampered.origins[ORIGIN].entries[0].size = 4;
  writeFileSync(state, JSON.stringify(tampered));
  assert.throws(() => s.open(), /inconsistent: the newest leaf and frontier do not fold/);
  writeFileSync(state, saved.subarray(0, 100));
  assert.throws(() => s.open(), /unreadable .* restore it from backup/);
  rmSync(state);
  assert.throws(() => s.open(), /No signer state .* never re-created/);
  writeFileSync(state, saved);
  core = s.open();
  assert.equal(core.head(ORIGIN).size, 2);
  core.close();
  // The backend key must be the key the state signs with.
  const other = generateKeyPairSync('ed25519').privateKey, otherFile = join(s.root, 'other.pem');
  writeFileSync(otherFile, other.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  assert.throws(() => openSigner({stateDir: s.stateDir, backend: fileBackend({keyFile: otherFile})}), /not the key of this state/);
});

test('the state directory may not live on the vault data volume', t => {
  const root = mkdtempSync(join(tmpdir(), 'evs-signer-dir-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  mkdirSync(join(root, 'data', 'signer'), {recursive: true});
  writeFileSync(join(root, 'data', 'evidence.db'), '');
  assert.throws(() => assertSignerStateDir(join(root, 'data', 'signer'), {vaultDataDir: undefined}), /holds evidence.db/);
  assert.throws(() => assertSignerStateDir(join(root, 'data'), {vaultDataDir: undefined}), /holds evidence.db/);
  mkdirSync(join(root, 'vault', 'nested'), {recursive: true});
  assert.throws(() => assertSignerStateDir(join(root, 'vault', 'nested'), {vaultDataDir: join(root, 'vault')}), /inside the vault data directory/);
  assert.throws(() => assertSignerStateDir(join(root, 'vault'), {vaultDataDir: join(root, 'vault')}), /inside the vault data directory/);
  assert.equal(assertSignerStateDir(join(root, 'signer'), {vaultDataDir: join(root, 'vault')}), join(root, 'signer'));
});

test('a vault-key heads log moves to the signer only from the authorized, witnessed checkpoint', async t => {
  const s = setup(t), vault = generateKeyPairSync('ed25519'), core = s.open();
  t.after(() => core.close());
  // The vault-key heads log the deployment ran before: two leaves.
  const a = tenant(4), b = tenant(2), leaves = [[entry('alpha', a.slice(0, 2))], sorted([entry('alpha', a), entry('beta', b)])];
  const hashes = leaves.map(e => T.headsLeafHash(T.headsLeafContent(e))), peaksBefore = T.frontierAppend([], 0, hashes[0]);
  const root = T.mth(hashes), note = T.signNote(T.formatCheckpoint({origin: ORIGIN, size: 2, root}), T.noteSigner(ORIGIN, vault.privateKey));
  const witness = generateKeyPairSync('ed25519'), w = {name: 'witness.test/w1', privateKey: witness.privateKey, pub: T.ed25519RawPublic(witness.publicKey)};
  const wvkey = T.vkeyString(w.name, T.SIG_COSIG_ED25519, w.pub);
  assert.throws(() => handoverAuthorization({stateDir: s.stateDir, checkpoint: note, vaultKey: vault.publicKey, witnesses: [wvkey]}),
    /0 of 1 required witness/);
  assert.throws(() => handoverAuthorization({stateDir: s.stateDir, checkpoint: note, vaultKey: generateKeyPairSync('ed25519').publicKey}), /signature|signed/);
  const cosigned = note + T.cosign(T.noteText(note), w, Math.floor(Date.now() / 1000));
  const auth = handoverAuthorization({stateDir: s.stateDir, checkpoint: cosigned, vaultKey: vault.publicKey, witnesses: [wvkey]});
  assert.deepEqual([auth.kind, auth.predecessor.size, auth.predecessor.cosignatures], ['handover', 2, 1]);
  const seed = {entries: leaves[1], peaksBefore: peaksBefore.map(h => h.toString('hex'))};
  const req = extra => core.signHeads({origin: ORIGIN, previous: {size: 2, root: root.toString('hex')}, leaf: {entries: leaves[1]}, seed, ...extra});
  // A seed that does not fold to the authorized checkpoint (a forged history) is refused.
  await refused(req({seed: {...seed, entries: [entry('alpha', a)]}}), 'fork', /does not fold to the authorized heads checkpoint/);
  await refused(core.signHeads({origin: ORIGIN, previous: {size: 1, root: hashes[0].toString('hex')}, leaf: {entries: leaves[1]}, seed}), 'unauthorized',
    /continues .* at size 2/);
  // The first signer leaf may repeat the last vault-key leaf: it re-anchors the same state under the signer key.
  const first = await req({});
  assert.equal(first.size, 3);
  assert.equal(verifyNote(first.note, s.backend.publicKey).size, 3);
  // From now on the policy continues from the seeded entries.
  await refused(core.signHeads({origin: ORIGIN, previous: {size: 3, root: first.root}, leaf: {entries: [entry('alpha', a)]}}), 'tenant_removal');
});

test('a restore epoch to a new origin base needs a matching single-use authorization and retires the old heads origin', async t => {
  const s = setup(t), core = s.open(), NEW = 'vault.test/evidscope-2', NEW_ORIGIN = T.headsOrigin(NEW);
  s.authorize({kind: 'genesis', origin: ORIGIN, predecessor: null});
  const a = tenant(6), b = tenant(4), c = tenant(2);
  const one = await core.signHeads({origin: ORIGIN, previous: {size: 0, root: EMPTY},
    leaf: {entries: sorted([entry('alpha', a), entry('beta', b), entry('gamma', c)])}});
  // Restored ledgers carry one more record (the epoch record). beta may come back from an older archive (size 2), gamma not at all.
  const alpha = [...a, ...tenant(1)], betaKept = [...b, ...tenant(1)], betaLost = [...b.slice(0, 2), ...tenant(1)], gamma = [...c, ...tenant(1)];
  const leaf = (list, proofs) => ({origin: NEW_ORIGIN, previous: {size: 0, root: EMPTY}, leaf: {entries: sorted(list.map(([n, l]) => entry(n, l, NEW)))},
    proofs: Object.fromEntries(Object.entries(proofs).map(([n, p]) => [logOf(n, NEW), p]))});
  const kept = leaf([['alpha', alpha], ['beta', betaKept]], {alpha: proof(alpha, 6), beta: proof(betaKept, 4)});
  await refused(core.signHeads(kept), 'unauthorized', /no authorization for the new heads origin/);
  const strict = epochAuthorization({stateDir: s.stateDir, fromBase: BASE, toBase: NEW});
  assert.deepEqual([strict.predecessor, strict.acceptLoss, strict.dropLogs, strict.restored], [{origin: ORIGIN, size: 1, root: one.root}, null, [], null]);
  await refused(core.signHeads(kept), 'tenant_removal', new RegExp(`drops tenant log ${id('gamma')}`));
  await refused(core.signHeads(leaf([['alpha', alpha], ['beta', betaLost], ['gamma', gamma]], {alpha: proof(alpha, 6), beta: proof(betaLost, 2),
    gamma: proof(gamma, 2)})), 'rollback', /does not continue its signed size 4 .* accepts no loss/);
  revokeAuthorization(s.stateDir, strict.id);
  // Bound loss: beta restarts from its restored prefix (size 2) and nothing earlier; gamma is dropped by name.
  const restored = {fromBase: BASE, toBase: NEW, restored: {[id('beta')]: {size: 2, root: T.mth(b.slice(0, 2)).toString('hex')}}};
  const auth = epochAuthorization({stateDir: s.stateDir, fromBase: BASE, toBase: NEW, acceptLoss: 'archive of the 3rd', restored, dropLogs: [id('gamma')]});
  const older = [...b.slice(0, 1), ...tenant(1)];
  await refused(core.signHeads(leaf([['alpha', alpha], ['beta', older]], {alpha: proof(alpha, 6), beta: proof(older, 1)})), 'rollback',
    /nor its authorized restored size 2/);
  await refused(core.signHeads(leaf([['alpha', alpha], ['beta', betaLost], ['gamma', gamma]], {alpha: proof(alpha, 6), beta: proof(betaLost, 2)})),
    'unauthorized', /authorized to be dropped/);
  const signed = await core.signHeads(leaf([['alpha', alpha], ['beta', betaLost]], {alpha: proof(alpha, 6), beta: proof(betaLost, 2)}));
  assert.equal(signed.size, 1);
  assert.equal(verifyNote(signed.note, s.backend.publicKey, NEW_ORIGIN).origin, NEW_ORIGIN);
  const line = audit(s.stateDir).find(e => e.event === 'signed' && e.origin === NEW_ORIGIN);
  assert.deepEqual([line.authorization.id, line.retired, line.lost, line.dropped],
    [auth.id, ORIGIN, [{log: id('beta'), signedSize: 4, restoredSize: 2}], [id('gamma')]]);
  // The old origin is retired: no more leaves, and the authorization is spent.
  await refused(core.signHeads({origin: ORIGIN, previous: {size: 1, root: one.root}, leaf: {entries: sorted([entry('alpha', alpha),
    entry('beta', b), entry('gamma', c)])}, proofs: {[logOf('alpha')]: proof(alpha, 6)}}), 'retired',
    /retired at the restore epoch to vault.test\/evidscope-2\/heads/);
  assert.ok(existsSync(join(s.stateDir, 'authorizations', 'used', auth.id + '.json')));
  assert.throws(() => epochAuthorization({stateDir: s.stateDir, fromBase: BASE, toBase: 'vault.test/evidscope-3'}), /no active heads origin/);
  // Replays: the same epoch leaf again (an older archive restored once more) is out of sync with the new origin, and the spent
  // authorization copied back into place neither restarts it nor opens another origin base.
  const replay = await refused(core.signHeads(leaf([['alpha', alpha], ['beta', betaLost]], {alpha: proof(alpha, 6), beta: proof(betaLost, 2)})), 'out_of_sync');
  assert.equal(replay.head.size, 1);
  const spent = JSON.parse(readFileSync(join(s.stateDir, 'authorizations', 'used', auth.id + '.json'), 'utf8'));
  writeFileSync(join(s.stateDir, 'authorizations', auth.id + '.json'), JSON.stringify({...spent, origin: T.headsOrigin('vault.test/evidscope-3')}));
  await refused(core.signHeads({...leaf([['alpha', alpha]], {alpha: proof(alpha, 6)}), origin: T.headsOrigin('vault.test/evidscope-3')}), 'unauthorized',
    /no longer holds \(retired at size 1\)|no authorization/);
  core.close();
  copyFileSync(join(s.stateDir, 'authorizations', 'used', auth.id + '.json'), join(s.stateDir, 'authorizations', auth.id + '.json'));
  s.open().close();
  assert.ok(!existsSync(join(s.stateDir, 'authorizations', auth.id + '.json')), 'a spent authorization found in place is moved away at start');
});

test('the signer server: Unix socket, token, request size and rate limits', async t => {
  const s = setup(t);
  s.authorize({kind: 'genesis', origin: ORIGIN, predecessor: null});
  const socket = join(s.root, 's.sock'), token = randomBytes(32).toString('hex');
  await assert.rejects(startSignerServer({stateDir: s.stateDir, backend: s.backend, listen: {host: '127.0.0.1', port: 0}}), /needs a bearer token/);
  await assert.rejects(startSignerServer({stateDir: s.stateDir, backend: s.backend, listen: {host: '0.0.0.0', port: 0}, token}), /needs TLS/);
  const server = await startSignerServer({stateDir: s.stateDir, backend: s.backend, listen: {socket}, log: () => {},
    limits: {maxRequestBytes: 4096, signsPerMinute: 60, signBurst: 2}});
  t.after(() => server.close());
  const client = createSignerClient({socket});
  const a = tenant(1);
  const one = await client.signHeads({origin: ORIGIN, previous: {size: 0, root: EMPTY}, leaf: {entries: [entry('alpha', a)]}});
  assert.deepEqual([one.httpStatus, one.body.status, one.body.size], [200, 'signed', 1]);
  const head = await client.head(ORIGIN);
  assert.deepEqual([head.body.size, head.body.root, head.body.note], [1, one.body.root, one.body.note]);
  const many = sorted(Array.from({length: 40}, (_, i) => entry('t' + i, a)));
  const big = await client.signHeads({origin: ORIGIN, previous: {size: 1, root: one.body.root}, leaf: {entries: many}});
  assert.equal(big.httpStatus, 413);
  const again = await client.signHeads({origin: ORIGIN, previous: {size: 1, root: one.body.root}, leaf: {entries: [entry('alpha', a)]}});
  assert.deepEqual([again.httpStatus, again.body.reason], [422, 'unchanged']);
  const limited = await client.signHeads({origin: ORIGIN, previous: {size: 1, root: one.body.root}, leaf: {entries: [entry('alpha', a)]}});
  assert.deepEqual([limited.httpStatus, limited.body.reason], [429, 'rate_limited']);
  const info = await client.info();
  assert.deepEqual([info.body.counters.tooLarge, info.body.counters.rateLimited, info.body.origins[0].size], [1, 1, 1]);
  assert.equal((await client.head('not a heads origin')).httpStatus, 400);
});

test('the signer server over loopback TCP needs the bearer token', async t => {
  const s = setup(t), token = randomBytes(32).toString('hex');
  const server = await startSignerServer({stateDir: s.stateDir, backend: s.backend, listen: {host: '127.0.0.1', port: 0}, token, log: () => {}});
  t.after(() => server.close());
  assert.match(server.address, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal((await createSignerClient({url: server.address}).head(ORIGIN)).httpStatus, 401);
  assert.equal((await createSignerClient({url: server.address, token: token.slice(1) + 'x'}).head(ORIGIN)).httpStatus, 401);
  const ok = await createSignerClient({url: server.address, token}).head(ORIGIN);
  assert.deepEqual([ok.httpStatus, ok.body.known], [200, false]);
  assert.equal(server.counters.unauthorized, 2);
});

const openssl = process.env.EVIDSCOPE_TEST_OPENSSL || 'openssl';
const hasOpenssl = spawnSync(openssl, ['version'], {encoding: 'utf8'}).status === 0;
test('the signer server over TLS: the vault trusts only the signer CA', {skip: hasOpenssl ? false : 'openssl is not available'}, async t => {
  const s = setup(t), token = randomBytes(32).toString('hex'), dir = join(s.root, 'tls');
  mkdirSync(dir);
  const run = args => assert.equal(spawnSync(openssl, args, {encoding: 'utf8'}).status, 0, args.join(' '));
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
  run(['req', '-x509', ...ec, '-days', '1', '-subj', '/CN=signer-test-ca', '-keyout', join(dir, 'ca.key'), '-out', join(dir, 'ca.pem')]);
  run(['req', ...ec, '-subj', '/CN=localhost', '-keyout', join(dir, 'server.key'), '-out', join(dir, 'server.csr')]);
  writeFileSync(join(dir, 'ext'), 'subjectAltName=IP:127.0.0.1,DNS:localhost\n');
  run(['x509', '-req', '-in', join(dir, 'server.csr'), '-CA', join(dir, 'ca.pem'), '-CAkey', join(dir, 'ca.key'), '-set_serial', '7', '-days', '1',
    '-extfile', join(dir, 'ext'), '-out', join(dir, 'server.pem')]);
  const server = await startSignerServer({stateDir: s.stateDir, backend: s.backend, listen: {host: '127.0.0.1', port: 0}, token, log: () => {},
    tls: {cert: readFileSync(join(dir, 'server.pem')), key: readFileSync(join(dir, 'server.key'))}});
  t.after(() => server.close());
  assert.match(server.address, /^https:/);
  const ok = await createSignerClient({url: server.address, token, ca: readFileSync(join(dir, 'ca.pem'))}).head(ORIGIN);
  assert.equal(ok.httpStatus, 200);
  await assert.rejects(createSignerClient({url: server.address, token}).head(ORIGIN), /SELF_SIGNED|UNABLE_TO_VERIFY|unable to verify|self.signed/i);
});
