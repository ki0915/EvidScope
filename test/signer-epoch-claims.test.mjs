// Round 3 re-audit: the restored prefixes of a restore epoch come from the vault (scripts/transparency.mjs epoch-claims), so a
// vault-host attacker writes them. authorize-epoch printed only claims shorter than the signed size as losses, and the signer
// accepted any leaf matching a claim. A claim at (or above) the signed size with another root was therefore a fork the operator
// never saw, and --accept-loss without --restored printed no losses while it let every tenant log restart from anything.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, randomBytes} from 'node:crypto';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as T from '../src/tlog.mjs';
import {fileBackend} from '../src/signer-backends.mjs';
import {createAuthorization, initSignerState, openSigner} from '../src/signer.mjs';
import {epochAuthorization} from '../scripts/signer.mjs';

const BASE = 'vault.test/evidscope', NEW = 'vault.test/evidscope-2', ORIGIN = T.headsOrigin(BASE), NEW_ORIGIN = T.headsOrigin(NEW);
const EMPTY = T.EMPTY_ROOT.toString('hex'), id = name => T.tenantLogId(name), logOf = (name, base) => `${base}/t/${id(name)}`;
const leaves = n => Array.from({length: n}, () => T.leafHash(randomBytes(16)));
const entry = (name, list, base) => ({log: logOf(name, base), size: list.length, root: T.mth(list).toString('hex')});
const proof = (list, from) => ({from, hashes: T.consistencyProof(list, from).map(T.b64)});

async function signedOrigin(t) {
  const root = mkdtempSync(join(tmpdir(), 'evs-epoch-claims-')), stateDir = join(root, 'state'), keyFile = join(root, 'signer.pem');
  t.after(() => rmSync(root, {recursive: true, force: true}));
  writeFileSync(keyFile, generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  const backend = fileBackend({keyFile});
  initSignerState(stateDir, backend.publicKey);
  const core = openSigner({stateDir, backend});
  t.after(() => core.close());
  createAuthorization(stateDir, {kind: 'genesis', origin: ORIGIN, predecessor: null});
  const alpha = leaves(6), beta = leaves(4);
  const first = T.sortHeadsEntries([entry('alpha', alpha, BASE), entry('beta', beta, BASE)]);
  await core.signHeads({origin: ORIGIN, previous: {size: 0, root: EMPTY}, leaf: {entries: first}});
  return {stateDir, core, alpha, beta};
}
const epochLeaf = (list, proofs = {}) => ({origin: NEW_ORIGIN, previous: {size: 0, root: EMPTY},
  leaf: {entries: T.sortHeadsEntries(list.map(([name, l]) => entry(name, l, NEW)))}, proofs});

test('a restored claim that contradicts the signed tenant log at or above its size is refused, not hidden among the losses', async t => {
  const {stateDir, core, alpha, beta} = await signedOrigin(t);
  // The attacker's history: alpha replaced by six other records (the same size) and beta by five (larger than signed).
  const forgedAlpha = leaves(6), forgedBeta = leaves(5);
  const claims = {fromBase: BASE, toBase: NEW, restored: {[id('alpha')]: {size: 6, root: T.mth(forgedAlpha).toString('hex')},
    [id('beta')]: {size: 5, root: T.mth(forgedBeta).toString('hex')}}};
  assert.throws(() => epochAuthorization({stateDir, fromBase: BASE, toBase: NEW, restored: claims}),
    /differs from the entry the signer signed at size 6 \(fork\)/);
  // A claim beyond the signed size cannot be checked here; it binds nothing, and the leaf must continue the signed entry.
  const larger = epochAuthorization({stateDir, fromBase: BASE, toBase: NEW,
    restored: {fromBase: BASE, toBase: NEW, restored: {[id('beta')]: claims.restored[id('beta')]}}});
  assert.deepEqual([larger.restored, larger.losses], [{}, []]);
  const refused = await core.signHeads(epochLeaf([['alpha', alpha], ['beta', forgedBeta]], {[logOf('alpha', NEW)]: proof(alpha, 6)})).then(() => null, e => e);
  assert.equal(refused?.refusal, 'rollback', 'the signer signed a forked beta under the new origin');
  const kept = [...beta, ...leaves(1)];
  const signed = await core.signHeads(epochLeaf([['alpha', alpha], ['beta', kept]], {[logOf('alpha', NEW)]: proof(alpha, 6),
    [logOf('beta', NEW)]: proof(kept, 4)}));
  assert.equal(signed.size, 1);
});

test('the signer accepts a restored prefix only below the size it signed, whatever an authorization file says', async t => {
  const {stateDir, core, alpha, beta} = await signedOrigin(t);
  const forged = leaves(6);
  // Written directly (an authorization made before this check, or by hand): the claim equals alpha's signed size.
  createAuthorization(stateDir, {kind: 'epoch', origin: NEW_ORIGIN, predecessor: {origin: ORIGIN, size: 1, root: core.head(ORIGIN).root},
    acceptLoss: {reason: 'archive'}, dropLogs: [], restored: {[id('alpha')]: {size: 6, root: T.mth(forged).toString('hex')}}});
  const error = await core.signHeads(epochLeaf([['alpha', forged], ['beta', beta]])).then(() => null, e => e);
  assert.equal(error?.refusal, 'rollback', 'a restored claim at the signed size replaced the signed history');
});

test('authorize-epoch with --accept-loss and no --restored lists every tenant log as an unbounded loss', async t => {
  const {stateDir} = await signedOrigin(t);
  const auth = epochAuthorization({stateDir, fromBase: BASE, toBase: NEW, acceptLoss: 'no archive'});
  assert.deepEqual(auth.losses.map(l => [l.log, l.signedSize, l.restoredSize]).sort(), [[id('alpha'), 6, null], [id('beta'), 4, null]].sort());
});
