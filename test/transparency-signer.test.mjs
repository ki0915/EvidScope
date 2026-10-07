// The vault with a heads signer (src/signer.mjs, docs/signer.md): the signer signs every heads leaf after its own policy check,
// witnesses accept only its key for the heads origin, and verifiers that pin it get rollbackCheckedAgainst 'vault_host'.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {readFileSync, rmSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {setTimeout as delay} from 'node:timers/promises';
import {promisify} from 'node:util';
import {verifyBundle} from '../src/crypto.mjs';
import * as T from '../src/tlog.mjs';
import {createSignerClient} from '../src/signer-client.mjs';
import {createAuthorization, signerHead as storedHead} from '../src/signer.mjs';
import {headsRow, headsSize, normalizeTransparencyConfig, transparencyPinPath} from '../src/transparency.mjs';
import {createVaultBackup, createVaultRecoveryFrontier, restoreVaultBackup} from '../src/vault-recovery.mjs';
import {epochAuthorization, handoverAuthorization} from '../scripts/signer.mjs';
import {epochClaims, headsCheckpoint} from '../scripts/transparency.mjs';
import {BASE, principals, replaceDatabase, snapshot, tamper, transparencyFixture} from './support/transparency-fixture.mjs';
import {headsSigner, signerKeys} from './support/heads-signer.mjs';

const HEADS = T.headsOrigin(BASE);
async function setup(t, {genesis = true, mode = 'enforce', config = {}} = {}) {
  const keys = signerKeys(BASE), f = await transparencyFixture(t, {headsKeys: [keys.vkey]});
  const signer = await headsSigner(t, {base: BASE, keys, genesis});
  const cfg = f.config(mode, {signer: signer.config, ...config});
  return {f, signer, cfg, open: (extra = {}) => f.open(mode, {cfg, ...extra})};
}
const policy = (f, extra = {}) => ({witnesses: [f.w.vkey], quorum: 1, originBase: BASE, require: true, ...extra});
const headsRows = s => s.store.db.prepare('SELECT idx,note FROM tlog_heads WHERE origin=? ORDER BY idx').all(HEADS);
const signerHead = async signer => (await createSignerClient({socket: signer.socket}).head(HEADS)).body;
const audit = signer => readFileSync(join(signer.stateDir, 'audit.log'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
const refusedStart = (f, mode, cfg) => f.open(mode, {cfg}).then(() => null, error => error.message);

// The vault host attacker's next heads leaf: the database's newest leaf with `change` applied to its entries, signed by the vault key,
// with the consistency proof a witness needs and the leaves before it. insert: also store it as the next row of the database heads log.
function vaultSignedLeaf(dataDir, key, change = entries => entries, {insert = false} = {}) {
  const db = new DatabaseSync(join(dataDir, 'evidence.db'), {readOnly: true});
  let n, row, leaves;
  try {
    n = headsSize(db, HEADS);
    row = headsRow(db, HEADS, n - 1);
    leaves = db.prepare('SELECT leaf FROM tlog_heads WHERE origin=? ORDER BY idx').all(HEADS).map(r => Buffer.from(r.leaf));
  } finally { db.close(); }
  const peaks = T.frontierAppend(T.blobToPeaks(row.peaks, n - 1), n - 1, Buffer.from(row.leaf));
  const sorted = T.sortHeadsEntries(change(JSON.parse(row.entries))), leaf = T.headsLeafHash(T.headsLeafContent(sorted));
  const note = T.signNote(T.formatCheckpoint({origin: HEADS, size: n + 1, root: T.frontierRoot(T.frontierAppend(peaks, n, leaf))}), T.noteSigner(HEADS, key));
  if (insert) {
    const values = [HEADS, n, leaf, T.peaksToBlob(peaks), T.canonicalJson(sorted), note, 'x'];
    tamper(dataDir, w => w.prepare('INSERT INTO tlog_heads VALUES(?,?,?,?,?,?,?)').run(...values));
  }
  return {size: n, root: T.frontierRoot(peaks), entries: sorted, note, proof: T.consistencyProofFromFrontier(n, peaks, [leaf]), leaves: [...leaves, leaf]};
}

test('the heads signer signs every heads leaf; exports pinned to its key are checked against a vault host compromise', async t => {
  const {f, signer, open} = await setup(t);
  const s = await open();
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  f.write(s, 'beta', 2);
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const rows = headsRows(s), signerV = T.noteVerifier(signer.vkey);
  assert.equal(rows.length, 2);
  // Every heads checkpoint carries the signer's signature and not the vault key's.
  for (const r of rows) {
    const sigs = T.openNote(r.note, [signerV]).sigs;
    assert.deepEqual(sigs.map(x => x.name), [HEADS]);
    assert.throws(() => T.openNote(r.note, [T.noteVerifier(T.logVkey(HEADS, f.publicKey))]), /no known signature|signature/);
  }
  const status = s.transparency.status();
  assert.equal(status.signer.status, 'consistent');
  assert.equal(status.signer.size, 2);
  assert.equal(status.heads.signedBy, signer.vkey);
  assert.equal(status.witnesses[0].status, 'consistent');
  // Each tenant checkpoint a signed leaf names keeps its frontier, so the next growth proof starts there.
  const kept = s.store.db.prepare('SELECT origin,size FROM tlog_checkpoints ORDER BY origin,size').all().map(r => `${r.origin}@${r.size}`);
  const named = s.store.db.prepare('SELECT log,size FROM tlog_heads_entries WHERE origin=? ORDER BY log,size').all(HEADS).map(r => `${r.log}@${r.size}`);
  assert.deepEqual(kept, named);
  assert.equal(kept.filter(k => k.startsWith(T.tenantOrigin(BASE, 'alpha'))).length, 2);

  const exported = await f.call(s, '/api/export');
  assert.equal(exported.transparency.heads.logVkey, signer.vkey);
  const pinned = verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey]})}).transparency;
  assert.equal(pinned.rollbackCheckedAgainst, 'vault_host');
  assert.deepEqual([pinned.heads.signedBy, pinned.heads.headsKeyPinned, pinned.heads.headsKey], ['heads_key', true, signer.vkey]);
  verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey], requireHeadsSigner: true})});
  // The key the evidence carries proves nothing by itself: without --heads-key the anchor binds database tamper only.
  const unpinned = verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f)}).transparency;
  assert.equal(unpinned.rollbackCheckedAgainst, 'database_tamper');
  assert.deepEqual([unpinned.heads.signedBy, unpinned.heads.headsKeyPinned], ['heads_key', false]);
  assert.throws(() => verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {requireHeadsSigner: true})}), /needs a pinned heads key/);
  // A different pinned heads key rejects the checkpoint outright.
  const other = signerKeys(BASE).vkey;
  assert.throws(() => verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [other]})}),
    /signed by a key other than the vault key and the pinned heads keys/);
  const integrity = await f.call(s, '/api/integrity');
  assert.equal(integrity.valid, true, integrity.error);
  assert.equal(integrity.transparency.rollbackCheckedAgainst, 'vault_host');
  assert.ok(integrity.verificationScope.checks.includes('heads_signer'));
  // The signer's own record agrees with the vault.
  const head = await signerHead(signer);
  assert.deepEqual([head.size, head.root], [2, T.parseCheckpoint(T.noteText(rows[1].note)).root.toString('hex')]);
});

// A connection that loses the answer of the next signature: the signer signed, the vault never heard back.
function lossy(socket) {
  const real = createSignerClient({socket});
  let lose = false;
  const signHeads = async request => {
    const answer = await real.signHeads(request);
    if (!lose) return answer;
    lose = false;
    throw Error(`heads signer at ${socket}: ECONNRESET`);
  };
  return {client: {...real, signHeads}, loseNext: () => { lose = true; }};
}
test('a heads checkpoint the vault never received is adopted from the signer, at runtime and after a restart', async t => {
  const {f, signer, open} = await setup(t);
  const link = lossy(signer.socket), s = await open({signerClient: link.client});
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  link.loseNext();
  f.write(s, 'beta', 1);
  await s.transparency.pump();
  assert.equal(s.transparency.status().signer.status, 'unreachable');
  assert.deepEqual([headsRows(s).length, (await signerHead(signer)).size], [1, 2]);
  // The next request is out of sync with the signer, whose newest leaf appends to the local log: the vault stores it.
  await s.transparency.pump();
  let status = s.transparency.status();
  assert.deepEqual([status.heads.size, status.signer.status, status.violations, status.witnesses[0].status], [2, 'consistent', [], 'consistent']);
  // Again, but the vault stops first: the startup check accepts the one leaf the signer is ahead and the first round stores it.
  link.loseNext();
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  await f.close(s);
  assert.equal((await signerHead(signer)).size, 3);
  const again = await open();
  status = again.transparency.status();
  assert.deepEqual([status.startup.signer, status.heads.size, status.violations], [{known: true, status: 'active', size: 3, pending: true}, 2, []]);
  await again.transparency.pump();
  status = again.transparency.status();
  assert.deepEqual([status.heads.size, status.signer.status, status.violations], [3, 'consistent', []]);
  assert.equal(audit(signer).filter(e => e.event === 'signed').length, 3);
});

test('startup refuses a database the heads signer has moved past, and heads rows the signer never signed', async t => {
  const {f, signer, open, cfg} = await setup(t);
  const s = await open();
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  snapshot(f.dataDir, join(f.root, 'older.db'));
  for (const n of [1, 2]) {
    f.write(s, 'alpha', n);
    await s.transparency.pump();
  }
  assert.equal(s.transparency.status().heads.size, 3);
  await f.close(s);
  // The vault key signs one more heads row into the database, past the signer.
  vaultSignedLeaf(f.dataDir, f.privateKey, entries => entries, {insert: true});
  assert.match(await refusedStart(f, 'enforce', cfg), /database holds heads size 4 beyond the 3 the heads signer signed/);
  // Monitor mode starts and reports it; the vault key cannot get the extra row cosigned, and the signer does not continue it.
  const monitor = await f.open('monitor', {cfg: f.config('monitor', {signer: signer.config})});
  const beyond = /the database holds heads size 4 beyond the 3 the heads signer signed/;
  assert.ok(monitor.transparency.status().violations.some(v => beyond.test(v.message)));
  f.write(monitor, 'alpha', 1);
  await monitor.transparency.pump();
  assert.deepEqual([monitor.transparency.status().signer.status, monitor.transparency.status().witnesses[0].status], ['out_of_sync', 'untrusted']);
  await f.close(monitor);
  // An older copy of the database (with its pin removed, as the vault host can) is behind what the signer signed.
  rmSync(transparencyPinPath(f.dataDir));
  replaceDatabase(f.dataDir, join(f.root, 'older.db'));
  assert.match(await refusedStart(f, 'enforce', cfg), /Ledger heads log \(size 1\) is behind the heads signer, which signed heads size 3 \(rollback\)/);
  assert.equal((await signerHead(signer)).size, 3);
});

test('without an authorization the vault waits for the operator, and continues once the signer has one', async t => {
  const {f, signer, open} = await setup(t, {genesis: false, config: {refreshSeconds: 1}});
  const s = await open();
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  let status = s.transparency.status();
  assert.deepEqual([status.signer.status, status.heads.size, status.violations, status.quarantine], ['unauthorized', 0, [], null]);
  assert.match(status.signer.message, /no authorization for the new heads origin vault\.test\/evidscope\/heads/);
  createAuthorization(signer.stateDir, {kind: 'genesis', origin: HEADS, predecessor: null});
  await s.transparency.pump();
  assert.equal(s.transparency.status().signer.status, 'unauthorized', 'a refusal is asked again after refreshSeconds, not every round');
  await delay(1100);
  await s.transparency.pump();
  status = s.transparency.status();
  assert.deepEqual([status.signer.status, status.heads.size, status.witnesses[0].status], ['consistent', 1, 'consistent']);
  assert.deepEqual(audit(signer).filter(e => e.event === 'refused').map(e => e.reason), ['unauthorized']);
});

test('a policy refusal of the signer is a violation that quarantines an enforce-mode vault', async t => {
  const {f, signer, open} = await setup(t);
  const real = createSignerClient({socket: signer.socket});
  let answer = null;
  const s = await open({signerClient: {...real, signHeads: request => (answer ? answer(request) : real.signHeads(request))}});
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  answer = () => ({httpStatus: 422, body: {status: 'refused', reason: 'rollback', message: 'heads leaf shrinks tenant log x from 5 to 3 (rollback)'}});
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  const status = s.transparency.status();
  assert.deepEqual([status.signer.status, status.quarantine?.kind, status.heads.size], ['rollback', 'rollback', 1]);
  assert.match(status.violations.at(-1).message, /Heads signer refused heads size 2: heads leaf shrinks tenant log x from 5 to 3 \(rollback\)/);
});

test('a signed checkpoint other than the leaf the vault sent is not stored', async t => {
  const {f, signer, open} = await setup(t, {mode: 'monitor'});
  const real = createSignerClient({socket: signer.socket});
  let answer = null;
  const s = await open({signerClient: {...real, signHeads: request => (answer ? answer(request) : real.signHeads(request))}});
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  // Signed by the signer key, but for another root (a confused or replaced signer): rejected before anything is written.
  answer = request => ({httpStatus: 200, body: {status: 'signed', note: T.signNote(T.formatCheckpoint({origin: HEADS, size: request.previous.size + 1,
    root: randomBytes(32)}), T.noteSigner(HEADS, signer.keys.privateKey))}});
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  const status = s.transparency.status();
  assert.equal(status.heads.size, 1);
  assert.equal(headsRows(s).length, 1);
  assert.match(status.violations.at(-1).message, /answered with a checkpoint other than heads size 2 of the leaf the vault sent/);
  // A note signed by another key is no signature of the signer at all.
  answer = request => ({httpStatus: 200, body: {status: 'signed', note: T.signNote(T.formatCheckpoint({origin: HEADS, size: request.previous.size + 1,
    root: request.previous.size ? randomBytes(32) : T.EMPTY_ROOT}), T.noteSigner(HEADS, f.privateKey))}});
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  assert.equal(headsRows(s).length, 1);
});

test('a vault-key heads log moves to the heads signer from its witnessed checkpoint; old exports verify as before', async t => {
  const keys = signerKeys(BASE), f = await transparencyFixture(t);
  const legacy = f.config('enforce'), vaultVkey = T.logVkey(HEADS, f.publicKey);
  let s = await f.open('enforce', {cfg: legacy});
  f.write(s, 'alpha', 3);
  f.write(s, 'beta', 1);
  await s.transparency.pump();
  const old = await f.call(s, '/api/export'), before = verifyBundle(old, f.publicKey, undefined, {transparency: policy(f)}).transparency;
  assert.deepEqual([before.rollbackCheckedAgainst, before.heads.signedBy], ['database_tamper', undefined]);
  await f.close(s);
  // Operator: the newest heads checkpoint of the stopped vault with its cosignature, a handover authorization on the signer, and the
  // signer's key registered at the witness beside the vault key.
  const checkpoint = await headsCheckpoint({config: legacy, key: f.privateKey, dataDir: f.dataDir});
  assert.deepEqual([checkpoint.size, checkpoint.cosignatures], [1, 1]);
  const signer = await headsSigner(t, {base: BASE, keys, genesis: false});
  const auth = handoverAuthorization({stateDir: signer.stateDir, checkpoint: checkpoint.checkpoint, vaultKey: f.publicKey, witnesses: [f.w.vkey]});
  assert.deepEqual([auth.kind, auth.predecessor.size], ['handover', 1]);
  f.w.addLog(HEADS, signer.vkey);
  const cfg = f.config('enforce', {signer: signer.config});
  s = await f.open('enforce', {cfg});
  assert.deepEqual(s.transparency.status().startup.signer, {known: false});
  // The first signer leaf repeats the vault-key leaf (re-anchored under the signer key), then the heads log grows as usual.
  await s.transparency.pump();
  let status = s.transparency.status();
  assert.deepEqual([status.heads.size, status.heads.signedBy, status.signer.status, status.witnesses[0].status], [2, signer.vkey, 'consistent', 'consistent']);
  assert.equal(audit(signer).find(e => e.event === 'signed').authorization.kind, 'handover');
  f.w.removeLogKey(HEADS, vaultVkey);
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  status = s.transparency.status();
  assert.deepEqual([status.heads.size, status.witnesses[0].status], [3, 'consistent']);
  const fresh = await f.call(s, '/api/export');
  assert.equal(verifyBundle(fresh, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey]})}).transparency.rollbackCheckedAgainst,
    'vault_host');
  // Exports from before the handover verify exactly as they did, and still do once a verifier pins the heads key.
  assert.deepEqual(verifyBundle(old, f.publicKey, undefined, {transparency: policy(f)}), verifyBundle(old, f.publicKey, undefined, {transparency: policy(f)}));
  assert.deepEqual(verifyBundle(old, f.publicKey, undefined, {transparency: policy(f)}).transparency, before);
  const oldPinned = verifyBundle(old, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey]})}).transparency;
  assert.deepEqual([oldPinned.rollbackCheckedAgainst, oldPinned.heads.signedBy, oldPinned.heads.headsKeyPinned], ['database_tamper', 'vault_key', false]);
  assert.throws(() => verifyBundle(old, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey], requireHeadsSigner: true})}),
    /signed by the vault key, not by the pinned heads key/);
  // The vault key no longer gets a heads checkpoint cosigned, and restarts probe the witness with the signer's checkpoint.
  await f.close(s);
  const forged = vaultSignedLeaf(f.dataDir, f.privateKey);
  const answer = await T.postAddCheckpoint(f.ws.url, T.addCheckpointBody(forged.size, forged.proof, forged.note));
  assert.equal(answer.status, 403);
  s = await f.open('enforce', {cfg});
  assert.deepEqual([s.transparency.status().witnesses[0].status, s.transparency.status().violations], ['consistent', []]);
});

test('a vault host attacker gets no cosigned heads checkpoint that rolls a tenant back once the signer holds the heads key', async t => {
  const {f, signer, open} = await setup(t);
  const s = await open();
  f.write(s, 'alpha', 2);
  f.write(s, 'beta', 3);
  await s.transparency.pump();
  const older = await f.call(s, '/api/export', 'beta');
  f.write(s, 'beta', 2);
  await s.transparency.pump();
  await f.close(s);
  const beta = T.tenantOrigin(BASE, 'beta'), was = T.parseCheckpoint(T.noteText(older.transparency.checkpoint));
  const rollback = entries => entries.map(e => (e.log === beta ? T.headsEntry(beta, was.size, was.root) : e));
  const forged = vaultSignedLeaf(f.dataDir, f.privateKey, rollback);
  // The witness knows only the signer's key for the heads origin, and the signer refuses the leaf.
  assert.equal((await T.postAddCheckpoint(f.ws.url, T.addCheckpointBody(forged.size, forged.proof, forged.note))).status, 403);
  const refused = await createSignerClient({socket: signer.socket}).signHeads({origin: HEADS, previous: {size: forged.size,
    root: forged.root.toString('hex')}, leaf: {entries: forged.entries}});
  assert.deepEqual([refused.httpStatus, refused.body.reason], [422, 'rollback']);
  assert.match(refused.body.message, new RegExp(`shrinks tenant log ${beta.replace(/[./]/g, '\\$&')} from ${was.size + 2} to ${was.size}`));
  // A witness that still accepts the vault key (handover not finished) cosigns it, yet a verifier that pins the heads key refuses
  // the older export with that anchor: the vault key signed it.
  f.w.addLog(HEADS, T.logVkey(HEADS, f.publicKey));
  const cosigned = await T.postAddCheckpoint(f.ws.url, T.addCheckpointBody(forged.size, forged.proof, forged.note));
  assert.equal(cosigned.status, 200);
  const i = forged.entries.findIndex(e => e.log === beta);
  const heads = {origin: HEADS, checkpoint: forged.note + T.parseCosignatureResponse(cosigned.body).join(''), leafIndex: forged.size,
    leafProof: T.inclusionProof(forged.leaves, forged.size).map(T.b64),
    leaf: T.headsLeafContent(forged.entries), entry: forged.entries[i], entryIndex: i,
    entryProof: T.inclusionProof(forged.entries.map(T.headsEntryLeaf), i).map(T.b64)};
  const replayed = {...older, transparency: {...older.transparency, heads}};
  assert.equal(verifyBundle(replayed, f.publicKey, undefined, {transparency: policy(f)}).transparency.rollbackCheckedAgainst, 'database_tamper');
  assert.throws(() => verifyBundle(replayed, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey], requireHeadsSigner: true})}),
    /signed by the vault key, not by the pinned heads key/);
  assert.notEqual(verifyBundle(replayed, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey]})}).transparency.rollbackCheckedAgainst,
    'vault_host');
});

test('a restore epoch moves the heads signer to the new origin base from the restored prefixes the operator authorized', async t => {
  const {f, signer, cfg} = await setup(t, {config: {refreshSeconds: 1}});
  const rawOld = {origin: BASE, mode: 'enforce', witnesses: [{vkey: f.w.vkey, url: f.ws.url}], intervalMs: 100, timeoutMs: 2000, refreshSeconds: 1,
    signer: signer.config};
  const s = await f.open('enforce', {cfg});
  f.write(s, 'alpha', 3);
  f.write(s, 'beta', 2);
  await s.transparency.pump();
  const backupDir = join(f.root, 'backup'), serviceConfig = {principals};
  const anchor = await createVaultBackup({dataDir: f.dataDir, backupDir, privateKey: f.privateKey, publicKey: f.publicKey});
  const archived = s.store._tlogRow('alpha').size;
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const latest = await createVaultRecoveryFrontier({dataDir: f.dataDir, privateKey: f.privateKey, publicKey: f.publicKey, anchor, config: serviceConfig,
    transparency: rawOld});
  assert.equal(latest.transparency.headsSize, 2);
  await f.close(s);
  const NEW = 'vault.test/evidscope-s2', rawNew = {...rawOld, origin: NEW}, head = storedHead(signer.stateDir, HEADS);
  const restore = (name, transparency) => restoreVaultBackup({backupDir, restoreDir: join(f.root, name), privateKey: f.privateKey, publicKey: f.publicKey,
    anchor, frontier: latest.frontier, frontierAnchor: latest.anchor, config: serviceConfig, transparency});
  // The signer signed heads size 2; the archive holds 1. Its head alone shows the gap; the frontier companion (size 2) covers it.
  await assert.rejects(restore('stale', {config: rawNew, previous: rawOld, signerHead: head}),
    /cannot establish freshness for vault\.test\/evidscope\/heads: the previous origin was signed up to heads size 2, beyond the archive \(1\)/);
  const receipt = await restore('epoch', {config: rawNew, previous: rawOld, signerHead: head, frontierTransparency: latest.transparency});
  assert.deepEqual([receipt.freshnessEstablished, receipt.transparency.signerHeadsSize, receipt.transparency.logVkey],
    [true, 2, T.logVkey(T.headsOrigin(NEW), signer.keys.publicKey)]);
  assert.match(receipt.transparency.signerAuthorization,
    /authorize-epoch --state-dir SIGNER_STATE --from-base vault\.test\/evidscope --to-base vault\.test\/evidscope-s2/);
  const dir = join(f.root, 'epoch'), newCfg = normalizeTransparencyConfig(rawNew, {dataDir: dir});
  f.w.addLog(newCfg.headsOrigin, newCfg.signer.vkey);
  const restored = await f.open('enforce', {dir, cfg: newCfg});
  await restored.transparency.pump();
  let status = restored.transparency.status();
  assert.deepEqual([status.signer.status, status.signer.epochFrom, status.heads.size], ['unauthorized', BASE, 0]);
  // The operator authorizes exactly the restored prefixes the epoch records state; alpha loses what came after the archive.
  const claims = epochClaims({config: newCfg, dataDir: dir}), alpha = T.tenantLogId('alpha');
  assert.deepEqual([claims.fromBase, claims.toBase, claims.restored[alpha].size], [BASE, NEW, archived]);
  const auth = epochAuthorization({stateDir: signer.stateDir, fromBase: BASE, toBase: NEW, restored: claims});
  assert.deepEqual(auth.losses, [{log: alpha, signedSize: archived + 2, restoredSize: archived}]);
  await delay(1100);
  await restored.transparency.pump();
  status = restored.transparency.status();
  assert.deepEqual([status.signer.status, status.heads.size, status.witnesses[0].status, status.violations], ['consistent', 1, 'consistent', []]);
  const line = audit(signer).find(e => e.event === 'signed' && e.origin === newCfg.headsOrigin);
  assert.deepEqual([line.authorization.kind, line.retired, line.lost], ['epoch', HEADS, [{log: alpha, signedSize: archived + 2, restoredSize: archived}]]);
  assert.equal(storedHead(signer.stateDir, HEADS).status, 'retired');
  // A verifier that pinned the signer key (under the old origin's name) gets 'vault_host' once it pins the new origin base.
  const exported = await f.call(restored, '/api/export');
  const pinnedNew = verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {originBase: NEW, headsKeys: [signer.vkey]})}).transparency;
  assert.equal(pinnedNew.rollbackCheckedAgainst, 'vault_host');
  const pinnedOld = verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey]})}).transparency;
  assert.deepEqual([pinnedOld.pinnedOriginBase, pinnedOld.rollbackCheckedAgainst], [BASE, 'database_tamper']);
  assert.throws(() => verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {headsKeys: [signer.vkey], requireHeadsSigner: true})}),
    /continues origin base vault\.test\/evidscope-s2 after a tlog epoch from the pinned vault\.test\/evidscope/);
  // The old heads origin is closed: the original vault, started again, is refused by the signer (retired) and stops in enforce mode.
  assert.match(await refusedStart(f, 'enforce', cfg), /retired vault\.test\/evidscope\/heads at a restore epoch .* \(fork\)/);
});

// Asynchronous: the signer and the development witness answer from this process's event loop.
const run = async (script, args) => {
  const r = await promisify(execFile)(process.execPath, [script, ...args], {encoding: 'utf8', windowsHide: true, timeout: 30000})
    .then(x => ({...x, code: 0}), error => ({stdout: error.stdout || '', stderr: error.stderr || '', code: error.code}));
  return {status: r.code, out: r.code === 0 && r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};
test('the CLIs: verify.mjs pins the heads key and can require it; transparency.mjs registers and reports the signer', async t => {
  const {f, signer, open} = await setup(t);
  const s = await open();
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const file = name => join(f.root, name), keyPath = file('trusted.pem'), privatePath = file('vault.pem');
  writeFileSync(keyPath, f.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(privatePath, f.privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  writeFileSync(file('export.json'), JSON.stringify(await f.call(s, '/api/export')));
  const flags = [file('export.json'), keyPath, '--witness', f.w.vkey, '--quorum', '1', '--origin-base', BASE];
  let r = await run('scripts/verify.mjs', [...flags, '--heads-key', signer.vkey, '--require-heads-signer']);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual([r.out.transparency.rollbackCheckedAgainst, r.out.transparency.heads.headsKeyPinned], ['vault_host', true]);
  r = await run('scripts/verify.mjs', flags);
  assert.deepEqual([r.status, r.out.transparency.rollbackCheckedAgainst], [0, 'database_tamper']);
  r = await run('scripts/verify.mjs', [...flags, '--require-heads-signer']);
  assert.equal(r.status, 1);
  assert.match(r.err, /needs a pinned heads key \(--heads-key\)/);
  r = await run('scripts/verify.mjs', [...flags, '--heads-key', signerKeys(BASE).vkey]);
  assert.equal(r.status, 1);
  assert.match(r.err, /signed by a key other than the vault key and the pinned heads keys/);

  const config = file('transparency.json');
  writeFileSync(config, JSON.stringify({origin: BASE, mode: 'enforce', witnesses: [{vkey: f.w.vkey, url: f.ws.url}], signer: signer.config}));
  r = await run('scripts/transparency.mjs', ['vkeys', '--config', config, '--key', privatePath]);
  assert.deepEqual([r.out.logVkey, r.out.vaultLogVkey], [signer.vkey, T.logVkey(HEADS, f.publicKey)]);
  r = await run('scripts/transparency.mjs', ['witnessctl', '--config', config, '--key', privatePath, '--db', '/srv/witness.db']);
  assert.ok(r.out.includes(`witnessctl add-key -db /srv/witness.db -origin ${HEADS} -key ${signer.vkey}`), r.out);
  r = await run('scripts/signer.mjs', ['vkey', '--state-dir', signer.stateDir, '--origin-base', BASE]);
  assert.equal(r.out.trim(), signer.vkey);
  await f.close(s);
  r = await run('scripts/transparency.mjs', ['status', '--config', config, '--key', privatePath, '--data-dir', f.dataDir, '--probe']);
  assert.equal(r.status, 0, r.err + JSON.stringify(r.out));
  assert.deepEqual([r.out.ok, r.out.signer], [true, {known: true, status: 'active', size: 1}]);
});
