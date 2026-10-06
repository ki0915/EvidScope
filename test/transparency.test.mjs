import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdirSync, readFileSync, rmSync} from 'node:fs';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';
import {verifyBundle} from '../src/crypto.mjs';
import * as T from '../src/tlog.mjs';
import {transparencyPinPath} from '../src/transparency.mjs';
import {createWitness} from '../scripts/witness.mjs';
import {BASE, ledgerCount, principals, replaceDatabase, snapshot, tamper, transparencyFixture, wipeTenant} from './support/transparency-fixture.mjs';

const UNANCHORED = ['rollback', 'truncation', 'tenant_removal'];
const tableCount = (service, table) => service.store.db.prepare(`SELECT COUNT(*) n FROM ${table}`).get().n;

test('off mode keeps the vault unchanged and reports integrity as unanchored', async t => {
  const f = await transparencyFixture(t, {witness: false});
  const direct = createService({dataDir: f.dataDir, key: f.privateKey, config: {principals}});
  assert.equal(direct.transparency.mode, 'off');
  direct.store.close();
  const s = await f.open('off');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  for (const table of ['tlog_state', 'tlog_heads', 'tlog_cosignatures']) assert.equal(tableCount(s, table), 0);
  const exported = await f.call(s, '/api/export');
  assert.equal(exported.transparency, undefined);
  assert.equal(verifyBundle(exported, f.publicKey).transparency, undefined);
  const integrity = await f.call(s, '/api/integrity');
  assert.equal(integrity.valid, true);
  assert.equal(integrity.rollbackChecked, false);
  assert.equal(integrity.transparency, undefined);
  assert.deepEqual(integrity.verificationScope.notChecked, UNANCHORED);
  assert.equal(existsSync(transparencyPinPath(f.dataDir)), false);
});

test('legacy ledgers are rebuilt from signed history and witnessed exports verify offline with prefix semantics', async t => {
  const f = await transparencyFixture(t);
  const legacy = await f.open('off');
  f.write(legacy, 'alpha', 5);
  await f.close(legacy);
  const s = await f.open('enforce');
  const leaves = s.store.db.prepare('SELECT hash FROM ledger WHERE tenant=? ORDER BY seq').all('alpha').map(r => T.recordLeaf(r.hash));
  const row = s.store._tlogRow('alpha'), early = row.note;
  assert.equal(row.size, leaves.length);
  assert.ok(T.mth(leaves).equals(Buffer.from(row.root)));
  assert.equal(s.store.tlogCheckpoint('alpha').note, early);
  f.write(s, 'alpha', 4);
  await s.transparency.pump();
  const exported = await f.call(s, '/api/export'), policy = {witnesses: [f.w.vkey], quorum: 1, originBase: BASE, require: true};
  assert.equal(exported.format, 'evidscope-export-v2');
  assert.equal(exported.transparency.format, 'evidscope-transparency-v1');
  const verified = verifyBundle(exported, f.publicKey, undefined, {transparency: {...policy, minimumCheckpoint: early}});
  assert.equal(verified.rollbackChecked, true);
  assert.equal(verified.transparency.heads.quorumMet, true);
  assert.equal(verified.transparency.minimumCheckpoint.satisfied, true);
  assert.equal(verified.transparency.size, exported.checkpoint.count);
  assert.equal(verifyBundle(exported, f.publicKey, undefined, {transparency: {minimumCheckpoint: exported.checkpoint}}).rollbackChecked, true);
  // A later checkpoint pinned by the verifier exposes an older export as rollback; a foreign witness cannot meet the quorum.
  f.write(s, 'alpha', 2);
  const later = s.store._tlogRow('alpha').note;
  assert.throws(() => verifyBundle(exported, f.publicKey, undefined, {transparency: {...policy, minimumCheckpoint: later}}), /rollback or truncation/);
  const other = createWitness({dir: join(f.root, 'other'), name: 'witness.test/other'});
  t.after(() => other.close());
  assert.throws(() => verifyBundle(exported, f.publicKey, undefined, {transparency: {...policy, witnesses: [other.vkey]}}), /quorum not met/);
  const dropped = {...exported, records: exported.records.slice(0, -1), checkpoint: exported.checkpoint};
  assert.throws(() => verifyBundle(dropped, f.publicKey, undefined, {transparency: policy}), /Truncated or inconsistent/);
  const forged = structuredClone(exported);
  forged.transparency.heads.entry.root = '0'.repeat(64);
  assert.throws(() => verifyBundle(forged, f.publicKey, undefined, {transparency: policy}), /inclusion proof failed/);
  // Live integrity is anchored by the fresh witness quorum, and the pin follows each cosigned round.
  await s.transparency.pump();
  const integrity = await f.call(s, '/api/integrity');
  assert.equal(integrity.valid, true, integrity.error);
  assert.equal(integrity.rollbackChecked, true);
  assert.deepEqual(integrity.verificationScope.notChecked, []);
  assert.ok(integrity.verificationScope.checks.includes('witness_freshness'));
  assert.equal(integrity.transparency.runtime.witnesses[0].status, 'consistent');
  const pin = JSON.parse(readFileSync(transparencyPinPath(f.dataDir), 'utf8'));
  assert.equal(pin.format, 'evidscope-transparency-pin-v1');
  assert.equal(pin.size, s.transparency.status().heads.size);
  assert.equal(T.openNote(pin.checkpoint, [T.cosignatureVerifier(f.w.vkey)]).sigs.length, 1);
});

for (const anchor of ['witness', 'pin']) {
  test(`S1 full tenant wipe is refused at startup in enforce mode (${anchor} anchor)`, async t => {
    const f = await transparencyFixture(t, {witness: anchor === 'witness'});
    const s = await f.open('enforce');
    f.write(s, 'alpha', 3);
    f.write(s, 'beta', 2);
    await s.transparency.pump();
    await f.close(s);
    if (anchor === 'witness') rmSync(transparencyPinPath(f.dataDir));
    tamper(f.dataDir, db => wipeTenant(db, 'alpha'));
    await assert.rejects(f.open('enforce'), /Transparency startup check failed: .*tenant removal/);
    // Covering tracks by also deleting the heads log leaves the external anchor: witness or pin.
    tamper(f.dataDir, db => db.exec('DELETE FROM tlog_heads; DELETE FROM tlog_cosignatures;'));
    await assert.rejects(f.open('enforce'), /Transparency startup check failed: .*rollback/);
  });

  test(`S1 older database copy is refused at startup in enforce mode (${anchor} anchor)`, async t => {
    const f = await transparencyFixture(t, {witness: anchor === 'witness'});
    const legacy = await f.open('off');
    f.write(legacy, 'alpha', 2);
    await f.close(legacy);
    snapshot(f.dataDir, join(f.root, 'pre-transparency.db'));
    const s = await f.open('enforce');
    f.write(s, 'alpha', 3);
    await s.transparency.pump();
    snapshot(f.dataDir, join(f.root, 'older.db'));
    f.write(s, 'alpha', 3);
    f.write(s, 'beta', 1);
    await s.transparency.pump();
    await f.close(s);
    if (anchor === 'witness') rmSync(transparencyPinPath(f.dataDir));
    replaceDatabase(f.dataDir, join(f.root, 'older.db'));
    await assert.rejects(f.open('enforce'), /Transparency startup check failed: .*rollback/);
    replaceDatabase(f.dataDir, join(f.root, 'pre-transparency.db'));
    await assert.rejects(f.open('enforce'), /Transparency startup check failed: .*rollback/);
  });
}

test('monitor mode reports a rollback without blocking startup or writes', async t => {
  const f = await transparencyFixture(t);
  const s = await f.open('monitor');
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  snapshot(f.dataDir, join(f.root, 'older.db'));
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  await f.close(s);
  replaceDatabase(f.dataDir, join(f.root, 'older.db'));
  const restored = await f.open('monitor');
  const status = restored.transparency.status();
  assert.equal(status.quarantine, null);
  assert.ok(status.violations.some(v => v.kind === 'rollback'), JSON.stringify(status.violations));
  f.write(restored, 'alpha', 1);
  await restored.transparency.pump();
  const integrity = await f.call(restored, '/api/integrity');
  assert.equal(integrity.valid, true, integrity.error);
  assert.ok(integrity.transparency.runtime.violations.some(v => v.kind === 'rollback'));
  assert.deepEqual(integrity.verificationScope.notChecked, UNANCHORED);
  assert.ok((await f.call(restored, '/api/export')).records.length > 0);
});

test('a history re-signed with the host key is rejected by the witness (422) and quarantines the running vault', async t => {
  const f = await transparencyFixture(t);
  let s = await f.open('enforce');
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  await f.close(s);
  const forkDir = join(f.root, 'fork');
  mkdirSync(forkDir);
  snapshot(f.dataDir, join(forkDir, 'evidence.db'));
  s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const witnessed = f.w.logs()[0].size;
  await f.close(s);
  // The key holder continues the stale copy while the witness is unreachable, then the witness returns.
  f.w.setAvailable(false);
  const forked = await f.open('enforce', {dir: forkDir});
  assert.equal(forked.transparency.status().witnesses[0].status, 'unreachable');
  for (let i = 0; i <= witnessed + 1; i++) { f.write(forked, 'alpha', 1); await forked.transparency.pump(); }
  assert.ok(forked.transparency.status().heads.size > witnessed);
  assert.equal(forked.store.quarantine, null);
  f.w.setAvailable(true);
  await forked.transparency.pump();
  assert.equal(forked.transparency.status().witnesses[0].status, 'fork');
  assert.match(forked.store.quarantine?.reason || '', /\(fork\)/);
  const before = ledgerCount(forked, 'alpha');
  await assert.rejects(f.call(forked, '/api/export'), error => error.status === 503 && /Transparency quarantine/.test(error.message));
  const integrity = await f.call(forked, '/api/integrity');
  assert.equal(integrity.valid, false);
  assert.match(integrity.error, /Transparency quarantine: .*fork/);
  assert.equal(integrity.failureRecorded, false);
  assert.throws(() => forked.store.append('alpha', 'note', {}, 'test'), /Transparency quarantine/);
  assert.equal(ledgerCount(forked, 'alpha'), before);
  assert.equal(f.w.logs()[0].size, witnessed);
  await f.close(forked);
  await assert.rejects(f.open('enforce', {dir: forkDir}), /Transparency startup check failed: .*fork/);
});

test('startup refuses tenant tlog state that conflicts with the signed ledger', async t => {
  const f = await transparencyFixture(t, {witness: false});
  const s = await f.open('monitor');
  f.write(s, 'alpha', 4);
  await f.close(s);
  tamper(f.dataDir, db => db.prepare('UPDATE tlog_state SET root=? WHERE tenant=?').run(Buffer.alloc(32, 7), 'alpha'));
  await assert.rejects(f.open('monitor'), /refusing to re-seal|Truncated or inconsistent/);
  await assert.rejects(f.open('enforce'), /Transparency startup check failed: .*fork/);
});

test('development witness follows tlog-witness status codes', async t => {
  const f = await transparencyFixture(t, {witness: false});
  const w = createWitness({dir: join(f.root, 'unit-witness'), name: 'witness.test/unit', now: () => 1_800_000_000_000});
  t.after(() => w.close());
  const origin = 'log.test/unit', signer = T.noteSigner(origin, f.privateKey), logV = T.logVkey(origin, f.publicKey);
  const leaves = n => Array.from({length: n}, (_, i) => T.leafHash(Buffer.from(`leaf-${i}`)));
  const note = (size, root = T.mth(leaves(size)), who = signer) => T.signNote(T.formatCheckpoint({origin, size, root}), who);
  const post = (old, proof, n) => w.addCheckpoint(T.addCheckpointBody(old, proof, n));
  assert.equal(post(0, [], note(3)).status, 404);
  w.addLog(origin, logV);
  const stranger = T.noteSigner(origin, (await import('node:crypto')).generateKeyPairSync('ed25519').privateKey);
  assert.equal(post(0, [], note(3, undefined, stranger)).status, 403);
  assert.equal(w.addCheckpoint('old x\n\n' + note(3)).status, 400);
  assert.equal(w.addCheckpoint(`old 0\n${T.b64(leaves(1)[0])}\n\n` + note(3)).status, 422);
  assert.equal(post(0, [], T.signNote(`${origin}\n0\n${T.b64(Buffer.alloc(32, 1))}\n`, signer)).status, 422);
  const first = post(0, [], note(3));
  assert.equal(first.status, 200);
  const opened = T.openNote(note(3) + first.body, [T.noteVerifier(logV), T.cosignatureVerifier(w.vkey)]);
  assert.equal(T.cosignatureTimestamp(opened.sigs.find(sig => sig.type === T.SIG_COSIG_ED25519).raw), 1_800_000_000);
  const conflict = post(0, [], note(5));
  assert.deepEqual([conflict.status, conflict.type, conflict.body], [409, 'text/x.tlog.size', '3\n']);
  assert.equal(post(5, [], note(3)).status, 400);
  assert.equal(post(3, [], note(3, Buffer.alloc(32, 2))).status, 422);
  assert.equal(post(3, [], note(3)).status, 200);
  assert.equal(post(3, T.consistencyProof(leaves(5), 3).reverse(), note(5)).status, 422);
  assert.equal(post(3, T.consistencyProof(leaves(5), 3), note(5)).status, 200);
  assert.deepEqual(w.logs().map(l => [l.origin, l.size]), [[origin, 5]]);
});
