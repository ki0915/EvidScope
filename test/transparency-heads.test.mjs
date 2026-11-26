// Heads rows store only the entries that changed (tlog_heads_entries); the signed heads leaf, its proofs and the
// exported evidence are unchanged, and legacy rows with a full JSON entry list keep verifying.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createPublicKey} from 'node:crypto';
import {verifyBundle} from '../src/crypto.mjs';
import * as T from '../src/tlog.mjs';
import {headsRow, verifyHeadsRow} from '../src/transparency.mjs';
import {BASE, tamper, transparencyFixture} from './support/transparency-fixture.mjs';

const hOrigin = T.headsOrigin(BASE);
const stored = (s, idx) => s.store.db
  .prepare('SELECT COUNT(*) n, COALESCE(SUM(length(log)+length(root)+16),0) bytes FROM tlog_heads_entries WHERE origin=? AND idx=?').get(hOrigin, idx);
const rowEntries = (s, idx) => s.store.db.prepare('SELECT entries FROM tlog_heads WHERE origin=? AND idx=?').get(hOrigin, idx).entries;
const verified = (s, f, idx) => verifyHeadsRow(headsRow(s.store.db, hOrigin, idx), hOrigin, T.noteVerifier(T.logVkey(hOrigin, createPublicKey(f.privateKey))));

test('heads rows grow with the tenants that changed, not with all tenants', async t => {
  const f = await transparencyFixture(t, {witness: false});
  const s = await f.open('enforce');
  const tenants = ['alpha', 'beta', ...Array.from({length: 298}, (_, i) => `t${String(i).padStart(3, '0')}`)];
  s.store.transaction(() => { for (const tenant of tenants) s.store.append(tenant, 'note', {}, 'test'); });
  await s.transparency.pump();
  assert.equal(stored(s, 0).n, tenants.length);
  const full = Buffer.byteLength(T.canonicalJson(verified(s, f, 0).entries));
  for (const [idx, changed] of [[1, 1], [2, 5], [3, 1]]) {
    s.store.transaction(() => { for (const tenant of tenants.slice(0, changed)) s.store.append(tenant, 'note', {idx}, 'test'); });
    await s.transparency.pump();
    assert.equal(s.transparency.status().heads.size, idx + 1);
    assert.equal(rowEntries(s, idx), '');
    const row = stored(s, idx);
    assert.equal(row.n, changed);
    assert.ok(row.bytes * 20 < full, `${row.bytes} bytes stored for ${changed} changed of ${tenants.length} tenants (full list ${full} bytes)`);
    const v = verified(s, f, idx);
    assert.equal(v.entries.length, tenants.length);
    assert.equal(v.entries.find(e => e.log === T.tenantOrigin(BASE, 'alpha')).size, s.store._tlogRow('alpha').size);
  }
  // Export evidence and its offline verification are unchanged.
  const exported = await f.call(s, '/api/export');
  assert.equal(exported.transparency.heads.leafIndex, 3);
  const result = verifyBundle(exported, f.publicKey, undefined, {transparency: {originBase: BASE, require: true}});
  assert.equal(result.transparency.heads.witnessedTenantSize, verified(s, f, 3).entries.find(e => e.log === T.tenantOrigin(BASE, 'alpha')).size);
  assert.equal(result.transparency.heads.size, 4);
  await f.close(s);
  const again = await f.open('enforce');
  assert.equal(again.transparency.status().startup.ok, true);
});

test('legacy heads rows with a full entry list keep verifying and the first normalized row seeds every entry', async t => {
  const f = await transparencyFixture(t, {witness: false});
  let s = await f.open('enforce');
  f.write(s, 'alpha', 2);
  f.write(s, 'beta', 1);
  await f.close(s);
  // Rows written by an earlier build: full canonical JSON list per row.
  tamper(f.dataDir, db => {
    const state = db.prepare('SELECT origin,size,root FROM tlog_state').all();
    const entries = T.sortHeadsEntries(state.map(r => T.headsEntry(r.origin, r.size, Buffer.from(r.root))));
    const leaf = T.headsLeafHash(T.headsLeafContent(entries)), root = T.frontierRoot(T.frontierAppend([], 0, leaf));
    const note = T.signNote(T.formatCheckpoint({origin: hOrigin, size: 1, root}), T.noteSigner(hOrigin, f.privateKey));
    db.prepare('INSERT INTO tlog_heads VALUES(?,?,?,?,?,?,?)').run(hOrigin, 0, leaf, T.peaksToBlob([]), T.canonicalJson(entries), note, 'legacy');
  });
  s = await f.open('enforce');
  assert.equal(s.transparency.status().heads.size, 1);
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  assert.deepEqual([rowEntries(s, 1), stored(s, 1).n], ['', 2]);
  f.write(s, 'beta', 1);
  await s.transparency.pump();
  assert.deepEqual([rowEntries(s, 2), stored(s, 2).n], ['', 1]);
  for (const idx of [0, 1, 2]) assert.equal(verified(s, f, idx).entries.length, 2);
  const exported = await f.call(s, '/api/export', 'beta');
  assert.equal(verifyBundle(exported, f.publicKey, undefined, {transparency: {originBase: BASE, require: true}}).transparency.heads.leafIndex, 2);
  await f.close(s);
  s = await f.open('enforce');
  assert.equal(s.transparency.status().startup.ok, true);
  await f.close(s);
  // Normalized entries are bound to the signed leaf like the JSON list was.
  tamper(f.dataDir, db => db.prepare('UPDATE tlog_heads_entries SET root=? WHERE idx=2').run('ab'.repeat(32)));
  await assert.rejects(f.open('enforce'), /Truncated or inconsistent heads log: leaf differs from its entries/);
});
