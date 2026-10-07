// Regression tests for the transparency anchors: the pin only advances along a consistent heads log, a missing or
// unwritable pin fails closed in enforce mode, the startup check covers the database it opens, a live tlog_state
// tamper cannot re-seal a tenant log, and every heads row after the pin is monotone per tenant log.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createService} from '../src/service.mjs';
import * as T from '../src/tlog.mjs';
import {assertTransparencyAnchors, bootstrapPin, headsRow, normalizeTransparencyConfig, probeTransparency, transparencyPinPath} from '../src/transparency.mjs';
import {BASE, principals, replaceDatabase, snapshot, tamper, transparencyFixture} from './support/transparency-fixture.mjs';

const requirements = JSON.parse(readFileSync(new URL('../data/requirements.json', import.meta.url), 'utf8'));

const ROOT = new URL('..', import.meta.url).pathname;
const run = (script, args) => new Promise(r => execFile(process.execPath, [script, ...args], {cwd: ROOT},
  (error, out, err) => r({code: error ? error.code : 0, out, err})));
const keyFile = f => {
  const file = join(f.root, 'vault.pem');
  writeFileSync(file, f.privateKey.export({format: 'pem', type: 'pkcs8'}));
  return file;
};
const configFile = (f, extra) => {
  const file = join(f.root, 'transparency.json');
  writeFileSync(file, JSON.stringify({origin: BASE, mode: 'enforce', witnesses: [], ...extra}));
  return file;
};

const pinOf = dir => JSON.parse(readFileSync(transparencyPinPath(dir), 'utf8'));

test('monitor mode never moves the pin onto a heads log that does not extend it', async t => {
  const f = await transparencyFixture(t, {witness: false});
  let s = await f.open('monitor');
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  snapshot(f.dataDir, join(f.root, 'older.db'));
  for (let i = 0; i < 3; i++) { f.write(s, 'alpha', 1); await s.transparency.pump(); }
  const pinned = pinOf(f.dataDir);
  await f.close(s);
  replaceDatabase(f.dataDir, join(f.root, 'older.db'));
  s = await f.open('monitor');
  assert.ok(s.transparency.status().violations.some(v => v.kind === 'rollback'));
  for (let i = 0; i < 6; i++) { f.write(s, 'alpha', 1); await s.transparency.pump(); }
  const status = s.transparency.status();
  assert.ok(status.heads.size > pinned.size);
  assert.deepEqual(pinOf(f.dataDir), pinned);
  assert.equal(status.pinSize, pinned.size);
  assert.equal(status.pinFrozen, true);
  assert.ok(status.violations.some(v => v.kind === 'pin' && /pin not advanced past size \d+ after: .*rollback/.test(v.message)));
  await f.close(s);
  // The anchor survives: the forked heads log is still refused.
  await assert.rejects(f.open('enforce'), /Transparency startup check failed: .*conflicts with the pinned heads checkpoint \(fork\)/);

  // A heads row rewritten underneath a running vault is caught before the pin moves past it.
  const g = await transparencyFixture(t, {witness: false});
  s = await g.open('monitor');
  g.write(s, 'alpha', 2);
  await s.transparency.pump();
  const first = pinOf(g.dataDir);
  tamper(g.dataDir, db => db.prepare('UPDATE tlog_heads SET leaf=? WHERE idx=0').run(Buffer.alloc(32, 3)));
  g.write(s, 'alpha', 1);
  await s.transparency.pump();
  assert.deepEqual(pinOf(g.dataDir), first);
  assert.ok(s.transparency.status().violations.some(v => v.kind === 'inconsistent'), JSON.stringify(s.transparency.status().violations));
  assert.equal(s.transparency.status().pinFrozen, true);
});

test('enforce mode fails closed when the pin is missing, dangling or cannot be written', async t => {
  const f = await transparencyFixture(t, {witness: false});
  // An unwritable pin location refuses the first start; the message names the pin file, never a temporary name.
  const lost = join(f.root, 'missing-dir', 'pin.json');
  await assert.rejects(f.open('enforce', {cfg: f.config('enforce', {pinFile: lost})}), error => {
    assert.match(error.message, new RegExp(`Transparency startup check failed: .*pin write to ${lost} failed \\(ENOENT\\)`));
    assert.doesNotMatch(error.message, /\.tmp|\.probe/);
    return true;
  });
  // A fresh vault writes a size-0 pin at startup, so every later start has one.
  const pinDir = join(f.root, 'pin'), pinFile = join(pinDir, 'pin.json'), cfg = f.config('enforce', {pinFile});
  mkdirSync(pinDir);
  let s = await f.open('enforce', {cfg});
  assert.equal(JSON.parse(readFileSync(pinFile, 'utf8')).size, 0);
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  snapshot(f.dataDir, join(f.root, 'older.db'));
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  await f.close(s);
  // A missing pin is no longer a first boot.
  const saved = readFileSync(pinFile);
  rmSync(pinFile);
  replaceDatabase(f.dataDir, join(f.root, 'older.db'));
  await assert.rejects(f.open('enforce', {cfg}), /Transparency pin for vault\.test\/evidscope\/heads is missing although the heads log has size 1/);
  writeFileSync(pinFile, saved);
  await assert.rejects(f.open('enforce', {cfg}), /behind the pinned heads checkpoint .*\(rollback\)/);
  // A dangling symlink at the pin path is refused, not read as a missing pin.
  rmSync(pinFile);
  symlinkSync(join(f.root, 'nowhere.json'), pinFile);
  await assert.rejects(f.open('enforce', {cfg}), /pin path must not contain symlinks/);
  rmSync(pinFile);
  const m = await f.open('monitor', {cfg: f.config('monitor', {pinFile})});
  assert.ok(m.transparency.status().violations.some(v => v.kind === 'pin' && v.missingPin));
  await f.close(m);
  rmSync(pinFile, {force: true});
  // Explicit bootstrap pins the current heads log; then enforce starts again.
  const r = await run('scripts/transparency.mjs', ['pin-bootstrap', '--config', configFile(f, {pinFile}), '--key', keyFile(f), '--data-dir', f.dataDir]);
  assert.equal(r.code, 0, r.err);
  assert.equal(JSON.parse(r.out).size, 1);
  const again = await run('scripts/transparency.mjs', ['pin-bootstrap', '--config', configFile(f, {pinFile}), '--key', keyFile(f), '--data-dir', f.dataDir]);
  assert.match(again.err, /already exists/);
  s = await f.open('enforce', {cfg});
  // A pin that cannot move at runtime quarantines an enforce vault.
  rmSync(pinDir, {recursive: true});
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  assert.equal(s.store.quarantine?.kind, 'pin');
  assert.match(s.store.quarantine.reason, new RegExp(`pin write to ${pinFile} failed \\(ENOENT\\)`));
  assert.throws(() => s.store.append('alpha', 'note', {}, 'test'), /Transparency quarantine/);
});

test('pin bootstrap with witnesses needs the quorum to cosign the pinned heads checkpoint', async t => {
  const f = await transparencyFixture(t);
  let s = await f.open('enforce');
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  await f.close(s);
  rmSync(transparencyPinPath(f.dataDir));
  await assert.rejects(f.open('enforce'), /is missing although the heads log has size 1/);
  const cfg = f.config('enforce');
  assert.throws(() => bootstrapPin({dataDir: f.dataDir, key: f.privateKey, config: cfg, probe: null}),
    /needs 1 witness cosignature\(s\) on heads size 1; got 0/);
  const probe = await probeTransparency({dataDir: f.dataDir, key: f.privateKey, config: cfg});
  assert.deepEqual(bootstrapPin({dataDir: f.dataDir, key: f.privateKey, config: cfg, probe}),
    {pinFile: cfg.pinFile, origin: cfg.headsOrigin, size: 1, cosignatures: 1});
  s = await f.open('enforce');
  assert.equal(s.transparency.status().startup.ok, true);
});

test('the default pin path beside a mount-point data directory is refused', () => {
  assert.throws(() => normalizeTransparencyConfig({origin: BASE, mode: 'monitor'}, {dataDir: '/'}), /pinFile \(or TRANSPARENCY_PIN_FILE\) is required/);
  assert.equal(normalizeTransparencyConfig({origin: BASE, mode: 'monitor', pinFile: '/pin/p.json'}, {dataDir: '/'}).pinFile, '/pin/p.json');
  const env = {TRANSPARENCY_PIN_FILE: '/pin/q.json'};
  assert.equal(normalizeTransparencyConfig({origin: BASE, mode: 'monitor'}, {dataDir: '/', env}).pinFile, '/pin/q.json');
});

test('the startup check covers the database the vault opens, not the one the witnesses were probed with', async t => {
  const f = await transparencyFixture(t);
  let s = await f.open('enforce');
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  snapshot(f.dataDir, join(f.root, 'older.db'));
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  await f.close(s);
  snapshot(f.dataDir, join(f.root, 'current.db'));
  const pin = readFileSync(transparencyPinPath(f.dataDir));
  rmSync(transparencyPinPath(f.dataDir));
  const cfg = f.config('enforce'), probe = await probeTransparency({dataDir: f.dataDir, key: f.privateKey, config: cfg});
  assert.deepEqual(probe.witnesses.map(w => w.status), ['consistent']);
  replaceDatabase(f.dataDir, join(f.root, 'older.db'));
  const swapped = /Transparency startup check failed: .*heads size 1\) differs from the one the witnesses were probed with \(heads size 2\)/;
  assert.throws(() => createService({dataDir: f.dataDir, key: f.privateKey, config: {principals}, requirements, transparency: {config: cfg, probe}}), swapped);
  // The writer connection re-runs the check inside the startup transaction: a swap after the read-only check is caught too.
  replaceDatabase(f.dataDir, join(f.root, 'current.db'));
  writeFileSync(transparencyPinPath(f.dataDir), pin);
  const ok = assertTransparencyAnchors({dataDir: f.dataDir, key: f.privateKey, config: cfg, probe});
  assert.equal(ok.ok, true);
  const older = new DatabaseSync(join(f.root, 'older.db')), current = new DatabaseSync(join(f.dataDir, 'evidence.db'));
  t.after(() => { older.close(); current.close(); });
  assert.throws(() => ok.recheck(older), /Transparency startup check failed: .*probed with \(heads size 2\).*behind the pinned heads checkpoint/);
  ok.recheck(current);
});

test('a live tlog_state tamper cannot make the running vault re-seal a tenant log', async t => {
  const f = await transparencyFixture(t);
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  const older = s.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body, olderCount = JSON.parse(older).count;
  const olderState = s.store.db.prepare('SELECT size,peaks,root,note FROM tlog_state WHERE tenant=?').get('alpha');
  f.write(s, 'alpha', 4);
  await s.transparency.pump();
  const witnessed = s.store._tlogRow('alpha').note, size = s.store._tlogRow('alpha').size;
  const rollBack = db => {
    db.prepare('DELETE FROM ledger WHERE tenant=? AND seq>?').run('alpha', olderCount);
    db.prepare('UPDATE checkpoints SET body=? WHERE tenant=?').run(older, 'alpha');
  };
  // Deleting the row no longer rebuilds it from whatever v1 history still verifies.
  tamper(f.dataDir, db => { rollBack(db); db.prepare('DELETE FROM tlog_state WHERE tenant=?').run('alpha'); });
  assert.throws(() => s.store.transaction(() => s.store.append('alpha', 'note', {forged: 1}, 'test')),
    new RegExp(`Ledger head \\(size ${olderCount}\\) is behind its heads log entry \\(size ${size}\\) \\(rollback\\)`));
  assert.equal(s.store._tlogRow('alpha'), null);
  // An older genuine row matching the rolled-back ledger is refused against the heads entry as well.
  tamper(f.dataDir, db => db.prepare('INSERT INTO tlog_state VALUES(?,?,?,?,?,?)')
    .run('alpha', T.tenantOrigin(BASE, 'alpha'), olderState.size, olderState.peaks, olderState.root, olderState.note));
  assert.throws(() => s.store.transaction(() => s.store.append('alpha', 'note', {forged: 2}, 'test')),
    new RegExp(`behind its heads log entry \\(size ${size}\\)`));
  assert.equal(s.store._tlogRow('alpha').note, olderState.note);
  assert.notEqual(s.store._tlogRow('alpha').note, witnessed);
  // A missing row beneath history is refused even where no heads entry exists yet.
  f.write(s, 'beta', 2);
  tamper(f.dataDir, db => db.prepare('DELETE FROM tlog_state WHERE tenant=?').run('beta'));
  assert.throws(() => s.store.transaction(() => s.store.append('beta', 'note', {}, 'test')), /tenant checkpoint is missing beneath existing history/);
  await s.transparency.pump();
  assert.match(s.store.quarantine?.reason || '', /rollback|tenant removal|missing/);
});

test('every heads row after the pin keeps each tenant log monotone', async t => {
  const f = await transparencyFixture(t, {witness: false});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  f.write(s, 'beta', 1);
  await s.transparency.pump();
  const old = s.store._tlogRow('alpha');
  f.write(s, 'alpha', 5);
  await s.transparency.pump();
  await f.close(s);
  const hOrigin = T.headsOrigin(BASE), alpha = T.tenantOrigin(BASE, 'alpha'), beta = T.tenantOrigin(BASE, 'beta');
  const saved = join(f.root, 'saved.db');
  snapshot(f.dataDir, saved);
  // A key holder appends heads rows that the pin does not cover yet: each must keep every tenant log monotone.
  const forge = change => tamper(f.dataDir, db => {
    const n = db.prepare('SELECT COUNT(*) n FROM tlog_heads WHERE origin=?').get(hOrigin).n;
    const last = headsRow(db, hOrigin, n - 1);
    let peaks = T.frontierAppend(T.blobToPeaks(last.peaks, n - 1), n - 1, Buffer.from(last.leaf));
    const rows = [JSON.parse(last.entries).filter(e => e.log !== beta), change(JSON.parse(last.entries))];
    rows.forEach((entries, i) => {
      const sorted = T.sortHeadsEntries(entries), leaf = T.headsLeafHash(T.headsLeafContent(sorted)), before = peaks;
      peaks = T.frontierAppend(peaks, n + i, leaf);
      const note = T.signNote(T.formatCheckpoint({origin: hOrigin, size: n + i + 1, root: T.frontierRoot(peaks)}), T.noteSigner(hOrigin, f.privateKey));
      db.prepare('INSERT INTO tlog_heads VALUES(?,?,?,?,?,?,?)').run(hOrigin, n + i, leaf, T.peaksToBlob(before), T.canonicalJson(sorted), note, 'x');
    });
  });
  const shrink = entries => entries.map(e => e.log === alpha ? T.headsEntry(alpha, old.size, Buffer.from(old.root)) : e);
  forge(shrink);
  await assert.rejects(f.open('enforce'), error => {
    assert.match(error.message, /Heads log row \d+ drops tenant log .* \(tenant removal\)/);
    assert.match(error.message, new RegExp(`Heads log row \\d+ shrinks tenant log ${alpha} from \\d+ to ${old.size} \\(rollback\\)`));
    return true;
  });
  replaceDatabase(f.dataDir, saved);
  forge(entries => entries.map(e => e.log === alpha ? T.headsEntry(alpha, e.size, Buffer.alloc(32, 5)) : e));
  await assert.rejects(f.open('enforce'), new RegExp(`changes tenant log ${alpha} at size \\d+ \\(fork\\)`));

  // Without a pin, the witness's previous size is the anchor, and the probe refuses to submit the regressing rows.
  const g = await transparencyFixture(t);
  const w = await g.open('enforce');
  g.write(w, 'alpha', 3);
  g.write(w, 'beta', 1);
  await w.transparency.pump();
  const gOld = w.store._tlogRow('alpha');
  g.write(w, 'alpha', 2);
  await w.transparency.pump();
  await g.close(w);
  const witnessed = g.w.logs()[0].size;
  rmSync(transparencyPinPath(g.dataDir));
  tamper(g.dataDir, db => {
    const last = headsRow(db, hOrigin, witnessed - 1);
    const sorted = T.sortHeadsEntries(JSON.parse(last.entries).map(e => e.log === alpha ? T.headsEntry(alpha, gOld.size, Buffer.from(gOld.root)) : e));
    const leaf = T.headsLeafHash(T.headsLeafContent(sorted));
    const before = T.frontierAppend(T.blobToPeaks(last.peaks, witnessed - 1), witnessed - 1, Buffer.from(last.leaf));
    const root = T.frontierRoot(T.frontierAppend(before, witnessed, leaf));
    const note = T.signNote(T.formatCheckpoint({origin: hOrigin, size: witnessed + 1, root}), T.noteSigner(hOrigin, g.privateKey));
    db.prepare('INSERT INTO tlog_heads VALUES(?,?,?,?,?,?,?)').run(hOrigin, witnessed, leaf, T.peaksToBlob(before), T.canonicalJson(sorted), note, 'x');
  });
  await assert.rejects(g.open('enforce'), new RegExp(`Witness witness.test/w1: Heads log row ${witnessed} shrinks tenant log ${alpha}`));
  assert.equal(g.w.logs()[0].size, witnessed);
});

test('startupProbe defaults to required in enforce mode and best_effort in monitor mode, and is validated', () => {
  const at = (raw, dataDir = '/tmp/evs') => normalizeTransparencyConfig({origin: BASE, ...raw}, {dataDir});
  assert.equal(at({mode: 'enforce'}).startupProbe, 'required');
  assert.equal(at({mode: 'monitor'}).startupProbe, 'best_effort');
  assert.equal(at({mode: 'enforce', startupProbe: 'best_effort'}).startupProbe, 'best_effort');
  assert.equal(at({mode: 'monitor', startupProbe: 'required'}).startupProbe, 'required');
  assert.throws(() => at({mode: 'enforce', startupProbe: 'maybe'}), /startupProbe must be required or best_effort/);
});

test('the shipped transparency example is strict about its placeholders and valid once they are filled in', () => {
  const example = JSON.parse(readFileSync(new URL('../deploy/transparency/transparency.example.json', import.meta.url), 'utf8'));
  assert.equal(example.mode, 'monitor');
  assert.equal(example.quorum, 1);
  assert.equal(example.witnesses.length, 2);
  assert.throws(() => normalizeTransparencyConfig(example, {dataDir: '/tmp/evs'}), /vkey/);
  const vkeys = ['witness-1.example.org', 'witness-2.example.org'].map(name => T.vkeyString(name, T.SIG_COSIG_ED25519, Buffer.alloc(32, name.length)));
  const filled = {...example, witnesses: example.witnesses.map((w, i) => ({...w, vkey: vkeys[i]}))};
  const config = normalizeTransparencyConfig(filled, {dataDir: '/tmp/evs'});
  assert.deepEqual([config.mode, config.quorum, config.witnesses.length, config.startupProbe, config.pinFile, config.witnessTenantLogs],
    ['monitor', 1, 2, 'best_effort', '/var/lib/evidscope-transparency/pin.json', false]);
  assert.throws(() => normalizeTransparencyConfig({...filled, witnessQuorum: 1}, {dataDir: '/tmp/evs'}), /Unknown transparency config field: witnessQuorum/);
  // witnessTenantLogs is opt-in: every tenant origin must be registered at every witness before it is turned on.
  assert.equal(normalizeTransparencyConfig({...filled, witnessTenantLogs: true}, {dataDir: '/tmp/evs'}).witnessTenantLogs, true);
  assert.equal(normalizeTransparencyConfig({...filled, witnessTenantLogs: undefined}, {dataDir: '/tmp/evs'}).witnessTenantLogs, false);
  assert.throws(() => normalizeTransparencyConfig({...filled, witnessTenantLogs: 'yes'}, {dataDir: '/tmp/evs'}), /witnessTenantLogs must be true or false/);
});
