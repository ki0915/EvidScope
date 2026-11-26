import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {verifyBundle} from '../src/crypto.mjs';
import * as T from '../src/tlog.mjs';
import {transparencyPinPath} from '../src/transparency.mjs';
import {createVaultBackup, createVaultRecoveryFrontier, restoreVaultBackup} from '../src/vault-recovery.mjs';
import {BASE, principals, transparencyFixture} from './support/transparency-fixture.mjs';

const serviceConfig = {principals};
// Asynchronous: the development witness answers from this process's event loop.
const execute = promisify(execFile);
const run = async (script, args) => {
  const r = await execute(process.execPath, [script, ...args], {encoding: 'utf8', windowsHide: true, timeout: 30000})
    .then(x => ({...x, code: 0}), error => ({stdout: error.stdout || '', stderr: error.stderr || '', code: error.code}));
  return {status: r.code, out: r.code === 0 && r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};
const register = (f, base) => f.w.addLog(T.headsOrigin(base), T.logVkey(T.headsOrigin(base), f.publicKey));

// An enforce-mode vault with a cosigned history, an older backup, more cosigned history after it, and a fresh frontier.
async function lossyHistory(t) {
  const f = await transparencyFixture(t);
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  f.write(s, 'beta', 2);
  await s.transparency.pump();
  const anchor = await createVaultBackup({dataDir: f.dataDir, backupDir: join(f.root, 'backup'), privateKey: f.privateKey, publicKey: f.publicKey});
  const archived = {alpha: s.store._tlogRow('alpha'), headsSize: s.transparency.status().heads.size};
  f.write(s, 'alpha', 4);
  await s.transparency.pump();
  const later = s.store._tlogRow('alpha'), witnessed = f.w.logs()[0].size;
  assert.ok(witnessed > archived.headsSize);
  const rawOld = {origin: BASE, mode: 'enforce', witnesses: [{vkey: f.w.vkey, url: f.ws.url}], intervalMs: 100, timeoutMs: 2000};
  const latest = await createVaultRecoveryFrontier({dataDir: f.dataDir, privateKey: f.privateKey, publicKey: f.publicKey, anchor, config: serviceConfig,
    transparency: rawOld});
  const oldPin = JSON.parse(readFileSync(transparencyPinPath(f.dataDir), 'utf8'));
  await f.close(s);
  const restore = (name, transparency, activation = latest) => restoreVaultBackup({backupDir: join(f.root, 'backup'), restoreDir: join(f.root, name),
    privateKey: f.privateKey, publicKey: f.publicKey, anchor, frontier: activation.frontier, frontierAnchor: activation.anchor, config: serviceConfig,
    ...(transparency ? {transparency} : {})});
  return {f, anchor, archived, later, witnessed, rawOld, latest, oldPin, restore, epochConfig: base => ({...rawOld, origin: base})};
}

test('restoring an enforce-mode vault from an older backup needs a new origin epoch and stays verifiable offline', async t => {
  const h = await lossyHistory(t), {f, archived, later} = h, NEW = 'vault.test/evidscope-e2';
  await assert.rejects(h.restore('no-decision'), /Transparency restore refused: the archive carries transparency state/);
  await assert.rejects(h.restore('same-base', {config: h.rawOld}), /already used by this vault; a restore always forks the log/);
  // Without an epoch the restored ledger cannot run under the old origin in any mode: it would sign a fork of the lost history.
  const off = await h.restore('without-epoch', {config: {mode: 'off'}});
  assert.deepEqual(off.transparency.retiredOriginBases, [BASE]);
  const dir = join(f.root, 'without-epoch');
  await assert.rejects(f.open('enforce', {dir, cfg: f.config('enforce', {dir})}), /Transparency startup check failed: .*rollback.*across its restore \(fork\)/);
  await assert.rejects(f.open('monitor', {dir, cfg: f.config('monitor', {dir})}), /across its restore \(fork\)/);
  await assert.rejects(f.open('enforce', {dir, cfg: f.config('enforce', {dir, origin: 'vault.test/unrelated'})}), /unacknowledged origin change/);

  // The frontier's companion heads checkpoint covers what the witness cosigned, so freshness is established without acceptLoss.
  const receipt = await h.restore('epoch', {config: h.epochConfig(NEW), frontierTransparency: h.latest.transparency});
  assert.equal(receipt.activationAccepted, true);
  assert.equal(receipt.freshnessEstablished, true);
  assert.match(receipt.scope, /freshness was established against the witness quorum/);
  assert.equal(receipt.transparency.previousOriginBase, BASE);
  assert.deepEqual(receipt.transparency.lostHeadsRange, [archived.headsSize + 1, h.witnessed]);
  assert.equal(receipt.transparency.witnesses[0].status, 'consistent');
  assert.equal(receipt.transparency.logVkey, T.logVkey(T.headsOrigin(NEW), f.publicKey));
  const restored = join(f.root, 'epoch'), cfg = f.config('enforce', {dir: restored, origin: NEW});
  await assert.rejects(f.open('enforce', {dir: restored, cfg: f.config('enforce', {dir: restored})}), /retired by a signed tlog epoch.*\(fork\)/);
  register(f, NEW);
  const s = await f.open('enforce', {dir: restored, cfg});
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  assert.equal(s.transparency.status().witnesses[0].status, 'consistent');
  const exported = await f.call(s, '/api/export');
  assert.equal(exported.transparency.origin, T.tenantOrigin(NEW, 'alpha'));
  const [epoch] = exported.transparency.epochs;
  assert.deepEqual([epoch.previousOriginBase, epoch.originBase, epoch.restoredSize], [BASE, NEW, archived.alpha.size]);
  assert.deepEqual(epoch.lostRange, [archived.alpha.size + 1, later.size]);
  assert.deepEqual([epoch.freshnessEstablished, epoch.lossAccepted], [true, false]);
  // An auditor who pinned the old origin base follows the signed epoch chain; old checkpoints are prefixes up to the restore.
  const policy = {witnesses: [f.w.vkey], quorum: 1, originBase: BASE, require: true};
  const verified = verifyBundle(exported, f.publicKey, undefined, {transparency: {...policy, minimumCheckpoint: archived.alpha.note}});
  assert.equal(verified.rollbackChecked, true);
  assert.equal(verified.transparency.pinnedOriginBase, BASE);
  assert.equal(verified.transparency.epochs[0].previousCheckpointSize, archived.alpha.size);
  assert.ok(verified.transparency.epochs[0].previousCosigned.witnesses.length >= 1);
  assert.equal(verified.transparency.minimumCheckpoint.epochSeq, epoch.seq);
  assert.throws(() => verifyBundle(exported, f.publicKey, undefined, {transparency: {...policy, minimumCheckpoint: later.note}}),
    new RegExp(`rollback or truncation; sequence numbers after ${archived.alpha.size} were replaced .*lost range ${archived.alpha.size + 1}-${later.size}`
      + ', acknowledged as lost'));
  const forged = structuredClone(exported);
  forged.transparency.epochs[0].lostRange = null;
  assert.throws(() => verifyBundle(forged, f.publicKey, undefined, {transparency: policy}), /epoch summary differs from the signed epoch records/);
  assert.throws(() => verifyBundle(exported, f.publicKey, undefined, {transparency: {...policy, originBase: 'vault.test/other'}}), /pinned origin base/);
  // The offline CLI surfaces the epoch chain.
  const file = join(f.root, 'export.json'), keyPath = join(f.root, 'trusted.pem');
  writeFileSync(file, JSON.stringify(exported));
  writeFileSync(keyPath, f.publicKey.export({format: 'pem', type: 'spki'}));
  const r = await run('scripts/verify.mjs', [file, keyPath, '--witness', f.w.vkey, '--origin-base', BASE, '--require-transparency']);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual(r.out.transparency.epochs[0].lostRange, epoch.lostRange);
  assert.equal(r.out.rollbackChecked, true);
  const integrity = await f.call(s, '/api/integrity');
  assert.equal(integrity.valid, true, integrity.error);
  assert.equal(integrity.transparency.epochs.length, 1);
  await f.close(s);
  const reopened = await f.open('enforce', {dir: restored, cfg});
  assert.equal(reopened.transparency.status().startup.ok, true);
});

test('a restore that cannot establish freshness needs a recorded acceptLoss, and the retired pin must lie within it', async t => {
  const h = await lossyHistory(t), {f, archived} = h, NEW = 'vault.test/evidscope-e3';
  const noCompanion = await createVaultRecoveryFrontier({dataDir: f.dataDir, privateKey: f.privateKey, publicKey: f.publicKey, anchor: h.anchor,
    config: serviceConfig});
  assert.ok(noCompanion.transparency, 'the companion is produced whenever the source has a heads log');
  await assert.rejects(h.restore('stale', {config: h.epochConfig(NEW)}),
    new RegExp(`cannot establish freshness .*witnessed up to heads size ${h.witnessed}, beyond the archive \\(${archived.headsSize}\\).*rollback.*acceptLoss`));
  f.w.setAvailable(false);
  await assert.rejects(h.restore('unreachable', {config: h.epochConfig(NEW)}), /0 of 1 required witnesses answered/);
  f.w.setAvailable(true);
  // A pin larger than anything acknowledged keeps the startup refusal; the recorded loss covers the real pin.
  const sharedPin = join(f.root, 'shared-pin.json'), pinned = {...h.epochConfig(NEW), pinFile: sharedPin};
  const receipt = await h.restore('accepted', {config: pinned, previousPin: h.oldPin, acceptLoss: 'backup older than the last witnessed checkpoint'});
  assert.equal(receipt.freshnessEstablished, false);
  assert.equal(receipt.transparency.lossAccepted, true);
  assert.equal(receipt.transparency.witnessedHeadsSize, h.witnessed);
  register(f, NEW);
  const dir = join(f.root, 'accepted'), cfg = f.config('enforce', {dir, origin: NEW, pinFile: sharedPin});
  const oldHeads = T.headsOrigin(BASE), beyond = h.witnessed + 5;
  const forgedNote = T.signNote(T.formatCheckpoint({origin: oldHeads, size: beyond, root: Buffer.alloc(32, 9)}), T.noteSigner(oldHeads, f.privateKey));
  writeFileSync(sharedPin, JSON.stringify({...h.oldPin, size: beyond, checkpoint: forgedNote}));
  await assert.rejects(f.open('enforce', {dir, cfg}), new RegExp(`retired heads origin ${oldHeads} \\(size ${beyond}\\) exceeds .*\\(rollback\\)`));
  writeFileSync(sharedPin, JSON.stringify(h.oldPin));
  const s = await f.open('enforce', {dir, cfg});
  assert.equal(s.transparency.status().pinSize, 0);
  f.write(s, 'beta', 1);
  await s.transparency.pump();
  const pin = JSON.parse(readFileSync(sharedPin, 'utf8'));
  assert.equal(pin.origin, T.headsOrigin(NEW));
  const exported = await f.call(s, '/api/export', 'beta');
  const [epoch] = exported.transparency.epochs;
  assert.deepEqual([epoch.lossAccepted, epoch.freshnessEstablished, epoch.acceptLossReason], [true, false, 'backup older than the last witnessed checkpoint']);
  assert.deepEqual(epoch.lostRange, [epoch.restoredSize + 1, null]);
  assert.deepEqual(epoch.lostHeadsRange, [archived.headsSize + 1, h.witnessed]);
  const verified = verifyBundle(exported, f.publicKey, undefined, {transparency: {witnesses: [f.w.vkey], originBase: BASE, require: true}});
  assert.equal(verified.transparency.epochs[0].lossAccepted, true);
});

test('restore epoch operator path runs through the CLIs', async t => {
  const h = await lossyHistory(t), {f} = h, NEW = 'vault.test/evidscope-e4', file = name => join(f.root, name);
  writeFileSync(file('vault.pem'), f.privateKey.export({format: 'pem', type: 'pkcs8'}));
  writeFileSync(file('trust.pem'), f.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(file('old.json'), JSON.stringify(h.rawOld));
  writeFileSync(file('anchor.json'), JSON.stringify(h.anchor));
  writeFileSync(file('config.json'), JSON.stringify(serviceConfig));
  let r = await run('scripts/transparency.mjs',
    ['new-epoch', '--config', file('old.json'), '--origin', BASE, '--out', file('new.json'), '--key', file('vault.pem')]);
  assert.equal(r.status, 1);
  assert.match(r.err, /different from the current one/);
  r = await run('scripts/transparency.mjs', ['new-epoch', '--config', file('old.json'), '--origin', NEW, '--out', file('new.json'), '--key', file('vault.pem'),
    '--db', '/srv/w.db']);
  assert.equal(r.status, 0, r.err);
  assert.ok(r.out.includes(`witnessctl add-log -db /srv/w.db -origin ${NEW}/heads`), r.out);
  assert.ok(r.out.includes(`-key ${T.logVkey(T.headsOrigin(NEW), f.publicKey)}`));
  assert.equal(JSON.parse(readFileSync(file('new.json'), 'utf8')).origin, NEW);
  r = await run('scripts/vault-backup.mjs', ['frontier', f.dataDir, file('vault.pem'), file('trust.pem'), file('anchor.json'), file('config.json'),
    file('frontier.json'), file('frontier-anchor.json'), '--transparency-config', file('old.json'), '--transparency-out', file('frontier-tlog.json')]);
  assert.equal(r.status, 0, r.err);
  assert.equal(r.out.frontierTransparency.headsOrigin, T.headsOrigin(BASE));
  const restoreArgs = ['restore', join(f.root, 'backup'), file('cli-restored'), file('vault.pem'), file('trust.pem'), file('anchor.json'),
    file('frontier.json'), file('frontier-anchor.json'), file('config.json')];
  r = await run('scripts/vault-backup.mjs', [...restoreArgs, '--accept-loss', 'x']);
  assert.equal(r.status, 1);
  assert.match(r.err, /--transparency-config \(the new epoch\) is required/);
  r = await run('scripts/vault-backup.mjs', [...restoreArgs, '--transparency-config', file('new.json'), '--frontier-transparency', file('frontier-tlog.json')]);
  assert.equal(r.status, 0, r.err);
  assert.equal(r.out.freshnessEstablished, true);
  assert.equal(r.out.transparency.originBase, NEW);
  register(f, NEW);
  const dir = file('cli-restored'), s = await f.open('enforce', {dir, cfg: f.config('enforce', {dir, origin: NEW})});
  await s.transparency.pump();
  r = await run('scripts/transparency.mjs', ['status', '--config', file('new.json'), '--key', file('vault.pem'), '--data-dir', dir]);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual(r.out.retiredOriginBases, [BASE]);
});
