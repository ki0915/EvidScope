// Round 3 re-audit: a witness cosigns a re-submitted checkpoint afresh, also the last one of a heads origin the signer retired at a
// restore epoch. A vault host attacker could therefore keep an export from before the epoch (tenant behind what the signer later
// signed) anchored by a fresh heads quorum, and a verifier that pinned the signer key but no origin base got 'vault_host'.
// 'vault_host' now needs --origin-base, and --require-heads-signer without it is a usage error.
import test from 'node:test';
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {verifyBundle} from '../src/crypto.mjs';
import * as T from '../src/tlog.mjs';
import {signerHead as storedHead} from '../src/signer.mjs';
import {normalizeTransparencyConfig} from '../src/transparency.mjs';
import {main} from '../src/verify-cli.mjs';
import {transparencyOptions} from '../src/verify-options.mjs';
import {createVaultBackup, createVaultRecoveryFrontier, restoreVaultBackup} from '../src/vault-recovery.mjs';
import {epochAuthorization} from '../scripts/signer.mjs';
import {epochClaims} from '../scripts/transparency.mjs';
import {BASE, principals, transparencyFixture} from './support/transparency-fixture.mjs';
import {headsSigner, signerKeys} from './support/heads-signer.mjs';

const HEADS = T.headsOrigin(BASE), NEW = 'vault.test/evidscope-s2';
test('an export from before a restore epoch, re-anchored on the retired heads origin, is not vault_host without a pinned base', async t => {
  let clock = Date.now();
  const keys = signerKeys(BASE), f = await transparencyFixture(t, {headsKeys: [keys.vkey], witnessNow: () => clock});
  const signer = await headsSigner(t, {base: BASE, keys});
  const rawOld = {origin: BASE, mode: 'enforce', witnesses: [{vkey: f.w.vkey, url: f.ws.url}], intervalMs: 100, timeoutMs: 2000, refreshSeconds: 1,
    signer: signer.config};
  const s = await f.open('enforce', {cfg: f.config('enforce', {signer: signer.config, refreshSeconds: 1})});
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const backupDir = join(f.root, 'backup'), anchor = await createVaultBackup({dataDir: f.dataDir, backupDir, privateKey: f.privateKey, publicKey: f.publicKey});
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const old = await f.call(s, '/api/export');
  const latest = await createVaultRecoveryFrontier({dataDir: f.dataDir, privateKey: f.privateKey, publicKey: f.publicKey, anchor,
    config: {principals}, transparency: rawOld});
  await f.close(s);
  // The restore epoch to NEW (docs/signer.md 복구 epoch), then alpha grows well beyond the old export under the new origin.
  const rawNew = {...rawOld, origin: NEW}, dir = join(f.root, 'epoch');
  await restoreVaultBackup({backupDir, restoreDir: dir, privateKey: f.privateKey, publicKey: f.publicKey, anchor, frontier: latest.frontier,
    frontierAnchor: latest.anchor, config: {principals},
    transparency: {config: rawNew, previous: rawOld, signerHead: storedHead(signer.stateDir, HEADS), frontierTransparency: latest.transparency}});
  const newCfg = normalizeTransparencyConfig(rawNew, {dataDir: dir});
  f.w.addLog(newCfg.headsOrigin, newCfg.signer.vkey);
  const restored = await f.open('enforce', {dir, cfg: newCfg});
  epochAuthorization({stateDir: signer.stateDir, fromBase: BASE, toBase: NEW, restored: epochClaims({config: newCfg, dataDir: dir})});
  await delay(1100);
  await restored.transparency.pump();
  f.write(restored, 'alpha', 10);
  await delay(1100);
  await restored.transparency.pump();
  const current = await f.call(restored, '/api/export');
  await f.close(restored);
  const h = storedHead(signer.stateDir, HEADS);
  assert.equal(h.status, 'retired');
  // Two days later the attacker re-submits the retired origin's last checkpoint and gets a fresh cosignature for the old export.
  clock += 2 * 86400 * 1000;
  const answer = f.w.addCheckpoint(`old ${h.size}\n\n${h.note}`);
  assert.equal(answer.status, 200);
  assert.equal(T.parseCheckpoint(T.noteText(old.transparency.heads.checkpoint)).size, h.size);
  const replayed = structuredClone(old);
  replayed.transparency.heads.checkpoint = h.note + answer.body;
  assert.ok(replayed.records.length < current.records.length);
  const opts = extra => ({transparency: {witnesses: [f.w.vkey], quorum: 1, headsKeys: [signer.vkey], now: clock, ...extra}});
  // Without a pinned base: the next lower level that still holds, and --require-heads-signer refuses to decide.
  assert.equal(verifyBundle(replayed, f.publicKey, undefined, opts()).transparency.rollbackCheckedAgainst, 'database_tamper');
  assert.throws(() => verifyBundle(replayed, f.publicKey, undefined, opts({requireHeadsSigner: true})), /needs a pinned origin base \(--origin-base\)/);
  // Pinned to the new base: the old export is refused, the current one is vault_host.
  assert.throws(() => verifyBundle(replayed, f.publicKey, undefined, opts({originBase: NEW})), /differs from pinned origin base/);
  const pinned = verifyBundle(current, f.publicKey, undefined, opts({originBase: NEW, requireHeadsSigner: true, now: Date.now()})).transparency;
  assert.equal(pinned.rollbackCheckedAgainst, 'vault_host');
  // A verifier still pinning the old base cannot tell offline; the witnesses drop the signer key for the retired origin (step 7).
  f.w.removeLogKey(HEADS, signer.vkey);
  assert.equal(f.w.addCheckpoint(`old ${h.size}\n\n${h.note}`).status, 404);
});

test('--require-heads-signer without --origin-base is a usage error', () => {
  const out = [], sink = {write: x => out.push(x)};
  // No file is read: the paths do not exist.
  const status = main(['bundle', 'missing-export.json', 'missing-key.pem', '--heads-key', signerKeys(BASE).vkey, '--require-heads-signer'],
    {stdout: sink, stderr: sink});
  assert.equal(status, 2, out.join(''));
  assert.match(out.join(''), /--require-heads-signer needs --origin-base BASE/);
  assert.throws(() => transparencyOptions({'require-heads-signer': true}, true), /--require-heads-signer needs --origin-base BASE/);
  assert.equal(transparencyOptions({'require-heads-signer': true, 'origin-base': BASE}, true).requireHeadsSigner, true);
});
