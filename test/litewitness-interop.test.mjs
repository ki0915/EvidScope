// Interop with a real litewitness (filippo.io/torchwood). Gated: EVIDSCOPE_LITEWITNESS_BIN=/path/to/litewitness.
// witnessctl is used when it sits next to litewitness (or EVIDSCOPE_WITNESSCTL_BIN); otherwise the log is registered
// directly in litewitness's SQLite schema. The witness key lives in an in-process ssh-agent (test/support/ssh-agent.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {createServer} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import {DatabaseSync} from 'node:sqlite';
import {verifyBundle} from '../src/crypto.mjs';
import * as T from '../src/tlog.mjs';
import {normalizeTransparencyConfig, transparencyPinPath} from '../src/transparency.mjs';
import {newEpochConfig, witnessCommands} from '../scripts/transparency.mjs';
import {createVaultBackup, createVaultRecoveryFrontier, restoreVaultBackup} from '../src/vault-recovery.mjs';
import {startSshAgent} from './support/ssh-agent.mjs';
import {BASE, principals, replaceDatabase, snapshot, transparencyFixture} from './support/transparency-fixture.mjs';

const LW = process.env.EVIDSCOPE_LITEWITNESS_BIN;
const skip = !LW ? 'EVIDSCOPE_LITEWITNESS_BIN is not set' : !existsSync(LW) ? `litewitness binary not found at ${LW}` : false;
const V = JSON.parse(readFileSync(new URL('./fixtures/c2sp-vectors.json', import.meta.url), 'utf8'));
const freePort = () => new Promise(r => { const s = createServer().listen(0, '127.0.0.1', () => { const {port} = s.address(); s.close(() => r(port)); }); });

// Registers the heads origin and, with witnessTenantLogs, the origins of `tenants`.
function register(db, config, key, tenants = []) {
  const ctl = process.env.EVIDSCOPE_WITNESSCTL_BIN || join(dirname(LW), 'witnessctl');
  if (existsSync(ctl)) {
    for (const line of witnessCommands({config, key, db, tenants})) execFileSync(ctl, line.split(' ').slice(1), {stdio: ['ignore', 'pipe', 'pipe']});
    return 'witnessctl';
  }
  const d = new DatabaseSync(db);
  d.exec(`CREATE TABLE IF NOT EXISTS log (origin TEXT PRIMARY KEY, tree_size INTEGER NOT NULL, tree_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS key (origin TEXT NOT NULL, key TEXT NOT NULL, FOREIGN KEY(origin) REFERENCES log(origin));
    CREATE TABLE IF NOT EXISTS bastion (origin TEXT NOT NULL, bastion TEXT NOT NULL, FOREIGN KEY(origin) REFERENCES log(origin));`);
  const origins = [config.headsOrigin, ...(config.witnessTenantLogs ? tenants.map(tenant => T.tenantOrigin(config.base, tenant)) : [])];
  for (const origin of origins) {
    d.prepare('INSERT INTO log VALUES(?,0,?)').run(origin, T.b64(T.EMPTY_ROOT));
    d.prepare('INSERT INTO key VALUES(?,?)').run(origin, T.logVkey(origin, key));
  }
  d.close();
  return 'sqlite';
}

// Starts litewitness on a fresh database; before(db, url) registers logs before it serves.
async function startLitewitness(t, before) {
  const run = mkdtempSync(join(tmpdir(), 'evs-lw-')), sock = join(run, 'a.sock'), db = join(run, 'w.db'), port = await freePort();
  t.after(() => rmSync(run, {recursive: true, force: true}));
  const agent = await startSshAgent(sock, V.witness_key.seed_hex), url = `http://127.0.0.1:${port}`;
  const registration = before(db, url);
  const lw = spawn(LW, ['-db', db, '-name', V.witness_key.key_name, '-key', agent.fingerprint, '-ssh-agent', sock, '-listen', `127.0.0.1:${port}`]);
  let logs = '';
  lw.stderr.on('data', d => { logs += d; });
  t.after(async () => {
    if (lw.exitCode === null && lw.signalCode === null) {
      const exited = new Promise(r => lw.once('exit', r)), timer = setTimeout(() => lw.kill('SIGKILL'), 3000);
      lw.kill('SIGINT');
      await exited;
      clearTimeout(timer);
    }
    await agent.close();
  });
  for (let i = 0; i < 200 && !/verifier key/.test(logs); i++) await delay(25);
  for (let i = 0; i < 100; i++) { try { await fetch(`${url}/metrics`); break; } catch { await delay(50); } }
  assert.equal((logs.match(/msg="verifier key" vkey=(\S+)/) || [])[1], V.witness_key.vkey, logs);
  return {run, db, url, registration};
}

test('vault heads log interoperates with litewitness: cosign, consistency, rollback refusal and fork (422)', {skip}, async t => {
  const f = await transparencyFixture(t, {witness: false});
  let raw = null;
  const config = (mode, dir = f.dataDir) => normalizeTransparencyConfig({...raw, mode}, {dataDir: dir});
  const {run, registration} = await startLitewitness(t, (db, url) => {
    raw = {origin: BASE, mode: 'enforce', witnesses: [{vkey: V.witness_key.vkey, url}], intervalMs: 100, timeoutMs: 5000};
    return register(db, config('enforce'), f.privateKey);
  });

  const s = await f.open('enforce', {cfg: config('enforce')});
  assert.equal(s.transparency.status().witnesses[0].status, 'consistent');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  f.write(s, 'alpha', 5);
  f.write(s, 'beta', 2);
  await s.transparency.pump();
  const first = s.transparency.status();
  assert.equal(first.witnesses[0].status, 'consistent');
  const exported = await f.call(s, '/api/export');
  const policy = {witnesses: [V.witness_key.vkey], quorum: 1, originBase: BASE, require: true};
  const verified = verifyBundle(exported, f.publicKey, undefined, {transparency: policy});
  assert.equal(verified.rollbackChecked, true);
  snapshot(f.dataDir, join(run, 'older.db'));
  f.write(s, 'alpha', 4);
  await s.transparency.pump();
  const witnessedSize = s.transparency.status().heads.size;
  await f.close(s);

  rmSync(transparencyPinPath(f.dataDir));
  replaceDatabase(f.dataDir, join(run, 'older.db'));
  const refused = await f.open('enforce', {cfg: config('enforce')}).then(() => null, error => error.message);
  assert.match(refused || '', /Transparency startup check failed: .*rollback/);

  const forked = await f.open('monitor', {cfg: config('monitor')});
  for (let i = 0; i <= witnessedSize + 1 && forked.transparency.status().witnesses[0].status !== 'fork'; i++) {
    f.write(forked, 'alpha', 1);
    await forked.transparency.pump();
  }
  assert.ok(forked.transparency.status().violations.some(v => v.kind === 'fork'));
  // Past the witnessed size the submission carries a consistency proof, which litewitness rejects with 422 as well.
  f.write(forked, 'alpha', 1);
  await forked.transparency.pump();
  const fork = forked.transparency.status();
  assert.equal(fork.witnesses[0].status, 'fork');
  assert.ok(fork.heads.size > witnessedSize);
  assert.match(fork.witnesses[0].message, new RegExp(`checkpoint ${fork.heads.size} .* size ${witnessedSize} \\(fork\\)`));
  await f.close(forked);
  const refusedFork = await f.open('enforce', {cfg: config('enforce')}).then(() => null, error => error.message);
  assert.match(refusedFork || '', /fork/);
  t.diagnostic(JSON.stringify({litewitness: LW, registration, witnessVkey: V.witness_key.vkey, cosignedHeadsSize: witnessedSize,
    exportVerified: {rollbackChecked: verified.rollbackChecked, quorumMet: verified.transparency.heads.quorumMet},
    olderCopy: refused, forkStatus: fork.witnesses[0], forkRestart: refusedFork}));
});

test('restore epochs interoperate with litewitness: freshness of the old heads origin and registration of the new one', {skip}, async t => {
  const f = await transparencyFixture(t, {witness: false});
  let raw = null;
  const {db} = await startLitewitness(t, (file, url) => {
    raw = {origin: BASE, mode: 'enforce', witnesses: [{vkey: V.witness_key.vkey, url}], intervalMs: 100, timeoutMs: 5000};
    return register(file, normalizeTransparencyConfig(raw, {dataDir: f.dataDir}), f.privateKey);
  });
  const s = await f.open('enforce', {cfg: normalizeTransparencyConfig(raw, {dataDir: f.dataDir})});
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const backupDir = join(f.root, 'backup'), serviceConfig = {principals};
  const anchor = await createVaultBackup({dataDir: f.dataDir, backupDir, privateKey: f.privateKey, publicKey: f.publicKey});
  const archived = {heads: s.transparency.status().heads.size, alpha: s.store._tlogRow('alpha').size};
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const witnessed = s.transparency.status().heads.size;
  assert.equal(s.transparency.status().witnesses[0].status, 'consistent');
  const latest = await createVaultRecoveryFrontier({dataDir: f.dataDir, privateKey: f.privateKey, publicKey: f.publicKey, anchor, config: serviceConfig,
    transparency: raw});
  await f.close(s);
  const NEW = 'vault.test/evidscope-lw2', next = newEpochConfig(raw, NEW);
  const restore = (name, transparency) => restoreVaultBackup({backupDir, restoreDir: join(f.root, name), privateKey: f.privateKey, publicKey: f.publicKey,
    anchor, frontier: latest.frontier, frontierAnchor: latest.anchor, config: serviceConfig, transparency});
  // litewitness answers the archive's heads checkpoint with 409 (it holds more): freshness needs the frontier companion.
  await assert.rejects(restore('stale', {config: next, previous: raw}),
    new RegExp(`witnessed up to heads size ${witnessed}, beyond the archive \\(${archived.heads}\\)`));
  const receipt = await restore('epoch', {config: next, previous: raw, frontierTransparency: latest.transparency});
  assert.equal(receipt.freshnessEstablished, true);
  assert.deepEqual([receipt.transparency.witnesses[0].status, receipt.transparency.witnessedHeadsSize], ['consistent', witnessed]);
  // The operator registers the new heads origin at the running witness with the printed witnessctl lines.
  const dir = join(f.root, 'epoch'), cfg = normalizeTransparencyConfig(next, {dataDir: dir});
  for (const line of witnessCommands({config: cfg, key: f.privateKey, db})) execFileSync(join(dirname(LW), 'witnessctl'), line.split(' ').slice(1));
  const restored = await f.open('enforce', {dir, cfg});
  f.write(restored, 'alpha', 1);
  await restored.transparency.pump();
  assert.equal(restored.transparency.status().witnesses[0].status, 'consistent');
  const exported = await f.call(restored, '/api/export');
  const policy = {witnesses: [V.witness_key.vkey], quorum: 1, originBase: BASE, require: true};
  const verified = verifyBundle(exported, f.publicKey, undefined, {transparency: policy});
  assert.equal(verified.transparency.pinnedOriginBase, BASE);
  assert.deepEqual(verified.transparency.epochs[0].lostRange, [archived.alpha + 1, archived.alpha + 2]);
  assert.equal(verified.transparency.heads.quorumMet, true);
});

test('tenant logs interoperate with litewitness: two tenant origins cosigned, and a tenant rollback refused', {skip}, async t => {
  const f = await transparencyFixture(t, {witness: false});
  let raw = null;
  const config = mode => normalizeTransparencyConfig({...raw, mode}, {dataDir: f.dataDir});
  const {run, url, registration} = await startLitewitness(t, (db, witnessUrl) => {
    raw = {origin: BASE, mode: 'enforce', witnesses: [{vkey: V.witness_key.vkey, url: witnessUrl}], intervalMs: 100, timeoutMs: 5000,
      witnessTenantLogs: true};
    return register(db, config('enforce'), f.privateKey, ['alpha', 'beta']);
  });
  const s = await f.open('enforce', {cfg: config('enforce')});
  f.write(s, 'alpha', 3);
  f.write(s, 'beta', 2);
  await s.transparency.pump();
  assert.deepEqual(s.transparency.status().tenantLogs[0].logs, {consistent: 2});
  const policy = {witnesses: [V.witness_key.vkey], quorum: 1, originBase: BASE, require: true, requireTenantWitness: true};
  const exports = {alpha: await f.call(s, '/api/export'), beta: await f.call(s, '/api/export', 'beta')};
  for (const [tenant, bundle] of Object.entries(exports)) {
    const verified = verifyBundle(bundle, f.publicKey, undefined, {transparency: policy});
    assert.deepEqual([verified.tenant, verified.transparency.rollbackCheckedAgainst, verified.transparency.tenantCosigned.origin],
      [tenant, 'signing_key_holder', T.tenantOrigin(BASE, tenant)]);
  }
  snapshot(f.dataDir, join(run, 'older.db'));
  f.write(s, 'alpha', 4);
  await s.transparency.pump();
  const alpha = T.tenantOrigin(BASE, 'alpha'), witnessed = s.store._tlogRow('alpha').size, older = exports.alpha.checkpoint.count;
  assert.equal(s.transparency.status().tenantLogs[0].logs.consistent, 2);
  await f.close(s);
  // litewitness will not cosign the older tenant checkpoint again: it answers 409 with the size it holds.
  const again = await T.postAddCheckpoint(url, T.addCheckpointBody(older, [], exports.alpha.transparency.checkpoint));
  assert.deepEqual([again.status, T.parseConflictBody(again.type, again.body)], [409, witnessed]);
  rmSync(transparencyPinPath(f.dataDir));
  replaceDatabase(f.dataDir, join(run, 'older.db'));
  const refused = await f.open('enforce', {cfg: config('enforce')}).then(() => null, error => error.message);
  const log = alpha.replace(/[./]/g, '\\$&');
  assert.match(refused || '', new RegExp(`witness holds tenant log ${log} size ${witnessed} but the local tenant log ${log} has ${older} \\(rollback\\)`));
  t.diagnostic(JSON.stringify({litewitness: LW, registration, tenantOrigins: Object.keys(exports).map(x => T.tenantOrigin(BASE, x)),
    resubmittedOlderTenantCheckpoint: again.status, olderCopy: refused}));
});
