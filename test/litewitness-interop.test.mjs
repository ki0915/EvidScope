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
import {witnessCommands} from '../scripts/transparency.mjs';
import {startSshAgent} from './support/ssh-agent.mjs';
import {BASE, replaceDatabase, snapshot, transparencyFixture} from './support/transparency-fixture.mjs';

const LW = process.env.EVIDSCOPE_LITEWITNESS_BIN;
const skip = !LW ? 'EVIDSCOPE_LITEWITNESS_BIN is not set' : !existsSync(LW) ? `litewitness binary not found at ${LW}` : false;
const V = JSON.parse(readFileSync(new URL('./fixtures/c2sp-vectors.json', import.meta.url), 'utf8'));
const freePort = () => new Promise(r => { const s = createServer().listen(0, '127.0.0.1', () => { const {port} = s.address(); s.close(() => r(port)); }); });

function register(db, config, key) {
  const ctl = process.env.EVIDSCOPE_WITNESSCTL_BIN || join(dirname(LW), 'witnessctl');
  if (existsSync(ctl)) {
    for (const line of witnessCommands({config, key, db})) execFileSync(ctl, line.split(' ').slice(1), {stdio: ['ignore', 'pipe', 'pipe']});
    return 'witnessctl';
  }
  const d = new DatabaseSync(db);
  d.exec(`CREATE TABLE IF NOT EXISTS log (origin TEXT PRIMARY KEY, tree_size INTEGER NOT NULL, tree_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS key (origin TEXT NOT NULL, key TEXT NOT NULL, FOREIGN KEY(origin) REFERENCES log(origin));
    CREATE TABLE IF NOT EXISTS bastion (origin TEXT NOT NULL, bastion TEXT NOT NULL, FOREIGN KEY(origin) REFERENCES log(origin));`);
  d.prepare('INSERT INTO log VALUES(?,0,?)').run(config.headsOrigin, T.b64(T.EMPTY_ROOT));
  d.prepare('INSERT INTO key VALUES(?,?)').run(config.headsOrigin, T.logVkey(config.headsOrigin, key));
  d.close();
  return 'sqlite';
}

test('vault heads log interoperates with litewitness: cosign, consistency, rollback refusal and fork (422)', {skip}, async t => {
  const f = await transparencyFixture(t, {witness: false});
  const run = mkdtempSync(join(tmpdir(), 'evs-lw-')), sock = join(run, 'a.sock'), db = join(run, 'w.db'), port = await freePort();
  t.after(() => rmSync(run, {recursive: true, force: true}));
  const agent = await startSshAgent(sock, V.witness_key.seed_hex);
  const raw = {origin: BASE, mode: 'enforce', witnesses: [{vkey: V.witness_key.vkey, url: `http://127.0.0.1:${port}`}], intervalMs: 100, timeoutMs: 5000};
  const config = (mode, dir = f.dataDir) => normalizeTransparencyConfig({...raw, mode}, {dataDir: dir});
  const registration = register(db, config('enforce'), f.privateKey);
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
  for (let i = 0; i < 100; i++) { try { await fetch(`http://127.0.0.1:${port}/metrics`); break; } catch { await delay(50); } }
  assert.equal((logs.match(/msg="verifier key" vkey=(\S+)/) || [])[1], V.witness_key.vkey, logs);

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
