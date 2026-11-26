// A ledger replaced by an older copy (security review 2026-10-22): a fresh local install now pins its heads checkpoint outside the
// database (scripts/init.mjs writes transparency.json in monitor mode, the file scripts/upgrade-local.mjs --transparency writes), so
// a rolled-back evidence.db is reported as a rollback violation by /api/integrity and as an integrity alarm on the console home,
// where before it passed as valid. The vault keeps running (monitor mode); enforce mode would refuse to start.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';
import {loadTransparencyConfig, prepareTransparency} from '../src/transparency.mjs';

test('init writes a monitor-mode transparency file with a local pin and no witnesses', () => {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/init-tlog-'));
  try {
    initialize(dir);
    const file = join(dir, 'transparency.json'), raw = JSON.parse(readFileSync(file, 'utf8'));
    assert.deepEqual([raw.mode, raw.witnesses, raw.quorum], ['monitor', [], 0]);
    assert.match(raw.origin, /^evidscope\.local\/[a-f0-9]{16}$/);
    const config = loadTransparencyConfig({dataDir: join(dir, 'data'), env: {TRANSPARENCY_CONFIG_FILE: file}});
    assert.deepEqual([config.mode, config.witnesses.length, config.quorum], ['monitor', 0, 0]);
    assert.equal(JSON.parse(readFileSync(join(dir, 'transparency.json'), 'utf8')).origin, raw.origin, 'a second initialize keeps the file');
    initialize(dir);
  } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('a vault started from a fresh init reports a rolled-back ledger instead of calling it valid', async () => {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/rollback-pin-')), dataDir = join(dir, 'data');
  const config = initialize(dir), key = readFileSync(join(dir, 'signing-private.pem'), 'utf8');
  const requirements = JSON.parse(readFileSync(resolve('data/requirements.json'), 'utf8'));
  const env = {TRANSPARENCY_CONFIG_FILE: join(dir, 'transparency.json')};
  const principal = id => config.principals.find(p => p.id === id);
  const boot = async () => createService({transparency: await prepareTransparency({dataDir, key, env}), dataDir, key, config, requirements});
  const get = (svc, path, id = 'alpha-auditor') => svc.handle('GET', new URL('http://localhost' + path), {authorization: 'Bearer ' + principal(id).token}, '');
  const ingest = (svc, i) => {
    const p = principal('alpha-agent'), body = JSON.stringify({id: 'e' + i, kind: 'intent', occurredAt: new Date().toISOString(), traceId: 's1',
      actionId: 'a' + i, actor: 'codex@pc', tool: 'codex', action: 'shell_exec', resource: 'echo step' + i, status: 'requested', note: '[Bash] echo'});
    const ts = String(Date.now()), nonce = randomUUID();
    return svc.handle('POST', new URL('http://localhost/api/ingest'), {authorization: 'Bearer ' + p.token, 'x-evid-timestamp': ts, 'x-evid-nonce': nonce,
      'x-evid-signature': mac(p.hmacSecret, ts, nonce, body)}, body);
  };
  let svc;
  try {
    svc = await boot();
    for (let i = 1; i <= 4; i++) await ingest(svc, i);
    await svc.transparency.pump();
    const before = await get(svc, '/api/integrity');
    assert.deepEqual([before.valid, before.transparency.mode, before.transparency.runtime.violations], [true, 'monitor', []]);
    assert.equal((await get(svc, '/api/home')).threats.integrity.transparency.mode, 'monitor');
    svc.store.close();
    // The copy an attacker would restore later, then more records that the restore will erase.
    copyFileSync(join(dataDir, 'evidence.db'), join(dir, 'older.db'));
    svc = await boot();
    for (let i = 5; i <= 8; i++) await ingest(svc, i);
    await svc.transparency.pump();
    assert.ok((await get(svc, '/api/integrity')).count > before.count);
    svc.store.close();
    for (const suffix of ['-wal', '-shm']) if (existsSync(join(dataDir, 'evidence.db' + suffix))) unlinkSync(join(dataDir, 'evidence.db' + suffix));
    copyFileSync(join(dir, 'older.db'), join(dataDir, 'evidence.db'));
    svc = await boot();
    await svc.transparency.pump();
    const after = await get(svc, '/api/integrity');
    assert.ok(after.count < before.count + 4, 'the older copy is back (records 5-8 are gone)');
    assert.equal(after.rollbackChecked, false);
    assert.deepEqual(after.transparency.runtime.violations.map(v => v.kind), ['rollback'], JSON.stringify(after.transparency.runtime));
    assert.match(after.transparency.runtime.violations[0].message, /behind the pinned heads checkpoint/);
    const home = await get(svc, '/api/home');
    const t = home.threats.integrity.transparency;
    assert.deepEqual([t.rollbackChecked, t.violations.map(v => v.kind)], [false, ['rollback']]);
  } finally {
    try { svc?.store.close(); } catch {}
    rmSync(dir, {recursive: true, force: true});
  }
});
