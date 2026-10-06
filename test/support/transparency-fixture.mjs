// Shared fixture for transparency tests: a vault service driven through createService plus an in-process JS witness.
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createService} from '../../src/service.mjs';
import * as T from '../../src/tlog.mjs';
import {normalizeTransparencyConfig, probeTransparency} from '../../src/transparency.mjs';
import {createWitness} from '../../scripts/witness.mjs';

export const BASE = 'vault.test/evidscope';
const requirements = JSON.parse(readFileSync(new URL('../../data/requirements.json', import.meta.url), 'utf8'));
export const principals = ['alpha', 'beta'].map(tenant => ({id: `${tenant}-admin`, role: 'admin', tenant, token: tenant.repeat(40)}));

export async function transparencyFixture(t, {witness = true} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'evidscope-transparency-')), dataDir = join(root, 'data');
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  const services = [];
  let w = null, ws = null;
  if (witness) {
    w = createWitness({dir: join(root, 'witness'), name: 'witness.test/w1'});
    ws = await w.listen();
    w.addLog(T.headsOrigin(BASE), T.logVkey(T.headsOrigin(BASE), publicKey));
  }
  t.after(async () => {
    for (const s of services.splice(0)) { await s.transparency.stop(); s.store.close(); }
    if (ws) { await ws.close(); w.close(); }
    rmSync(root, {recursive: true, force: true});
  });
  const config = (mode, {dir = dataDir, ...extra} = {}) => normalizeTransparencyConfig(mode === 'off' ? null
    : {origin: BASE, mode, witnesses: w ? [{vkey: w.vkey, url: ws.url}] : [], intervalMs: 100, timeoutMs: 2000, ...extra}, {dataDir: dir});
  async function open(mode = 'enforce', {dir = dataDir, cfg = config(mode, {dir})} = {}) {
    const probe = cfg.mode !== 'off' && cfg.witnesses.length ? await probeTransparency({dataDir: dir, key: privateKey, config: cfg}) : null;
    const service = createService({dataDir: dir, key: privateKey, config: {principals}, requirements, transparency: {config: cfg, probe}});
    services.push(service);
    return service;
  }
  async function close(service) {
    services.splice(services.indexOf(service), 1);
    await service.transparency.stop();
    service.store.close();
  }
  const call = (service, path, tenant = 'alpha') => service.handle('GET', new URL(path, 'http://local'), {authorization: 'Bearer ' + tenant.repeat(40)}, '');
  const write = (service, tenant, n) => {
    for (let i = 0; i < n; i++) service.store.transaction(() => service.store.append(tenant, 'note', {i}, 'test'));
  };
  return {root, dataDir, privateKey, publicKey, w, ws, config, open, close, call, write};
}

// The S1 attacker: an external connection that drops the append-only triggers and deletes rows.
export function tamper(dataDir, fn) {
  const db = new DatabaseSync(join(dataDir, 'evidence.db'));
  try {
    for (const {name} of db.prepare("SELECT name FROM sqlite_schema WHERE type='trigger'").all()) db.exec(`DROP TRIGGER "${name}"`);
    fn(db);
  } finally { db.close(); }
}
export function wipeTenant(db, tenant) {
  for (const {name} of db.prepare("SELECT name FROM sqlite_schema WHERE type='table'").all()) {
    if (db.prepare(`PRAGMA table_info("${name}")`).all().some(c => c.name === 'tenant')) db.prepare(`DELETE FROM "${name}" WHERE tenant=?`).run(tenant);
  }
}
// Consistent copy of a live WAL database, as an operator backup or an attacker's stale copy would be.
export function snapshot(dataDir, target) {
  const db = new DatabaseSync(join(dataDir, 'evidence.db'), {readOnly: true});
  try { db.prepare('VACUUM INTO ?').run(target); } finally { db.close(); }
}
export function replaceDatabase(dataDir, source) {
  for (const suffix of ['-wal', '-shm']) rmSync(join(dataDir, 'evidence.db' + suffix), {force: true});
  rmSync(join(dataDir, 'evidence.db'), {force: true});
  const db = new DatabaseSync(source, {readOnly: true});
  try { db.prepare('VACUUM INTO ?').run(join(dataDir, 'evidence.db')); } finally { db.close(); }
}
export const ledgerCount = (service, tenant) => service.store.db.prepare('SELECT COUNT(*) n FROM ledger WHERE tenant=?').get(tenant).n;
