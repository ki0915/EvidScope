// Brings a local install created before the evidence-layer changes up to the new defaults. Run with `npm start` stopped.
//   node scripts/upgrade-local.mjs [--dir .local] [--transparency] [--dry-run]
// Steps (each skipped when already done, so the command is idempotent):
//   1. add a Bearer-only `<tenant>-otlp` source principal per tenant (OpenTelemetry /v1/traces intake);
//   2. create data-encryption.key and re-encrypt stored documents under it (signing key no longer encrypts data);
//   3. with --transparency, write transparency.json (monitor mode, local pin only) that `npm start` picks up.
// Every file it changes is first copied to <dir>/upgrade-backup-<timestamp>/. Tokens and key bytes are never printed.
import {copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {generateDataKeyFile, readDataKeyFile} from '../src/data-keys.mjs';
import {migrateDocuments} from './data-key.mjs';

const RESTORATION_MARKER = 'vault-restoration.json';

function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  writeFileSync(tmp, text, {mode: 0o600, flag: 'wx'});
  renameSync(tmp, file);
}

export function upgradeLocal({dir, transparency = false, dryRun = false, now = () => new Date()}) {
  dir = resolve(dir);
  const configFile = join(dir, 'config.json'), signingFile = join(dir, 'signing-private.pem'), dataDir = join(dir, 'data');
  if (!existsSync(configFile) || !existsSync(signingFile)) throw Error(`No local install in ${dir}: run npm start once first`);
  const steps = [], backupDir = join(dir, `upgrade-backup-${now().toISOString().replace(/[:.]/g, '-')}`);
  const backup = file => {
    if (dryRun) return;
    mkdirSync(backupDir, {recursive: true, mode: 0o700});
    copyFileSync(file, join(backupDir, file.slice(dir.length + 1).replace(/[\\/]/g, '__')));
  };

  // 1. OTLP principals. A restored vault binds config.json by hash, so editing it there would stop the vault from starting.
  const config = JSON.parse(readFileSync(configFile, 'utf8'));
  const tenants = [...new Set(config.principals.filter(p => p.role === 'source').map(p => p.tenant))].sort();
  const missing = tenants.filter(t => !config.principals.some(p => p.tenant === t && p.role === 'source' && p.kind === 'otlp'));
  if (!missing.length) steps.push({step: 'otlp_principals', status: 'already_present'});
  else if (existsSync(join(dataDir, RESTORATION_MARKER))) {
    steps.push({step: 'otlp_principals', status: 'skipped', reason: 'restored vault binds config.json; add principals before restoring or re-pin'});
  } else {
    const taken = new Set(config.principals.map(p => p.id)), added = [];
    for (const tenant of missing) {
      let id = `${tenant}-otlp`;
      for (let n = 2; taken.has(id); n++) id = `${tenant}-otlp-${n}`;
      taken.add(id);
      added.push({id, tenant, role: 'source', kind: 'otlp', token: randomBytes(32).toString('base64url')});
    }
    if (!dryRun) {
      backup(configFile);
      writeAtomic(configFile, JSON.stringify({...config, principals: [...config.principals, ...added]}, null, 2));
    }
    steps.push({step: 'otlp_principals', status: dryRun ? 'would_add' : 'added', principals: added.map(p => p.id),
      note: 'Tokens are in config.json; give each to the matching OpenTelemetry exporter as a Bearer header.'});
  }

  // 2. Data-encryption key separate from the signing key, then re-encrypt referenced documents under it.
  const keyFile = join(dir, 'data-encryption.key');
  if (existsSync(keyFile)) {
    readDataKeyFile(keyFile);
    steps.push({step: 'data_key', status: 'already_present'});
  } else if (dryRun) steps.push({step: 'data_key', status: 'would_create_and_migrate'});
  else {
    const kid = generateDataKeyFile(keyFile);
    let migration = null;
    if (existsSync(join(dataDir, 'evidence.db'))) {
      try {
        migration = migrateDocuments({dataDir, signingKey: readFileSync(signingFile, 'utf8'), dataKey: readDataKeyFile(keyFile)});
      } catch (error) {
        // The key file stays: data_key_usage may already reference it, and a vault without it would refuse to start.
        throw Error(`Data key created (${kid}) but document migration failed: ${error.message}. Stop the vault and re-run.`);
      }
    }
    steps.push({step: 'data_key', status: 'created', kid, file: keyFile, migration: migration && {
      tenants: migration.tenants, reencryptedFrom: migration.reencryptedFrom, retiredKeyIds: migration.retiredKeyIds}});
  }

  // 3. Transparency log in monitor mode with only the local pin as anchor; add witnesses later (docs/transparency-log.md).
  const tlogFile = join(dir, 'transparency.json');
  if (!transparency) steps.push({step: 'transparency', status: existsSync(tlogFile) ? 'already_present' : 'not_requested'});
  else if (existsSync(tlogFile)) steps.push({step: 'transparency', status: 'already_present'});
  else {
    const body = {origin: `evidscope.local/${randomBytes(8).toString('hex')}`, witnesses: [], quorum: 0, mode: 'monitor'};
    if (!dryRun) writeAtomic(tlogFile, JSON.stringify(body, null, 2) + '\n');
    steps.push({step: 'transparency', status: dryRun ? 'would_create' : 'created', file: tlogFile, origin: body.origin,
      note: 'Monitor mode with a local pin only detects rollback against that pin; add an independent witness for real assurance.'});
  }

  const changed = !dryRun && steps.some(s => ['added', 'created'].includes(s.status));
  return {upgraded: changed, dryRun, dir, backupDir: changed && existsSync(backupDir) ? backupDir : null, steps,
    nextSteps: changed ? ['Start the service again with npm start.', 'Create a new vault backup; older backups stay readable with the signing key.'] : []};
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const {values} = parseArgs({options: {dir: {type: 'string'}, transparency: {type: 'boolean'}, 'dry-run': {type: 'boolean'}}});
    const dir = values.dir || process.env.EVIDSCOPE_LOCAL_DIR || '.local';
    console.log(JSON.stringify(upgradeLocal({dir, transparency: !!values.transparency, dryRun: !!values['dry-run']}), null, 2));
  } catch (error) {
    console.error(JSON.stringify({ok: false, error: error.message}));
    process.exitCode = 1;
  }
}
