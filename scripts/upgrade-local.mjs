// Brings a local install created before the evidence-layer changes up to the new defaults. Run with `npm start` stopped.
//   node scripts/upgrade-local.mjs [--dir .local] [--transparency] [--heads-signer [--heads-signer-port N]] [--dry-run]
// Steps (each skipped when already done, so the command is idempotent):
//   1. add a Bearer-only `<tenant>-otlp` source principal per tenant (OpenTelemetry /v1/traces intake);
//   2. create data-encryption.key and re-encrypt stored documents under it (signing key no longer encrypts data); when the key
//      already exists but referenced documents are still under another key id (an interrupted run), finish the migration;
//   3. with --transparency, write transparency.json (monitor mode, local pin only) that `npm start` picks up;
//   4. with --heads-signer, set up a heads signer (docs/signer.md) under <dir>/signer that `npm start` runs beside the vault.
// Every file it changes is first copied to <dir>/upgrade-backup-<timestamp>/. Tokens and key bytes are never printed.
import {copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync} from 'node:fs';
import {createPublicKey, generateKeyPairSync, randomBytes} from 'node:crypto';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {DatabaseSync} from 'node:sqlite';
import {dataKeyId, generateDataKeyFile, readDataKeyFile} from '../src/data-keys.mjs';
import * as T from '../src/tlog.mjs';
import {createAuthorization, initSignerState} from '../src/signer.mjs';
import {hasTable, headsSize, normalizeTransparencyConfig} from '../src/transparency.mjs';
import {documentKeyUsage, migrateDocuments} from './data-key.mjs';
import {handoverAuthorization} from './signer.mjs';
import {headsCheckpoint} from './transparency.mjs';

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

  // 1. OTLP principals. A restored vault binds config.json by hash, so editing it in place would stop the vault from starting
  //    until the operator records a signed config rebinding (scripts/vault-backup.mjs rebind).
  const config = JSON.parse(readFileSync(configFile, 'utf8'));
  const tenants = [...new Set(config.principals.filter(p => p.role === 'source').map(p => p.tenant))].sort();
  const missing = tenants.filter(t => !config.principals.some(p => p.tenant === t && p.role === 'source' && p.kind === 'otlp'));
  if (!missing.length) steps.push({step: 'otlp_principals', status: 'already_present'});
  else if (existsSync(join(dataDir, RESTORATION_MARKER))) {
    steps.push({step: 'otlp_principals', status: 'skipped',
      reason: 'restored vault binds config.json; add the principals to a new config file and record a signed rebinding with '
        + 'scripts/vault-backup.mjs rebind (docs/vault-recovery.md) before starting the vault with it'});
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
  const keyFile = join(dir, 'data-encryption.key'), hasDatabase = existsSync(join(dataDir, 'evidence.db'));
  const migrate = kid => {
    try {
      const m = migrateDocuments({dataDir, signingKey: readFileSync(signingFile, 'utf8'), dataKey: readDataKeyFile(keyFile)});
      return {tenants: m.tenants, reencryptedFrom: m.reencryptedFrom, retiredKeyIds: m.retiredKeyIds};
    } catch (error) {
      // The key file stays: data_key_usage may already reference it, and a vault without it would refuse to start.
      throw Error(`Data key ${kid} is in place but document migration failed: ${error.message}. Stop the vault and re-run.`);
    }
  };
  if (existsSync(keyFile)) {
    // An earlier run may have created the key and failed mid-migration; migrateDocuments is idempotent, so finish it.
    const dataKey = readDataKeyFile(keyFile), kid = dataKeyId(dataKey);
    const pending = Object.fromEntries(Object.entries(hasDatabase ? documentKeyUsage({dataDir, signingKey: readFileSync(signingFile, 'utf8'), dataKey}) : {})
      .filter(([id]) => id !== kid));
    if (!Object.keys(pending).length) steps.push({step: 'data_key', status: 'already_present'});
    else if (dryRun) steps.push({step: 'data_key', status: 'would_migrate', kid, pendingFilesByKeyId: pending});
    else steps.push({step: 'data_key', status: 'migrated', kid, pendingFilesByKeyId: pending, migration: migrate(kid)});
  } else if (dryRun) steps.push({step: 'data_key', status: 'would_create_and_migrate'});
  else {
    const kid = generateDataKeyFile(keyFile);
    steps.push({step: 'data_key', status: 'created', kid, file: keyFile, migration: hasDatabase ? migrate(kid) : null});
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

  const changed = !dryRun && steps.some(s => ['added', 'created', 'migrated'].includes(s.status));
  return {upgraded: changed, dryRun, dir, backupDir: changed && existsSync(backupDir) ? backupDir : null, steps,
    nextSteps: changed ? ['Start the service again with npm start.', 'Create a new vault backup; older backups stay readable with the signing key.'] : []};
}

// 4. A heads signer beside the local vault: its own key and state under <dir>/signer, served by `npm start` from signer/serve.json
//    on a Unix socket (Windows: a named pipe; --heads-signer-port: loopback TCP), both with a bearer token except the socket, and
//    transparency.json pointing the vault at it. A vault whose heads log already has leaves hands it over (signer.mjs
//    authorize-handover); a new one starts it (authorize-genesis). On one machine and account this separates processes, not
//    hosts: the protection of docs/signer.md needs the signer on another host or container.
export async function setupLocalSigner({dir, port, dryRun = false, platform = process.platform}) {
  dir = resolve(dir);
  const tlogFile = join(dir, 'transparency.json'), signerDir = join(dir, 'signer'), serveFile = join(signerDir, 'serve.json');
  const dataDir = join(dir, 'data'), signingFile = join(dir, 'signing-private.pem');
  if (!existsSync(tlogFile)) return {step: 'heads_signer', status: 'skipped', reason: 'needs transparency.json: add --transparency'};
  const raw = JSON.parse(readFileSync(tlogFile, 'utf8'));
  if (raw.signer || existsSync(serveFile)) return {step: 'heads_signer', status: 'already_present'};
  if (existsSync(signerDir)) throw Error(`${signerDir} exists without serve.json (an interrupted run): move it away and run again`);
  if (port !== undefined && !(Number.isSafeInteger(port) && port >= 1024 && port <= 65535)) throw Error('--heads-signer-port must be 1024..65535');
  const config = normalizeTransparencyConfig(raw, {dataDir}), key = readFileSync(signingFile, 'utf8');
  const file = join(dataDir, 'evidence.db'), db = existsSync(file) ? new DatabaseSync(file, {readOnly: true}) : null;
  let size = 0;
  try { size = db && hasTable(db, 'tlog_heads') ? headsSize(db, config.headsOrigin) : 0; } finally { db?.close(); }
  const tokenFile = join(signerDir, 'token'), withToken = port !== undefined || platform === 'win32';
  const listen = port !== undefined ? {url: `http://127.0.0.1:${port}`, args: ['--host', '127.0.0.1', '--port', String(port)]}
    : platform === 'win32' ? (pipe => ({pipe, args: ['--pipe', pipe]}))(`\\\\.\\pipe\\evidscope-signer-${randomBytes(8).toString('hex')}`)
      : {socket: join(signerDir, 'signer.sock'), args: ['--socket', join(signerDir, 'signer.sock')]};
  const authorization = size ? 'handover' : 'genesis', address = listen.url ?? listen.pipe ?? listen.socket;
  if (dryRun) return {step: 'heads_signer', status: 'would_create', authorization, listen: address};
  // The vault's newest heads checkpoint (with the cosignatures the handover needs) before anything is written.
  const checkpoint = size ? (await headsCheckpoint({config, key, dataDir})).checkpoint : null;
  mkdirSync(signerDir, {recursive: true, mode: 0o700});
  try {
    const {privateKey, publicKey} = generateKeyPairSync('ed25519'), stateDir = join(signerDir, 'state');
    const keyFile = join(signerDir, 'signer-key.pem'), publicKeyFile = join(signerDir, 'signer-public.pem');
    writeFileSync(keyFile, privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600, flag: 'wx'});
    writeFileSync(publicKeyFile, publicKey.export({format: 'pem', type: 'spki'}), {flag: 'wx'});
    if (withToken) writeFileSync(tokenFile, randomBytes(32).toString('hex') + '\n', {mode: 0o600, flag: 'wx'});
    initSignerState(stateDir, publicKey);
    if (checkpoint) {
      handoverAuthorization({stateDir, checkpoint, vaultKey: createPublicKey(key), witnesses: config.witnesses.map(w => w.vkey), quorum: config.quorum});
    } else createAuthorization(stateDir, {kind: 'genesis', origin: config.headsOrigin, predecessor: null});
    const args = ['--state-dir', stateDir, '--backend', 'file', '--key-file', keyFile, ...listen.args, ...(withToken ? ['--token-file', tokenFile] : [])];
    writeAtomic(serveFile, JSON.stringify({format: 'evidscope-local-signer-v1', args}, null, 2) + '\n');
    const signer = {...(listen.socket ? {socket: listen.socket} : listen.pipe ? {pipe: listen.pipe} : {url: listen.url}),
      ...(withToken ? {tokenFile} : {}), publicKeyFile};
    copyFileSync(tlogFile, join(signerDir, 'transparency.before-signer.json'));
    writeAtomic(tlogFile, JSON.stringify({...raw, signer}, null, 2) + '\n');
    return {step: 'heads_signer', status: 'created', authorization, listen: address, stateDir, headsOrigin: config.headsOrigin,
      vkey: T.logVkey(config.headsOrigin, publicKey), vaultVkey: T.logVkey(config.headsOrigin, createPublicKey(key)),
      note: (config.witnesses.length ? 'Before npm start, add vkey for the heads origin at every witness (witnessctl add-key); once the first '
        + 'signer checkpoint is cosigned, remove vaultVkey there (witnessctl del-key). ' : '')
        + 'The signer runs on this machine under this account: it separates processes, not hosts (docs/signer.md).'};
  } catch (error) {
    rmSync(signerDir, {recursive: true, force: true});
    throw error;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const {values} = parseArgs({options: {dir: {type: 'string'}, transparency: {type: 'boolean'}, 'heads-signer': {type: 'boolean'},
      'heads-signer-port': {type: 'string'}, 'dry-run': {type: 'boolean'}}});
    const dir = values.dir || process.env.EVIDSCOPE_LOCAL_DIR || '.local', dryRun = !!values['dry-run'];
    const result = upgradeLocal({dir, transparency: !!values.transparency, dryRun});
    if (values['heads-signer']) {
      const port = values['heads-signer-port'] === undefined ? undefined : Number(values['heads-signer-port']);
      // A dry run may only plan transparency.json: plan the signer as if it were there.
      const planned = dryRun && result.steps.at(-1).status === 'would_create';
      const step = planned ? {step: 'heads_signer', status: 'would_create', authorization: 'genesis'} : await setupLocalSigner({dir, port, dryRun});
      result.steps.push(step);
      if (step.status === 'created') {
        result.upgraded = true;
        result.nextSteps = ['Start the service again with npm start; it starts the heads signer first.', ...result.nextSteps.slice(1)];
      }
    }
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(JSON.stringify({ok: false, error: error.message}));
    process.exitCode = 1;
  }
}
