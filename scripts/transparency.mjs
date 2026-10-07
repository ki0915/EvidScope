// Operator helper for the vault transparency log. Starting config: deploy/transparency/transparency.example.json (fill in
// the witness vkeys and URLs; keep pinFile on a volume outside the data directory).
//   node scripts/transparency.mjs vkeys      --config TRANSPARENCY.json --key VAULT_KEY.pem
//   node scripts/transparency.mjs witnessctl --config TRANSPARENCY.json --key VAULT_KEY.pem [--db litewitness.db] [--witness-dir DIR]
//                                            [--data-dir DIR] [--tenant NAME]...
//   node scripts/transparency.mjs tenants    --config TRANSPARENCY.json --key VAULT_KEY.pem --data-dir DIR [--tenant NAME]...
//   node scripts/transparency.mjs status     --config TRANSPARENCY.json --key VAULT_KEY.pem --data-dir DIR [--probe]
//   node scripts/transparency.mjs monitor    --config TRANSPARENCY.json --key VAULT_PUBLIC_OR_PRIVATE_KEY.pem --data-dir DIR
//   node scripts/transparency.mjs new-epoch  --config CURRENT.json --origin NEW_BASE --out NEW.json --key VAULT_KEY.pem [--db litewitness.db]
//   node scripts/transparency.mjs heads-checkpoint --config TRANSPARENCY.json --key VAULT_KEY.pem --data-dir DIR [--out FILE]
//   node scripts/transparency.mjs epoch-claims --config NEW_TRANSPARENCY.json --key VAULT_KEY.pem --data-dir RESTORED_DIR [--out FILE]
// With a heads signer (config.signer, docs/signer.md) the heads origin is registered with the signer's key instead of the vault
// key. heads-checkpoint prints the newest heads checkpoint of a stopped vault with the witness cosignatures (submitting it once),
// for scripts/signer.mjs authorize-handover. epoch-claims prints the restored prefix of every tenant log from the tlog epoch
// records of a restored data directory, for scripts/signer.mjs authorize-epoch --restored.
// new-epoch writes the config of a restore epoch (same witnesses and policy, new origin base) and prints the witness
// registration of its heads origin; then restore with scripts/vault-backup.mjs restore ... --transparency-config NEW.json.
// The heads origin is always registered at the witnesses. With witnessTenantLogs every tenant origin is registered too
// (witnessctl prints the lines for the tenants of --data-dir's ledger and every --tenant; tenants lists origin and log key
// per tenant). Without it, tenant origins are covered by heads leaves only, which bind database tamper but not a holder
// of the vault signing key: monitor replays every heads leaf of a database copy and reports a leaf that shrinks a tenant.
// --probe submits the vault's latest heads checkpoint, which advances a witness that has not seen it yet.
//   node scripts/transparency.mjs pin-bootstrap --config TRANSPARENCY.json --key VAULT_KEY.pem --data-dir DIR
// pin-bootstrap is the explicit decision to pin a non-empty heads log that has no pin (enforce refuses to start without
// one); it runs the startup check and, with witnesses, needs the quorum to cosign the latest heads checkpoint.
import {createPublicKey} from 'node:crypto';
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {DatabaseSync} from 'node:sqlite';
import * as T from '../src/tlog.mjs';
import {
  assertTransparencyAnchors, bootstrapPin, hasTable, headsRow, headsSize, headsVerifiers, monitorHeads, normalizeTransparencyConfig, probeTransparency,
  readEpochs, verifyHeadsRow,
} from '../src/transparency.mjs';

const quote = s => (/^[A-Za-z0-9_./:+=@-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

// logVkey: the key the witnesses register for the heads origin (the heads signer's, when there is one). After a handover from the
// vault key, the vault's own heads vkey (vaultLogVkey) is removed at the witnesses with witnessctl del-key.
export function transparencyKeys({config, key}) {
  const vault = T.logVkey(config.headsOrigin, key);
  return {headsOrigin: config.headsOrigin, logVkey: config.signer ? config.signer.vkey : vault, ...(config.signer ? {vaultLogVkey: vault} : {}),
    mode: config.mode, quorum: config.quorum, witnesses: config.witnesses.map(w => ({name: w.name, vkey: w.vkey, url: w.url}))};
}
// The heads origin, then (witnessTenantLogs) the origin of every given tenant, each with its log key.
export function witnessCommands({config, key, db = 'litewitness.db', witnessDir, tenants = []}) {
  const origins = [config.headsOrigin, ...(config.witnessTenantLogs ? [...new Set(tenants)].sort().map(t => T.tenantOrigin(config.base, t)) : [])];
  return origins.flatMap(origin => {
    const vkey = config.signer && origin === config.headsOrigin ? config.signer.vkey : T.logVkey(origin, key);
    return [`witnessctl add-log -db ${quote(db)} -origin ${quote(origin)}`, `witnessctl add-key -db ${quote(db)} -origin ${quote(origin)} -key ${quote(vkey)}`,
      ...(witnessDir ? [`node scripts/witness.mjs add-log --dir ${quote(witnessDir)} --origin ${quote(origin)} --key ${quote(vkey)}`] : [])];
  });
}
// Tenants of a data directory's ledger (read-only) plus any named explicitly, sorted and unique.
export function knownTenants({dataDir, extra = []} = {}) {
  const out = new Set(extra), file = dataDir ? join(dataDir, 'evidence.db') : null;
  if (file && existsSync(file)) {
    const db = new DatabaseSync(file, {readOnly: true});
    try {
      if (hasTable(db, 'ledger')) for (const r of db.prepare('SELECT DISTINCT tenant FROM ledger').iterate()) out.add(r.tenant);
    } finally { db.close(); }
  }
  return [...out].sort();
}
// Per tenant: its log origin and key (what a witness registers), its signed size and, per configured witness, the newest
// size that witness cosigned (null: never, for example because the origin is not registered there yet).
export function tenantLogs({config, key, dataDir, extra = []}) {
  const file = join(dataDir, 'evidence.db'), db = existsSync(file) ? new DatabaseSync(file, {readOnly: true}) : null;
  try {
    const state = db && hasTable(db, 'tlog_state') ? db.prepare('SELECT size FROM tlog_state WHERE tenant=? AND origin=?') : null;
    const cosigned = db && hasTable(db, 'tlog_cosignatures')
      ? db.prepare('SELECT size,timestamp FROM tlog_cosignatures WHERE origin=? AND key_id=? AND name=? ORDER BY size DESC LIMIT 1') : null;
    const tenants = knownTenants({dataDir, extra}).map(tenant => {
      const origin = T.tenantOrigin(config.base, tenant);
      return {tenant, origin, logVkey: T.logVkey(origin, key), size: state?.get(tenant, origin)?.size ?? 0, witnesses: config.witnesses.map(w => {
        const c = cosigned?.get(origin, w.keyId, w.name);
        return {name: w.name, cosignedSize: c?.size ?? null, timestamp: c?.timestamp ?? null};
      })};
    });
    return {originBase: config.base, headsOrigin: config.headsOrigin, witnessTenantLogs: config.witnessTenantLogs, tenants};
  } finally { db?.close(); }
}
// A restore always forks the log, so the restored vault continues under a new origin base registered at every witness.
export function newEpochConfig(raw, origin) {
  T.validateOriginBase(origin);
  if (raw?.origin === origin) throw Error('A new epoch needs an origin base different from the current one');
  return {...raw, origin};
}
// The newest heads checkpoint of a stopped vault with the cosignatures of the configured witnesses: those stored for its size and
// those one probe returns (the probe submits it). scripts/signer.mjs authorize-handover continues the heads log from it.
export async function headsCheckpoint({config, key, dataDir, fetchImpl}) {
  const publicKey = createPublicKey(key), hOrigin = config.headsOrigin, file = join(dataDir, 'evidence.db');
  if (!existsSync(file)) throw Error('No evidence database at ' + file);
  const db = new DatabaseSync(file, {readOnly: true}), lines = new Map();
  let latest;
  try {
    const n = hasTable(db, 'tlog_heads') ? headsSize(db, hOrigin) : 0;
    if (!n) throw Error(`The heads log ${hOrigin} is empty: a heads signer starts it with scripts/signer.mjs authorize-genesis`);
    latest = verifyHeadsRow(headsRow(db, hOrigin, n - 1), hOrigin, headsVerifiers(hOrigin, publicKey, config));
    const stored = hasTable(db, 'tlog_cosignatures')
      ? db.prepare('SELECT key_id,name,line FROM tlog_cosignatures WHERE origin=? AND size=?').all(hOrigin, n) : [];
    for (const r of stored) if (config.witnesses.some(w => w.keyId === r.key_id && w.name === r.name)) lines.set(`${r.name}+${r.key_id}`, r.line);
  } finally { db.close(); }
  const probe = config.witnesses.length ? await probeTransparency({dataDir, key, config, tenants: false, ...(fetchImpl ? {fetchImpl} : {})}) : null;
  for (const w of probe?.witnesses || []) if (w.status === 'consistent' && w.size === latest.size) lines.set(`${w.name}+${w.keyId}`, w.line);
  return {origin: hOrigin, size: latest.size, root: latest.root.toString('hex'), cosignatures: lines.size, quorum: config.quorum,
    witnesses: (probe?.witnesses || []).map(w => ({name: w.name, status: w.status, size: w.size ?? null})),
    checkpoint: latest.note + [...lines.values()].join('')};
}
// The restored prefix of every tenant log as the tlog epoch records of a restored data directory state it, for scripts/signer.mjs
// authorize-epoch --restored: the heads signer then accepts exactly these prefixes for logs whose newer entries the restore lost.
export function epochClaims({config, dataDir}) {
  const file = join(dataDir, 'evidence.db');
  if (!existsSync(file)) throw Error('No evidence database at ' + file);
  const db = new DatabaseSync(file, {readOnly: true}), restored = {}, from = new Set();
  try {
    for (const [tenant, list] of hasTable(db, 'ledger') ? readEpochs(db) : []) {
      const p = list.find(e => e.payload.originBase === config.base)?.payload;
      if (!p) continue;
      from.add(p.previousOriginBase);
      restored[T.tenantLogId(tenant)] = {size: p.restoredSize, root: p.restoredRoot};
    }
  } finally { db.close(); }
  if (from.size !== 1) throw Error(`The tlog epoch records of ${dataDir} do not move one origin base to ${config.base}`);
  return {fromBase: [...from][0], toBase: config.base, restored};
}
// Read-only: never raises in enforce mode, so operators can inspect a refused vault.
export async function transparencyStatus({config, key, dataDir, probe = false}) {
  const p = probe ? await probeTransparency({dataDir, key, config}) : null;
  const anchors = assertTransparencyAnchors({dataDir, key, config: {...config, mode: 'monitor', ...(p ? {} : {startupProbe: 'best_effort'})}, probe: p,
    inspectOnly: true});
  const file = join(dataDir, 'evidence.db'), cosignatures = [];
  if (existsSync(file)) {
    const db = new DatabaseSync(file, {readOnly: true});
    try {
      if (db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='tlog_cosignatures'").get()) {
        for (const r of db.prepare('SELECT name,key_id,MAX(size) size,MAX(timestamp) timestamp FROM tlog_cosignatures WHERE origin=? GROUP BY name,key_id')
          .all(config.headsOrigin)) cosignatures.push({...r, configured: config.witnesses.some(w => w.name === r.name && w.keyId === r.key_id)});
      }
    } finally { db.close(); }
  }
  return {mode: config.mode, headsOrigin: config.headsOrigin, ok: anchors.ok, headsSize: anchors.headsSize, pin: anchors.pin,
    ...(anchors.retired ? {retiredOriginBases: anchors.retired} : {}), ...(anchors.retiredPin ? {retiredPin: anchors.retiredPin} : {}),
    ...(anchors.signer ? {signer: anchors.signer} : {}), violations: anchors.violations, probe: p, cosignatures};
}

async function main(argv) {
  const [command, ...rest] = argv;
  const {values} = parseArgs({args: rest, options: {config: {type: 'string'}, key: {type: 'string'}, 'data-dir': {type: 'string'}, db: {type: 'string'},
    'witness-dir': {type: 'string'}, probe: {type: 'boolean'}, origin: {type: 'string'}, out: {type: 'string'}, tenant: {type: 'string', multiple: true}}});
  const commands = ['vkeys', 'witnessctl', 'tenants', 'status', 'monitor', 'new-epoch', 'pin-bootstrap', 'heads-checkpoint', 'epoch-claims'];
  if (!commands.includes(command) || !values.config || !values.key
    || ['tenants', 'status', 'monitor', 'pin-bootstrap', 'heads-checkpoint', 'epoch-claims'].includes(command) && !values['data-dir']
    || command === 'new-epoch' && (!values.origin || !values.out)) {
    throw Error(`Usage: node scripts/transparency.mjs ${commands.join('|')} --config TRANSPARENCY.json`
      + ' --key VAULT_KEY.pem [--data-dir DIR] [--tenant NAME]... [--probe] [--origin NEW_BASE] [--out FILE]');
  }
  const key = readFileSync(values.key, 'utf8'), dataDir = values['data-dir'] ? resolve(values['data-dir']) : resolve('.local', 'data');
  let raw = JSON.parse(readFileSync(values.config, 'utf8'));
  if (command === 'new-epoch') {
    raw = newEpochConfig(raw, values.origin);
    normalizeTransparencyConfig(raw, {dataDir, env: process.env});
    writeFileSync(values.out, JSON.stringify(raw, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  }
  const config = normalizeTransparencyConfig(raw, {dataDir, env: process.env});
  if (config.mode === 'off') throw Error('Transparency mode is off in this config');
  const output = value => {
    const text = JSON.stringify(value, null, 2) + '\n';
    if (values.out && command !== 'new-epoch') writeFileSync(values.out, text, {flag: 'wx', mode: 0o600});
    else process.stdout.write(text);
  };
  if (command === 'vkeys') console.log(JSON.stringify(transparencyKeys({config, key}), null, 2));
  else if (command === 'heads-checkpoint') output(await headsCheckpoint({config, key, dataDir}));
  else if (command === 'epoch-claims') output(epochClaims({config, dataDir}));
  else if (command === 'pin-bootstrap') {
    const probe = config.witnesses.length ? await probeTransparency({dataDir, key, config}) : null;
    console.log(JSON.stringify(bootstrapPin({dataDir, key, config, probe}), null, 2));
  }
  else if (command === 'witnessctl' || command === 'new-epoch') {
    const tenants = knownTenants({dataDir: values['data-dir'] ? dataDir : null, extra: values.tenant || []});
    if (config.witnessTenantLogs && !tenants.length) {
      console.error('witnessTenantLogs is on: pass --data-dir DIR or --tenant NAME to print the tenant origins as well');
    }
    for (const line of witnessCommands({config, key, db: values.db, witnessDir: values['witness-dir'], tenants})) console.log(line);
  }
  else if (command === 'tenants') console.log(JSON.stringify(tenantLogs({config, key, dataDir, extra: values.tenant || []}), null, 2));
  else if (command === 'monitor') {
    const result = monitorHeads({dataDir, publicKey: createPublicKey(key), config});
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 2;
  }
  else {
    const result = await transparencyStatus({config, key, dataDir, probe: !!values.probe});
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
