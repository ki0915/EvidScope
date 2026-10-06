// Operator helper for the vault transparency log.
//   node scripts/transparency.mjs vkeys      --config TRANSPARENCY.json --key VAULT_KEY.pem
//   node scripts/transparency.mjs witnessctl --config TRANSPARENCY.json --key VAULT_KEY.pem [--db litewitness.db] [--witness-dir DIR]
//   node scripts/transparency.mjs status     --config TRANSPARENCY.json --key VAULT_KEY.pem --data-dir DIR [--probe]
//   node scripts/transparency.mjs new-epoch  --config CURRENT.json --origin NEW_BASE --out NEW.json --key VAULT_KEY.pem [--db litewitness.db]
// new-epoch writes the config of a restore epoch (same witnesses and policy, new origin base) and prints the witness
// registration of its heads origin; then restore with scripts/vault-backup.mjs restore ... --transparency-config NEW.json.
// Only the heads origin is registered at witnesses; tenant origins are covered by heads leaves.
// --probe submits the vault's latest heads checkpoint, which advances a witness that has not seen it yet.
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {DatabaseSync} from 'node:sqlite';
import * as T from '../src/tlog.mjs';
import {assertTransparencyAnchors, normalizeTransparencyConfig, probeTransparency} from '../src/transparency.mjs';

const quote = s => (/^[A-Za-z0-9_./:+=@-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

export function transparencyKeys({config, key}) {
  return {headsOrigin: config.headsOrigin, logVkey: T.logVkey(config.headsOrigin, key), mode: config.mode, quorum: config.quorum,
    witnesses: config.witnesses.map(w => ({name: w.name, vkey: w.vkey, url: w.url}))};
}
export function witnessCommands({config, key, db = 'litewitness.db', witnessDir}) {
  const origin = config.headsOrigin, vkey = T.logVkey(origin, key), lines = [
    `witnessctl add-log -db ${quote(db)} -origin ${quote(origin)}`,
    `witnessctl add-key -db ${quote(db)} -origin ${quote(origin)} -key ${quote(vkey)}`,
  ];
  if (witnessDir) lines.push(`node scripts/witness.mjs add-log --dir ${quote(witnessDir)} --origin ${quote(origin)} --key ${quote(vkey)}`);
  return lines;
}
// A restore always forks the log, so the restored vault continues under a new origin base registered at every witness.
export function newEpochConfig(raw, origin) {
  T.validateOriginBase(origin);
  if (raw?.origin === origin) throw Error('A new epoch needs an origin base different from the current one');
  return {...raw, origin};
}
// Read-only: never raises in enforce mode, so operators can inspect a refused vault.
export async function transparencyStatus({config, key, dataDir, probe = false}) {
  const p = probe ? await probeTransparency({dataDir, key, config}) : null;
  const anchors = assertTransparencyAnchors({dataDir, key, config: {...config, mode: 'monitor'}, probe: p, inspectOnly: true});
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
    violations: anchors.violations, probe: p, cosignatures};
}

async function main(argv) {
  const [command, ...rest] = argv;
  const {values} = parseArgs({args: rest, options: {config: {type: 'string'}, key: {type: 'string'}, 'data-dir': {type: 'string'}, db: {type: 'string'},
    'witness-dir': {type: 'string'}, probe: {type: 'boolean'}, origin: {type: 'string'}, out: {type: 'string'}}});
  if (!['vkeys', 'witnessctl', 'status', 'new-epoch'].includes(command) || !values.config || !values.key || command === 'status' && !values['data-dir']
    || command === 'new-epoch' && (!values.origin || !values.out)) {
    throw Error('Usage: node scripts/transparency.mjs vkeys|witnessctl|status|new-epoch --config TRANSPARENCY.json --key VAULT_KEY.pem'
      + ' [--data-dir DIR] [--probe] [--origin NEW_BASE --out NEW.json]');
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
  if (command === 'vkeys') console.log(JSON.stringify(transparencyKeys({config, key}), null, 2));
  else if (command === 'witnessctl' || command === 'new-epoch') {
    for (const line of witnessCommands({config, key, db: values.db, witnessDir: values['witness-dir']})) console.log(line);
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
