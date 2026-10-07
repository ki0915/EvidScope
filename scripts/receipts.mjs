// Operator side of the standard receipts (docs/receipts.md), read-only on a vault data directory:
//   node scripts/receipts.mjs record --config TRANSPARENCY.json --key VAULT_KEY.pem --data-dir DIR --tenant NAME --seq N [--out DIR]
//   node scripts/receipts.mjs policy --config TRANSPARENCY.json --key VAULT_KEY.pem --tenant NAME
// record writes the files GET /api/receipts/record unpacks to: <name>.json (the ledger record body as hashed),
// <name>.tlog-proof and <name>.tlog-policy; check them with evidscope-verify tlog-proof. policy prints the tenant log's
// c2sp.org/tlog-policy for publication next to the vault public key.
import {createPublicKey} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {DatabaseSync} from 'node:sqlite';
import {recordReceipt} from '../src/receipt-service.mjs';
import {deploymentTlogPolicy, unpackResponse} from '../src/receipts.mjs';
import {normalizeTransparencyConfig} from '../src/transparency.mjs';

// One read transaction, so the record, the tenant checkpoint and its cosignatures come from the same database state.
export function recordReceiptFromDataDir({config, key, dataDir, tenant, seq}) {
  const file = join(dataDir, 'evidence.db');
  if (!existsSync(file)) throw Error('No vault database at ' + file);
  const db = new DatabaseSync(file, {readOnly: true});
  try {
    db.exec('BEGIN');
    try { return recordReceipt({db, config, publicKey: createPublicKey(key), tenant, seq}); } finally { db.exec('ROLLBACK'); }
  } finally { db.close(); }
}

function main(argv) {
  const [command, ...rest] = argv;
  const {values} = parseArgs({args: rest, options: {config: {type: 'string'}, key: {type: 'string'}, 'data-dir': {type: 'string'}, tenant: {type: 'string'},
    seq: {type: 'string'}, out: {type: 'string'}}});
  if (!['record', 'policy'].includes(command) || !values.config || !values.key || !values.tenant
    || command === 'record' && (!values['data-dir'] || !/^[1-9][0-9]{0,15}$/.test(values.seq || ''))) {
    throw Error('Usage: node scripts/receipts.mjs record|policy --config TRANSPARENCY.json --key VAULT_KEY.pem --tenant NAME'
      + ' [--data-dir DIR --seq N [--out DIR]]');
  }
  const key = readFileSync(values.key, 'utf8'), dataDir = resolve(values['data-dir'] || '.');
  const config = normalizeTransparencyConfig(JSON.parse(readFileSync(values.config, 'utf8')), {dataDir, env: process.env});
  if (config.mode === 'off') throw Error('Transparency mode is off in this config: there is no tenant log to prove records in');
  if (command === 'policy') { process.stdout.write(deploymentTlogPolicy(config, createPublicKey(key), values.tenant)); return; }
  const receipt = recordReceiptFromDataDir({config, key, dataDir, tenant: values.tenant, seq: Number(values.seq)}), out = resolve(values.out || '.');
  mkdirSync(out, {recursive: true});
  const files = unpackResponse(receipt).map(f => { writeFileSync(join(out, f.name), f.bytes, {flag: 'wx'}); return join(out, f.name); });
  console.log(JSON.stringify({tenant: receipt.tenant, seq: receipt.seq, origin: receipt.origin, checkpointSize: receipt.checkpointSize,
    witnessed: receipt.witnessed, quorum: receipt.quorum, files}, null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { main(process.argv.slice(2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
