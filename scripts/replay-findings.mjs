// Offline policy replay: verify an EvidScope export with a trusted public key, then recompute every signed evaluation
// from the ledger records that precede it and compare with the recorded findings.
// Usage: node scripts/replay-findings.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json]
//          [--witness VKEY]... [--quorum N] [--origin-base BASE] [--min-checkpoint FILE] [--max-staleness S] [--require-transparency]
//          [--require-tenant-witness] [--heads-key VKEY]... [--require-heads-signer]
// The transparency flags pin the ledger order to a witnessed checkpoint, so ordering findings also exclude rollback;
// --require-tenant-witness demands that this holds against a holder of the vault signing key as well (see verify.mjs), and
// --require-heads-signer against whoever controls the vault host, through the pinned heads signer key (docs/signer.md).
// Exit status: 0 = verified and no mismatch (not_replayable entries are reported, not failures);
//              1 = usage, verification failure or at least one mismatch.
import {readFileSync} from 'node:fs';
import {parseArgs} from 'node:util';
import {verifyAndReplay} from '../src/policy-replay.mjs';
import {transparencyFlags, transparencyOptions} from './transparency-flags.mjs';

try {
  const {values, positionals} = parseArgs({allowPositionals: true, options: {...transparencyFlags, 'min-checkpoint': {type: 'string'}}});
  const [bundlePath, keyPath, checkpointPath] = positionals;
  if (!bundlePath || !keyPath || positionals.length > 3) {
    throw Error('Usage: node scripts/replay-findings.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json] [transparency flags]');
  }
  const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
  const checkpoint = checkpointPath ? JSON.parse(readFileSync(checkpointPath, 'utf8')) : undefined;
  const transparency = transparencyOptions(values, bundle.transparency !== undefined);
  const result = verifyAndReplay(bundle, readFileSync(keyPath, 'utf8'), checkpoint, transparency ? {transparency} : {});
  console.log(JSON.stringify(result, null, 2));
  if (!result.valid) process.exitCode = 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
