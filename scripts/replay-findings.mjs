// Offline policy replay: verify an EvidScope export with a trusted public key, then recompute every signed evaluation
// from the ledger records that precede it and compare with the recorded findings.
// Usage: node scripts/replay-findings.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json]
// Exit status: 0 = verified and no mismatch (not_replayable entries are reported, not failures);
//              1 = usage, verification failure or at least one mismatch.
import {readFileSync} from 'node:fs';
import {verifyAndReplay} from '../src/policy-replay.mjs';

try {
  const [bundlePath, keyPath, checkpointPath] = process.argv.slice(2);
  if (!bundlePath || !keyPath) throw Error('Usage: node scripts/replay-findings.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json]');
  const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
  const checkpoint = checkpointPath ? JSON.parse(readFileSync(checkpointPath, 'utf8')) : undefined;
  const result = verifyAndReplay(bundle, readFileSync(keyPath, 'utf8'), checkpoint);
  console.log(JSON.stringify(result, null, 2));
  if (!result.valid) process.exitCode = 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
