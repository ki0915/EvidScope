// Round 3 re-audit: evidscope-verify tlog-proof with both --policy and --key must accept only the pinned vault key for the tenant
// log (docs/receipts.md). The check looked at the first policy log named after the origin, so a receipt whose policy listed the
// vault key and then a second key under the same origin passed with a record and checkpoint signed by that second key alone.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {canonical} from '../src/crypto.mjs';
import {sha256Hex} from '../src/dsse.mjs';
import {verifyRecordReceipt} from '../src/receipts.mjs';
import {main} from '../src/verify-cli.mjs';
import * as T from '../src/tlog.mjs';

const BASE = 'vault.test/evidscope', ORIGIN = T.tenantOrigin(BASE, 'alpha');
// A forged receipt: a record the vault never wrote, in a one-leaf tree whose checkpoint the attacker's key signed.
function forgedReceipt() {
  const vault = generateKeyPairSync('ed25519'), attacker = generateKeyPairSync('ed25519');
  const record = canonical({tenant: 'alpha', seq: 1, type: 'assessment', previous: '0'.repeat(64), payload: {assessment: 'sufficient'}});
  const leaf = T.recordLeaf(sha256Hex(Buffer.from(record))), note = T.signNote(T.formatCheckpoint({origin: ORIGIN, size: 1, root: leaf}),
    T.noteSigner(ORIGIN, attacker.privateKey));
  const policy = `log ${T.logVkey(ORIGIN, vault.privateKey)}\nlog ${T.logVkey(ORIGIN, attacker.privateKey)}\nquorum none\n`;
  return {vault, record, proof: T.formatTlogProof(0, [], note), policy};
}

test('a policy that lists another key beside the pinned vault key for the same origin is refused', () => {
  const r = forgedReceipt();
  assert.throws(() => verifyRecordReceipt({proof: r.proof, record: Buffer.from(r.record), policy: r.policy, publicKey: r.vault.publicKey}),
    /not the pinned vault key/);
  // The same receipt through the published CLI: exit status 1 (not verified).
  const dir = mkdtempSync(join(tmpdir(), 'evs-pinned-policy-'));
  try {
    const file = name => join(dir, name);
    writeFileSync(file('r.json'), r.record);
    writeFileSync(file('r.tlog-proof'), r.proof);
    writeFileSync(file('r.tlog-policy'), r.policy);
    writeFileSync(file('vault.pem'), r.vault.publicKey.export({format: 'pem', type: 'spki'}));
    const out = [], sink = {write: s => out.push(s)};
    const status = main(['tlog-proof', file('r.tlog-proof'), file('r.json'), '--policy', file('r.tlog-policy'), '--key', file('vault.pem')],
      {stdout: sink, stderr: sink});
    assert.equal(status, 1, out.join(''));
  } finally { rmSync(dir, {recursive: true, force: true}); }
  // Without a pinned key the policy is the trust anchor, as documented.
  assert.equal(verifyRecordReceipt({proof: r.proof, record: Buffer.from(r.record), policy: r.policy}).valid, true);
});
