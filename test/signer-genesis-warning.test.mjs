// Round 3 re-audit: authorize-genesis starts a heads origin unchecked against what the signer signed before. Run while another
// origin is active (an operator restoring a vault under a new base, instead of authorize-epoch), it now says so in its output.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {generateKeyPairSync, randomBytes} from 'node:crypto';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {promisify} from 'node:util';
import * as T from '../src/tlog.mjs';
import {fileBackend} from '../src/signer-backends.mjs';
import {initSignerState, listAuthorizations, openSigner} from '../src/signer.mjs';
import {genesisAuthorization} from '../scripts/signer.mjs';

const BASE = 'vault.test/evidscope', EMPTY = T.EMPTY_ROOT.toString('hex');
function signerState(t) {
  const root = mkdtempSync(join(tmpdir(), 'evs-genesis-warning-')), stateDir = join(root, 'state'), keyFile = join(root, 'signer.pem');
  t.after(() => rmSync(root, {recursive: true, force: true}));
  writeFileSync(keyFile, generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  const backend = fileBackend({keyFile});
  initSignerState(stateDir, backend.publicKey);
  return {stateDir, backend};
}

test('authorize-genesis warns while the signer still signs another heads origin', async t => {
  const {stateDir, backend} = signerState(t);
  // The first genesis on an empty signer is the documented start: no warning.
  const first = genesisAuthorization({stateDir, originBase: BASE});
  assert.equal(first.warning, undefined);
  const core = openSigner({stateDir, backend});
  t.after(() => core.close());
  const log = `${BASE}/t/${T.tenantLogId('alpha')}`, root = T.mth([T.leafHash(randomBytes(16))]).toString('hex');
  await core.signHeads({origin: T.headsOrigin(BASE), previous: {size: 0, root: EMPTY}, leaf: {entries: [{log, size: 1, root}]}});
  const second = genesisAuthorization({stateDir, originBase: 'vault.test/evidscope-2'});
  assert.match(second.warning, /still signs vault\.test\/evidscope\/heads: this genesis starts vault\.test\/evidscope-2\/heads unchecked/);
  assert.match(second.warning, new RegExp(`authorize-epoch .*revoke --id ${second.id}`));
  // The authorization is still made (a separate vault may share the signer); the operator decides.
  assert.ok(listAuthorizations(stateDir).some(a => a.id === second.id && a.status === 'pending'));
  // The CLI prints the warning on standard error and the authorization on standard output.
  const r = await promisify(execFile)(process.execPath, ['scripts/signer.mjs', 'authorize-genesis', '--state-dir', stateDir,
    '--origin-base', 'vault.test/evidscope-3'], {encoding: 'utf8', timeout: 30000});
  assert.match(JSON.parse(r.stderr).warning, /still signs vault\.test\/evidscope\/heads/);
  assert.equal(JSON.parse(r.stdout).kind, 'genesis');
});
