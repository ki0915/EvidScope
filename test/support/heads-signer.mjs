// A heads signer (src/signer.mjs) for vault tests: file key, its own state directory beside the vault data directory, a Unix
// socket, and the transparency config fragment ({socket, publicKeyFile}) the vault uses to reach it.
import {generateKeyPairSync} from 'node:crypto';
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as T from '../../src/tlog.mjs';
import {fileBackend} from '../../src/signer-backends.mjs';
import {createAuthorization, initSignerState, startSignerServer} from '../../src/signer.mjs';

// The key pair exists before the vault fixture, so the witness can register the signer's vkey for the heads origin.
export function signerKeys(base) {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  return {privateKey, publicKey, vkey: T.logVkey(T.headsOrigin(base), publicKey)};
}
// genesis: create the single-use genesis authorization for <base>/heads. start: false leaves the server stopped.
export async function headsSigner(t, {base, keys = signerKeys(base), genesis = true, start = true, limits = {}}) {
  const dir = mkdtempSync(join(tmpdir(), 'evs-signer-')), stateDir = join(dir, 'state'), socket = join(dir, 's.sock');
  const keyFile = join(dir, 'signer-key.pem'), publicKeyFile = join(dir, 'signer-public.pem');
  mkdirSync(dir, {recursive: true, mode: 0o700});
  writeFileSync(keyFile, keys.privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  writeFileSync(publicKeyFile, keys.publicKey.export({format: 'pem', type: 'spki'}));
  initSignerState(stateDir, keys.publicKey);
  if (genesis) createAuthorization(stateDir, {kind: 'genesis', origin: T.headsOrigin(base), predecessor: null});
  let server = null;
  const signer = {
    dir, stateDir, socket, keyFile, publicKeyFile, keys, vkey: keys.vkey, config: {socket, publicKeyFile},
    get server() { return server; },
    async start() { server ??= await startSignerServer({stateDir, backend: fileBackend({keyFile}), listen: {socket}, limits, log: () => {}}); return server; },
    async stop() { const s = server; server = null; await s?.close(); },
  };
  t.after(async () => { await signer.stop(); rmSync(dir, {recursive: true, force: true}); });
  if (start) await signer.start();
  return signer;
}
