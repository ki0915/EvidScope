// Heads signer (docs/signer.md). Runs on its own host or container with its own state volume; the vault reaches it over a Unix
// socket, a Windows named pipe, or TCP with a bearer token (TLS off loopback).
//   node scripts/signer.mjs keygen --out SIGNER_KEY.pem [--public-out SIGNER_PUBLIC.pem]
//   node scripts/signer.mjs token  --out TOKEN_FILE
//   node scripts/signer.mjs init   --state-dir DIR BACKEND [--if-missing]   (--if-missing: keep an existing state of the same key)
//   node scripts/signer.mjs serve  --state-dir DIR BACKEND (--socket PATH [--socket-mode 600] | --pipe NAME | --host 127.0.0.1 --port N)
//                                  [--token-file FILE] [--tls-cert CERT.pem --tls-key KEY.pem] [--signs-per-minute N] [--max-request-bytes N]
//   node scripts/signer.mjs public-key --state-dir DIR [--out SIGNER_PUBLIC.pem]       (the vault's signer.publicKeyFile)
//   node scripts/signer.mjs vkey   --state-dir DIR --origin-base BASE                   (witnessctl add-key, verify --heads-key)
//   node scripts/signer.mjs status --state-dir DIR
//   node scripts/signer.mjs head   --state-dir DIR --origin-base BASE [--out FILE]     (restore --signer-head)
//   node scripts/signer.mjs authorize-genesis  --state-dir DIR --origin-base BASE
//   node scripts/signer.mjs authorize-handover --state-dir DIR --checkpoint FILE --vault-key VAULT_PUBLIC.pem [--witness VKEY]... [--quorum N]
//                                             [--max-age SECONDS]   (FILE: scripts/transparency.mjs heads-checkpoint of the stopped vault)
//   node scripts/signer.mjs authorize-epoch    --state-dir DIR --from-base OLD --to-base NEW [--accept-loss REASON] [--restored FILE]
//                                             [--drop-log LOG_ID]...
//   node scripts/signer.mjs authorizations --state-dir DIR | revoke --state-dir DIR --id ID
//   node scripts/signer.mjs rotate-key --state-dir DIR BACKEND     (signer stopped; register the new vkey at the witnesses first)
//   node scripts/signer.mjs audit  --state-dir DIR [--verify]
// BACKEND: --backend file --key-file SIGNER_KEY.pem
//        | --backend ssh-agent --fingerprint SHA256:... [--agent-socket PATH_OR_PIPE]
//        | --backend command --public-key SIGNER_PUBLIC.pem --command '["prog","arg",...]' [--command-timeout-ms N] [--command-output auto|raw|base64]
import {generateKeyPairSync, randomBytes} from 'node:crypto';
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import * as T from '../src/tlog.mjs';
import {createBackend, readEd25519PublicKey, selfTest} from '../src/signer-backends.mjs';
import {
  createAuthorization, initSignerState, listAuthorizations, readSignerState, revokeAuthorization, rotateSignerKey, signerHead, startSignerServer,
  verifyAuditLog,
} from '../src/signer.mjs';
import {readSignerToken} from '../src/signer-client.mjs';

const OPTIONS = {
  'state-dir': {type: 'string'}, out: {type: 'string'}, 'public-out': {type: 'string'}, backend: {type: 'string'}, 'key-file': {type: 'string'},
  'agent-socket': {type: 'string'}, fingerprint: {type: 'string'}, 'public-key': {type: 'string'}, command: {type: 'string'},
  'command-timeout-ms': {type: 'string'}, 'command-output': {type: 'string'}, socket: {type: 'string'}, 'socket-mode': {type: 'string'},
  pipe: {type: 'string'}, host: {type: 'string'}, port: {type: 'string'}, 'token-file': {type: 'string'}, 'tls-cert': {type: 'string'},
  'tls-key': {type: 'string'}, 'signs-per-minute': {type: 'string'}, 'max-request-bytes': {type: 'string'}, 'max-entries': {type: 'string'},
  'origin-base': {type: 'string'}, checkpoint: {type: 'string'}, 'vault-key': {type: 'string'}, witness: {type: 'string', multiple: true},
  quorum: {type: 'string'}, 'max-age': {type: 'string'}, 'from-base': {type: 'string'}, 'to-base': {type: 'string'}, 'accept-loss': {type: 'string'},
  restored: {type: 'string'}, 'if-missing': {type: 'boolean'},
  'drop-log': {type: 'string', multiple: true}, id: {type: 'string'}, verify: {type: 'boolean'}, note: {type: 'string'},
};
const need = (values, ...names) => { for (const n of names) if (values[n] === undefined) throw Error(`--${n} is required`); };
const int = (v, what) => { const n = Number(v); if (!Number.isSafeInteger(n) || n < 0) throw Error(`${what} must be a non-negative integer`); return n; };
const writeSecret = (file, text) => writeFileSync(resolve(file), text, {flag: 'wx', mode: 0o600});
export function backendSpec(values) {
  const kind = values.backend ?? 'file';
  if (kind === 'file') { need(values, 'key-file'); return {kind, keyFile: resolve(values['key-file'])}; }
  if (kind === 'ssh-agent') return {kind, fingerprint: values.fingerprint, ...(values['agent-socket'] ? {socket: values['agent-socket']} : {})};
  if (kind === 'command') {
    need(values, 'command', 'public-key');
    let argv;
    try { argv = JSON.parse(values.command); } catch { throw Error('--command must be a JSON array of strings (argv; no shell is used)'); }
    const timeout = values['command-timeout-ms'] ? {timeoutMs: int(values['command-timeout-ms'], '--command-timeout-ms')} : {};
    return {kind, argv, publicKeyFile: resolve(values['public-key']), ...timeout, ...(values['command-output'] ? {output: values['command-output']} : {})};
  }
  throw Error('--backend must be file, ssh-agent or command');
}
const stateKey = dir => T.ed25519Public(Buffer.from(readSignerState(dir).keys.at(-1), 'base64'));
const headsOriginOf = base => T.headsOrigin(T.validateOriginBase(base));
// The vault's heads checkpoint to continue: a signed note, or JSON with a `checkpoint` note (a pin file, transparency.mjs heads-checkpoint).
function readCheckpointFile(file) {
  const text = readFileSync(resolve(file), 'utf8');
  try { const j = JSON.parse(text); if (typeof j?.checkpoint === 'string') return j.checkpoint; } catch { /* a bare note */ }
  return text;
}
// Only cosignatures made within maxAgeSeconds count: an old cosigned checkpoint may lie behind what the witnesses saw since.
export function handoverAuthorization({stateDir, checkpoint, vaultKey, witnesses = [], quorum, maxAgeSeconds = 86400, now = () => Date.now()}) {
  const origin = T.parseCheckpoint(T.noteText(checkpoint)).origin, logV = T.noteVerifier(T.logVkey(origin, vaultKey));
  const cosigners = witnesses.map(w => T.cosignatureVerifier(w)), opened = T.openNote(checkpoint, [logV, ...cosigners]), c = T.parseCheckpoint(opened.text);
  if (!opened.sigs.some(s => s.name === logV.name && s.id === logV.id.toString('hex'))) throw Error('The checkpoint is not signed by the vault key');
  if (!origin.endsWith('/heads') || c.size < 1) throw Error('The checkpoint is not a non-empty heads checkpoint');
  const required = quorum ?? (witnesses.length ? 1 : 0), t = Math.floor(now() / 1000);
  const got = opened.sigs.filter(s => cosigners.some(v => v.name === s.name && v.id.toString('hex') === s.id)
    && Math.abs(t - T.cosignatureTimestamp(s.raw)) <= maxAgeSeconds).length;
  if (got < required) throw Error(`The checkpoint carries ${got} of ${required} required witness cosignatures made in the last ${maxAgeSeconds} s`);
  const state = readSignerState(stateDir);
  if (state.origins[origin]) throw Error(`The signer already signs ${origin}`);
  return createAuthorization(stateDir, {kind: 'handover', origin, predecessor: {origin, size: c.size, root: c.root.toString('hex'), key: logV.vkey,
    cosignatures: got}}, {now});
}
export function epochAuthorization({stateDir, fromBase, toBase, acceptLoss, restored, dropLogs = [], now}) {
  const from = headsOriginOf(fromBase), to = headsOriginOf(toBase), state = readSignerState(stateDir), p = state.origins[from];
  if (!p || p.status !== 'active') throw Error(`The signer holds no active heads origin ${from}`);
  if (state.origins[to]) throw Error(`The signer already signs ${to}`);
  const signed = new Map(p.entries.map(e => [e.log.slice(fromBase.length + 3), e]));
  for (const id of dropLogs) if (!signed.has(id)) throw Error(`--drop-log ${id} is not a tenant log of ${from}`);
  let bound = null;
  if (restored !== undefined) {
    bound = {};
    // A restored log the predecessor never named (it had no anchored records) needs no claim. The claims come from the vault: at
    // the signed size a claim must be the signed entry, and beyond it binds nothing (the leaf must then continue the signed entry).
    for (const [id, r] of Object.entries(restored.restored ?? restored)) {
      const e = signed.get(id);
      if (!e) continue;
      if (r?.size === e.size && r.root !== e.root) {
        throw Error(`The restored claim for tenant log ${id} differs from the entry the signer signed at size ${e.size} (fork)`);
      }
      if (!(r?.size >= e.size)) bound[id] = {size: r?.size, root: r?.root};
    }
    if (restored.fromBase !== undefined && (restored.fromBase !== fromBase || restored.toBase !== toBase)) {
      throw Error('The restored file names other origin bases');
    }
  }
  const auth = createAuthorization(stateDir, {kind: 'epoch', origin: to, predecessor: {origin: from, size: p.size, root: p.root},
    acceptLoss: acceptLoss === undefined ? null : {reason: acceptLoss}, dropLogs: [...dropLogs].sort(), restored: bound}, {now});
  // What the operator just accepted: every log whose restored prefix is shorter than the size the signer signed loses the rest, and
  // with --accept-loss but no --restored every log may restart from anything (restoredSize null).
  const unbounded = acceptLoss === undefined ? undefined : null;
  const losses = [...signed].map(([log, e]) => ({log, signedSize: e.size, restoredSize: bound ? bound[log]?.size : unbounded}))
    .filter(l => l.restoredSize === null || l.restoredSize !== undefined && l.restoredSize < l.signedSize);
  return {...auth, losses};
}

async function main(argv) {
  const [command, ...rest] = argv, {values} = parseArgs({args: rest, options: OPTIONS, allowPositionals: false});
  const dir = values['state-dir'] && resolve(values['state-dir']), print = v => console.log(JSON.stringify(v, null, 2));
  switch (command) {
    case 'keygen': {
      need(values, 'out');
      const {privateKey, publicKey} = generateKeyPairSync('ed25519');
      writeSecret(values.out, privateKey.export({format: 'pem', type: 'pkcs8'}));
      if (values['public-out']) writeFileSync(resolve(values['public-out']), publicKey.export({format: 'pem', type: 'spki'}), {flag: 'wx'});
      return print({keyFile: resolve(values.out), publicKey: T.b64(T.ed25519RawPublic(publicKey))});
    }
    case 'token':
      need(values, 'out');
      writeSecret(values.out, randomBytes(32).toString('hex') + '\n');
      return print({tokenFile: resolve(values.out)});
    case 'init': {
      need(values, 'state-dir');
      const backend = await createBackend(backendSpec(values));
      await selfTest(backend);
      // For an init container: an existing state is kept (and checked), never replaced.
      if (values['if-missing'] && existsSync(resolve(dir, 'state.json'))) {
        const key = T.b64(T.ed25519RawPublic(backend.publicKey)), current = readSignerState(dir).keys.at(-1);
        if (key !== current) throw Error(`The backend key ${key} is not the key of the existing signer state (${current})`);
        return print({stateDir: dir, publicKey: key, existing: true});
      }
      return print(initSignerState(dir, backend.publicKey));
    }
    case 'rotate-key': {
      need(values, 'state-dir');
      const backend = await createBackend(backendSpec(values));
      await selfTest(backend);
      return print(rotateSignerKey(dir, backend.publicKey));
    }
    case 'serve': {
      need(values, 'state-dir');
      const pipe = values.pipe?.startsWith('\\\\') ? values.pipe : `\\\\.\\pipe\\${values.pipe}`;
      const listen = values.socket ? {socket: resolve(values.socket)} : values.pipe ? {pipe}
        : values.port ? {host: values.host ?? '127.0.0.1', port: int(values.port, '--port')} : null;
      if (!listen) throw Error('serve needs --socket, --pipe or --port');
      const limits = {...(values['signs-per-minute'] ? {signsPerMinute: int(values['signs-per-minute'], '--signs-per-minute')} : {}),
        ...(values['max-request-bytes'] ? {maxRequestBytes: int(values['max-request-bytes'], '--max-request-bytes')} : {}),
        ...(values['max-entries'] ? {maxEntries: int(values['max-entries'], '--max-entries')} : {})};
      const server = await startSignerServer({stateDir: dir, backend: await createBackend(backendSpec(values)), listen, limits,
        token: values['token-file'] ? readSignerToken(resolve(values['token-file'])) : null,
        tls: values['tls-cert'] ? {cert: readFileSync(resolve(values['tls-cert'])), key: readFileSync(resolve(values['tls-key']))} : null,
        socketMode: values['socket-mode'] ? parseInt(values['socket-mode'], 8) : 0o600});
      let stopping = null;
      const stop = () => (stopping ??= server.close().then(() => process.exit(0)));
      process.once('SIGTERM', stop);
      process.once('SIGINT', stop);
      // Started by scripts/local.mjs: it asks for a clean stop over IPC, like the vault processes.
      if (process.send) {
        process.on('message', message => { if (message === 'shutdown') stop(); });
        process.send({ready: true, address: server.address});
      }
      return;
    }
    case 'public-key': {
      need(values, 'state-dir');
      const pem = stateKey(dir).export({format: 'pem', type: 'spki'});
      if (values.out) writeFileSync(resolve(values.out), pem, {flag: 'wx'}); else process.stdout.write(pem);
      return;
    }
    case 'vkey': {
      need(values, 'origin-base');
      const key = values['public-key'] ? readEd25519PublicKey(resolve(values['public-key'])) : stateKey(dir);
      return console.log(T.logVkey(headsOriginOf(values['origin-base']), key));
    }
    case 'status': {
      need(values, 'state-dir');
      const state = readSignerState(dir);
      return print({stateDir: dir, generation: state.generation, key: state.keys.at(-1), previousKeys: state.keys.slice(0, -1),
        origins: Object.entries(state.origins).map(([origin, r]) => ({origin, status: r.status, size: r.size, root: r.root, logs: r.entries.length,
          updated: r.updated, ...(r.retired ? {retired: r.retired} : {})})),
        authorizations: listAuthorizations(dir).filter(a => a.status === 'pending' && !state.consumed.includes(a.id))
          .map(a => ({id: a.id, kind: a.kind, origin: a.origin}))});
    }
    case 'head': {
      need(values, 'state-dir', 'origin-base');
      const head = signerHead(dir, headsOriginOf(values['origin-base']));
      if (values.out) writeFileSync(resolve(values.out), JSON.stringify(head, null, 2) + '\n', {flag: 'wx'});
      return print({...head, entries: head.entries?.length});
    }
    case 'authorize-genesis': {
      need(values, 'state-dir', 'origin-base');
      const origin = headsOriginOf(values['origin-base']);
      if (readSignerState(dir).origins[origin]) throw Error(`The signer already signs ${origin}`);
      return print(createAuthorization(dir, {kind: 'genesis', origin, predecessor: null, ...(values.note ? {note: values.note} : {})}));
    }
    case 'authorize-handover':
      need(values, 'state-dir', 'checkpoint', 'vault-key');
      return print(handoverAuthorization({stateDir: dir, checkpoint: readCheckpointFile(values.checkpoint),
        vaultKey: readEd25519PublicKey(resolve(values['vault-key'])), witnesses: values.witness ?? [],
        ...(values.quorum ? {quorum: int(values.quorum, '--quorum')} : {}),
        ...(values['max-age'] ? {maxAgeSeconds: int(values['max-age'], '--max-age')} : {})}));
    case 'authorize-epoch':
      need(values, 'state-dir', 'from-base', 'to-base');
      return print(epochAuthorization({stateDir: dir, fromBase: values['from-base'], toBase: values['to-base'], acceptLoss: values['accept-loss'],
        dropLogs: values['drop-log'] ?? [], ...(values.restored ? {restored: JSON.parse(readFileSync(resolve(values.restored), 'utf8'))} : {})}));
    case 'authorizations':
      need(values, 'state-dir');
      return print(listAuthorizations(dir));
    case 'revoke':
      need(values, 'state-dir', 'id');
      revokeAuthorization(dir, values.id);
      return print({revoked: values.id});
    case 'audit': {
      need(values, 'state-dir');
      if (values.verify) return print(verifyAuditLog(resolve(dir, 'audit.log')));
      return process.stdout.write(readFileSync(resolve(dir, 'audit.log'), 'utf8'));
    }
    default:
      throw Error('Usage: node scripts/signer.mjs keygen|token|init|serve|public-key|vkey|status|head|authorize-genesis|authorize-handover|authorize-epoch'
        + '|authorizations|revoke|rotate-key|audit (see the header of scripts/signer.mjs)');
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => { console.error(JSON.stringify({ok: false, error: error.message})); process.exitCode = 1; });
}
