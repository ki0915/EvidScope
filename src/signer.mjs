// Heads signer (docs/signer.md): a process outside the vault host that holds the heads-log key and signs a heads checkpoint only
// when its new leaf keeps every tenant log of the previous leaf: still present, never smaller, the same root at the same size,
// and an RFC 6962 consistency proof from the previously signed (size, root) when it grew. The vault never supplies a root to
// sign: the signer appends the leaf to its own compact range. A heads origin it has not signed before (a first deployment, a
// restore epoch to a new origin base, a vault-key heads log that moves to the signer) needs a single-use authorization the
// operator creates on the signer volume (scripts/signer.mjs authorize-*). State and audit live on that volume only.
import {chmodSync, closeSync, existsSync, fsyncSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync,
  renameSync, rmSync, statSync, writeSync} from 'node:fs';
import {createHash, randomBytes, timingSafeEqual, verify as edVerify} from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import {dirname, isAbsolute, join, relative, resolve} from 'node:path';
import * as T from './tlog.mjs';
import {selfTest} from './signer-backends.mjs';

export const STATE_FORMAT = 'evidscope-signer-state-v1';
export const AUTHORIZATION_FORMAT = 'evidscope-signer-authorization-v1';
export const AUDIT_FORMAT = 'evidscope-signer-audit-v1';
export const AUTHORIZATION_KINDS = ['genesis', 'handover', 'epoch'];
export const DEFAULT_LIMITS = Object.freeze({maxRequestBytes: 8 * 1024 * 1024, maxEntries: 100000, signsPerMinute: 60, signBurst: 10,
  requestsPerMinute: 600, requestBurst: 60, handshakeTimeoutMs: 5000, maxConnectionsPerAddress: 8});
const HEX64 = /^[a-f0-9]{64}$/, LOG_ID = /^[a-f0-9]{32}$/, AUTH_ID = /^[a-f0-9]{32}$/, MAX_PROOF = 128;
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const hex = buf => Buffer.from(buf).toString('hex');
const sha256 = data => createHash('sha256').update(data).digest();
const paths = dir => ({state: join(dir, 'state.json'), audit: join(dir, 'audit.log'), lock: join(dir, 'signer.lock'),
  pending: join(dir, 'authorizations'), used: join(dir, 'authorizations', 'used'), revoked: join(dir, 'authorizations', 'revoked')});
const refusal = (reason, message, status = 422, extra = {}) => Object.assign(Error(message), {refusal: reason, status, ...extra});
const invalid = message => refusal('invalid_request', message, 400);

export function headsBaseOf(origin) {
  if (typeof origin !== 'string' || !origin.endsWith('/heads')) throw invalid('heads origin must end in /heads');
  try { return T.validateOriginBase(origin.slice(0, -'/heads'.length)); } catch (error) { throw invalid(error.message); }
}

// ---------- state directory ----------
// The state must not share the vault's data volume. The signer can tell when the directory or a parent holds an EvidScope
// evidence database, or when it lies inside the vault data directory named by DATA_DIR (as in the vault's environment).
export function assertSignerStateDir(dir, {vaultDataDir = process.env.DATA_DIR} = {}) {
  const real = p => { try { return realpathSync(p); } catch { return resolve(p); } };
  const abs = real(dir);
  for (let d = abs; ; d = dirname(d)) {
    if (existsSync(join(d, 'evidence.db'))) throw Error(`Signer state directory ${abs} is inside a vault data directory (${d} holds evidence.db)`);
    if (dirname(d) === d) break;
  }
  if (vaultDataDir) {
    const v = real(vaultDataDir), rel = relative(v, abs);
    if (!rel || !rel.startsWith('..') && !isAbsolute(rel)) throw Error(`Signer state directory ${abs} is inside the vault data directory ${v}`);
  }
  return abs;
}
const held = new Set();
const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; } };
// One signer per state directory: two would sign different leaves at the same size (a fork). A lock of a dead process, or of
// this pid after a container restart (pid 1 again), is stale. Run a single replica with the Recreate strategy.
function lock(dir) {
  const file = paths(dir).lock, body = `${process.pid} ${randomBytes(8).toString('hex')}\n`;
  if (held.has(resolve(dir))) throw Error(`Signer state directory ${dir} is already open in this process`);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(file, 'wx', 0o600);
      writeSync(fd, body);
      fsyncSync(fd);
      closeSync(fd);
      held.add(resolve(dir));
      return () => {
        held.delete(resolve(dir));
        try { if (readFileSync(file, 'utf8') === body) rmSync(file); } catch { /* already gone */ }
      };
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const pid = Number(readFileSync(file, 'utf8').split(' ')[0]);
      if (Number.isSafeInteger(pid) && pid > 0 && pid !== process.pid && alive(pid)) throw Error(`Signer state directory ${dir} is in use by process ${pid}`);
      rmSync(file, {force: true});
    }
  }
  throw Error(`Signer state lock ${file} could not be acquired`);
}
function syncDir(dir) {
  if (process.platform === 'win32') return;
  const fd = openSync(dir, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
// fsync + atomic rename: a crash leaves the old or the new file, never a torn one (a stray .tmp is ignored and removed).
function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`, fd = openSync(tmp, 'wx', 0o600);
  try { writeSync(fd, text); fsyncSync(fd); } catch (error) { closeSync(fd); rmSync(tmp, {force: true}); throw error; }
  closeSync(fd);
  try { renameSync(tmp, file); } catch (error) { rmSync(tmp, {force: true}); throw error; }
  syncDir(dirname(file));
}
const keyName = raw => T.b64(raw);
function parseEntries(list, base, maxEntries, what = 'heads leaf') {
  if (!Array.isArray(list) || !list.length || list.length > maxEntries) throw invalid(`${what} needs 1 to ${maxEntries} entries`);
  const prefix = base + '/t/';
  let last = '';
  return list.map(e => {
    if (!plain(e) || Object.keys(e).length !== 3 || typeof e.log !== 'string' || !e.log.startsWith(prefix) || !LOG_ID.test(e.log.slice(prefix.length))
      || !Number.isSafeInteger(e.size) || e.size < 1 || typeof e.root !== 'string' || !HEX64.test(e.root)) {
      throw invalid(`${what} entry is not {log: "${prefix}<32 hex>", size >= 1, root: <64 hex>}`);
    }
    if (e.log <= last) throw invalid(`${what} entries must be sorted by log and unique`);
    last = e.log;
    return {log: e.log, size: e.size, root: e.root};
  });
}
function parsePeaks(list, size) {
  if (!Array.isArray(list) || list.length > 64) throw invalid('frontier must be a list of hashes');
  if (!list.every(h => typeof h === 'string' && HEX64.test(h))) throw invalid('bad frontier hash');
  const peaks = list.map(h => Buffer.from(h, 'hex'));
  try { T.blobToPeaks(T.peaksToBlob(peaks), size); } catch { throw invalid('frontier does not match its size'); }
  return peaks;
}
// A stored origin re-derives its root from the newest leaf's entries and the frontier before it, and its note must be signed
// by a key this state has used.
function loadOrigin(origin, r, keys) {
  const base = headsBaseOf(origin), fail = what => { throw Error(`Signer state for ${origin} is inconsistent: ${what}`); };
  if (!plain(r) || !['active', 'retired'].includes(r.status) || !Number.isSafeInteger(r.size) || r.size < 1 || !HEX64.test(r.root ?? '')) fail('fields');
  const entries = parseEntries(r.entries, base, Infinity, 'stored leaf'), peaksBefore = parsePeaks(r.peaksBefore, r.size - 1);
  const leaf = T.headsLeafHash(T.headsLeafContent(entries)), peaks = T.frontierAppend(peaksBefore, r.size - 1, leaf), root = T.frontierRoot(peaks);
  if (hex(root) !== r.root) fail('the newest leaf and frontier do not fold to the stored root');
  let c = null;
  const verifiers = keys.map(k => T.noteVerifier(T.vkeyString(origin, T.SIG_ED25519, Buffer.from(k, 'base64'))));
  try { c = T.parseCheckpoint(T.openNote(r.note, verifiers).text); } catch { c = null; }
  if (c?.origin !== origin || c.size !== r.size || !c.root.equals(root)) fail('the stored note is not the signed checkpoint of the stored root');
  return {...r, entries, peaksBefore, peaks, rootBuf: root};
}
export function readSignerState(dir) {
  const file = paths(dir).state;
  if (!existsSync(file)) throw Error(`No signer state at ${file}: run scripts/signer.mjs init (a lost state must be restored from backup, never re-created)`);
  const st = statSync(file);
  if (!st.isFile() || st.size > 512 * 1024 * 1024) throw Error('Signer state file is not a regular file of at most 512 MiB');
  let raw;
  try { raw = JSON.parse(readFileSync(file, 'utf8')); } catch (error) {
    throw Error(`Signer state ${file} is unreadable (${error.message}); restore it from backup`);
  }
  if (raw?.format !== STATE_FORMAT || !Array.isArray(raw.keys) || !raw.keys.length || !plain(raw.origins) || !Array.isArray(raw.consumed)
    || !Number.isSafeInteger(raw.generation)) {
    throw Error(`Signer state ${file} is not an ${STATE_FORMAT} file`);
  }
  const origins = {};
  for (const [origin, r] of Object.entries(raw.origins)) origins[origin] = loadOrigin(origin, r, raw.keys);
  return {...raw, origins};
}
const storedOrigin = r => ({status: r.status, size: r.size, root: r.root, peaksBefore: r.peaksBefore.map(hex), entries: r.entries, note: r.note,
  created: r.created, updated: r.updated, genesis: r.genesis, ...(r.retired ? {retired: r.retired} : {})});
function writeState(dir, state) {
  const out = {format: STATE_FORMAT, generation: state.generation, createdAt: state.createdAt, keys: state.keys, consumed: state.consumed, origins: {}};
  for (const [origin, r] of Object.entries(state.origins)) out.origins[origin] = storedOrigin(r);
  writeAtomic(paths(dir).state, JSON.stringify(out) + '\n');
}
export function initSignerState(dir, publicKey, {now = () => Date.now()} = {}) {
  const abs = assertSignerStateDir(dir), p = paths(abs);
  mkdirSync(abs, {recursive: true, mode: 0o700});
  for (const d of [p.pending, p.used, p.revoked]) mkdirSync(d, {recursive: true, mode: 0o700});
  if (existsSync(p.state)) throw Error(`Signer state already exists at ${p.state}`);
  // An audit log without a state is a lost state: a new one would sign the old origins again from scratch.
  if (existsSync(p.audit)) throw Error(`Signer state ${p.state} is missing but ${p.audit} exists: restore state.json from backup, never re-create it`);
  const release = lock(abs);
  try {
    writeState(abs, {generation: 0, createdAt: new Date(now()).toISOString(), keys: [keyName(T.ed25519RawPublic(publicKey))], consumed: [], origins: {}});
    const audit = openAudit(p.audit, now);
    audit.append({event: 'init', key: keyName(T.ed25519RawPublic(publicKey))});
    audit.close();
  } finally { release(); }
  return {stateDir: abs, publicKey: keyName(T.ed25519RawPublic(publicKey))};
}
// Key rotation keeps every origin: the new key signs from now on (witnesses get it with add-key, then drop the old one).
export function rotateSignerKey(dir, publicKey, {now = () => Date.now()} = {}) {
  const abs = assertSignerStateDir(dir), release = lock(abs);
  try {
    const state = readSignerState(abs), key = keyName(T.ed25519RawPublic(publicKey));
    if (state.keys.at(-1) === key) throw Error('The signer already uses this key');
    state.keys = [...state.keys.filter(k => k !== key), key];
    state.generation++;
    writeState(abs, state);
    const audit = openAudit(paths(abs).audit, now);
    audit.append({event: 'rotate_key', key, previous: state.keys.at(-2) ?? null});
    audit.close();
    return {stateDir: abs, keys: state.keys};
  } finally { release(); }
}

// ---------- audit ----------
// Append-only JSON lines chained by the SHA-256 of the previous line, fsynced before the answer leaves the signer. A torn last
// line (a crash while writing it) was never acknowledged; it is cut off and recorded.
function openAudit(file, now) {
  let seq = 0, prev = '0'.repeat(64), recovered = null;
  const fd = openSync(file, 'a+', 0o600), size = statSync(file).size;
  if (size) {
    const length = Math.min(size, 1024 * 1024), buf = Buffer.alloc(length);
    readSync(fd, buf, 0, length, size - length);
    const end = buf.lastIndexOf(0x0a);
    if (end < 0 && size > length) { closeSync(fd); throw Error(`Signer audit log ${file} ends in an unreadable line`); }
    if (end !== length - 1) {
      ftruncateSync(fd, size - length + end + 1);
      fsyncSync(fd);
      recovered = length - end - 1;
    }
    const start = end < 0 ? -1 : buf.lastIndexOf(0x0a, end - 1), line = end < 0 ? '' : buf.subarray(start + 1, end).toString('utf8');
    if (line) {
      try { seq = JSON.parse(line).seq; } catch { throw Error(`Signer audit log ${file} ends in an unreadable line`); }
      prev = hex(sha256(line));
    }
  }
  const audit = {
    append(event) {
      const line = JSON.stringify({format: AUDIT_FORMAT, seq: ++seq, time: new Date(now()).toISOString(), ...event, prev});
      writeSync(fd, line + '\n');
      fsyncSync(fd);
      prev = hex(sha256(line));
    },
    close() { closeSync(fd); },
  };
  if (recovered !== null) audit.append({event: 'audit_recovered', droppedBytes: recovered});
  return audit;
}
export function verifyAuditLog(file) {
  let prev = '0'.repeat(64), seq = 0;
  const lines = readFileSync(file, 'utf8').split('\n');
  if (lines.at(-1) !== '') throw Error('Signer audit log does not end with a newline');
  for (const line of lines.slice(0, -1)) {
    const e = JSON.parse(line);
    if (e.format !== AUDIT_FORMAT || e.seq !== seq + 1 || e.prev !== prev) throw Error(`Signer audit log breaks at line ${seq + 1}`);
    seq = e.seq;
    prev = hex(sha256(line));
  }
  return {lines: seq, head: prev};
}

// ---------- authorizations (created by the operator on the signer volume, consumed once by the first leaf of an origin) ----------
function validateAuthorization(a) {
  const fail = what => { throw Error(`Signer authorization is invalid: ${what}`); };
  if (!plain(a) || a.format !== AUTHORIZATION_FORMAT || !AUTH_ID.test(a.id ?? '') || !AUTHORIZATION_KINDS.includes(a.kind)) fail('format, id or kind');
  headsBaseOf(a.origin);
  if (a.kind === 'genesis' && a.predecessor !== null) fail('a genesis has no predecessor');
  if (a.kind !== 'genesis') {
    const p = a.predecessor;
    if (!plain(p) || !Number.isSafeInteger(p.size) || p.size < 1 || !HEX64.test(p.root ?? '')) fail('predecessor size and root');
    if (a.kind === 'handover' && (p.origin !== a.origin || typeof p.key !== 'string')) fail('a handover continues its own origin from the vault key');
    if (a.kind === 'epoch' && (headsBaseOf(p.origin) === headsBaseOf(a.origin))) fail('an epoch moves to another origin base');
  }
  if (a.kind === 'epoch') {
    if (a.acceptLoss !== null && !(plain(a.acceptLoss) && typeof a.acceptLoss.reason === 'string' && a.acceptLoss.reason.trim())) fail('acceptLoss');
    if (!Array.isArray(a.dropLogs) || !a.dropLogs.every(id => LOG_ID.test(id))) fail('dropLogs');
    if (a.restored !== null && !(plain(a.restored) && Object.entries(a.restored).every(([id, r]) => LOG_ID.test(id) && plain(r)
      && Number.isSafeInteger(r.size) && r.size >= 0 && HEX64.test(r.root ?? '')))) fail('restored');
  }
  return a;
}
export function createAuthorization(dir, fields, {now = () => Date.now()} = {}) {
  const abs = resolve(dir), p = paths(abs);
  const a = validateAuthorization({format: AUTHORIZATION_FORMAT, id: randomBytes(16).toString('hex'), createdAt: new Date(now()).toISOString(), ...fields});
  mkdirSync(p.pending, {recursive: true, mode: 0o700});
  writeAtomic(join(p.pending, a.id + '.json'), JSON.stringify(a, null, 2) + '\n');
  return a;
}
export function listAuthorizations(dir) {
  const p = paths(resolve(dir)), out = [];
  for (const [status, d] of [['pending', p.pending], ['used', p.used], ['revoked', p.revoked]]) {
    if (!existsSync(d)) continue;
    for (const name of readdirSync(d).sort()) {
      if (!/^[a-f0-9]{32}\.json$/.test(name)) continue;
      try { out.push({status, ...validateAuthorization(JSON.parse(readFileSync(join(d, name), 'utf8')))}); } catch (error) {
        out.push({status: 'invalid', file: join(d, name), error: error.message});
      }
    }
  }
  return out;
}
export function revokeAuthorization(dir, id) {
  if (!AUTH_ID.test(id ?? '')) throw Error('Authorization id must be 32 hex characters');
  const p = paths(resolve(dir));
  mkdirSync(p.revoked, {recursive: true, mode: 0o700});
  renameSync(join(p.pending, id + '.json'), join(p.revoked, id + '.json'));
  syncDir(p.pending);
}
// The CLI binds an epoch to the predecessor exactly as this state holds it now.
export function signerHead(dir, origin) {
  const state = readSignerState(resolve(dir)), r = state.origins[origin];
  return r ? headOf(origin, r) : {origin, known: false};
}
const headOf = (origin, r) => ({origin, known: true, status: r.status, size: r.size, root: r.root, note: r.note, entries: r.entries, updated: r.updated,
  ...(r.retired ? {retired: r.retired} : {})});

// ---------- policy ----------
const proofOf = (proofs, log) => {
  const p = proofs[log];
  if (p === undefined) return null;
  if (!plain(p) || !Number.isSafeInteger(p.from) || p.from < 0 || !Array.isArray(p.hashes) || p.hashes.length > MAX_PROOF) {
    throw invalid(`bad proof for ${log}`);
  }
  const hashes = p.hashes.map(h => (typeof h === 'string' ? Buffer.from(h, 'base64') : null));
  if (!hashes.every(b => b?.length === 32)) throw invalid(`bad proof hash for ${log}`);
  return {from: p.from, hashes};
};
// The new entry extends (size, root) when it is that entry or a valid consistency proof from it is given.
function extendsEntry(from, next, proof) {
  if (next.size === from.size) return next.root === from.root;
  return next.size > from.size && !!proof && proof.from === from.size
    && T.verifyConsistency(from.size, next.size, Buffer.from(from.root, 'hex'), Buffer.from(next.root, 'hex'), proof.hashes);
}
function checkContinuation(previous, next, proofs) {
  const byLog = new Map(next.map(e => [e.log, e]));
  for (const e of previous) {
    const n = byLog.get(e.log);
    if (!n) throw refusal('tenant_removal', `heads leaf drops tenant log ${e.log} (signed at size ${e.size}) (tenant removal)`);
    if (n.size < e.size) throw refusal('rollback', `heads leaf shrinks tenant log ${e.log} from ${e.size} to ${n.size} (rollback)`);
    if (n.size === e.size && n.root !== e.root) throw refusal('fork', `heads leaf changes tenant log ${e.log} at size ${e.size} (fork)`);
    if (n.size > e.size && !extendsEntry(e, n, proofOf(proofs, e.log))) {
      throw refusal('fork', `tenant log ${e.log} grew from ${e.size} to ${n.size} without a valid consistency proof from the signed size (fork)`);
    }
  }
}
// A restore epoch: every log of the retired origin continues under the new base (same tenant log id), from its last signed entry,
// or from its authorized restored prefix, or (acceptLoss without restored prefixes) at all; dropped logs are named one by one.
// A restored prefix is a loss, so it counts only below the signed size: at or above it, it could only stand for another history.
function checkEpoch(auth, predecessor, base, next, proofs) {
  const byLog = new Map(next.map(e => [e.log, e])), from = headsBaseOf(predecessor.origin) + '/t/', lost = [], dropped = [];
  for (const e of predecessor.entries) {
    const id = e.log.slice(from.length), log = `${base}/t/${id}`, n = byLog.get(log), proof = proofOf(proofs, log);
    if (auth.dropLogs.includes(id)) {
      if (n) throw refusal('unauthorized', `tenant log ${id} is authorized to be dropped at this epoch, but the leaf still names it`, 403);
      dropped.push(id);
      continue;
    }
    if (!n) throw refusal('tenant_removal', `the epoch leaf drops tenant log ${id} (signed at size ${e.size} under ${predecessor.origin}) (tenant removal)`);
    if (extendsEntry(e, n, proof)) continue;
    const restored = auth.restored?.[id], below = restored && restored.size < e.size;
    if (below && extendsEntry(restored, n, proof)) { lost.push({log: id, signedSize: e.size, restoredSize: restored.size}); continue; }
    if (auth.acceptLoss && !auth.restored) { lost.push({log: id, signedSize: e.size, restoredSize: null}); continue; }
    throw refusal('rollback', `tenant log ${id} does not continue its signed size ${e.size} under ${predecessor.origin}`
      + (restored ? ` nor its authorized restored size ${restored.size}` : ' and the epoch authorization accepts no loss') + ' (rollback)');
  }
  return {lost, dropped};
}

// ---------- signer core ----------
export function openSigner({stateDir, backend, limits = {}, now = () => Date.now()}) {
  const dir = assertSignerStateDir(stateDir), p = paths(dir), release = lock(dir);
  let state, audit;
  try {
    state = readSignerState(dir);
    const key = keyName(T.ed25519RawPublic(backend.publicKey));
    if (state.keys.at(-1) !== key) {
      throw Error(`The signer backend key ${key} is not the key of this state (${state.keys.at(-1)}); rotate with scripts/signer.mjs rotate-key`);
    }
    for (const d of [p.pending, p.used, p.revoked]) mkdirSync(d, {recursive: true, mode: 0o700});
    for (const name of readdirSync(dir)) if (/^state\.json\..*\.tmp$/.test(name)) rmSync(join(dir, name), {force: true});
    audit = openAudit(p.audit, now);
  } catch (error) { release(); throw error; }
  const max = {...DEFAULT_LIMITS, ...limits}, pub = T.ed25519RawPublic(backend.publicKey), consumed = new Set(state.consumed);
  // Only this process writes the state file (rename gives every write a new file). A different file under it means a second
  // signer on the same state directory (the lock cannot see another container) or a copy restored while running: refuse to sign.
  const stamp = () => { const s = statSync(p.state); return `${s.ino}:${s.size}:${s.mtimeMs}`; };
  let written = stamp();
  const unchangedState = () => {
    if (stamp() !== written) {
      throw refusal('state_changed', 'the signer state file changed outside this signer process (a second signer on the same state directory, or a '
        + 'restored copy); stop every other signer and restart this one', 503);
    }
  };
  // A consumed authorization whose file was not yet moved (a crash right after the state write) is moved now and never reused.
  for (const id of consumed) if (existsSync(join(p.pending, id + '.json'))) renameSync(join(p.pending, id + '.json'), join(p.used, id + '.json'));
  audit.append({event: 'start', pid: process.pid, backend: backend.kind, key: keyName(pub), origins: Object.keys(state.origins).length});
  const iso = () => new Date(now()).toISOString();
  function authorizationFor(origin) {
    const found = [];
    for (const name of readdirSync(p.pending)) {
      const m = /^([a-f0-9]{32})\.json$/.exec(name);
      if (!m || consumed.has(m[1])) continue;
      let a;
      try { a = validateAuthorization(JSON.parse(readFileSync(join(p.pending, name), 'utf8'))); } catch { continue; }
      if (a.id === m[1] && a.origin === origin) found.push(a);
    }
    if (found.length > 1) throw refusal('unauthorized', `${found.length} pending authorizations name ${origin}; revoke all but one`, 403);
    return found[0] ?? null;
  }
  // The state of the origin before the new leaf: its stored record, or what its authorization starts it from.
  function startOf(req, origin, base) {
    const r = state.origins[origin], prevSize = req.previous?.size, prevRoot = req.previous?.root;
    if (!Number.isSafeInteger(prevSize) || prevSize < 0 || typeof prevRoot !== 'string' || !HEX64.test(prevRoot)) throw invalid('previous needs size and root');
    if (r) {
      if (r.status === 'retired') {
        throw refusal('retired', `heads origin ${origin} was retired at the restore epoch to ${r.retired.by}; it takes no more leaves`, 403);
      }
      if (prevSize !== r.size || prevRoot !== r.root) {
        throw refusal('out_of_sync', `the vault holds heads size ${prevSize}, the signer signed size ${r.size}`, 409, {head: headOf(origin, r)});
      }
      return {size: r.size, root: r.root, peaks: r.peaks, entries: r.entries, record: r, auth: null};
    }
    const auth = authorizationFor(origin);
    if (!auth) {
      throw refusal('unauthorized', `the signer has no authorization for the new heads origin ${origin}; create one on the signer with `
        + 'scripts/signer.mjs authorize-genesis, authorize-handover or authorize-epoch', 403, {head: {origin, known: false}});
    }
    if (auth.kind === 'handover') {
      const seed = req.seed, k = auth.predecessor.size;
      if (prevSize !== k || prevRoot !== auth.predecessor.root) {
        throw refusal('unauthorized', `the handover authorization continues ${origin} at size ${k}, the vault holds size ${prevSize}`, 403);
      }
      if (!plain(seed)) throw invalid('a handover needs seed {entries, peaksBefore} of the newest vault-key leaf');
      const entries = parseEntries(seed.entries, base, max.maxEntries, 'handover seed'), peaksBefore = parsePeaks(seed.peaksBefore, k - 1);
      const peaks = T.frontierAppend(peaksBefore, k - 1, T.headsLeafHash(T.headsLeafContent(entries)));
      if (hex(T.frontierRoot(peaks)) !== auth.predecessor.root) {
        throw refusal('fork', 'the handover seed does not fold to the authorized heads checkpoint (fork)');
      }
      return {size: k, root: auth.predecessor.root, peaks, entries, record: null, auth};
    }
    if (prevSize !== 0 || prevRoot !== hex(T.EMPTY_ROOT)) throw invalid('a new heads origin starts at size 0');
    if (auth.kind === 'epoch') {
      const pr = state.origins[auth.predecessor.origin];
      if (!pr || pr.status !== 'active' || pr.size !== auth.predecessor.size || pr.root !== auth.predecessor.root) {
        throw refusal('unauthorized', `the epoch authorization binds ${auth.predecessor.origin} at size ${auth.predecessor.size}, which the signer `
          + `no longer holds (${pr ? `${pr.status} at size ${pr.size}` : 'unknown'})`, 403);
      }
      return {size: 0, root: prevRoot, peaks: [], entries: [], record: null, auth, predecessor: {...pr, origin: auth.predecessor.origin}};
    }
    return {size: 0, root: prevRoot, peaks: [], entries: [], record: null, auth};
  }
  async function sign(req) {
    if (!plain(req) || !plain(req.leaf) || (req.proofs !== undefined && !plain(req.proofs))) throw invalid('request needs origin, previous, leaf and proofs');
    unchangedState();
    const origin = req.origin, base = headsBaseOf(origin), start = startOf(req, origin, base), proofs = req.proofs ?? {};
    const next = parseEntries(req.leaf.entries, base, max.maxEntries);
    let epoch = null;
    if (start.auth?.kind === 'epoch') epoch = checkEpoch(start.auth, start.predecessor, base, next, proofs);
    else checkContinuation(start.entries, next, proofs);
    if (!start.auth && next.length === start.entries.length && next.every((e, i) => e.root === start.entries[i].root && e.size === start.entries[i].size)) {
      throw refusal('unchanged', 'heads leaf changes no tenant log');
    }
    const size = start.size + 1, peaks = T.frontierAppend(start.peaks, start.size, T.headsLeafHash(T.headsLeafContent(next)));
    const root = T.frontierRoot(peaks), text = T.formatCheckpoint({origin, size, root}), message = Buffer.from(text, 'utf8');
    let signature;
    try { signature = await backend.sign(message); } catch (error) { throw refusal('backend', `signing backend failed: ${error.message}`, 503); }
    if (!Buffer.isBuffer(signature) || signature.length !== 64 || !edVerify(null, message, backend.publicKey, signature)) {
      throw refusal('backend', 'signing backend returned a signature that does not verify', 503);
    }
    const note = T.noteWithSignature(text, origin, pub, signature), at = iso();
    const record = {status: 'active', size, root: hex(root), peaksBefore: start.peaks, peaks, entries: next, note, created: start.record?.created ?? at,
      updated: at, genesis: start.record?.genesis ?? (start.auth ? {kind: start.auth.kind, authorization: start.auth.id, at} : null)};
    const origins = {...state.origins, [origin]: record};
    if (epoch) origins[start.predecessor.origin] = {...start.predecessor, status: 'retired', retired: {at, by: origin, authorization: start.auth.id}};
    const updated = {...state, generation: state.generation + 1, origins, consumed: start.auth ? [...state.consumed, start.auth.id] : state.consumed};
    unchangedState();
    writeState(dir, updated);
    written = stamp();
    state = updated;
    if (start.auth) {
      consumed.add(start.auth.id);
      try { renameSync(join(p.pending, start.auth.id + '.json'), join(p.used, start.auth.id + '.json')); } catch { /* moved on the next start */ }
    }
    // An epoch line names at most 100 lost and dropped logs (with their counts); the authorization file keeps the rest.
    audit.append({event: 'signed', origin, oldSize: start.size, newSize: size, root: hex(root),
      ...(start.auth ? {authorization: {id: start.auth.id, kind: start.auth.kind}} : {}),
      ...(epoch ? {retired: start.predecessor.origin, lostLogs: epoch.lost.length, lost: epoch.lost.slice(0, 100), droppedLogs: epoch.dropped.length,
        dropped: epoch.dropped.slice(0, 100)} : {})});
    return {status: 'signed', origin, size, root: hex(root), note};
  }
  let queue = Promise.resolve();
  // Serialized (all origins): an epoch touches two origins, and a slow backend must never interleave two leaves of one origin.
  function signHeads(req) {
    const run = queue.then(() => sign(req)).catch(error => {
      if (!error.refusal) throw error;
      if (error.refusal !== 'invalid_request') {
        const r = typeof req?.origin === 'string' ? state.origins[req.origin] : null;
        audit.append({event: 'refused', origin: typeof req?.origin === 'string' ? req.origin.slice(0, 300) : null, reason: error.refusal,
          message: error.message.slice(0, 500), oldSize: r?.size ?? null, requestedPrevious: req?.previous?.size ?? null});
      }
      throw error;
    });
    queue = run.catch(() => {});
    return run;
  }
  return {
    publicKey: backend.publicKey, signHeads, audit,
    head(origin) { headsBaseOf(origin); const r = state.origins[origin]; return r ? headOf(origin, r) : {origin, known: false}; },
    info() {
      return {format: 'evidscope-signer-info-v1', key: keyName(pub), backend: backend.kind, origins: Object.entries(state.origins)
        .map(([origin, r]) => ({origin, status: r.status, size: r.size, updated: r.updated}))};
    },
    close() { audit.append({event: 'stop'}); audit.close(); release(); },
  };
}

// ---------- HTTP server ----------
function bucket(perMinute, burst, now) {
  let tokens = burst, at = now();
  return () => {
    const t = now();
    tokens = Math.min(burst, tokens + (t - at) * perMinute / 60000);
    at = t;
    if (tokens < 1) return Math.ceil((1 - tokens) * 60000 / perMinute / 1000);
    tokens -= 1;
    return 0;
  };
}
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
const tokenDigest = token => sha256(Buffer.from(token, 'utf8'));
// listen: {socket: path} (Unix socket; token optional) | {pipe: name} (Windows named pipe; token required) | {host, port} (loopback, or
// any host with tls: {cert, key}; token required). The token is compared in constant time.
export async function startSignerServer({stateDir, backend, listen, token = null, tls = null, limits = {}, socketMode = 0o600, now = () => Date.now(),
  log = line => process.stderr.write(JSON.stringify({component: 'signer', ...line}) + '\n')}) {
  if (!plain(listen)) throw Error('Signer listen address missing');
  const tcp = listen.port !== undefined, pipe = listen.pipe !== undefined;
  if (tcp && !tls && !LOOPBACK.has(listen.host ?? '127.0.0.1')) throw Error('A signer on a non-loopback address needs TLS (--tls-cert/--tls-key)');
  if ((tcp || pipe) && !token) throw Error('A signer on TCP or a named pipe needs a bearer token file (--token-file)');
  if (token !== null && (typeof token !== 'string' || token.length < 32)) throw Error('Signer token must be at least 32 characters');
  await selfTest(backend);
  const core = openSigner({stateDir, backend, limits, now}), max = {...DEFAULT_LIMITS, ...limits}, expected = token && tokenDigest(token);
  const signBucket = bucket(max.signsPerMinute, max.signBurst, now), requestBucket = bucket(max.requestsPerMinute, max.requestBurst, now);
  const counters = {unauthorized: 0, rateLimited: 0, tooLarge: 0, refusedConnections: 0};
  const send = (res, status, body, headers = {}) => {
    const text = JSON.stringify(body);
    res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store', ...headers}).end(text);
  };
  const handler = async (req, res) => {
    try {
      const path = new URL(req.url, 'http://signer').pathname;
      if (req.method !== 'POST' || !['/v1/sign-heads', '/v1/head', '/v1/info'].includes(path)) return send(res, 404, {status: 'error', reason: 'not_found'});
      if (expected) {
        const given = /^Bearer (\S+)$/.exec(req.headers.authorization ?? '')?.[1];
        if (!given || !timingSafeEqual(tokenDigest(given), expected)) {
          counters.unauthorized++;
          return send(res, 401, {status: 'error', reason: 'unauthenticated'});
        }
      }
      if (Number(req.headers['content-length'] ?? 0) > max.maxRequestBytes) {
        counters.tooLarge++;
        res.setHeader('connection', 'close');
        return send(res, 413, {status: 'error', reason: 'too_large'});
      }
      const wait = requestBucket() || (path === '/v1/sign-heads' ? signBucket() : 0);
      if (wait) { counters.rateLimited++; return send(res, 429, {status: 'error', reason: 'rate_limited'}, {'retry-after': String(wait)}); }
      const parts = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > max.maxRequestBytes) {
          counters.tooLarge++;
          res.setHeader('connection', 'close');
          send(res, 413, {status: 'error', reason: 'too_large'});
          return req.destroy();
        }
        parts.push(chunk);
      }
      let body;
      try { body = JSON.parse(Buffer.concat(parts).toString('utf8')); } catch {
        return send(res, 400, {status: 'refused', reason: 'invalid_request', message: 'body is not JSON'});
      }
      if (path === '/v1/info') return send(res, 200, {...core.info(), counters});
      if (path === '/v1/head') return send(res, 200, core.head(body?.origin));
      return send(res, 200, await core.signHeads(body));
    } catch (error) {
      if (error.refusal) {
        return send(res, error.status, {status: 'refused', reason: error.refusal, message: error.message, ...(error.head ? {head: error.head} : {})});
      }
      log({error: error.message});
      if (!res.headersSent) send(res, 500, {status: 'error', reason: 'internal'});
    }
  };
  const server = tls ? https.createServer({cert: tls.cert, key: tls.key, minVersion: 'TLSv1.2', handshakeTimeout: max.handshakeTimeoutMs}, handler)
    : http.createServer(handler);
  Object.assign(server, {requestTimeout: 15000, headersTimeout: 5000, keepAliveTimeout: 5000, maxHeadersCount: 50, maxConnections: 64});
  // A TCP peer is unauthenticated until its request carries the token: one address holds at most a few of the 64 connections (and a
  // TLS handshake must finish within handshakeTimeoutMs), so a peer that opens sockets and sends nothing cannot lock the vault out.
  if (tcp) {
    const open = new Map();
    server.prependListener('connection', socket => {
      const from = socket.remoteAddress, n = open.get(from) ?? 0;
      if (n >= max.maxConnectionsPerAddress) { counters.refusedConnections++; return socket.destroy(); }
      open.set(from, n + 1);
      socket.once('close', () => { if (open.get(from) > 1) open.set(from, open.get(from) - 1); else open.delete(from); });
    });
  }
  const target = listen.socket ?? listen.pipe;
  if (listen.socket !== undefined && lstatSync(listen.socket, {throwIfNoEntry: false})?.isSocket()) rmSync(listen.socket);
  try {
    await new Promise((done, fail) => {
      server.once('error', fail);
      if (target !== undefined) server.listen(target, done); else server.listen(listen.port, listen.host ?? '127.0.0.1', done);
    });
    if (listen.socket !== undefined && process.platform !== 'win32') chmodSync(listen.socket, socketMode);
  } catch (error) { core.close(); throw error; }
  const address = target ?? (a => `${tls ? 'https' : 'http'}://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`)(server.address());
  log({listening: address, backend: backend.kind, key: T.b64(T.ed25519RawPublic(backend.publicKey))});
  return {
    address, core, counters,
    close: () => new Promise(done => {
      server.closeAllConnections?.();
      server.close(() => { core.close(); done(); });
    }),
  };
}
