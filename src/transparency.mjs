// Vault-side transparency: config, startup anchors (pin file + witness probe), the heads-log pump with
// C2SP tlog-witness submission, runtime quarantine, and export/report evidence. Format code lives in tlog.mjs.
import {closeSync, existsSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, rmSync, statSync, writeSync} from 'node:fs';
import {basename, dirname, join, resolve} from 'node:path';
import {createHash, createPublicKey, randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import * as T from './tlog.mjs';

export const TRANSPARENCY_MODES = ['off', 'monitor', 'enforce'];
export const UNANCHORED = ['rollback', 'truncation', 'tenant_removal'];
const PIN_FORMAT = 'evidscope-transparency-pin-v1';
const OFF = Object.freeze({mode: 'off', witnesses: [], quorum: 0});
const QUARANTINE_KINDS = new Set(['rollback', 'fork', 'tenant_removal', 'inconsistent']), PIN_FREEZE_KINDS = QUARANTINE_KINDS;
export const transparencyPinPath = dataDir => join(dirname(resolve(dataDir)), '.' + basename(resolve(dataDir)) + '-transparency-pin.json');

// lstat, not existsSync: a dangling symlink at the pin path must not read as a missing pin.
const lexists = path => !!lstatSync(path, {throwIfNoEntry: false});
function noLinks(path) {
  for (let current = resolve(path); ;) {
    if (lstatSync(current, {throwIfNoEntry: false})?.isSymbolicLink()) throw Error('Transparency pin path must not contain symlinks');
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
const kinded = (kind, message) => Object.assign(Error(message), {kind});

// ---------- config ----------
const isMountPoint = dir => {
  try { return dirname(dir) === dir || statSync(dir).dev !== statSync(dirname(dir)).dev; } catch { return false; }
};
export function normalizeTransparencyConfig(raw, {dataDir, env = {}} = {}) {
  if (raw === undefined || raw === null) return OFF;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw Error('Transparency config must be a JSON object');
  const allowed = ['origin', 'witnesses', 'quorum', 'intervalMs', 'maxStalenessSeconds', 'refreshSeconds', 'timeoutMs', 'mode', 'pinFile'];
  for (const k of Object.keys(raw)) if (!allowed.includes(k)) throw Error('Unknown transparency config field: ' + k);
  const mode = raw.mode ?? 'monitor';
  if (!TRANSPARENCY_MODES.includes(mode)) throw Error('Transparency mode must be off, monitor or enforce');
  if (mode === 'off') return OFF;
  const base = T.validateOriginBase(raw.origin), list = raw.witnesses ?? [];
  if (!Array.isArray(list) || list.length > 32) throw Error('Transparency witnesses must be an array of at most 32 entries');
  const witnesses = list.map(w => {
    if (!w || typeof w !== 'object' || typeof w.vkey !== 'string' || typeof w.url !== 'string') throw Error('Transparency witness needs vkey and url');
    const verifier = T.cosignatureVerifier(w.vkey), url = new URL(w.url);
    if (w.name !== undefined && w.name !== verifier.name) throw Error('Transparency witness name differs from its vkey name');
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw Error('Transparency witness url must be a plain http(s) submission prefix');
    }
    return Object.freeze({name: verifier.name, keyId: verifier.id.toString('hex'), vkey: w.vkey, url: url.href, verifier});
  });
  if (new Set(witnesses.map(w => w.name + '+' + w.keyId)).size !== witnesses.length) throw Error('Duplicate transparency witness');
  const int = (v, d, lo, hi, what) => {
    const n = v ?? d;
    if (!Number.isSafeInteger(n) || n < lo || n > hi) throw Error(`Transparency ${what} must be an integer in [${lo}, ${hi}]`);
    return n;
  };
  const maxStalenessSeconds = int(raw.maxStalenessSeconds, 3600, 1, 30 * 86400, 'maxStalenessSeconds');
  if (raw.pinFile !== undefined && typeof raw.pinFile !== 'string') throw Error('Transparency pinFile must be a path');
  if (!env.TRANSPARENCY_PIN_FILE && raw.pinFile === undefined && dataDir && isMountPoint(resolve(dataDir))) {
    throw Error(`Transparency pinFile (or TRANSPARENCY_PIN_FILE) is required: the data directory ${resolve(dataDir)} is a mount point, `
      + 'so the default pin path beside it would live on another (often read-only or ephemeral) filesystem');
  }
  return Object.freeze({
    mode, base, headsOrigin: T.headsOrigin(base), witnesses,
    quorum: int(raw.quorum, witnesses.length ? 1 : 0, 0, witnesses.length, 'quorum'),
    intervalMs: int(raw.intervalMs, 2000, 50, 3600000, 'intervalMs'),
    maxStalenessSeconds,
    refreshSeconds: int(raw.refreshSeconds, Math.max(1, Math.min(300, Math.floor(maxStalenessSeconds / 2))), 1, maxStalenessSeconds, 'refreshSeconds'),
    timeoutMs: int(raw.timeoutMs, 5000, 100, 60000, 'timeoutMs'),
    pinFile: resolve(env.TRANSPARENCY_PIN_FILE || raw.pinFile || transparencyPinPath(dataDir)),
  });
}
// Lives outside config.json so witness changes never alter the restore-bound config hash.
export function loadTransparencyConfig({dataDir, env = process.env} = {}) {
  const file = env.TRANSPARENCY_CONFIG_FILE;
  if (!file) return OFF;
  const st = statSync(file);
  if (!st.isFile() || st.size > 1024 * 1024) throw Error('Transparency config file must be a regular file of at most 1 MiB');
  return normalizeTransparencyConfig(JSON.parse(readFileSync(file, 'utf8')), {dataDir, env});
}

// ---------- pin file ----------
function readPinFile(file) {
  noLinks(file);
  if (!lexists(file)) return null;
  const st = lstatSync(file);
  if (!st.isFile() || st.size > 1024 * 1024) throw Error('Transparency pin file invalid');
  const pin = JSON.parse(readFileSync(file, 'utf8'));
  if (pin?.format !== PIN_FORMAT || typeof pin.origin !== 'string' || typeof pin.checkpoint !== 'string') {
    throw Error('Transparency pin file invalid or bound to another origin');
  }
  return pin;
}
// A pin holds a heads checkpoint signed by this vault plus the cosignatures known when it was written.
export function openPin(pin, origin, publicKey, witnesses = []) {
  if (pin?.format !== PIN_FORMAT || pin.origin !== origin || typeof pin.checkpoint !== 'string') {
    throw Error('Transparency pin file invalid or bound to another origin');
  }
  const logV = T.noteVerifier(T.logVkey(origin, publicKey));
  const opened = T.openNote(pin.checkpoint, [logV, ...witnesses.map(w => w.verifier)]), c = T.parseCheckpoint(opened.text);
  if (!opened.sigs.some(s => s.name === logV.name && s.id === logV.id.toString('hex')) || c.origin !== origin) {
    throw Error('Transparency pin is not a heads checkpoint signed by this vault');
  }
  return {size: c.size, root: c.root, note: pin.checkpoint, cosignatures: opened.sigs.length - 1};
}
const fsCode = error => error.code || error.message;
// Proves at startup that the pin can be rewritten later (the probe file name never reaches a message).
function assertPinWritable(config) {
  const probe = `${config.pinFile}.${process.pid}.${randomBytes(6).toString('hex')}.probe`;
  noLinks(config.pinFile);
  try { closeSync(openSync(probe, 'wx', 0o600)); } catch (error) {
    throw Error(`Transparency pin file ${config.pinFile} is not writable (${fsCode(error)})`);
  }
  rmSync(probe, {force: true});
}
function writePin(config, size, checkpoint) {
  const file = config.pinFile, tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  noLinks(file);
  const body = JSON.stringify({format: PIN_FORMAT, origin: config.headsOrigin, size, checkpoint, updatedAt: new Date().toISOString()}, null, 2) + '\n';
  const fd = openSync(tmp, 'wx', 0o600);
  try { writeSync(fd, body); fsyncSync(fd); } catch (error) { closeSync(fd); rmSync(tmp, {force: true}); throw error; }
  closeSync(fd);
  try { renameSync(tmp, file); } catch (error) { rmSync(tmp, {force: true}); throw error; }
}
const writePinOrExplain = (config, size, checkpoint) => {
  try { writePin(config, size, checkpoint); } catch (error) { throw Error(`Transparency pin write to ${config.pinFile} failed (${fsCode(error)})`); }
};

// ---------- heads log rows (also used by transparency-epoch.mjs on restore archives) ----------
export const hasTable = (db, name) => !!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?").get(name);
export function headsSize(db, origin) {
  const r = db.prepare('SELECT MAX(idx) m, COUNT(*) n FROM tlog_heads WHERE origin=?').get(origin);
  if (!r.n) return 0;
  if (r.m !== r.n - 1) throw kinded('inconsistent', 'Truncated or inconsistent heads log');
  return r.n;
}
export const headsRow = (db, origin, idx) => db.prepare('SELECT idx,leaf,peaks,entries,note FROM tlog_heads WHERE origin=? AND idx=?').get(origin, idx) || null;
const validEntry = e => e && Object.keys(e).length === 3 && typeof e.log === 'string' && /^[a-f0-9]{64}$/.test(e.root)
  && Number.isSafeInteger(e.size) && e.size > 0;
// A row stores its frontier before the leaf and its own signed note, so every row authenticates itself in O(log n).
export function verifyHeadsRow(row, origin, logV) {
  if (!row) throw kinded('inconsistent', 'Truncated or inconsistent heads log: row missing');
  const entries = JSON.parse(row.entries), leaf = Buffer.from(row.leaf), peaksBefore = T.blobToPeaks(row.peaks, row.idx);
  if (!Array.isArray(entries) || !entries.every(validEntry) || T.canonicalJson(T.sortHeadsEntries(entries)) !== row.entries) {
    throw kinded('inconsistent', 'Truncated or inconsistent heads log: entries are not canonical');
  }
  const content = T.headsLeafContent(entries);
  if (leaf.length !== 32 || !T.headsLeafHash(content).equals(leaf)) {
    throw kinded('inconsistent', 'Truncated or inconsistent heads log: leaf differs from its entries');
  }
  const peaks = T.frontierAppend(peaksBefore, row.idx, leaf), root = T.frontierRoot(peaks), c = T.parseCheckpoint(T.openNote(row.note, [logV]).text);
  if (c.origin !== origin || c.size !== row.idx + 1 || !c.root.equals(root) || c.extensions.length) {
    throw kinded('inconsistent', 'Truncated or inconsistent heads log: row differs from its signed note');
  }
  return {size: row.idx + 1, root, peaks, peaksBefore, leaf, entries, content, note: row.note};
}
function* headsLeaves(db, origin, from = 0, to = Infinity) {
  let expected = from;
  const rows = db.prepare('SELECT idx,leaf FROM tlog_heads WHERE origin=? AND idx>=? AND idx<? ORDER BY idx');
  for (const r of rows.iterate(origin, from, to === Infinity ? Number.MAX_SAFE_INTEGER : to)) {
    if (r.idx !== expected++) throw kinded('inconsistent', 'Truncated or inconsistent heads log');
    yield Buffer.from(r.leaf);
  }
}
// The heads log at `size` (root `root`) must extend the pinned checkpoint: the row at the pin folds to the pinned root and
// the stored leaves after it fold to `root`. Returns the verified pinned row or the violation.
function foldFromPin(db, origin, logV, pin, size, root) {
  if (size < pin.size) {
    return {error: {kind: 'rollback', message: `Ledger heads log (size ${size}) is behind the pinned heads checkpoint (size ${pin.size}) (rollback)`}};
  }
  const at = verifyHeadsRow(headsRow(db, origin, pin.size - 1), origin, logV);
  if (!at.root.equals(pin.root)) return {error: {kind: 'fork', message: 'Ledger heads log conflicts with the pinned heads checkpoint (fork)'}};
  let peaks = at.peaks, n = pin.size;
  for (const leaf of headsLeaves(db, origin, pin.size, size)) peaks = T.frontierAppend(peaks, n++, leaf);
  if (n !== size || !T.frontierRoot(peaks).equals(root)) {
    return {error: {kind: 'inconsistent', message: 'Truncated or inconsistent heads log after the pinned checkpoint'}};
  }
  return {at};
}
// Proof m -> n built from the verified frontier at m plus stored leaves, checked locally before it leaves the vault.
export function headsConsistencyProof(db, origin, logV, m, n, rootN) {
  const at = verifyHeadsRow(headsRow(db, origin, m - 1), origin, logV), leaves = [...headsLeaves(db, origin, m, n)];
  if (leaves.length !== n - m) throw kinded('inconsistent', 'Truncated or inconsistent heads log');
  const proof = T.consistencyProofFromFrontier(m, at.peaks, leaves);
  if (!T.verifyConsistency(m, n, at.root, rootN, proof)) throw kinded('inconsistent', 'Truncated or inconsistent heads log: stored history is not consistent');
  return proof;
}
// Never ask a witness to cosign rows that regress a tenant log since the size it cosigned before.
function witnessProof(db, origin, logV, m, n, rootN) {
  checkHeadsMonotone(db, origin, m, n, (kind, message) => { throw kinded(kind, message); });
  return headsConsistencyProof(db, origin, logV, m, n, rootN);
}
export function* ledgerLeaves(db, tenant) {
  let expected = 0;
  for (const r of db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq').iterate(tenant)) {
    if (r.seq !== ++expected) throw kinded('inconsistent', 'Truncated or inconsistent ledger sequence for tenant');
    yield T.recordLeaf(r.hash);
  }
}

// ---------- witness exchange (shared by the startup probe and the pump) ----------
// One add-checkpoint submission with a single 409 resynchronisation. Protocol outcomes never throw.
export async function exchange({w, size, note, old, proofFor, logV, config, fetchImpl, now}) {
  for (let attempt = 0; ; attempt++) {
    if (old > size) return {status: 'rollback', size: old, message: `witness holds heads size ${old} but the local heads log has ${size} (rollback)`};
    let proof;
    try { proof = old === 0 || old === size ? [] : proofFor(old); } catch (error) { return {status: 'inconsistent', message: error.message}; }
    const r = await T.postAddCheckpoint(w.url, T.addCheckpointBody(old, proof, note), {timeoutMs: config.timeoutMs, fetchImpl});
    if (r.status === 200) {
      try {
        const opened = T.openNote(note + T.parseCosignatureResponse(r.body).join(''), [logV, w.verifier]);
        const sig = opened.sigs.find(s => s.name === w.name && s.id === w.keyId);
        if (!sig) throw Error('no cosignature from the configured key');
        const timestamp = T.cosignatureTimestamp(sig.raw);
        if (timestamp > Math.floor(now() / 1000) + 300) throw Error('cosignature timestamp is in the future');
        return {status: 'consistent', size, previousSize: old, timestamp, line: sig.line};
      } catch (error) { return {status: 'invalid_response', message: error.message}; }
    }
    if (r.status === 409 && attempt === 0) {
      try { old = T.parseConflictBody(r.type, r.body); } catch (error) { return {status: 'invalid_response', message: error.message}; }
      continue;
    }
    if (r.status === 409) return {status: 'unknown', message: 'witness size changed during resynchronisation'};
    if (r.status === 422) return {status: 'fork', size: old, message: `witness rejected heads checkpoint ${size} as inconsistent with its size ${old} (fork)`};
    if (r.status === 404) return {status: 'unregistered', message: 'heads origin is not registered at the witness'};
    if (r.status === 403) return {status: 'untrusted', message: 'witness does not trust the vault log key'};
    if (r.status === 400) return {status: 'rejected', message: 'witness rejected the request as malformed'};
    return {status: 'unreachable', message: r.status ? `HTTP ${r.status}` : r.error || 'network error'};
  }
}
const witnessId = w => w.name + '+' + w.keyId;

// Async, read-only, before createService. An empty local heads log is probed with a signed size-0 checkpoint
// (empty-tree root), the only checkpoint that cannot conflict with anything, so a witness answers 409 S.
export async function probeTransparency({dataDir, key, config, fetchImpl = fetch, now = () => Date.now()}) {
  if (!config || config.mode === 'off' || !config.witnesses.length) return null;
  const publicKey = createPublicKey(key), hOrigin = config.headsOrigin, logV = T.noteVerifier(T.logVkey(hOrigin, publicKey));
  const file = join(dataDir, 'evidence.db'), db = existsSync(file) ? new DatabaseSync(file, {readOnly: true, timeout: 5000}) : null;
  try {
    let local = {size: 0, root: T.EMPTY_ROOT, note: T.signNote(T.formatCheckpoint({origin: hOrigin, size: 0, root: T.EMPTY_ROOT}), T.noteSigner(hOrigin, key))};
    let error = null;
    try {
      if (db && hasTable(db, 'tlog_heads')) {
        const n = headsSize(db, hOrigin);
        if (n) local = verifyHeadsRow(headsRow(db, hOrigin, n - 1), hOrigin, logV);
      }
    } catch (e) { error = e.message; }
    if (error) return {checkedAt: new Date(now()).toISOString(), headsSize: null, error, witnesses: []};
    const proofFor = m => witnessProof(db, hOrigin, logV, m, local.size, local.root);
    const witnesses = await Promise.all(config.witnesses.map(async w => ({
      name: w.name, keyId: w.keyId,
      ...await exchange({w, size: local.size, note: local.note, old: 0, proofFor, logV, config, fetchImpl, now}),
    })));
    return {checkedAt: new Date(now()).toISOString(), headsSize: local.size, headsRoot: local.root.toString('hex'), witnesses};
  } finally { db?.close(); }
}
// Explicit operator decision for a non-empty heads log without a pin (lost pin volume, upgrade from a build that never
// wrote one): the latest heads checkpoint becomes the pin once the read-only startup check passes and, with witnesses,
// once the quorum cosigned it in `probe` (which submits that checkpoint).
export function bootstrapPin({dataDir, key, config, probe = null}) {
  if (!config || config.mode === 'off') throw Error('Transparency mode is off in this config');
  const report = assertTransparencyAnchors({dataDir, key, config: {...config, mode: 'monitor'}, probe, inspectOnly: true});
  if (report.pin) throw Error(`A transparency pin for ${config.headsOrigin} already exists at ${config.pinFile}; refusing to replace it`);
  const blocking = report.violations.filter(v => !v.missingPin);
  if (blocking.length) throw Error('Transparency pin bootstrap refused: ' + blocking.map(v => v.message).join('; '));
  if (!report.headsSize) throw Error('The heads log is empty; the vault writes its first pin when it starts');
  const hOrigin = config.headsOrigin, logV = T.noteVerifier(T.logVkey(hOrigin, createPublicKey(key)));
  const db = new DatabaseSync(join(dataDir, 'evidence.db'), {readOnly: true, timeout: 5000});
  let latest;
  try { latest = verifyHeadsRow(headsRow(db, hOrigin, report.headsSize - 1), hOrigin, logV); } finally { db.close(); }
  const lines = (probe?.witnesses || []).filter(w => w.status === 'consistent' && w.size === report.headsSize).map(w => w.line);
  const quorum = config.witnesses.length ? Math.max(1, config.quorum) : 0;
  if (lines.length < quorum) {
    throw Error(`Transparency pin bootstrap needs ${quorum} witness cosignature(s) on heads size ${report.headsSize}; got ${lines.length}`);
  }
  writePinOrExplain(config, latest.size, latest.note + lines.join(''));
  const pin = openPin(readPinFile(config.pinFile), hOrigin, createPublicKey(key), config.witnesses);
  return {pinFile: config.pinFile, origin: hOrigin, size: pin.size, cosignatures: pin.cosignatures};
}
export async function prepareTransparency({dataDir, key, env = process.env, fetchImpl}) {
  const config = loadTransparencyConfig({dataDir, env});
  return {config, probe: config.mode !== 'off' && config.witnesses.length ? await probeTransparency({dataDir, key, config, fetchImpl}) : null};
}

// ---------- synchronous startup anchors (read-only, before Store opens a writer) ----------
// The DB heads log must extend the pinned heads checkpoint, every tenant named by a heads leaf must still exist with an
// identical prefix, every tlog_state root must match its ledger, and no witness may report rollback or fork. Hard
// violations (the vault would sign a fork of an origin) refuse startup in every mode; inspectOnly only reports them.
export function assertTransparencyAnchors({dataDir, key, config, probe = null, inspectOnly = false}) {
  if (!config || config.mode === 'off') return {mode: 'off'};
  const file = join(dataDir, 'evidence.db'), db = existsSync(file) ? new DatabaseSync(file, {readOnly: true, timeout: 5000}) : null;
  let checked;
  try { checked = checkAnchors({db, key, config, probe}); } finally { db?.close(); }
  const {report, pin} = checked, violations = report.violations, hOrigin = config.headsOrigin;
  // A started vault must be able to move its pin. An empty heads log gets a size-0 pin at once (bootstrap), so a later
  // missing pin is always a violation.
  if (!inspectOnly) {
    try {
      if (!violations.length && !pin && !report.headsSize) {
        writePinOrExplain(config, 0, T.signNote(T.formatCheckpoint({origin: hOrigin, size: 0, root: T.EMPTY_ROOT}), T.noteSigner(hOrigin, key)));
        report.pin = {size: 0, root: T.EMPTY_ROOT.toString('hex'), cosignatures: 0, bootstrapped: true};
      } else assertPinWritable(config);
    } catch (error) { violations.push({kind: 'pin', message: error.message}); }
  }
  report.ok = !violations.length;
  if (inspectOnly) return report;
  refuseFatal(config, violations);
  // The writer re-runs the check inside the startup transaction, before syncTlog can extend or re-seal anything: the
  // database may have been replaced after the read-only check above or after the witness probe.
  Object.defineProperty(report, 'recheck', {value: writer => {
    const again = checkAnchors({db: writer, key, config, probe}).report.violations;
    for (const v of again) if (!violations.some(x => x.kind === v.kind && x.message === v.message)) violations.push(v);
    report.ok = !violations.length;
    refuseFatal(config, again);
  }});
  return report;
}
function refuseFatal(config, violations) {
  const fatal = config.mode === 'enforce' ? violations : violations.filter(v => v.hard);
  if (fatal.length) throw Error('Transparency startup check failed: ' + fatal.map(v => v.message).join('; '));
}
function checkAnchors({db, key, config, probe}) {
  const publicKey = createPublicKey(key), hOrigin = config.headsOrigin, logV = T.noteVerifier(T.logVkey(hOrigin, publicKey));
  const violations = [], violate = (kind, message, hard = false) => violations.push(hard ? {kind, message, hard} : {kind, message});
  const report = {mode: config.mode, checkedAt: new Date().toISOString(), pin: null, headsSize: 0, probe, violations};
  let rawPin = null, pin = null, rawPinError = false;
  try { rawPin = readPinFile(config.pinFile); } catch (error) { rawPinError = true; violate('pin', error.message); }
  if (probe?.error) violate('inconsistent', probe.error);
  for (const w of probe?.witnesses || []) if (['rollback', 'fork', 'inconsistent'].includes(w.status)) violate(w.status, `Witness ${w.name}: ${w.message}`);
  try {
    if (rawPin?.origin === hOrigin) {
      try { pin = openPin(rawPin, hOrigin, publicKey, config.witnesses); } catch (error) { rawPinError = true; violate('pin', error.message); }
    }
    const ledger = !!db && hasTable(db, 'ledger'), retiredPin = rawPin && rawPin.origin !== hOrigin ? rawPin : null;
    if (retiredPin && !ledger) violate('pin', 'Transparency pin file invalid or bound to another origin');
    const epochs = ledger ? checkEpochs({db, config, publicKey, violate, retiredPin, report}) : {requirements: []};
    if (pin) report.pin = {size: pin.size, root: pin.root.toString('hex'), cosignatures: pin.cosignatures};
    const size = db && hasTable(db, 'tlog_heads') ? headsSize(db, hOrigin) : 0, anchors = [];
    report.headsSize = size;
    const latest = size ? verifyHeadsRow(headsRow(db, hOrigin, size - 1), hOrigin, logV) : null;
    if (latest) anchors.push(latest.entries);
    // Witness answers describe the heads log the probe read; they say nothing about a database swapped in since.
    if (probe && !probe.error && (probe.headsSize !== size || probe.headsRoot !== (latest?.root ?? T.EMPTY_ROOT).toString('hex'))) {
      violate('inconsistent', `Truncated or inconsistent heads log: the database (heads size ${size}) differs from the one the witnesses were `
        + `probed with (heads size ${probe.headsSize}); it changed after the probe`);
    }
    if (!pin && size && !rawPinError) {
      violations.push({kind: 'pin', missingPin: true, message: `Transparency pin for ${hOrigin} is missing although the heads log has size ${size}; `
        + 'restore the pin file or create one explicitly with scripts/transparency.mjs pin-bootstrap'});
    }
    let monotoneFrom = null;
    if (pin && pin.size) {
      const folded = foldFromPin(db, hOrigin, logV, pin, size, latest?.root);
      if (folded.error) violate(folded.error.kind, folded.error.message);
      else if (pin.size < size) { anchors.push(folded.at.entries); monotoneFrom = pin.size; }
    } else {
      const seen = (probe?.witnesses || []).filter(w => w.status === 'consistent' && w.size === size).map(w => w.previousSize ?? 0);
      if (seen.length) monotoneFrom = Math.min(...seen);
    }
    if (monotoneFrom !== null && monotoneFrom < size) checkHeadsMonotone(db, hOrigin, monotoneFrom, size, violate);
    if (ledger) checkTenants(db, config.base, anchors, violate, epochs.requirements);
  } catch (error) { violate(error.kind || 'inconsistent', error.message); }
  return {report, pin};
}
// Every heads row after the anchor (the pin, or what a witness had cosigned before) keeps each tenant log monotone:
// sizes never decrease, logs never disappear and an unchanged size keeps its root. The leaves themselves were already
// folded to the signed latest root, so each row's entries only have to hash to its leaf.
function checkHeadsMonotone(db, origin, from, to, violate) {
  const rows = db.prepare('SELECT idx,leaf,entries FROM tlog_heads WHERE origin=? AND idx>=? AND idx<? ORDER BY idx');
  let previous = null, expected = Math.max(0, from - 1);
  for (const row of rows.iterate(origin, expected, to)) {
    if (row.idx !== expected++) throw kinded('inconsistent', 'Truncated or inconsistent heads log');
    const entries = JSON.parse(row.entries);
    if (!Array.isArray(entries) || !entries.every(validEntry) || T.canonicalJson(T.sortHeadsEntries(entries)) !== row.entries
      || !T.headsLeafHash(T.headsLeafContent(entries)).equals(Buffer.from(row.leaf))) {
      throw kinded('inconsistent', `Truncated or inconsistent heads log: row ${row.idx} entries differ from its leaf`);
    }
    const current = new Map(entries.map(e => [e.log, e]));
    for (const [log, e] of previous || []) {
      const next = current.get(log);
      if (!next) violate('tenant_removal', `Heads log row ${row.idx} drops tenant log ${log} (tenant removal)`);
      else if (next.size < e.size) violate('rollback', `Heads log row ${row.idx} shrinks tenant log ${log} from ${e.size} to ${next.size} (rollback)`);
      else if (next.size === e.size && next.root !== e.root) violate('fork', `Heads log row ${row.idx} changes tenant log ${log} at size ${e.size} (fork)`);
    }
    previous = current;
  }
}
const ledgerTenants = db => db.prepare('SELECT DISTINCT tenant FROM ledger').all().map(r => r.tenant);
// Each requirement names a tenant tree size and root that the ledger prefix must reproduce.
function checkTenants(db, base, anchors, violate, extra = []) {
  const prefix = base + '/t/', want = new Map(), missing = new Set(), seen = new Set();
  const tenants = new Map(ledgerTenants(db).map(t => [T.tenantOrigin(base, t), t]));
  const add = (tenant, log, size, root, what) => {
    if (seen.has(`${log}|${size}|${root}`)) return;
    seen.add(`${log}|${size}|${root}`);
    if (!want.has(tenant)) want.set(tenant, []);
    want.get(tenant).push({log, size, root, what});
  };
  const addLog = (log, size, root, what) => {
    const tenant = tenants.get(log);
    if (tenant !== undefined) return add(tenant, log, size, root, what);
    if (!missing.has(log)) violate('tenant_removal', `Witnessed tenant missing for log ${log} (tenant removal)`);
    missing.add(log);
  };
  for (const entries of anchors) for (const e of entries) addLog(e.log, e.size, e.root, 'witnessed head');
  if (hasTable(db, 'tlog_state')) {
    for (const r of db.prepare('SELECT origin,size,root FROM tlog_state WHERE substr(origin,1,?)=? AND size>0').all(prefix.length, prefix)) {
      addLog(r.origin, r.size, Buffer.from(r.root).toString('hex'), 'signed tlog checkpoint');
    }
  }
  for (const x of extra) add(x.tenant, x.log, x.size, x.root, x.what);
  for (const [tenant, list] of want) {
    const {roots, size} = T.rootsAtSizes(ledgerLeaves(db, tenant), [...new Set(list.map(x => x.size))]);
    for (const x of list) {
      if (size < x.size) violate('rollback', `Ledger for tenant log ${x.log} (size ${size}) is behind its ${x.what} (size ${x.size}) (rollback)`);
      else if (roots.get(x.size).toString('hex') !== x.root) {
        violate('fork', `Ledger for tenant log ${x.log} conflicts with its ${x.what} at size ${x.size} (fork)`);
      }
    }
  }
}

// ---------- restore epochs at startup ----------
const sha256Hex = text => createHash('sha256').update(text).digest('hex');
export function readEpochs(db) {
  const out = new Map(), rows = db.prepare(`SELECT tenant,seq,hash,body FROM ledger WHERE body LIKE '%"type":"${T.TLOG_EPOCH_TYPE}"%' ORDER BY tenant,seq`);
  for (const r of rows.iterate()) {
    const record = JSON.parse(r.body);
    if (record.type !== T.TLOG_EPOCH_TYPE) continue;
    if (sha256Hex(r.body) !== r.hash || record.tenant !== r.tenant || record.seq !== r.seq) {
      throw kinded('inconsistent', 'Truncated or inconsistent ledger: tlog epoch record differs from its hash');
    }
    if (!out.has(r.tenant)) out.set(r.tenant, []);
    out.get(r.tenant).push({seq: r.seq, payload: T.tlogEpochPayload(record)});
  }
  return out;
}
export function headsOrigins(db) {
  if (!hasTable(db, 'tlog_heads')) return [];
  const out = [], next = db.prepare('SELECT origin FROM tlog_heads WHERE origin>? ORDER BY origin LIMIT 1');
  for (let r = next.get(''); r; r = next.get(r.origin)) out.push(r.origin);
  return out;
}
const retiredBaseOf = origin => (origin.endsWith('/heads') ? origin.slice(0, -'/heads'.length) : null);
// A restore moves every tenant to a new origin base with signed tlog_epoch records (src/transparency-epoch.mjs). State of
// another base is accepted only when those records retire it: retired logs stay at or below the restored size and are
// prefixes of the ledger, a retired pin lies within the acknowledged heads range, and the configured base is never a retired
// one. A restored ledger must not extend the origin it was restored from: that would sign a fork of the lost history.
function checkEpochs({db, config, publicKey, violate, retiredPin, report}) {
  const base = config.base, prefix = base + '/t/', requirements = [], hasState = hasTable(db, 'tlog_state');
  let crossed = false;
  if (hasState) {
    const crossing = db.prepare("SELECT 1 FROM ledger WHERE tenant=? AND seq>? AND json_extract(body,'$.type')='recovery_restore' LIMIT 1");
    for (const r of db.prepare('SELECT tenant,origin,size FROM tlog_state WHERE substr(origin,1,?)=?').all(prefix.length, prefix)) {
      if (!crossing.get(r.tenant, r.size)) continue;
      crossed = true;
      violate('fork', `Restored ledger would extend tenant log ${r.origin} across its restore (fork); `
        + 'configure a new origin base so the restore starts a tlog epoch', true);
    }
  }
  const foreignState = hasState ? db.prepare('SELECT tenant,origin,size,root,note FROM tlog_state WHERE substr(origin,1,?)<>? AND size>0')
    .all(prefix.length, prefix) : [];
  const foreignHeads = headsOrigins(db).filter(o => o !== config.headsOrigin);
  if (!foreignState.length && !foreignHeads.length && !retiredPin && !crossed) return {requirements};
  const epochs = readEpochs(db), retired = new Map(), tenants = ledgerTenants(db);
  const epochOf = (tenant, previousBase) => (epochs.get(tenant) || []).find(e => e.payload.previousOriginBase === previousBase);
  for (const [tenant, list] of epochs) {
    for (let i = 1; i < list.length; i++) {
      if (list[i].payload.previousOriginBase !== list[i - 1].payload.originBase) violate('inconsistent', `Tlog epoch chain of tenant ${tenant} is broken`);
    }
    if (list.some(e => e.payload.previousOriginBase === base)) {
      violate('fork', `Transparency origin base ${base} was retired by a signed tlog epoch of tenant ${tenant}; refusing to extend it (fork)`, true);
    } else if (list.at(-1).payload.originBase !== base) {
      violate('inconsistent', `Tenant ${tenant} moved to origin base ${list.at(-1).payload.originBase} by a tlog epoch but the vault is configured for ${base}`
        + ' (unacknowledged origin change)');
    }
    for (const {seq, payload: p} of list) {
      requirements.push({tenant, log: p.previousOrigin, size: p.restoredSize, root: p.restoredRoot, what: `tlog epoch restored root (sequence ${seq})`});
      if (p.previousCheckpoint !== null) {
        let c = null;
        try { c = T.parseCheckpoint(T.openNote(p.previousCheckpoint, [T.noteVerifier(T.logVkey(p.previousOrigin, publicKey))]).text); } catch { c = null; }
        if (c?.origin !== p.previousOrigin || c.size > p.restoredSize) {
          violate('inconsistent', `Tlog epoch at sequence ${seq} carries an invalid previous checkpoint`);
        }
        else requirements.push({tenant, log: p.previousOrigin, size: c.size, root: c.root.toString('hex'), what: 'previous origin checkpoint'});
      }
      const r = retired.get(p.previousOriginBase), acknowledged = Math.max(p.restoredHeadsSize, p.witnessedHeadsSize ?? 0);
      if (r && r.restoredHeadsSize !== p.restoredHeadsSize) violate('inconsistent', `Tlog epochs disagree on the restored heads of ${p.previousOriginBase}`);
      retired.set(p.previousOriginBase, {restoredHeadsSize: p.restoredHeadsSize, acknowledged: Math.max(r?.acknowledged ?? 0, acknowledged)});
    }
  }
  report.retired = [...retired.keys()].sort();
  for (const r of foreignState) {
    let rowBase = null;
    try { rowBase = T.originBaseOf(r.origin, r.tenant); } catch { rowBase = null; }
    const e = rowBase && epochOf(r.tenant, rowBase)?.payload;
    if (!e) {
      violate('inconsistent', `Ledger holds tenant log ${r.origin} of another origin base without a signed tlog epoch for tenant ${r.tenant}`
        + ' (rollback or unacknowledged origin change)');
      continue;
    }
    let c = null;
    try { c = T.parseCheckpoint(T.openNote(r.note, [T.noteVerifier(T.logVkey(r.origin, publicKey))]).text); } catch { c = null; }
    if (c?.origin !== r.origin || c.size !== r.size || !c.root.equals(Buffer.from(r.root))) {
      violate('inconsistent', `Truncated or inconsistent tlog state for retired tenant log ${r.origin}`);
    } else if (r.size > e.restoredSize) {
      violate('fork', `Retired tenant log ${r.origin} (size ${r.size}) extends beyond its tlog epoch restored size ${e.restoredSize} (fork)`);
    } else requirements.push({tenant: r.tenant, log: r.origin, size: r.size, root: c.root.toString('hex'), what: 'retired tlog checkpoint'});
  }
  for (const origin of foreignHeads) {
    const oldBase = retiredBaseOf(origin), ack = oldBase && retired.get(oldBase);
    if (!ack) {
      violate('inconsistent', `Ledger holds heads log ${origin} without a signed tlog epoch retiring it (rollback or unacknowledged origin change)`);
      continue;
    }
    const n = headsSize(db, origin);
    if (n > ack.restoredHeadsSize) {
      violate('fork', `Retired heads log ${origin} (size ${n}) extends beyond its tlog epoch heads size ${ack.restoredHeadsSize} (fork)`);
      continue;
    }
    if (!n) continue;
    const latest = verifyHeadsRow(headsRow(db, origin, n - 1), origin, T.noteVerifier(T.logVkey(origin, publicKey)));
    const logs = new Map(tenants.map(t => [T.tenantOrigin(oldBase, t), t]));
    for (const entry of latest.entries) {
      const tenant = logs.get(entry.log), e = tenant !== undefined && epochOf(tenant, oldBase)?.payload;
      if (tenant === undefined) violate('tenant_removal', `Witnessed tenant missing for log ${entry.log} of retired origin base ${oldBase} (tenant removal)`);
      else if (!e) violate('inconsistent', `Retired heads log ${origin} names ${entry.log} without a signed tlog epoch (unacknowledged origin change)`);
      else if (entry.size > e.restoredSize) violate('fork', `Retired heads entry for ${entry.log} (size ${entry.size}) is beyond its tlog epoch (fork)`);
      else requirements.push({tenant, log: entry.log, size: entry.size, root: entry.root, what: 'retired heads entry'});
    }
  }
  if (retiredPin) {
    const oldBase = retiredBaseOf(retiredPin.origin), ack = oldBase && retired.get(oldBase);
    if (!ack) violate('pin', 'Transparency pin file invalid or bound to another origin');
    else {
      try {
        const p = openPin(retiredPin, retiredPin.origin, publicKey, config.witnesses), n = headsSize(db, retiredPin.origin);
        report.retiredPin = {origin: retiredPin.origin, size: p.size, cosignatures: p.cosignatures, acknowledgedHeadsSize: ack.acknowledged};
        if (p.size > ack.acknowledged) {
          violate('rollback', `Transparency pin of retired heads origin ${retiredPin.origin} (size ${p.size}) exceeds the heads size `
            + `its tlog epoch acknowledged (${ack.acknowledged}) (rollback)`);
        } else if (p.size && p.size <= n) {
          const at = verifyHeadsRow(headsRow(db, retiredPin.origin, p.size - 1), retiredPin.origin, T.noteVerifier(T.logVkey(retiredPin.origin, publicKey)));
          if (!at.root.equals(p.root)) violate('fork', 'Retired heads log conflicts with the pinned heads checkpoint (fork)');
        }
      } catch (error) { violate('pin', error.message); }
    }
  }
  return {requirements};
}

// ---------- runtime controller ----------
const offController = Object.freeze({
  mode: 'off', start() {}, async stop() {}, async pump() {}, bundleOptions: () => ({}), integrity: result => result, quarantined: () => null,
  status: () => ({mode: 'off'}),
});
export function createTransparency({store, config, key, startup = null, probe = null, fetchImpl = fetch, now = () => Date.now()}) {
  if (!config || config.mode === 'off') return offController;
  if (!store.tlog) throw Error('Store was opened without transparency state');
  const db = store.db, hOrigin = config.headsOrigin, publicKey = createPublicKey(key), logV = T.noteVerifier(T.logVkey(hOrigin, publicKey));
  const signer = T.noteSigner(hOrigin, key), tenantVerifiers = new Map();
  const violations = (startup?.violations || []).map(v => ({...v, at: startup.checkedAt}));
  const tenantVerifier = origin => {
    if (!tenantVerifiers.has(origin)) tenantVerifiers.set(origin, T.noteVerifier(T.logVkey(origin, publicKey)));
    return tenantVerifiers.get(origin);
  };
  const iso = () => new Date(now()).toISOString();
  const loadLatest = () => {
    const n = headsSize(db, hOrigin);
    if (!n) return {size: 0, root: T.EMPTY_ROOT, peaks: [], entries: new Map(), note: null};
    const v = verifyHeadsRow(headsRow(db, hOrigin, n - 1), hOrigin, logV);
    return {size: n, root: v.root, peaks: v.peaks, entries: new Map(v.entries.map(e => [e.log, e])), note: v.note};
  };
  let heads = loadLatest(), busy = null, timer = null, stopped = false;
  // The pin only ever moves forward along a heads log that extends it, and never after a rollback, fork, tenant removal or
  // inconsistency was seen (in monitor mode the vault keeps running, but its pin stays the last trustworthy anchor).
  let pinned = startup?.pin?.root ? {size: startup.pin.size, root: Buffer.from(startup.pin.root, 'hex')} : null;
  let pinFrozen = violations.find(v => PIN_FREEZE_KINDS.has(v.kind))?.message ?? null, pinFreezeReported = false;
  const witnessState = new Map(config.witnesses.map(w => {
    const last = db.prepare('SELECT MAX(size) s FROM tlog_cosignatures WHERE origin=? AND key_id=? AND name=?').get(hOrigin, w.keyId, w.name).s;
    const p = probe?.witnesses?.find(x => x.name === w.name && x.keyId === w.keyId);
    return [witnessId(w), {name: w.name, keyId: w.keyId, old: p?.status === 'consistent' ? p.size : last ?? null, status: p?.status || 'pending',
      message: p?.message || null, size: p?.size ?? null, timestamp: null, lastSuccessAt: null, lastAttemptAt: probe?.checkedAt || null}];
  }));

  function violation(kind, message, quarantine = QUARANTINE_KINDS.has(kind)) {
    const last = violations.at(-1);
    if (last?.kind === kind && last.message === message) return;
    violations.push({kind, message, at: iso()});
    if (violations.length > 50) violations.shift();
    process.stderr.write(JSON.stringify({component: 'transparency', mode: config.mode, violation: kind, message}) + '\n');
    if (PIN_FREEZE_KINDS.has(kind)) pinFrozen ??= message;
    if (config.mode === 'enforce' && quarantine && !store.quarantine) store.quarantine = {reason: message, kind, at: iso()};
  }
  function recordCosignature(size, w, r) {
    const sql = `INSERT INTO tlog_cosignatures VALUES(?,?,?,?,?,?,?) ON CONFLICT(origin,size,key_id)
      DO UPDATE SET name=excluded.name,timestamp=excluded.timestamp,line=excluded.line,received_at=excluded.received_at
      WHERE excluded.timestamp>tlog_cosignatures.timestamp`;
    store.transaction(() => store.projectionMutation(() => db.prepare(sql).run(hOrigin, size, w.keyId, w.name, r.timestamp, r.line, iso())));
  }
  for (const w of config.witnesses) {
    const p = probe?.witnesses?.find(x => x.name === w.name && x.keyId === w.keyId);
    if (p?.status === 'consistent' && p.size === heads.size && heads.size > 0) {
      recordCosignature(p.size, w, p);
      witnessState.get(witnessId(w)).timestamp = p.timestamp;
    }
  }
  // Tenant sets in heads leaves only grow and tenant sizes never shrink; changed tenant notes are re-verified before use.
  function appendHeads() {
    return store.transaction(() => {
      if (headsSize(db, hOrigin) !== heads.size) throw kinded('inconsistent', 'Truncated or inconsistent heads log: size changed outside the pump');
      const prefix = config.base + '/t/';
      const rows = db.prepare('SELECT origin,size,root,note FROM tlog_state WHERE substr(origin,1,?)=? AND size>0').all(prefix.length, prefix);
      const seen = new Set(), entries = [];
      let changed = false;
      for (const r of rows) {
        const prev = heads.entries.get(r.origin), root = Buffer.from(r.root);
        seen.add(r.origin);
        if (prev && r.size < prev.size) throw kinded('rollback', `Tenant log ${r.origin} shrank below its heads entry (rollback)`);
        if (prev && r.size === prev.size && root.toString('hex') !== prev.root) {
          throw kinded('fork', `Tenant log ${r.origin} changed below its heads entry (fork)`);
        }
        if (!prev || prev.size !== r.size) {
          let c = null;
          try { c = T.parseCheckpoint(T.openNote(r.note, [tenantVerifier(r.origin)]).text); } catch { c = null; }
          if (c?.origin !== r.origin || c.size !== r.size || !c.root.equals(root)) {
            throw kinded('inconsistent', 'Truncated or inconsistent tlog state for tenant log ' + r.origin);
          }
          changed = true;
        }
        entries.push(T.headsEntry(r.origin, r.size, root));
      }
      for (const log of heads.entries.keys()) {
        if (!seen.has(log)) throw kinded('tenant_removal', `Tenant log ${log} is missing beneath the heads log (tenant removal)`);
      }
      if (!changed) return null;
      const sorted = T.sortHeadsEntries(entries), leaf = T.headsLeafHash(T.headsLeafContent(sorted));
      const peaks = T.frontierAppend(heads.peaks, heads.size, leaf), root = T.frontierRoot(peaks), size = heads.size + 1;
      const note = T.signNote(T.formatCheckpoint({origin: hOrigin, size, root}), signer);
      store.projectionMutation(() => db.prepare('INSERT INTO tlog_heads VALUES(?,?,?,?,?,?,?)')
        .run(hOrigin, heads.size, leaf, T.peaksToBlob(heads.peaks), T.canonicalJson(sorted), note, iso()));
      return {size, root, peaks, entries: new Map(sorted.map(e => [e.log, e])), note};
    });
  }
  function cosignedCheckpoint(size) {
    const row = headsRow(db, hOrigin, size - 1);
    if (!row) return null;
    const lines = db.prepare('SELECT key_id,name,line FROM tlog_cosignatures WHERE origin=? AND size=? ORDER BY name,key_id').all(hOrigin, size)
      .filter(r => config.witnesses.some(w => w.keyId === r.key_id && w.name === r.name));
    return {row, checkpoint: row.note + lines.map(r => r.line).join(''), count: lines.length};
  }
  function maybeWritePin(target, checkpoint) {
    if (target.size <= (pinned?.size ?? 0)) return;
    if (pinFrozen) {
      if (!pinFreezeReported) violation('pin', `Transparency pin not advanced past size ${pinned?.size ?? 0} after: ${pinFrozen}`);
      pinFreezeReported = true;
      return;
    }
    if (pinned?.size) {
      let folded;
      try { folded = foldFromPin(db, hOrigin, logV, pinned, target.size, target.root); } catch (error) {
        folded = {error: {kind: error.kind || 'inconsistent', message: error.message}};
      }
      if (folded.error) return violation(folded.error.kind, folded.error.message);
    }
    // In enforce mode a pin that cannot move leaves rollbacks undetectable, so the vault stops instead.
    try { writePinOrExplain(config, target.size, checkpoint); pinned = {size: target.size, root: target.root}; } catch (error) {
      violation('pin', error.message, true);
    }
  }
  async function submit(w, target) {
    const st = witnessState.get(witnessId(w)), nowSeconds = Math.floor(now() / 1000);
    if (st.old === target.size && st.timestamp && nowSeconds - st.timestamp < config.refreshSeconds) return;
    st.lastAttemptAt = iso();
    const r = await exchange({w, size: target.size, note: target.note, old: st.old ?? 0, logV, config, fetchImpl, now,
      proofFor: m => witnessProof(db, hOrigin, logV, m, target.size, target.root)});
    const previous = st.status;
    Object.assign(st, {status: r.status, message: r.message || null, size: r.size ?? null});
    if (r.status === 'consistent') {
      Object.assign(st, {old: target.size, timestamp: r.timestamp, lastSuccessAt: iso()});
      if (!stopped) recordCosignature(target.size, w, r);
    } else if (['rollback', 'fork', 'inconsistent'].includes(r.status)) {
      st.old = r.size ?? null;
      if (previous !== r.status || config.mode === 'enforce') violation(r.status, `Witness ${w.name}: ${r.message}`);
    } else st.old = null;
  }
  async function round() {
    if (store.quarantine || stopped) return;
    try {
      const next = appendHeads();
      if (next) heads = next;
    } catch (error) {
      if (!error.kind) throw error;
      violation(error.kind, error.message);
      return;
    }
    if (!heads.size) return;
    const target = heads;
    if (!config.witnesses.length) return maybeWritePin(target, target.note);
    await Promise.all(config.witnesses.map(w => submit(w, target)));
    if (stopped) return;
    const cosigned = cosignedCheckpoint(target.size);
    if (cosigned && cosigned.count >= config.quorum) maybeWritePin(target, cosigned.checkpoint);
  }
  // Single flight: overlapping timer ticks share the running round.
  function pump() {
    if (!busy) busy = round().catch(error => { if (!stopped) violation('error', error.message); }).finally(() => { busy = null; });
    return busy;
  }
  // Newest heads size with the configured quorum, else newest with any configured cosignature, else the newest row.
  function headsEvidence(tOrigin) {
    if (!heads.size) return null;
    let size = heads.size;
    if (config.witnesses.length) {
      const marks = config.witnesses.map(() => '?').join(','), ids = config.witnesses.map(w => w.keyId);
      const best = db.prepare(`SELECT size FROM tlog_cosignatures WHERE origin=? AND key_id IN (${marks}) GROUP BY size
        ORDER BY (COUNT(DISTINCT key_id)>=?) DESC,size DESC LIMIT 1`)
        .get(hOrigin, ...ids, Math.max(1, config.quorum));
      if (best) size = best.size;
    }
    const c = cosignedCheckpoint(size), v = verifyHeadsRow(c.row, hOrigin, logV), i = v.entries.findIndex(e => e.log === tOrigin);
    if (i < 0) return null;
    return {origin: hOrigin, checkpoint: c.checkpoint, leafIndex: size - 1, leafProof: v.peaksBefore.slice().reverse().map(T.b64), leaf: v.content,
      entry: v.entries[i], entryIndex: i, entryProof: T.inclusionProof(v.entries.map(T.headsEntryLeaf), i).map(T.b64)};
  }
  // Appends refuse to extend a tenant log below the size the in-memory heads log already committed to.
  store.tlogHeadsFloor = origin => heads.entries.get(origin)?.size ?? 0;
  // records: the export's records; their tlog_epoch chain is summarised additively (verifiers recompute it).
  store.tlogEvidence = (tenant, records = []) => {
    const row = store._tlogRow(tenant);
    if (!row) return null;
    const origin = T.tenantOrigin(config.base, tenant), heads = headsEvidence(origin), epochs = T.tlogEpochSummaries(records);
    return {format: T.TRANSPARENCY_FORMAT, origin, checkpoint: row.note, ...(heads ? {heads} : {}), ...(epochs.length ? {epochs} : {})};
  };
  // Case reports carry inclusion proofs for the action's records and the head, plus heads consistency to the report size.
  store.tlogReport = (tenant, checkpoint, events) => {
    const row = store._tlogRow(tenant);
    if (!row || row.size !== checkpoint.count || !row.size) return null;
    const leaves = [...ledgerLeaves(db, tenant)].slice(0, row.size), tree = T.merkleLevels(leaves);
    if (leaves.length !== row.size || !T.levelsRoot(tree).equals(Buffer.from(row.root))) throw Error('Truncated or inconsistent tlog state for tenant report');
    const wanted = new Map(events.map(e => [e.seq, e.hash]));
    wanted.set(checkpoint.count, checkpoint.head);
    const inclusion = [...wanted].sort((a, b) => a[0] - b[0]).map(([seq, hash]) => ({seq, hash, proof: T.levelsInclusionProof(tree, seq - 1).map(T.b64)}));
    const origin = T.tenantOrigin(config.base, tenant), h = headsEvidence(origin);
    const consistency = h && h.entry.size < row.size ? T.levelsConsistencyProof(tree, h.entry.size).map(T.b64) : [];
    const headsPart = h && h.entry.size <= row.size ? {...h, consistency} : null;
    return {format: T.TRANSPARENCY_FORMAT, origin, checkpoint: row.note, inclusion, ...(headsPart ? {heads: headsPart} : {})};
  };
  function status() {
    const nowSeconds = Math.floor(now() / 1000);
    return {mode: config.mode, origin: hOrigin, heads: {size: heads.size, root: T.b64(heads.root)}, quorum: config.quorum,
      pinSize: pinned?.size ?? 0, ...(pinFrozen ? {pinFrozen: true} : {}),
      witnesses: [...witnessState.values()].map(s => ({...s, ageSeconds: s.timestamp ? Math.max(0, nowSeconds - s.timestamp) : null})),
      quarantine: store.quarantine, violations: violations.slice(),
      startup: startup ? {checkedAt: startup.checkedAt, ok: startup.ok, headsSize: startup.headsSize} : null};
  }
  return {
    mode: config.mode, config, pump, status, violation,
    start() {
      if (timer || stopped) return;
      timer = setInterval(() => { pump(); }, config.intervalMs);
      timer.unref?.();
      pump();
    },
    async stop() { stopped = true; if (timer) clearInterval(timer); timer = null; await busy; },
    bundleOptions: () => ({transparency: {witnesses: config.witnesses.map(w => w.vkey), quorum: config.quorum, originBase: config.base,
      maxStalenessSeconds: config.maxStalenessSeconds, now: now()}}),
    integrity(result) {
      const t = result.transparency, scope = result.verificationScope;
      if (t?.present && t.unsignedTail) throw Error('Truncated or inconsistent tlog checkpoint: the signed tenant note lags the ledger');
      scope.checks = [...scope.checks, 'merkle_tree', 'heads_log', ...(config.witnesses.length ? ['witness_cosignatures', 'witness_freshness'] : [])];
      // A fresh cosignature only bounds rollback to its own time; a detected rollback or fork keeps this vault unanchored.
      const anchored = !!t?.rollbackChecked && !violations.some(v => QUARANTINE_KINDS.has(v.kind) || v.kind === 'pin');
      scope.notChecked = anchored ? [] : [...UNANCHORED];
      return {...result, rollbackChecked: anchored, transparency: {...t, rollbackChecked: anchored, mode: config.mode, runtime: status()}};
    },
    quarantined(scope) {
      if (!store.quarantine) return null;
      return {valid: false, error: 'Transparency quarantine: ' + store.quarantine.reason, failureRecorded: false, requiresExternalIncidentRecord: true,
        transparency: {mode: config.mode, runtime: status()}, verificationScope: scope};
    },
  };
}
