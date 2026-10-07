// Restore epochs (operator side). A restored ledger never continues the origin it was restored from: whatever the
// witnesses saw beyond the archive cannot be reproduced, so the restore moves every tenant to a new origin base and
// appends one signed tlog_epoch record per tenant (format in tlog.mjs). Where witnesses are reachable they establish
// whether the restore covers everything they cosigned for the previous origin (freshness); otherwise the loss must be
// accepted explicitly and is recorded in the epoch records. transparency.mjs (startup) and the offline verifier read them.
import {createHash, createPublicKey, sign, verify} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {canonical, digest} from './crypto.mjs';
import * as T from './tlog.mjs';
import {
  exchange, hasTable, headsConsistencyProof, headsOrigins, headsRow, headsSize, ledgerLeaves, normalizeTransparencyConfig, openPin, readEpochs,
  verifyHeadsRow,
} from './transparency.mjs';

const SIDECAR_FORMAT = 'evidscope-recovery-frontier-transparency-v1';
const SIDECAR_KEYS = ['format', 'frontierSha256', 'keyFingerprint', 'headsOrigin', 'headsSize', 'checkpoint', 'signature'];
const publicOf = key => (key?.type === 'public' ? key : createPublicKey(key));
const fingerprint = key => createHash('sha256').update(publicOf(key).export({format: 'der', type: 'spki'})).digest('hex');
const refuse = message => Error('Transparency restore refused: ' + message);
const logVerifier = (origin, publicKey) => T.noteVerifier(T.logVkey(origin, publicKey));

// ---------- frontier freshness evidence ----------
// Additive companion of a recovery frontier: the source vault's newest heads checkpoint in the same snapshot, bound to
// the frontier hash and signed by the vault key. A witness that has seen no larger heads size proves the frontier fresh.
export function frontierTransparency({db, key, frontier, headsOrigin = null}) {
  if (!hasTable(db, 'tlog_heads')) return null;
  const origins = headsOrigins(db);
  let origin = headsOrigin;
  if (!origin && origins.length === 1) origin = origins[0];
  else if (!origin && origins.length > 1) origin = db.prepare('SELECT origin FROM tlog_heads ORDER BY created_at DESC,idx DESC LIMIT 1').get().origin;
  const size = origin ? headsSize(db, origin) : 0;
  if (!size) return null;
  const row = verifyHeadsRow(headsRow(db, origin, size - 1), origin, logVerifier(origin, publicOf(key)));
  const statement = {format: SIDECAR_FORMAT, frontierSha256: digest(frontier), keyFingerprint: fingerprint(key), headsOrigin: origin, headsSize: size,
    checkpoint: row.note};
  return {...statement, signature: sign(null, Buffer.from(canonical(statement)), key).toString('base64')};
}
export function verifyFrontierTransparency(value, {frontierSha256, publicKey, headsOrigin}) {
  const keys = value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value) : [];
  if (keys.length !== SIDECAR_KEYS.length || !SIDECAR_KEYS.every(k => keys.includes(k))) throw refuse('invalid frontier transparency evidence');
  const {signature, ...statement} = value;
  if (statement.format !== SIDECAR_FORMAT || statement.frontierSha256 !== frontierSha256 || statement.keyFingerprint !== fingerprint(publicKey)
    || typeof signature !== 'string' || !verify(null, Buffer.from(canonical(statement)), publicKey, Buffer.from(signature, 'base64'))) {
    throw refuse('frontier transparency evidence is not bound to this frontier and vault key');
  }
  if (statement.headsOrigin !== headsOrigin) throw refuse(`frontier transparency evidence names ${statement.headsOrigin}, not ${headsOrigin}`);
  const c = T.parseCheckpoint(T.openNote(statement.checkpoint, [logVerifier(headsOrigin, publicKey)]).text);
  if (c.origin !== headsOrigin || c.size !== statement.headsSize) throw refuse('frontier transparency checkpoint differs from its statement');
  return {size: c.size, root: c.root, note: statement.checkpoint};
}

// ---------- archive state ----------
// Every origin base the archive already used, and the one it was running under (the last epoch's, else the only one).
function archiveState(db) {
  const bases = new Set(), add = (origin, tenant) => {
    try { bases.add(T.originBaseOf(origin, tenant)); } catch { /* not a tenant origin of this tenant */ }
  };
  for (const origin of headsOrigins(db)) if (origin.endsWith('/heads')) bases.add(origin.slice(0, -'/heads'.length));
  if (hasTable(db, 'tlog_state')) for (const r of db.prepare('SELECT DISTINCT tenant,origin FROM tlog_state').all()) add(r.origin, r.tenant);
  const epochs = hasTable(db, 'ledger') ? readEpochs(db) : new Map(), last = new Set();
  for (const list of epochs.values()) {
    for (const e of list) bases.add(e.payload.originBase).add(e.payload.previousOriginBase);
    last.add(list.at(-1).payload.originBase);
  }
  if (last.size > 1) throw refuse('the archive epoch chains end in different origin bases');
  if (last.size) return {bases, latest: [...last][0]};
  if (bases.size > 1) throw refuse(`the archive holds several origin bases without tlog epochs (${[...bases].sort().join(', ')})`);
  return {bases, latest: bases.size ? [...bases][0] : null};
}

// ---------- witness freshness for the previous origin ----------
// Submits the archive's newest heads checkpoint of the previous origin (old 0, then the 409 resynchronisation with a
// consistency proof from the archive). consistent: the witness had seen nothing beyond the archive; rollback: it holds a
// larger size, which a frontier companion of exactly that size can still cover (re-submitted to compare roots).
async function probePrevious({db, key, origin, archived, witnesses, timeoutMs, frontierHeads, fetchImpl, now}) {
  const publicKey = publicOf(key), logV = logVerifier(origin, publicKey), size = archived?.size ?? 0;
  const note = archived?.note ?? T.signNote(T.formatCheckpoint({origin, size: 0, root: T.EMPTY_ROOT}), T.noteSigner(origin, key));
  const proofFor = m => headsConsistencyProof(db, origin, logV, m, size, archived.root), config = {timeoutMs};
  return Promise.all(witnesses.map(async w => {
    let r = {...await exchange({w, size, note, old: 0, proofFor, logV, config, fetchImpl, now}), note};
    if (r.status === 'rollback' && frontierHeads && r.size === frontierHeads.size) {
      const again = await exchange({w, size: frontierHeads.size, note: frontierHeads.note, old: r.size, proofFor: () => [], logV, config, fetchImpl, now});
      if (again.status === 'consistent' || again.status === 'fork') r = {...again, size: frontierHeads.size, note: frontierHeads.note, viaFrontier: true};
    }
    return {name: w.name, keyId: w.keyId, ...r};
  }));
}
// Newest previous-origin heads checkpoint with at least one cosignature: witness answers, the old pin, or the archive.
function previousCosigned({db, origin, publicKey, witnesses, answers, pin}) {
  const candidates = [], verifiers = [logVerifier(origin, publicKey), ...witnesses.map(w => w.verifier)];
  const bySize = new Map();
  for (const a of answers) if (a.status === 'consistent' && a.size > 0) bySize.set(a.size, [...(bySize.get(a.size) || [a.note]), a.line]);
  for (const [size, [note, ...lines]] of bySize) candidates.push({size, note: note + lines.join(''), lines: lines.length});
  if (pin && pin.cosignatures > 0) candidates.push({size: pin.size, note: pin.note, lines: pin.cosignatures});
  if (hasTable(db, 'tlog_cosignatures')) {
    const ids = new Set(witnesses.map(w => w.keyId)), best = db.prepare('SELECT MAX(size) s FROM tlog_cosignatures WHERE origin=?').get(origin).s;
    const row = best ? headsRow(db, origin, best - 1) : null;
    const lines = row ? db.prepare('SELECT key_id,line FROM tlog_cosignatures WHERE origin=? AND size=? ORDER BY name,key_id').all(origin, best)
      .filter(r => ids.has(r.key_id)).map(r => r.line) : [];
    if (lines.length) candidates.push({size: best, note: row.note + lines.join(''), lines: lines.length});
  }
  candidates.sort((a, b) => b.size - a.size || b.lines - a.lines);
  for (const c of candidates) {
    try {
      const opened = T.openNote(c.note, verifiers);
      if (T.parseCheckpoint(opened.text).origin === origin && opened.sigs.length > 1) return c.note;
    } catch { /* skip evidence that does not verify against the configured witnesses */ }
  }
  return null;
}

// ---------- restore planning ----------
// Read-only on the restored (not yet published) database; throws before anything is written when the restore would
// reuse an origin base or cannot establish freshness without an explicit acceptLoss.
export async function planTlogEpoch({database, key, archiveAnchor, transparency, frontier = null, frontierSha256 = null, restoreDir, now = () => Date.now()}) {
  const db = new DatabaseSync(database, {readOnly: true, timeout: 5000});
  try {
    const archive = archiveState(db);
    if (!transparency) {
      if (!archive.bases.size) return {epoch: null, freshness: null, result: null};
      throw refuse(`the archive carries transparency state (origin base ${[...archive.bases].sort().join(', ')}); restore with a transparency config `
        + 'that names a new origin base (new epoch), or one with mode off');
    }
    const {config: raw, previous, previousPin, frontierTransparency: sidecar, acceptLoss, fetchImpl = fetch} = transparency;
    const config = normalizeTransparencyConfig(raw, {dataDir: restoreDir, env: {}});
    if (config.mode === 'off') return {epoch: null, freshness: null, result: {mode: 'off', retiredOriginBases: [...archive.bases].sort()}};
    const prev = previous ? normalizeTransparencyConfig(previous, {dataDir: restoreDir, env: {}}) : null;
    if (prev?.mode === 'off') throw refuse('the previous transparency config is in mode off');
    if (prev && archive.latest && archive.latest !== prev.base) throw refuse(`the archive runs origin base ${archive.latest}, not ${prev.base}`);
    const previousBase = prev?.base ?? archive.latest;
    if (!previousBase) {
      if (previousPin || sidecar || acceptLoss !== undefined) {
        throw refuse('no previous origin: the archive has no transparency state and no previous config was given');
      }
      return {epoch: null, freshness: null, result: {mode: config.mode, originBase: config.base, epoch: null}};
    }
    if (config.base === previousBase || archive.bases.has(config.base)) {
      throw refuse(`origin base ${config.base} was already used by this vault; a restore always forks the log, so configure a new origin base (new epoch)`);
    }
    if (acceptLoss !== undefined && (typeof acceptLoss !== 'string' || !acceptLoss.trim() || acceptLoss.length > 1000)) {
      throw refuse('acceptLoss must be a non-empty reason of at most 1000 characters');
    }
    if (sidecar && !frontier) throw refuse('frontier transparency evidence needs the activation frontier');
    const publicKey = publicOf(key), origin = T.headsOrigin(previousBase), source = prev ?? config;
    const restoredHeadsSize = hasTable(db, 'tlog_heads') ? headsSize(db, origin) : 0;
    const archived = restoredHeadsSize ? verifyHeadsRow(headsRow(db, origin, restoredHeadsSize - 1), origin, logVerifier(origin, publicKey)) : null;
    const frontierHeads = sidecar ? verifyFrontierTransparency(sidecar, {frontierSha256, publicKey, headsOrigin: origin}) : null;
    let pin = null;
    if (previousPin) {
      try { pin = openPin(previousPin, origin, publicKey, source.witnesses); } catch (error) { throw refuse('previous pin: ' + error.message); }
    }
    const answers = await probePrevious({db, key, origin, archived: archived && {size: restoredHeadsSize, root: archived.root, note: archived.note},
      witnesses: source.witnesses, timeoutMs: source.timeoutMs, frontierHeads, fetchImpl, now});
    const fork = answers.find(a => a.status === 'fork');
    if (fork) throw refuse(`witness ${fork.name} holds a heads log for ${origin} that conflicts with the archive (fork)`);
    const answered = answers.filter(a => a.status === 'consistent' || a.status === 'rollback');
    const quorum = source.witnesses.length ? Math.max(1, source.quorum) : 0;
    const witnessedHeadsSize = answered.length || pin ? Math.max(0, pin?.size ?? 0, ...answered.map(a => a.size)) : null;
    const known = Math.max(restoredHeadsSize, frontierHeads?.size ?? 0);
    const quorumMet = quorum ? answered.length >= quorum : !!pin, established = quorumMet && witnessedHeadsSize <= known;
    if (!established && acceptLoss === undefined) {
      const why = !quorumMet ? `${answered.length} of ${quorum || 'a pin or'} required witnesses answered`
        : `the previous origin was witnessed up to heads size ${witnessedHeadsSize}, beyond the archive (${restoredHeadsSize})`
          + ` and the frontier (${frontierHeads?.size ?? 'none'})`;
      throw refuse(`cannot establish freshness for ${origin}: ${why}; the restore would lose witnessed history (rollback) `
        + 'unless acceptLoss records the loss');
    }
    const freshness = {established, quorum, frontierHeadsSize: frontierHeads?.size ?? null, pinnedHeadsSize: pin?.size ?? null,
      witnesses: answers.map(a => ({name: a.name, keyId: a.keyId, status: a.status, size: a.size ?? null}))};
    const cosigned = previousCosigned({db, origin, publicKey, witnesses: source.witnesses, answers, pin});
    // Without established freshness nothing bounds what the previous origin held beyond the archive.
    const lostHeadsRange = T.lostHeadsRangeOf(restoredHeadsSize, witnessedHeadsSize), unknownLoss = !established;
    const payloads = Object.keys(archiveAnchor.checkpoints).sort().map(tenant => {
      const restoredSize = archiveAnchor.checkpoints[tenant].count, previousOrigin = T.tenantOrigin(previousBase, tenant);
      const row = hasTable(db, 'tlog_state')
        ? db.prepare('SELECT size,root,note FROM tlog_state WHERE tenant=? AND origin=?').get(tenant, previousOrigin) : null;
      const {roots, size} = T.rootsAtSizes(ledgerLeaves(db, tenant), [restoredSize, ...(row ? [row.size] : [])]);
      if (size !== restoredSize) throw refuse(`the archive ledger of tenant ${tenant} differs from its checkpoint`);
      if (row) {
        const c = T.parseCheckpoint(T.openNote(row.note, [logVerifier(previousOrigin, publicKey)]).text);
        if (c.origin !== previousOrigin || c.size !== row.size || !c.root.equals(Buffer.from(row.root)) || !roots.get(row.size)?.equals(c.root)) {
          throw refuse(`the archive tlog state of tenant ${tenant} conflicts with its ledger (fork)`);
        }
      }
      const current = frontier?.tenants.find(t => t.tenant === tenant)?.currentCheckpoint.count ?? restoredSize;
      const lostRange = unknownLoss ? [restoredSize + 1, null] : current > restoredSize ? [restoredSize + 1, current] : null;
      return [tenant, {format: T.TLOG_EPOCH_FORMAT, originBase: config.base, previousOriginBase: previousBase, origin: T.tenantOrigin(config.base, tenant),
        previousOrigin, restoredSize, restoredRoot: roots.get(restoredSize).toString('hex'), previousCheckpoint: row ? row.note : null, restoredHeadsSize,
        previousCosignedCheckpoint: cosigned, witnessedHeadsSize, lostRange, lostHeadsRange, freshness,
        acceptLoss: acceptLoss === undefined ? null : {reason: acceptLoss.trim()}, archiveManifestSha256: archiveAnchor.manifestSha256}];
    });
    for (const [tenant, payload] of payloads) T.tlogEpochPayload({tenant, seq: Number.MAX_SAFE_INTEGER, payload});
    return {
      epoch: {payloads}, freshness,
      result: {mode: config.mode, originBase: config.base, previousOriginBase: previousBase, headsOrigin: config.headsOrigin,
        logVkey: T.logVkey(config.headsOrigin, publicKey), previousHeadsOrigin: origin, restoredHeadsSize, witnessedHeadsSize, lostHeadsRange,
        freshnessEstablished: established, lossAccepted: acceptLoss !== undefined, witnesses: freshness.witnesses, epochRecords: payloads.length,
        registration: config.witnessTenantLogs
          ? 'Register the new heads origin and every tenant origin at every witness before starting the restored vault: '
            + 'node scripts/transparency.mjs witnessctl --config NEW_TRANSPARENCY.json --key VAULT_KEY.pem --data-dir RESTORED_DATA_DIR'
          : 'Register the new heads origin at every witness before starting the restored vault: '
            + 'node scripts/transparency.mjs witnessctl --config NEW_TRANSPARENCY.json --key VAULT_KEY.pem'},
    };
  } finally { db.close(); }
}
// One signed tlog_epoch record per tenant, in one transaction, before the restoration binding is sealed.
export function writeTlogEpochs(store, plan) {
  if (!plan?.epoch) return 0;
  store.transaction(() => { for (const [tenant, payload] of plan.epoch.payloads) store.append(tenant, T.TLOG_EPOCH_TYPE, payload, 'vault-recovery'); });
  return plan.epoch.payloads.length;
}
