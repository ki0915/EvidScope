// Period packages and bundled record receipts of auditor evidence packages (docs/evidence-pack.md). A period package carries
// only the contiguous ledger range of a period: every record as a standard receipt (the record body exactly as hashed and a
// c2sp.org/tlog-proof@v1 to the vault-signed tenant log, or to its witness-cosigned checkpoint when that covers the record),
// the export's v1 checkpoint, and the tenant log material in the case-report form (head inclusion, consistency from the
// witnessed checkpoints) that src/tlog.mjs verifyReportTransparency checks. Nothing outside the range is carried, so what a
// partial ledger cannot show is marked instead of claimed: absence inside the period, histories, and replays that need
// records before the range. Pure functions shared by the builder and the offline verifier.
import {canonical, digest, isEncryptedEvent, ENCRYPTED_EVENT_V2, PAYLOAD_COMMITMENT_V2, payloadCommitment, verifyCheckpoint} from './crypto.mjs';
import {inPeriod} from './evidence-inventory.mjs';
import {EVALUATION_ENGINE} from './model.mjs';
import {POLICY_REPLAY_FORMAT, replayEvaluations} from './policy-replay.mjs';
import {buildTlogProofs, flagPolicy, recordFromBytes, verifyAttestation} from './receipts.mjs';
import {verifyCaseReport} from './report-verifier.mjs';
import {verifyPolicyCheckpoint} from './tlog-policy.mjs';
import * as T from './tlog.mjs';
import {transparencyOptions} from './verify-options.mjs';

export const PERIOD_FORMAT = 'evidscope-evidence-pack-period-v1', RECEIPTS_FORMAT = 'evidscope-evidence-pack-receipts-v1';
export const NOT_REPLAYABLE = 'prior_records_not_in_package';
export const MAX_PERIOD_RECORDS = 200000;
const MiB = 1024 * 1024, ZERO = '0'.repeat(64);
const ISO_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/, HEX64 = /^[a-f0-9]{64}$/;
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
// New files carry exactly the fields their verification reads: nothing unverified rides along for readers of the package.
const only = (value, keys, what) => {
  const extra = Object.keys(value).find(k => !keys.includes(k));
  if (extra !== undefined) throw Error(`${what} has an unknown field ${JSON.stringify(extra.slice(0, 40))}`);
};
export const jsonBytes = value => Buffer.from(JSON.stringify(value, null, 1) + '\n', 'utf8');
export function parseJson(bytes, what) {
  const buf = Buffer.from(bytes), text = buf.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(buf)) throw Error(`${what} is not UTF-8`);
  try { return JSON.parse(text); } catch { throw Error(`${what} is not JSON`); }
}
export function checkPeriod(period) {
  if (period === null || period === undefined) return null;
  if (!plain(period) || !ISO_UTC.test(period.from ?? '') || !ISO_UTC.test(period.to ?? '') || !(Date.parse(period.from) < Date.parse(period.to))) {
    throw Error('Period must be {from, to}: ISO 8601 UTC times (…Z) with from before to');
  }
  return {from: period.from, to: period.to};
}
const bodyText = row => { const {hash, ...record} = row; return canonical(record); };

// ---------- record receipts ----------
// Which checkpoint a receipt proves a record against: the witness-cosigned tenant checkpoint when it covers the record (as
// /api/receipts/record and the export attestation choose), else the newest signed one.
function receiptNotes(material) {
  const latest = T.parseCheckpoint(T.noteText(material.checkpoint)), note = material.tenantCosigned?.checkpoint;
  const cosigned = typeof note === 'string' ? T.parseCheckpoint(T.noteText(note)) : null;
  return {origin: latest.origin, latest: {note: material.checkpoint, size: latest.size}, cosigned: cosigned ? {note, size: cosigned.size} : null};
}
const noteFor = (notes, seq) => (notes.cosigned && seq <= notes.cosigned.size ? notes.cosigned : notes.latest);
export const receiptCoverage = material => {
  const n = receiptNotes(material);
  return {origin: n.origin, checkpointSize: n.latest.size, cosignedCheckpointSize: n.cosigned?.size ?? null};
};
// records: verified ledger rows from sequence 1 (with hash); material: the export's transparency (checkpoint, tenantCosigned).
export function buildReceipts({tenant, records, material, seqs}) {
  const notes = receiptNotes(material), leaves = records.slice(0, notes.latest.size).map(r => T.recordLeaf(r.hash));
  const plan = seqs.map(seq => ({seq, hash: records[seq - 1].hash, cosigned: noteFor(notes, seq) === notes.cosigned}));
  const proofs = buildTlogProofs(plan, leaves, {checkpoint: notes.latest.note, cosignedCheckpoint: notes.cosigned?.note ?? null});
  return jsonBytes({format: RECEIPTS_FORMAT, tenant, origin: notes.origin, receipts: proofs.map(p => {
    const row = records[p.seq - 1];
    return {seq: p.seq, hash: row.hash, type: row.type ?? null, record: bodyText(row), proof: p.proof};
  })});
}
// Each entry is checked as evidscope-verify tlog-proof checks a receipt: the record file is the canonical body whose SHA-256 is the
// record hash, and the proof includes it in a checkpoint signed by the pinned vault key (witnesses and quorum from the flags).
export function verifyReceipts({bytes, tenant, material, seqs, publicKey, options = {}}) {
  if (bytes.length > 512 * MiB) throw Error('Receipts file exceeds 512 MiB');
  const file = parseJson(bytes, 'Receipts file'), notes = receiptNotes(material);
  if (!plain(file) || file.format !== RECEIPTS_FORMAT || file.tenant !== tenant || file.origin !== notes.origin || !Array.isArray(file.receipts)) {
    throw Error('Receipts file is not an evidence package receipts file of this tenant log');
  }
  only(file, ['format', 'tenant', 'origin', 'receipts'], 'Receipts file');
  if (file.receipts.length !== seqs.length || file.receipts.some((e, i) => !plain(e) || e.seq !== seqs[i])) {
    throw Error('Receipts file does not hold exactly the receipts of the records the package cites');
  }
  const policy = flagPolicy(notes.origin, publicKey, options), checked = new Map(), now = options.now ?? Date.now();
  const entries = file.receipts.map(e => {
    if (typeof e.record !== 'string' || typeof e.proof !== 'string' || Buffer.byteLength(e.proof) > MiB) throw Error(`Receipt ${e.seq} is malformed`);
    only(e, ['seq', 'hash', 'type', 'record', 'proof'], `Receipt ${e.seq}`);
    const r = recordFromBytes(Buffer.from(e.record, 'utf8')), p = T.parseTlogProof(e.proof);
    if (p.extra !== null) throw Error(`Receipt ${e.seq} carries extra data`);
    if (r.record.tenant !== tenant || r.record.seq !== e.seq || r.hash !== e.hash || e.type !== (r.record.type ?? null)) {
      throw Error(`Receipt ${e.seq} names another record, tenant or hash`);
    }
    if (p.index !== e.seq - 1 || p.signedCheckpoint !== noteFor(notes, e.seq).note) throw Error(`Receipt ${e.seq} proves against another checkpoint`);
    if (!checked.has(p.signedCheckpoint)) checked.set(p.signedCheckpoint, verifyPolicyCheckpoint(p.signedCheckpoint, policy, {now}));
    const c = checked.get(p.signedCheckpoint);
    if (!T.verifyInclusion(T.recordLeaf(r.hash), p.index, c.checkpoint.size, p.proof, c.checkpoint.root)) {
      throw Error(`Receipt ${e.seq}: tlog-proof inclusion proof failed`);
    }
    return {seq: e.seq, hash: r.hash, record: r.record, quorumMet: c.quorumMet};
  });
  return {entries, count: entries.length, witnessed: entries.filter(e => e.quorumMet).length, quorum: policy.quorum};
}

// ---------- period material, built from a verified whole export ----------
export function periodFiles({evidence, period}) {
  const {bundle, result} = evidence, records = bundle.records, count = records.length, t = bundle.transparency;
  if (!plain(t) || typeof t.checkpoint !== 'string') throw Error('A period package needs the tenant log checkpoint in the export (transparency on)');
  const size = T.parseCheckpoint(T.noteText(t.checkpoint)).size;
  if (size !== count || !count) throw Error(`The export's tenant log checkpoint (size ${size}) does not cover all ${count} records; export again`);
  const inside = records.filter(r => inPeriod(period, r.recordedAt));
  if (!inside.length) throw Error('No record of the export lies inside the period');
  const first = inside[0].seq, last = inside.at(-1).seq;
  if (last - first + 1 > MAX_PERIOD_RECORDS) throw Error(`A period package holds at most ${MAX_PERIOD_RECORDS} records; split the period`);
  const tree = T.merkleLevels(records.map(r => T.recordLeaf(r.hash))), proof = from => T.levelsConsistencyProof(tree, from).map(T.b64);
  const heads = t.heads && t.heads.entry.size <= count ? {heads: {...t.heads, consistency: t.heads.entry.size < count ? proof(t.heads.entry.size) : []}} : {};
  const cosignedSize = t.tenantCosigned ? T.parseCheckpoint(T.noteText(t.tenantCosigned.checkpoint)).size : 0;
  const material = {format: T.TRANSPARENCY_FORMAT, origin: t.origin, checkpoint: t.checkpoint,
    inclusion: [{seq: count, hash: bundle.checkpoint.head, proof: T.levelsInclusionProof(tree, count - 1).map(T.b64)}], ...heads,
    ...(t.tenantCosigned ? {tenantCosigned: {checkpoint: t.tenantCosigned.checkpoint, consistency: cosignedSize < count ? proof(cosignedSize) : []}} : {})};
  const manifest = {format: PERIOD_FORMAT, tenant: result.tenant, period, range: {first, last}, checkpoint: bundle.checkpoint, transparency: material,
    disclosures: (bundle.disclosures || []).filter(d => d.seq >= first && d.seq <= last)};
  const seqs = Array.from({length: last - first + 1}, (_, i) => first + i);
  return {manifest: jsonBytes(manifest), receipts: buildReceipts({tenant: result.tenant, records, material: t, seqs})};
}

// ---------- verifying a period package ----------
// The checks verifyBundle makes on disclosures, restricted to the range: a retention_disposition after the range is not
// there, so an encrypted event without a disclosure may have been erased later or withheld (counted as undisclosed).
function verifyDisclosures(rows, disclosures) {
  if (!Array.isArray(disclosures)) throw Error('Period disclosures must be a list');
  const byRow = new Map(rows.map(r => [r.seq, r])), given = new Map(), erased = new Map();
  for (const d of disclosures) {
    if (!plain(d) || !byRow.has(d.seq) || given.has(d.seq)) throw Error('Unexpected or duplicate event disclosure');
    given.set(d.seq, d);
  }
  for (const row of rows.filter(r => r.type === 'retention_disposition')) for (const id of row.payload?.keyIds || []) erased.set(id, row.seq);
  let disclosedEvents = 0, erasedEvents = 0, undisclosedEvents = 0;
  for (const row of rows.filter(r => r.type === 'event' && isEncryptedEvent(r.payload))) {
    if (row.payload.tenant !== row.tenant || row.payload.seq !== row.seq) throw Error('Encrypted event binding mismatch');
    const v2 = row.payload.format === ENCRYPTED_EVENT_V2, d = given.get(row.seq), event = d?.event;
    if (v2 && (row.payload.commitmentAlg !== PAYLOAD_COMMITMENT_V2 || !HEX64.test(row.payload.payloadCommitment))) {
      throw Error('Unsupported payload commitment');
    }
    if (erased.has(row.payload.keyId)) {
      if (erased.get(row.payload.keyId) <= row.seq || event) throw Error('Invalid erasure order or erased plaintext disclosed');
      erasedEvents++;
    } else if (!d) undisclosedEvents++;
    else {
      const salt = v2 && typeof d.salt === 'string' && HEX64.test(d.salt) ? Buffer.from(d.salt, 'hex') : null;
      if (!event || (v2 ? !salt || payloadCommitment(salt, event) !== row.payload.payloadCommitment : digest(event) !== row.payload.payloadHash)) {
        throw Error('Missing or altered retained event disclosure');
      }
      if (event.tenant !== row.tenant) throw Error('Disclosure tenant mismatch');
      disclosedEvents++;
    }
    given.delete(row.seq);
  }
  if (given.size) throw Error('Unexpected event disclosure');
  return {disclosedEvents, erasedEvents, undisclosedEvents};
}
// An evaluation is recomputed from every record before it. A range from sequence 1 holds that prefix; any other range does
// not, and its evaluations are not_replayable rather than reported as mismatches or matches.
export function periodReplay(bundle, first) {
  if (first === 1) return replayEvaluations(bundle);
  const evaluations = bundle.records.filter(r => r.type === 'evaluation').map(r => ({seq: r.seq, id: r.payload?.id ?? null,
    actionId: r.payload?.actionId ?? null, version: r.payload?.version ?? null, evaluationStatus: r.payload?.status ?? null,
    engine: r.payload?.replay?.engine ?? 'unrecorded', status: 'not_replayable', reason: NOT_REPLAYABLE}));
  const n = evaluations.length;
  return {format: POLICY_REPLAY_FORMAT, engine: EVALUATION_ENGINE, valid: true, evaluations, summary: {evaluations: n, replayed: 0, mismatch: 0,
    notReplayable: n, notReplayableReasons: n ? {[NOT_REPLAYABLE]: n} : {}, approvalRecordedAfterExecution: 0}};
}
// A case report is vault-signed on its own; inside a period package every event and decision it shows must be a record of the
// range (else it is refused: the package could not show it), and its head too when the range holds it.
function periodCase(c, {rows, bySeq, checkpoint, publicKey, tenant, options}) {
  const report = parseJson(c.bytes, 'Case report'), v = verifyCaseReport(report, publicKey, {expectedTenant: tenant, ...options});
  const cp = report.snapshot.checkpoint, head = bySeq.get(cp.count);
  if (cp.count > checkpoint.count || (head && head.hash !== cp.head)) throw Error(`Case report ${v.caseId} is not a snapshot of this ledger`);
  const events = Array.isArray(report.snapshot.action.events) ? report.snapshot.action.events : [];
  for (const e of events) {
    const row = bySeq.get(e.seq);
    if (!row || row.type !== 'event' || row.hash !== e.hash) throw Error(`Case report ${v.caseId} event ${e.seq} is not a record of this period package`);
  }
  const decisions = new Map(rows.filter(r => r.type === 'case_decision' && typeof r.payload?.id === 'string').map(r => [r.payload.id, r]));
  const shown = (Array.isArray(report.snapshot.review.decisions) ? report.snapshot.review.decisions : []).map(d => {
    const row = decisions.get(d?.id);
    if (!row || canonical(row.payload) !== canonical(d)) throw Error(`Case report ${v.caseId} decision ${d?.id} is not a record of this period package`);
    return {id: d.id, seq: row.seq, conclusion: d.conclusion};
  });
  const att = c.attestation ? verifyAttestation({envelope: c.attestation, subject: c.bytes, publicKey, options}) : null;
  return {bytes: Buffer.from(c.bytes), attestation: c.attestation, report, result: v, attestationResult: att, decisions: shown,
    eventSeqs: events.map(e => e.seq)};
}
// checkpoint: the auditor's evidscope-checkpoint-v1, compared exactly as verifyBundle does; flags as for whole exports.
export function verifyPeriodEvidence({manifestBytes, receiptsBytes, caseReports = [], publicKey, checkpoint, flags = {}}) {
  const m = parseJson(manifestBytes, 'Period manifest');
  if (!plain(m) || m.format !== PERIOD_FORMAT || typeof m.tenant !== 'string' || !plain(m.range) || !plain(m.checkpoint)) {
    throw Error('Period manifest is not an evidence package period manifest');
  }
  only(m, ['format', 'tenant', 'period', 'range', 'checkpoint', 'transparency', 'disclosures'], 'Period manifest');
  const period = checkPeriod(m.period), {first, last} = m.range, cp = m.checkpoint;
  verifyCheckpoint(cp, publicKey);
  if (cp.tenant !== m.tenant) throw Error('Period manifest tenant differs from its checkpoint');
  if (![first, last].every(Number.isSafeInteger) || first < 1 || last < first || last > cp.count || last - first + 1 > MAX_PERIOD_RECORDS) {
    throw Error('Period range is not a range of the checkpointed ledger');
  }
  if (checkpoint && canonical(cp) !== canonical(checkpoint)) throw Error('External checkpoint mismatch: possible rollback');
  const options = transparencyOptions(flags, true);
  if (options.minimumCheckpoint !== undefined) throw Error('--min-checkpoint needs the whole ledger; pass the checkpoint file to compare it exactly');
  if (!plain(m.transparency)) throw Error('Period manifest has no tenant log material');
  only(m.transparency, ['format', 'origin', 'checkpoint', 'inclusion', 'heads', 'tenantCosigned'], 'Period tenant log material');
  // The tenant checkpoint is the v1 checkpoint's ledger (same size, its head included), and the witnessed checkpoints it carries
  // are consistent with it; the same checks as for case reports.
  const tlog = T.verifyReportTransparency({report: {snapshot: {tenant: m.tenant, checkpoint: {count: cp.count, head: cp.head}, action: {events: []}},
    transparency: m.transparency}, publicKey, options});
  const seqs = Array.from({length: last - first + 1}, (_, i) => first + i);
  const receipts = verifyReceipts({bytes: receiptsBytes, tenant: m.tenant, material: m.transparency, seqs, publicKey, options});
  const rows = receipts.entries.map(e => ({...e.record, hash: e.hash}));
  rows.forEach((r, i) => {
    if (r.previous !== (i ? rows[i - 1].hash : first === 1 ? ZERO : r.previous)) throw Error(`Record ${r.seq} does not link to the record before it`);
  });
  if (last === cp.count && rows.at(-1).hash !== cp.head) throw Error('Last record is not the checkpoint head');
  if (!inPeriod(period, rows[0].recordedAt) || !inPeriod(period, rows.at(-1).recordedAt)) {
    throw Error('Period range must begin and end with records inside the period');
  }
  const counts = verifyDisclosures(rows, m.disclosures), bundle = {checkpoint: cp, records: rows, disclosures: m.disclosures};
  const replay = periodReplay(bundle, first);
  if (!replay.valid) throw Error(`Policy replay mismatch in ${replay.summary.mismatch} evaluation(s)`);
  const bySeq = new Map(rows.map(r => [r.seq, r]));
  const cases = caseReports.map(c => periodCase(c, {rows, bySeq, checkpoint: cp, publicKey, tenant: m.tenant, options: {transparency: options}}));
  if (new Set(cases.map(c => c.result.reportHash)).size !== cases.length) throw Error('The same case report is given twice');
  const result = {valid: true, count: cp.count, tenant: m.tenant, range: {first, last}, records: rows.length,
    rollbackChecked: !!checkpoint || !!tlog.rollbackChecked, ...counts, transparency: tlog,
    receipts: {count: receipts.count, witnessed: receipts.witnessed, quorum: receipts.quorum}};
  return {kind: 'period', bundle, manifest: m, manifestBytes: Buffer.from(manifestBytes), receiptsBytes: Buffer.from(receiptsBytes), result, replay,
    registry: null, approvals: null, stopOrders: null, attestation: null, exportAttestation: null, cases, receipts};
}
