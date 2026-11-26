// EvidScope receipts in standard formats (docs/receipts.md): in-toto attestations in DSSE envelopes for exports and case
// reports, and per-record c2sp.org/tlog-proof receipts verified under a c2sp.org/tlog-policy. Pure functions shared by the
// vault and the separately published verifier (scripts/package-verifier.mjs).
import {canonical, digest, verifyBundle} from './crypto.mjs';
import {ed25519Verifier, matchingSubject, openEnvelope, parseStatement, sha256Hex} from './dsse.mjs';
import {verifyCaseReport} from './report-verifier.mjs';
import {formatTlogPolicy, parseTlogPolicy, verifyPolicyProof} from './tlog-policy.mjs';
import * as T from './tlog.mjs';

const DOC = 'https://github.com/ki0915/EvidScope/blob/main/docs/receipts.md';
export const EXPORT_PREDICATE = `${DOC}#export-v1`, CASE_REPORT_PREDICATE = `${DOC}#case-report-v1`;
export const ATTESTED_FILE_FORMAT = 'evidscope-attested-file-v1', RECORD_RECEIPT_FORMAT = 'evidscope-record-receipt-v1';
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const str = v => (typeof v === 'string' ? v : null);
const uniqueSorted = values => [...new Set(values.filter(v => typeof v === 'string'))].sort();
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/, ISO_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$/;
export const safeFileName = name => (typeof name === 'string' && SAFE_NAME.test(name) && !name.includes('..') ? name : null);
export const exportFileName = bundle => `evidscope-export-${bundle.checkpoint.count}.json`;
export const caseReportFileName = report => `evidscope-case-${String(report.snapshot.case.id).replace(/[^A-Za-z0-9._-]|\.(?=\.)/g, '_').slice(0, 80)}`
  + `-${report.snapshot.checkpoint.count}.json`;
export const recordFileBase = (tenant, seq) => `evidscope-record-${T.tenantLogId(tenant).slice(0, 12)}-${seq}`;

// ---------- predicates: everything but issuedAt (exports) and the proofs is recomputed from the subject by verifiers ----------
// Latest signed human assessment per system and requirement, with the legal review recorded for it. Facts, not a verdict.
export function requirementResults(records) {
  const latest = new Map(), reviews = new Map();
  for (const r of records) {
    const p = r.payload;
    if (!plain(p)) continue;
    if (r.type === 'assessment' && typeof p.systemId === 'string' && typeof p.requirementId === 'string') {
      latest.set(JSON.stringify([p.systemId, p.requirementId]), r);
    }
    if (r.type === 'governance_legal_review' && typeof p.assessmentId === 'string') reviews.set(p.assessmentId, r);
  }
  return [...latest.values()].sort((a, b) => a.seq - b.seq).map(r => {
    const a = r.payload, review = typeof a.id === 'string' ? reviews.get(a.id) : undefined;
    return {systemId: a.systemId, requirementId: a.requirementId, assessmentId: str(a.id), seq: r.seq, recordHash: r.hash, applicability: str(a.applicability),
      assessment: str(a.assessment), legalReview: str(a.legalReview), nextReviewAt: str(a.nextReviewAt),
      legalReviewRecord: review ? {seq: review.seq, recordHash: review.hash, decision: str(review.payload.decision)} : null};
  });
}
function exportPolicyVersion(records) {
  let catalog = null;
  const rules = new Map(), engines = [];
  for (const r of records) {
    const p = r.payload;
    if (!plain(p)) continue;
    if (r.type === 'catalog') catalog = r;
    else if (r.type === 'rule' && typeof p.id === 'string') rules.set(p.id, r);
    else if (r.type === 'evaluation') engines.push(p.replay?.engine);
  }
  const c = catalog?.payload;
  return {
    applicability: c ? {policyVersion: str(c.policyVersion), catalogHash: str(c.hash), requirementsHash: str(c.requirementsHash), seq: catalog.seq,
      recordHash: catalog.hash} : null,
    rules: [...rules.keys()].sort().map(id => rules.get(id)).map(r => ({id: r.payload.id, seq: r.seq, recordHash: r.hash,
      activeVersions: (Array.isArray(r.payload.versions) ? r.payload.versions : []).filter(v => plain(v) && v.status === 'active')
        .map(v => v.version ?? null)})),
    evaluationEngines: uniqueSorted(engines),
  };
}
function tlogReference(t) {
  if (!plain(t)) return null;
  return {origin: str(t.origin), checkpoint: str(t.checkpoint), cosignedCheckpoint: plain(t.tenantCosigned) ? str(t.tenantCosigned.checkpoint) : null};
}
export function exportFacts(bundle) {
  return {tenant: bundle.checkpoint.tenant, checkpoint: bundle.checkpoint, records: bundle.records.length,
    requirementResults: requirementResults(bundle.records), policyVersion: exportPolicyVersion(bundle.records), tlog: tlogReference(bundle.transparency)};
}
export function caseReportFacts(report) {
  const s = report.snapshot, latest = s.review?.latestDecision ?? null;
  const evaluations = Array.isArray(s.action?.evaluations) ? s.action.evaluations : [], events = Array.isArray(s.action?.events) ? s.action.events : [];
  const rules = new Map();
  for (const e of evaluations) {
    for (const r of Array.isArray(e?.replay?.inputs?.rules) ? e.replay.inputs.rules : []) {
      if (plain(r) && typeof r.id === 'string') rules.set(JSON.stringify([r.id, r.version ?? null]), {id: r.id, version: r.version ?? null});
    }
  }
  return {
    tenant: s.tenant, caseId: str(s.case?.id), actionId: str(s.action?.actionId), issuedAt: str(s.exportedAt),
    reportHash: digest({format: report.format, snapshot: s}), checkpoint: s.checkpoint,
    requirementResults: {
      review: {state: str(s.review?.state), contextHash: str(s.review?.contextHash), decisionId: str(latest?.id), conclusion: str(latest?.conclusion),
        nextReviewAt: str(latest?.nextReviewAt)},
      evaluations: evaluations.map(e => ({id: str(e?.id), version: e?.version ?? null, status: str(e?.status), authority: str(e?.authority),
        effect: str(e?.effect), findings: (Array.isArray(e?.findings) ? e.findings : []).map(f => ({code: str(f?.code), severity: str(f?.severity)}))})),
    },
    policyVersion: {evaluationEngines: uniqueSorted(evaluations.map(e => e?.replay?.engine)), rules: [...rules.keys()].sort().map(k => rules.get(k)),
      eventPolicyVersions: uniqueSorted(events.map(e => e?.policyVersion)), analysis: s.action?.analysis ?? null},
    tlog: tlogReference(report.transparency),
  };
}
const noteSize = note => T.parseCheckpoint(T.noteText(note)).size;
// Which records get an embedded tlog-proof, and against which checkpoint: the newest witnessed one when it covers the record.
export function proofPlan(kind, value) {
  const t = value.transparency;
  if (!plain(t) || typeof t.checkpoint !== 'string') return [];
  const witnessedNote = plain(t.tenantCosigned) && typeof t.tenantCosigned.checkpoint === 'string' ? t.tenantCosigned.checkpoint : null;
  const size = noteSize(t.checkpoint), cosigned = witnessedNote ? noteSize(witnessedNote) : 0;
  const hashes = new Map();
  if (kind === 'export') for (const s of [cosigned, size]) { if (s >= 1 && s <= value.records.length) hashes.set(s, value.records[s - 1].hash); }
  else {
    for (const e of value.snapshot.action.events) hashes.set(e.seq, e.hash);
    if (size >= 1) hashes.set(size, value.snapshot.checkpoint.head);
  }
  return [...hashes].sort((a, b) => a[0] - b[0]).map(([seq, hash]) => ({seq, hash, cosigned: seq <= cosigned}));
}
// leaves: the tenant's leaf hashes from sequence 1 up to at least the largest checkpoint size. Each proof is checked before use.
export function buildTlogProofs(plan, leaves, tlog) {
  const trees = new Map(), tree = (note) => {
    const c = T.parseCheckpoint(T.noteText(note));
    if (!trees.has(c.size)) {
      const t = T.merkleLevels(leaves.slice(0, c.size));
      if (t.size !== c.size || !T.levelsRoot(t).equals(c.root)) throw Error('Ledger leaves differ from the signed tenant checkpoint');
      trees.set(c.size, t);
    }
    return trees.get(c.size);
  };
  return plan.map(({seq, hash, cosigned}) => {
    const note = cosigned ? tlog.cosignedCheckpoint : tlog.checkpoint, t = tree(note), proof = T.levelsInclusionProof(t, seq - 1);
    if (!T.recordLeaf(hash).equals(leaves[seq - 1]) || !T.verifyInclusion(T.recordLeaf(hash), seq - 1, t.size, proof, T.levelsRoot(t))) {
      throw Error('Record ' + seq + ' is not included in the signed tenant checkpoint');
    }
    return {seq, hash, proof: T.formatTlogProof(seq - 1, proof, note)};
  });
}

// ---------- c2sp.org/tlog-policy of a tenant log ----------
// Witness names are local labels (witness-N); quorum 0 or no witnesses gives "quorum none".
export function tenantTlogPolicy({origin, publicKey, witnesses = [], quorum = 0, note}) {
  const list = witnesses.map((w, i) => ({name: `witness-${i + 1}`, vkey: typeof w === 'string' ? w : w.vkey}));
  if (!Number.isSafeInteger(quorum) || quorum < 0 || quorum > list.length) throw Error('Witness quorum must be between 0 and the number of witnesses');
  const q = quorum === 0 ? 'none' : list.length === 1 ? list[0].name : {name: 'witnesses', k: quorum, members: list.map(w => w.name)};
  return formatTlogPolicy({comments: [`c2sp.org/tlog-policy for the EvidScope tenant log ${origin}`, ...(note ? [note] : []),
    'Compare these keys with ones obtained out of band: a policy received from the vault is not a trust anchor.'],
  logs: [T.logVkey(origin, publicKey)], witnesses: list, quorum: q});
}
// The policy of a vault deployment for one tenant. Without witnessTenantLogs the witnesses cosign only the heads log, which a
// tlog-proof cannot carry, so the tenant policy has quorum none.
export function deploymentTlogPolicy(config, publicKey, tenant) {
  const witnessed = config.witnessTenantLogs && config.witnesses.length > 0;
  return tenantTlogPolicy({origin: T.tenantOrigin(config.base, tenant), publicKey, witnesses: witnessed ? config.witnesses.map(w => w.vkey) : [],
    quorum: witnessed ? config.quorum : 0, note: witnessed ? null : 'The witnesses do not cosign this tenant log directly (witnessTenantLogs is off).'});
}
// A policy without logs takes the vault key from context; with a pinned key, every policy log for the origin must be that key
// (any of them may sign, so a second log line for the origin would let its key stand in for the vault).
function policyFor(policy, origin, publicKey) {
  const parsed = typeof policy === 'string' || Buffer.isBuffer(policy) ? parseTlogPolicy(policy) : policy;
  if (!publicKey) {
    if (!parsed.logs.length) throw Error('The tlog-policy lists no log: pass the vault public key');
    return parsed;
  }
  const vkey = T.logVkey(origin, publicKey), pinned = T.ed25519RawPublic(publicKey);
  if (!parsed.logs.length) return {...parsed, logs: [T.parseVkey(vkey)]};
  if (parsed.logs.some(l => l.name === origin && !l.pub.equals(pinned))) throw Error('The tlog-policy log key for ' + origin + ' is not the pinned vault key');
  return parsed;
}
// The policy an auditor states with flags: the pinned vault key for the origin, and the witnesses and quorum given.
export const flagPolicy = (origin, publicKey, transparency = {}) => {
  const witnesses = transparency.witnesses || [];
  return parseTlogPolicy(tenantTlogPolicy({origin, publicKey, witnesses, quorum: transparency.quorum ?? (witnesses.length ? 1 : 0)}));
};

// ---------- per-record receipts ----------
// The record file is the ledger record body exactly as hashed (canonical JSON), so SHA-256 of the file is the record hash for
// any tool, and no second reading of the bytes (duplicate keys, whitespace) can differ from the one verified here.
export function recordFromBytes(bytes) {
  const buf = Buffer.from(bytes), text = buf.toString('utf8');
  if (buf.length > 16 * 1024 * 1024 || !Buffer.from(text, 'utf8').equals(buf)) throw Error('Record file is not UTF-8 or larger than 16 MiB');
  let record;
  try { record = JSON.parse(text); } catch { throw Error('Record file is not JSON'); }
  if (!plain(record) || canonical(record) !== text || Object.hasOwn(record, 'hash')) {
    throw Error('Record file must be the exact ledger record body (canonical JSON without a hash field) as delivered with the receipt');
  }
  if (typeof record.tenant !== 'string' || !Number.isSafeInteger(record.seq) || record.seq < 1) throw Error('Record has no tenant or sequence');
  return {record, hash: sha256Hex(buf)};
}
// policy: the auditor's c2sp.org/tlog-policy text; without one, it is built from the pinned key, witnesses and quorum.
export function verifyRecordReceipt({proof, record, policy, publicKey, witnesses = [], quorum, originBase, now = Date.now()}) {
  if (typeof proof !== 'string' || Buffer.byteLength(proof) > 1024 * 1024) throw Error('tlog-proof must be text of at most 1 MiB');
  const r = recordFromBytes(record), p = T.parseTlogProof(proof), origin = T.parseCheckpoint(T.noteText(p.signedCheckpoint)).origin;
  if (p.index !== r.record.seq - 1) throw Error('tlog-proof index does not match the record sequence');
  const base = T.originBaseOf(origin, r.record.tenant);
  if (originBase !== undefined && originBase !== null && base !== T.validateOriginBase(originBase)) {
    throw Error('tlog-proof origin differs from the pinned origin base');
  }
  if (policy === undefined || policy === null) {
    if (!publicKey) throw Error('Pass a tlog-policy or the vault public key');
    policy = flagPolicy(origin, publicKey, {witnesses, quorum});
  }
  const parsed = policyFor(policy, origin, publicKey), v = verifyPolicyProof(proof, T.recordLeaf(r.hash), parsed, {now});
  if (!v.quorumMet) throw Error(`Witness quorum ${v.quorum} of the tlog-policy is not met (${v.cosignatures.length} cosignatures)`);
  return {valid: true, tenant: r.record.tenant, seq: r.record.seq, type: r.record.type ?? null, recordHash: r.hash, origin,
    checkpointSize: v.size, log: v.log, quorum: v.quorum, quorumMet: v.quorumMet, witnessed: v.quorum !== 'none', cosignatures: v.cosignatures,
    ...(v.extra ? {extraIgnored: true} : {}),
    scope: 'The vault key signed a tenant log checkpoint that includes this record; the quorum states which witnesses saw that checkpoint.'
      + ' The record content is what the vault signed, not proof that its claims are true.'};
}

// ---------- in-toto attestations ----------
// options: {transparency (as in verifyBundle/verifyCaseReport), expectedCheckpoint, policy, requireWitnessed, now}.
export function verifyAttestation({envelope, subject, publicKey, options = {}}) {
  const opened = openEnvelope(envelope, [ed25519Verifier(publicKey)]), statement = parseStatement(opened.body);
  if (canonical(statement) !== opened.body.toString('utf8')) throw Error('Attestation statement is not canonical JSON');
  const kind = statement.predicateType === EXPORT_PREDICATE ? 'export' : statement.predicateType === CASE_REPORT_PREDICATE ? 'case-report' : null;
  if (!kind) throw Error('Unsupported predicate type ' + JSON.stringify(statement.predicateType));
  const bytes = Buffer.from(subject), sha256 = sha256Hex(bytes), match = matchingSubject(statement, sha256);
  if (statement.subject.length !== 1 || !match) throw Error('Subject file digest is not the subject of the attestation');
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) throw Error('Subject file is not UTF-8');
  let value;
  try { value = JSON.parse(text); } catch { throw Error('Subject file is not JSON'); }
  const transparency = options.transparency ?? (value?.transparency !== undefined ? {} : undefined);
  const result = kind === 'export'
    ? verifyBundle(value, publicKey, options.expectedCheckpoint, transparency ? {transparency} : {})
    : verifyCaseReport(value, publicKey, {expectedCheckpoint: options.expectedCheckpoint, ...(transparency ? {transparency} : {})});
  const facts = kind === 'export' ? exportFacts(value) : caseReportFacts(value), predicate = plain(statement.predicate) ? statement.predicate : {};
  // Exactly the fields of the predicate type: nothing unverified rides along for tools that display the predicate.
  const known = new Set([...Object.keys(facts), 'issuedAt', 'tlogProofs']), extra = Object.keys(predicate).find(k => !known.has(k));
  if (extra !== undefined) throw Error('Attestation predicate has an unknown field ' + JSON.stringify(extra));
  for (const [k, v] of Object.entries(facts)) {
    if (canonical(predicate[k] ?? null) !== canonical(v)) throw Error(`Attestation predicate ${k} differs from the subject`);
  }
  if (kind === 'export' && !(typeof predicate.issuedAt === 'string' && ISO_TIME.test(predicate.issuedAt) && Number.isFinite(Date.parse(predicate.issuedAt)))) {
    throw Error('Attestation predicate issuedAt is not an ISO 8601 UTC time');
  }
  const plan = proofPlan(kind, value), proofs = Array.isArray(predicate.tlogProofs) ? predicate.tlogProofs : [];
  if (proofs.length !== plan.length) throw Error('Attestation tlog-proofs differ from the records they must cover');
  const policy = plan.length ? (options.policy !== undefined ? policyFor(options.policy, facts.tlog.origin, publicKey)
    : flagPolicy(facts.tlog.origin, publicKey, transparency)) : null;
  const tlogProofs = plan.map((step, i) => {
    const item = proofs[i], note = step.cosigned ? facts.tlog.cosignedCheckpoint : facts.tlog.checkpoint;
    if (!plain(item) || item.seq !== step.seq || item.hash !== step.hash || typeof item.proof !== 'string') {
      throw Error('Attestation tlog-proof list is malformed');
    }
    const p = T.parseTlogProof(item.proof);
    if (p.index !== step.seq - 1 || p.signedCheckpoint !== note) throw Error('Attestation tlog-proof for sequence ' + step.seq + ' names another checkpoint');
    const v = verifyPolicyProof(item.proof, T.recordLeaf(step.hash), policy, {now: options.now ?? Date.now()});
    return {seq: step.seq, checkpointSize: v.size, witnessedCheckpoint: step.cosigned, quorumMet: v.quorumMet, cosignatures: v.cosignatures.length};
  });
  const witnessed = policy && policy.quorum !== 'none' && tlogProofs.some(p => p.quorumMet);
  if (options.requireWitnessed && !witnessed) throw Error('No embedded tlog-proof meets the witness quorum of the policy');
  return {valid: true, predicateType: statement.predicateType, subject: {name: match.name ?? null, sha256}, keyid: opened.keyids[0],
    issuedAt: str(predicate.issuedAt), policyQuorum: policy ? policy.quorum : null, witnessed: !!witnessed, tlogProofs,
    [kind === 'export' ? 'bundle' : 'report']: result};
}

// ---------- API responses ----------
// The vault answers ?attest=intoto with the exact subject text and its envelope; this writes them out as two files.
export function unpackResponse(value) {
  if (value?.format === ATTESTED_FILE_FORMAT) {
    const f = value.file, name = safeFileName(f?.name);
    if (!name || typeof f.content !== 'string' || !plain(value.envelope)) throw Error('Malformed attested file response');
    const bytes = Buffer.from(f.content, 'utf8');
    if (sha256Hex(bytes) !== f.sha256) throw Error('Attested file content differs from its digest');
    return [{name, bytes}, {name: name + '.intoto.json', bytes: Buffer.from(JSON.stringify(value.envelope, null, 2) + '\n')}];
  }
  if (value?.format === RECORD_RECEIPT_FORMAT) {
    const texts = ['record', 'proof', 'policy'].every(k => typeof value[k] === 'string');
    if (typeof value.tenant !== 'string' || !Number.isSafeInteger(value.seq) || value.seq < 1 || !texts) {
      throw Error('Malformed record receipt response');
    }
    const base = recordFileBase(value.tenant, value.seq);
    return [{name: base + '.json', bytes: Buffer.from(value.record, 'utf8')}, {name: base + '.tlog-proof', bytes: Buffer.from(value.proof, 'utf8')},
      {name: base + '.tlog-policy', bytes: Buffer.from(value.policy, 'utf8')}];
  }
  throw Error('Not an EvidScope attested file or record receipt response');
}
