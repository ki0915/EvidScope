// Training, evaluation and promotion factsheets of the governance-mapping model (docs/governance-model.md, "팩트시트"). The operator
// builds a request on the PC (`governance-mapping.mjs factsheet`) and records it in the console; the vault checks what it can, binds
// the recording principal and time, and appends one signed ledger object (governance_model_factsheet). The vault re-derives the
// evaluation numbers from the full report, verifies a promotion receipt against promotion-trust.json, and compares the reviewed rows
// of a training set with the signed review decisions; training resource numbers stay the operator's report and are labelled so.
// A shakedown run is recorded as such: never promotable and never a quality result. `promotable` says whether the run can lead to a
// promotion at all (through the gate and a signed approval); `promoted` is true only for a verified promotion receipt.
import {createHash} from 'node:crypto';
import {canonical, digest} from './crypto.mjs';
import {parseStatement, openEnvelope} from './dsse.mjs';
import {TASK, TASK_VERSION, governanceCatalog} from './governance-mapping.mjs';
import {applyQueueDecisions, shakedownRows, toJsonl, trainingRows} from './governance-mapping-data.mjs';
import {MODEL_VARIANTS, PINNED_GGUF, SAFETY_CHECKS, assessGovernanceReport, hashOf, measurementProblem, scoreSummary, verifyGovernanceReport}
  from './governance-mapping-eval.mjs';
import {PROMOTION_PREDICATE, assessBaselineMode, readTrust} from './governance-model.mjs';
import {BASE_REPOSITORY} from './governance-training.mjs';

export const FACTSHEET_TYPE = 'governance_model_factsheet';
export const FACTSHEET_KINDS = Object.freeze(['training', 'evaluation', 'promotion']);
export const RUN_MODES = Object.freeze(['candidate', 'shakedown']);
const RECIPE_KEYS = ['rank', 'alpha', 'dropout', 'targetModules', 'sequenceLength', 'batchSize', 'gradientAccumulationSteps', 'epochs',
  'learningRatePerMillion', 'warmupStepsPer1000', 'seed', 'saveSteps', 'gpuMemoryFractionPercent'];
const TRAINING_METRICS = ['train_runtime', 'train_samples_per_second', 'train_steps_per_second', 'train_loss', 'epoch', 'cudaPeakAllocatedMiB'];
const RESOURCE_METRICS = ['train_runtime', 'train_samples_per_second', 'train_steps_per_second', 'epoch', 'cudaPeakAllocatedMiB'];
const SHA = /^[a-f0-9]{64}$/, REVISION = /^[a-f0-9]{40}$/;
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const bad = (code, status = 400) => { throw Object.assign(Error(code), {code, status}); };
const text = (v, max = 200) => (typeof v === 'string' && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v) ? v : null);
const count = v => (Number.isSafeInteger(v) && v >= 0 ? v : null);
const finite = v => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const pinnedBase = () => ({repository: PINNED_GGUF.repository, revision: PINNED_GGUF.revision, ggufSha256: PINNED_GGUF.sha256});

// ---------- requests (built on the operator's PC) ----------
// receipt: training-receipt.json of scripts/train-governance-mapping-lora.py; trainingSet: the exact bytes the trainer read.
export function trainingFactsheetRequest({receipt, trainingSet, adapterGgufSha256 = null}) {
  const bytes = Buffer.isBuffer(trainingSet) ? trainingSet : Buffer.from(String(trainingSet), 'utf8');
  const rows = bytes.toString('utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)), tally = key => {
    const out = {};
    for (const r of rows) out[r[key]] = (out[r[key]] || 0) + 1;
    return out;
  };
  const modes = [...new Set(rows.map(r => r.runMode ?? 'candidate'))];
  if (modes.length !== 1) throw Error('training_set_run_mode_mixed');
  if (sha256(bytes) !== receipt?.identity?.datasetSha256) throw Error('training_set_not_the_receipt_dataset');
  return {kind: 'training', schemaVersion: 1, receipt,
    trainingSet: {sha256: sha256(bytes), rows: rows.length, runMode: modes[0], bySplit: tally('split'), byLabelSource: tally('labelSource'),
      reviewedPayloadHashes: rows.filter(r => r.labelSource === 'claude_drafted').map(r => r.reviewedPayloadHash).sort()},
    adapter: {ggufSha256: adapterGgufSha256}};
}
export const evaluationFactsheetRequest = report => ({kind: 'evaluation', schemaVersion: 1, report});
export const promotionFactsheetRequest = (envelope, report = null) => ({kind: 'promotion', schemaVersion: 1, envelope, report});

// ---------- vault side ----------
const shakedownAdapters = factsheets => new Set(factsheets.filter(f => f.kind === 'training' && f.runMode === 'shakedown')
  .map(f => f.adapter?.ggufSha256).filter(Boolean));
// How many of the given reviewed rows carry a signed queue decision (approve) for exactly that reviewed payload.
function reviewedAgainstDecisions(hashes, decisions) {
  const approved = new Set(decisions.filter(d => d.decision === 'approve').map(d => d.reviewedPayloadHash));
  const signed = hashes.filter(h => approved.has(h)).length;
  return {humanReviewedRows: hashes.length, withSignedQueueDecision: signed, withoutSignedQueueDecision: hashes.length - signed};
}
function trainingFactsheet(x, {decisions, factsheets, dataset, now}) {
  const r = x.receipt, id = plain(r) ? r.identity : null, set = x.trainingSet;
  if (!plain(id) || !plain(set) || !plain(x.adapter ?? {})) bad('factsheet_training_fields');
  const runMode = id.runMode ?? (r.status === 'trained_candidate' ? 'candidate' : null);
  if (!RUN_MODES.includes(runMode) || set.runMode !== runMode
    || r.status !== (runMode === 'shakedown' ? 'shakedown_not_promotable' : 'trained_candidate')) bad('factsheet_training_run_mode');
  if (id.task !== TASK || id.baseRepository !== BASE_REPOSITORY || !REVISION.test(id.baseRevision || '') || !SHA.test(id.baseArtifactLockSha256 || '')
    || !SHA.test(id.datasetSha256 || '') || id.datasetSha256 !== set.sha256 || r.heldOutTestUsedForTraining !== false) bad('factsheet_training_identity');
  const hashes = Array.isArray(set.reviewedPayloadHashes) ? set.reviewedPayloadHashes : bad('factsheet_training_set');
  const bySplit = {tune: count(set.bySplit?.tune) ?? 0, validation: count(set.bySplit?.validation) ?? 0};
  const byLabelSource = {derived_mapping_table: count(set.byLabelSource?.derived_mapping_table) ?? 0,
    claude_drafted: count(set.byLabelSource?.claude_drafted) ?? 0};
  if (count(set.rows) === null || set.rows !== bySplit.tune + bySplit.validation
    || set.rows !== byLabelSource.derived_mapping_table + byLabelSource.claude_drafted
    || Object.keys(set.bySplit || {}).some(k => !(k in bySplit)) || Object.keys(set.byLabelSource || {}).some(k => !(k in byLabelSource))
    || hashes.length !== byLabelSource.claude_drafted || hashes.some(h => !SHA.test(h))
    || new Set(hashes).size !== hashes.length) bad('factsheet_training_set');
  if (runMode === 'shakedown' && byLabelSource.claude_drafted) bad('factsheet_shakedown_uses_reviewed_rows');
  const gguf = x.adapter?.ggufSha256 ?? null;
  if (gguf !== null && !SHA.test(gguf)) bad('factsheet_adapter_hash');
  if (runMode === 'candidate' && gguf && shakedownAdapters(factsheets).has(gguf)) bad('factsheet_adapter_is_shakedown', 409);
  // The vault rebuilds the training file from the repository (shakedown) or from its signed decisions (candidate) and compares bytes.
  let reproduced = false;
  try {
    const rows = runMode === 'shakedown' ? shakedownRows(dataset(), {now}) : trainingRows(applyQueueDecisions(dataset(), decisions).rows, {now});
    reproduced = sha256(Buffer.from(toJsonl(rows), 'utf8')) === set.sha256;
  } catch {}
  const metricKeys = runMode === 'shakedown' ? RESOURCE_METRICS : TRAINING_METRICS;
  const metrics = Object.fromEntries(metricKeys.map(k => [k, finite(r.trainingMetrics?.[k])]));
  metrics.globalStep = count(r.globalStep);
  for (const k of ['loadSeconds', 'trainSeconds', 'totalSeconds']) metrics[k] = finite(r.timing?.[k]);
  return {runMode, label: runMode, promotable: runMode === 'candidate', promoted: false, qualityResult: false,
    subjectSha256: digest(r), baseModel: {...pinnedBase(), training: {repository: id.baseRepository, revision: id.baseRevision,
      artifactLockSha256: id.baseArtifactLockSha256}},
    adapter: {ggufSha256: gguf, status: r.status},
    dataset: {sha256: set.sha256, rows: set.rows, bySplit, byLabelSource, ...reviewedAgainstDecisions(hashes, decisions),
      verification: reproduced ? (runMode === 'shakedown' ? 'reproduced_from_repository' : 'reproduced_from_signed_decisions') : 'operator_reported'},
    recipe: {...Object.fromEntries(RECIPE_KEYS.map(k => [k, Array.isArray(id[k]) ? id[k].map(v => text(v, 40)) : finite(id[k])])),
      image: text(id.image, 200), trainerSha256: SHA.test(id.trainerSha256 || '') ? id.trainerSha256 : null},
    metrics, metricsBasis: runMode === 'shakedown' ? 'resource_measurement_only' : 'training_diagnostics_not_quality',
    gate: null, approver: null};
}
function evaluationFactsheet(x, {decisions, factsheets, now}) {
  let m;
  try { m = verifyGovernanceReport(x.report, {now, requireCandidate: false}); }
  catch (error) { bad('factsheet_report_unverified: ' + (error.code || error.message)); }
  const report = x.report, adapter = report.variants.candidate?.receipt?.adapterSha256 ?? null,
    shakedown = !!adapter && shakedownAdapters(factsheets).has(adapter);
  const hashes = m.gateRows.filter(r => r.labelSource === 'claude_drafted').map(r => r.reviewedPayloadHash).sort();
  let gate;
  if (report.variants.candidate) {
    const a = assessGovernanceReport(report, {now});
    gate = {kind: 'promotion_gate', eligible: a.eligible && !shakedown,
      reasons: [...a.reasons, ...(shakedown ? ['candidate adapter is a shakedown adapter'] : [])],
      comparison: a.thresholds.comparison};
  } else {
    const b = assessBaselineMode(report, {now});
    gate = {kind: 'base_mode', eligible: b.allowed, reasons: b.reasons};
  }
  const scores = scoreSummary(m.metrics);
  for (const v of Object.keys(scores)) scores[v].safety = Object.fromEntries(SAFETY_CHECKS.map(k => [k, m.metrics[v].safety[k].rate]));
  if (shakedown) delete scores.candidate;
  const measurement = Object.fromEntries(MODEL_VARIANTS.filter(v => report.variants[v]).map(v => [v, {problem: measurementProblem(report, v),
    operator: text(report.variants[v].receipt?.operator, 120)}]));
  return {runMode: shakedown ? 'shakedown' : report.variants.candidate ? 'candidate' : null, label: shakedown ? 'shakedown' : report.variants.candidate
    ? 'candidate_evaluation' : 'baseline_evaluation', promotable: !!report.variants.candidate && !shakedown, promoted: false, qualityResult: !shakedown,
    subjectSha256: hashOf(report),
    baseModel: pinnedBase(), adapter: {ggufSha256: adapter},
    dataset: {sha256: report.datasetSha256, split: 'test', rows: report.rows.length, gateRows: m.gateRows.length,
      gateRowsDerived: m.gateRows.filter(r => r.labelSource === 'derived_mapping_table').length, ...reviewedAgainstDecisions(hashes, decisions),
      verification: 'recomputed_from_report'},
    recipe: null, metrics: scores, metricsBasis: shakedown ? 'withheld_shakedown_adapter' : 'gate_rows_recomputed_by_vault', measurement,
    preparedBy: text(report.preparedBy, 120), reportCreatedAt: text(report.createdAt, 40), gate, approver: null};
}
function promotionFactsheet(x, {factsheets, now, root}) {
  const trust = readTrust(root);
  if (!trust.length) bad('promotion_trust_empty', 409);
  let opened, statement;
  try { opened = openEnvelope(x.envelope, trust); statement = parseStatement(opened.body); } catch { bad('factsheet_promotion_signature', 409); }
  const p = statement.predicate, signer = trust.find(t => opened.keyids.includes(t.keyid));
  if (statement.predicateType !== PROMOTION_PREDICATE || !plain(p) || p.task !== TASK || p.taskVersion !== TASK_VERSION || p.automatic !== false
    || !signer || signer.reviewerId !== p.approval?.reviewerId) bad('factsheet_promotion_receipt_invalid', 409);
  if (canonical(p.baseModel) !== canonical(pinnedBase()) || !SHA.test(p.adapter?.sha256 || '')) bad('factsheet_promotion_receipt_invalid', 409);
  if (shakedownAdapters(factsheets).has(p.adapter.sha256)) bad('factsheet_adapter_is_shakedown', 409);
  let gate = {kind: 'promotion_gate', eligible: true, reasons: [], verified: 'receipt_only'};
  if (x.report !== null && x.report !== undefined) {
    if (hashOf(x.report) !== p.evalReportSha256) bad('factsheet_promotion_report_mismatch');
    let a;
    try { a = assessGovernanceReport(x.report, {now}); } catch { bad('factsheet_report_unverified'); }
    if (!a.eligible) bad('factsheet_promotion_report_fails_gate', 409);
    gate = {kind: 'promotion_gate', eligible: true, reasons: [], verified: 'report_reassessed', comparison: a.thresholds.comparison};
  }
  return {runMode: 'candidate', label: 'promotion', promotable: true, promoted: true, qualityResult: true, subjectSha256: digest(x.envelope),
    baseModel: pinnedBase(),
    adapter: {ggufSha256: p.adapter.sha256, file: text(p.adapter.file, 200)},
    dataset: {sha256: SHA.test(p.datasetSha256 || '') ? p.datasetSha256 : null, split: 'test', verification: 'from_signed_receipt'},
    recipe: null, metrics: plain(p.scores) ? p.scores : null, metricsBasis: 'from_signed_receipt', evalReportSha256: p.evalReportSha256, gate,
    preparedBy: text(p.preparedBy, 120),
    approver: {reviewerId: p.approval.reviewerId, reviewedAt: text(p.approval.reviewedAt, 40), keyid: signer.keyid, promotedAt: text(p.promotedAt, 40)}};
}

// request: what the operator posted; principal: the authenticated recorder; decisions and factsheets: verified ledger values.
export function buildFactsheet(request, {principal, decisions = [], factsheets = [], dataset, now = Date.now(), root} = {}) {
  if (!plain(request) || request.schemaVersion !== 1 || !FACTSHEET_KINDS.includes(request.kind)) bad('factsheet_request_invalid');
  const allowed = {training: ['receipt', 'trainingSet', 'adapter'], evaluation: ['report'], promotion: ['envelope', 'report']}[request.kind];
  if (Object.keys(request).some(k => !['kind', 'schemaVersion', ...allowed].includes(k))) bad('factsheet_request_fields');
  const built = request.kind === 'training' ? trainingFactsheet(request, {decisions, factsheets, dataset, now})
    : request.kind === 'evaluation' ? evaluationFactsheet(request, {decisions, factsheets, now}) : promotionFactsheet(request, {factsheets, now, root});
  const id = `${request.kind}-${built.subjectSha256.slice(0, 24)}`;
  if (factsheets.some(f => f.id === id)) bad('factsheet_already_recorded', 409);
  return {id, schemaVersion: 1, task: TASK, taskVersion: TASK_VERSION, kind: request.kind, ...built, catalogDigest: governanceCatalog().digest,
    operator: {id: principal.id, role: principal.role}, recordedAt: new Date(now).toISOString(), source: 'operator_submitted_vault_checked'};
}
// Lists newest first; the console and the model-status JSON read these.
export const listFactsheets = values => [...values].sort((a, b) => (a.recordedAt < b.recordedAt ? 1 : a.recordedAt > b.recordedAt ? -1 : 0)).slice(0, 50);
