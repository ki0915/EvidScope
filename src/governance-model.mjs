// The governance-assistant's local mapping model: which model runs (off, base model with retrieval and constrained output, or a
// promoted adapter), the signed promotion receipt that decides it, the status the console reads, and the runtime mapper.
// docs/governance-model.md. Fails closed: anything unverifiable leaves the model off.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {join, resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonical} from './crypto.mjs';
import {INTOTO_PAYLOAD_TYPE, ed25519Verifier, intotoStatement, openEnvelope, parseStatement, signEnvelope} from './dsse.mjs';
import {TASK, TASK_VERSION, buildMappingRequest, governanceCatalog, mappingError, parseModelContent, resolveMapping, RULE_KIND, normalizeMappingItem}
  from './governance-mapping.mjs';
import {BASELINES, PINNED_GGUF, SAFETY_CHECKS, assessGovernanceReport, beats, hashOf, measurementProblem, scoreSummary, verifyGovernanceReport}
  from './governance-mapping-eval.mjs';
import {governanceAdmission, buildDataset} from './governance-mapping-data.mjs';

export const PROMOTION_PREDICATE = 'https://evidscope.dev/attestations/governance-model-promotion/v1';
export const ROLE_DIR = 'roles/governance-assistant/v1';
export const PROMOTED_EVAL_STATUS = 'PROMOTED_HUMAN_APPROVED';
const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SHA = /^[a-f0-9]{64}$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const text = v => typeof v === 'string' && v.trim().length > 0 && v.length <= 200;
const relativeFile = v => typeof v === 'string' && /^[A-Za-z0-9._/-]{1,200}$/.test(v) && !v.split('/').some(p => p === '..' || p === '.' || !p);
export const adapterField = sha => `governance-mapping-lora@sha256:${sha}`;
export const modelVersionField = sha => `${PINNED_GGUF.repository}@${PINNED_GGUF.revision}+${adapterField(sha)}`;

// ---------- promotion: an in-toto statement over the adapter, signed by the approving reviewer's own key ----------
const APPROVAL_CHECKS = ['semanticGroundingReviewed', 'koreanQualityReviewed', 'privacyReviewed', 'injectionReviewed', 'mappingSampleReviewed'];
export async function promoteGovernanceCandidate({report, approval, signer, adapterFile, now = Date.now()}) {
  const gate = assessGovernanceReport(report, {now});
  if (!gate.eligible) throw Object.assign(Error('candidate_evaluation_failed'), {gate});
  const reportSha256 = hashOf(report), receipt = report.variants.candidate.receipt;
  if (!plain(approval) || approval.reportSha256 !== reportSha256 || approval.approved !== true || APPROVAL_CHECKS.some(k => approval[k] !== true)
    || !text(approval.reviewerId) || !Number.isFinite(Date.parse(approval.reviewedAt)) || Date.parse(approval.reviewedAt) > now) {
    throw Error('independent_human_approval_required');
  }
  if (approval.reviewerId.trim() === report.preparedBy || approval.reviewerId.trim() === receipt.operator) throw Error('approval_not_independent');
  if (!signer || typeof signer.sign !== 'function' || !SHA.test(signer.keyid || '')) throw Error('approver_signer_required');
  if (!relativeFile(adapterFile) || !adapterFile.endsWith('.gguf')) throw Error('adapter_file_invalid');
  const adapterSha256 = receipt.adapterSha256, metrics = scoreSummary(report.metrics);
  const predicate = {task: TASK, taskVersion: TASK_VERSION, roleId: 'governance-assistant', roleVersion: '1.0.0',
    baseModel: {repository: PINNED_GGUF.repository, revision: PINNED_GGUF.revision, ggufSha256: PINNED_GGUF.sha256},
    adapter: {sha256: adapterSha256, file: adapterFile, format: 'gguf-lora'}, catalogDigest: report.catalogDigest,
    evalReportSha256: reportSha256, datasetSha256: report.datasetSha256, gate: {eligible: true, gateItems: gate.gateItems, thresholds: gate.thresholds},
    scores: metrics, preparedBy: report.preparedBy,
    approval: {reviewerId: approval.reviewerId.trim(), reviewedAt: approval.reviewedAt, checks: Object.fromEntries(APPROVAL_CHECKS.map(k => [k, true]))},
    roleFields: {adapter: adapterField(adapterSha256), modelVersion: modelVersionField(adapterSha256), evalStatus: PROMOTED_EVAL_STATUS},
    promotedAt: new Date(now).toISOString(), automatic: false};
  const statement = intotoStatement([{name: adapterFile, sha256: adapterSha256}], PROMOTION_PREDICATE, predicate);
  return signEnvelope(INTOTO_PAYLOAD_TYPE, Buffer.from(JSON.stringify(statement)), signer);
}
export function readTrust(root = REPOSITORY_ROOT) {
  const doc = JSON.parse(readFileSync(join(root, ROLE_DIR, 'promotion-trust.json'), 'utf8'));
  if (doc?.schemaVersion !== 1 || !Array.isArray(doc.keys)) throw mappingError('promotion_trust_invalid');
  return doc.keys.map(k => {
    if (!plain(k) || !text(k.reviewerId) || typeof k.publicKeyPem !== 'string') throw mappingError('promotion_trust_invalid');
    const verifier = ed25519Verifier(k.publicKeyPem);
    if (k.keyid !== undefined && k.keyid !== verifier.keyid) throw mappingError('promotion_trust_keyid_mismatch');
    return {reviewerId: k.reviewerId, ...verifier};
  });
}
// Verifies the receipt, the report it names and the role package fields it sets. Returns the verified predicate.
export function verifyPromotion({envelope, report, role, trust, now = Date.now()}) {
  if (!trust.length) throw mappingError('promotion_trust_empty');
  const opened = openEnvelope(envelope, trust), statement = parseStatement(opened.body), p = statement.predicate;
  if (statement.predicateType !== PROMOTION_PREDICATE || !plain(p) || p.task !== TASK || p.taskVersion !== TASK_VERSION || p.automatic !== false) {
    throw mappingError('promotion_receipt_invalid');
  }
  const signer = trust.find(t => opened.keyids.includes(t.keyid));
  if (!signer || signer.reviewerId !== p.approval?.reviewerId) throw mappingError('promotion_signer_not_approver');
  if (canonical(p.baseModel) !== canonical({repository: PINNED_GGUF.repository, revision: PINNED_GGUF.revision, ggufSha256: PINNED_GGUF.sha256})) {
    throw mappingError('promotion_base_model_changed');
  }
  if (!SHA.test(p.adapter?.sha256 || '') || statement.subject.length !== 1 || statement.subject[0].digest.sha256 !== p.adapter.sha256) {
    throw mappingError('promotion_adapter_invalid');
  }
  if (hashOf(report) !== p.evalReportSha256
    || report.variants?.candidate?.receipt?.adapterSha256 !== p.adapter.sha256) throw mappingError('promotion_report_mismatch');
  if (p.approval.reviewerId === report.preparedBy) throw mappingError('approval_not_independent');
  const gate = assessGovernanceReport(report, {now});
  if (!gate.eligible) throw mappingError('promotion_report_no_longer_passes');
  const expected = {adapter: adapterField(p.adapter.sha256), modelVersion: modelVersionField(p.adapter.sha256), evalStatus: PROMOTED_EVAL_STATUS};
  if (canonical(p.roleFields) !== canonical(expected) || ['adapter', 'modelVersion', 'evalStatus'].some(k => role[k] !== expected[k])) {
    throw mappingError('role_package_not_from_receipt');
  }
  return {...p, keyid: signer.keyid};
}

// Base mode: the base model with retrieval and the constrained schema runs only when a measured report shows it beats rules-only
// on precision at no lower coverage and loses no safety check to it.
export function assessBaselineMode(report, {now = Date.now()} = {}) {
  let m;
  try { m = verifyGovernanceReport(report, {now, requireCandidate: false}); } catch (error) { return {allowed: false, reasons: [error.code || error.message]}; }
  const rc = m.metrics.retrieval_constrained, rules = m.metrics.rules_only, reasons = [], problem = measurementProblem(report, 'retrieval_constrained');
  if (problem) reasons.push(`retrieval_constrained: ${problem}`);
  if (!beats(rc, rules)) reasons.push('baseline_not_better_than_rules_on_precision');
  for (const k of SAFETY_CHECKS) if (rc.safety[k].rate < rules.safety[k].rate) reasons.push(`baseline_loses_${k}`);
  return {allowed: reasons.length === 0, reasons, metrics: m.metrics};
}

// ---------- status (read by GET /api/model-runtime as governanceModel; shape in docs/governance-model.md) ----------
const readJson = (root, path) => {
  const bytes = readFileSync(join(root, path)); return {bytes, value: JSON.parse(bytes.toString('utf8')), sha256: sha256(bytes)};
};
function datasetSummary() {
  const rows = buildDataset(), admission = governanceAdmission(rows), count = f => rows.filter(f).length;
  return {derived: count(r => r.labelSource === 'derived_mapping_table'), drafted: count(r => r.labelSource === 'claude_drafted'),
    humanReviewed: count(r => r.humanReviewed === true), needsHumanReview: count(r => r.labelSource === 'claude_drafted' && r.humanReviewed !== true),
    trainingAdmitted: admission.admitted, eligible: Object.fromEntries(Object.entries(admission.counts).map(([s, c]) => [s, c.eligible])),
    minimum: admission.minimum};
}
let statusCache;
export function governanceModelStatus({root = REPOSITORY_ROOT, now = Date.now()} = {}) {
  let catalog;
  try { catalog = governanceCatalog(); } catch {
    return {schemaVersion: 1, task: TASK, taskVersion: TASK_VERSION, roleId: 'governance-assistant', mode: 'off', reasons: ['governance_catalog_unverified'],
      model: {repository: PINNED_GGUF.repository, revision: PINNED_GGUF.revision, ggufSha256: PINNED_GGUF.sha256}, adapter: null, promoted: false,
      promotion: null, evaluation: null, scores: null, catalog: null, dataset: null, humanConfirmationRequired: true, qualityClaimAllowed: false,
      observedAt: new Date(now).toISOString()};
  }
  const frameworks = {};
  for (const e of catalog.entries) frameworks[e.framework] = (frameworks[e.framework] || 0) + 1;
  const status = {schemaVersion: 1, task: TASK, taskVersion: TASK_VERSION, roleId: 'governance-assistant', mode: 'off', reasons: [],
    model: {repository: PINNED_GGUF.repository, revision: PINNED_GGUF.revision, ggufSha256: PINNED_GGUF.sha256}, adapter: null, promoted: false,
    promotion: null, evaluation: null, scores: null, catalog: {digest: catalog.digest, requirements: catalog.ids.length, frameworks},
    dataset: null, humanConfirmationRequired: true, qualityClaimAllowed: false, observedAt: new Date(now).toISOString()};
  let role, config, key;
  try {
    role = readJson(root, `${ROLE_DIR}/role.json`).value;
    config = readJson(root, `${ROLE_DIR}/governance-mapping.json`);
    key = canonical({role, config: config.sha256, trust: readJson(root, `${ROLE_DIR}/promotion-trust.json`).sha256,
      files: [config.value.promotion, config.value.baselineReport].filter(Boolean).map(f => sha256(readFileSync(join(root, f.path ?? f.receiptPath))))});
  } catch { return {...status, reasons: ['governance_model_configuration_unreadable']}; }
  if (statusCache?.key === key && statusCache.root === root) return {...structuredClone(statusCache.status), observedAt: status.observedAt};
  try { status.dataset = datasetSummary(); } catch { status.reasons.push('governance_dataset_unavailable'); }
  const c = config.value;
  const evaluation = (report, sha) => ({reportSha256: hashOf(report), fileSha256: sha, split: report.split, items: report.rows.length,
    gateItems: report.gateItems, createdAt: report.createdAt, preparedBy: report.preparedBy});
  try {
    if (c?.schemaVersion !== 1 || c.task !== TASK || c.taskVersion !== TASK_VERSION) throw mappingError('governance_model_configuration_invalid');
    if (c.promotion) {
      for (const f of ['receiptPath', 'reportPath']) if (!relativeFile(c.promotion[f])) throw mappingError('governance_model_configuration_invalid');
      const envelope = readJson(root, c.promotion.receiptPath), report = readJson(root, c.promotion.reportPath);
      if (envelope.sha256 !== c.promotion.receiptSha256 || report.sha256 !== c.promotion.reportSha256) throw mappingError('promotion_file_changed');
      const p = verifyPromotion({envelope: envelope.value, report: report.value, role, trust: readTrust(root), now});
      Object.assign(status, {mode: 'promoted_adapter', promoted: true, adapter: {...p.adapter},
        promotion: {receiptSha256: envelope.sha256,
          reviewerId: p.approval.reviewerId, reviewedAt: p.approval.reviewedAt, promotedAt: p.promotedAt, keyid: p.keyid},
        evaluation: evaluation(report.value, report.sha256), scores: scoreSummary(report.value.metrics)});
    } else if (role.adapter !== 'none' || role.evalStatus === PROMOTED_EVAL_STATUS) {
      throw mappingError('role_adapter_without_promotion');
    } else if (c.baselineReport) {
      if (!relativeFile(c.baselineReport.path)) throw mappingError('governance_model_configuration_invalid');
      const report = readJson(root, c.baselineReport.path);
      if (report.sha256 !== c.baselineReport.sha256) throw mappingError('baseline_report_changed');
      const verdict = assessBaselineMode(report.value, {now});
      Object.assign(status, {evaluation: evaluation(report.value, report.sha256),
        scores: verdict.metrics ? scoreSummary(Object.fromEntries(BASELINES.map(b => [b, verdict.metrics[b]]))) : null});
      if (verdict.allowed) status.mode = 'base_retrieval_constrained'; else status.reasons.push(...verdict.reasons);
    } else status.reasons.push('no_measured_report');
  } catch (error) {
    Object.assign(status, {mode: 'off', promoted: false, adapter: null, promotion: null});
    status.reasons.push(error.code || 'governance_model_status_error');
  }
  statusCache = {key, root, status: structuredClone(status)};
  return status;
}

// ---------- runtime: rules first, the model only for free text, every answer advisory ----------
// infer({messages, schema, adapter, signal}) -> {content, providerReport}; the isolated client (src/isolated-inference-client.mjs).
export function provenanceOf(status) {
  return {source: 'model', mode: status.mode, model: status.model.repository, modelSha256: status.model.ggufSha256,
    adapterSha256: status.adapter?.sha256 ?? null, evalReportSha256: status.evaluation?.reportSha256 ?? null,
    promotionReceiptSha256: status.promotion?.receiptSha256 ?? null, catalogDigest: status.catalog.digest, taskVersion: TASK_VERSION};
}
export function createGovernanceMapper({status, infer}) {
  if (!plain(status) || typeof infer !== 'function') throw Error('governance_mapper_dependencies_required');
  return async (input, {signal} = {}) => {
    const item = normalizeMappingItem(input);
    if (item.kind === RULE_KIND) return {...resolveMapping(item), state: 'rule_mapping', humanConfirmationRequired: false};
    if (!['base_retrieval_constrained', 'promoted_adapter'].includes(status.mode)) {
      return {scope: 'model', abstain: true, mappings: [], provenance: 'none', state: 'model_off', reasons: [...status.reasons]};
    }
    const request = buildMappingRequest(item, {variant: status.mode === 'promoted_adapter' ? 'candidate' : 'retrieval_constrained'});
    if (request.catalogDigest !== status.catalog.digest) throw mappingError('mapping_catalog_mismatch');
    const result = await infer({messages: request.messages, schema: request.responseFormat.schema, adapter: request.adapter, signal});
    const resolved = resolveMapping(item, parseModelContent(result.content)), provenance = provenanceOf(status);
    return {scope: 'model', abstain: resolved.abstain, mappings: resolved.mappings.map(m => ({...m, provenance})), provenance: 'model',
      state: 'advisory_unconfirmed', humanConfirmationRequired: true, providerReport: result.providerReport ?? null};
  };
}
