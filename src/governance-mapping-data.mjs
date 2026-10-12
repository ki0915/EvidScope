// Dataset of the governance mapping task (docs/governance-model.md). Two label sources, never mixed up:
//  - derived_mapping_table: the label follows mechanically from a shipped mapping table (data/evidence-pack-mappings, the ISMS-P
//    alignment, the KR check definitions). Anyone can re-derive it; the promotion gate does. It is not generated and not reviewed.
//  - claude_drafted: text and label written by Claude (data/governance-mapping/v1/drafted-items.json). It counts for training or the
//    gate only after a named human approves it through the review sheet; it is never marked reviewed by code.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {canonical} from './crypto.mjs';
import {krGovernanceCheckDefinitions} from './kr-governance-evidence.mjs';
import {modelPolicy} from './model-policy.mjs';
import {MODEL_KINDS, TASK, TASK_VERSION, buildMappingRequest, governanceCatalog, outputMatchesTruth} from './governance-mapping.mjs';
import {injectionItems, localTablesFor, sourceItems} from './governance-mapping-sources.mjs';
import {exportHumanReviewPacket, importHumanReviews, recordHash, reviewedPayloadHash} from '../scripts/model-training-data.mjs';

export const ROLE_ID = 'governance-assistant';
export const SPLITS = ['tune', 'validation', 'test'];
export const DATASET_DIR = 'data/governance-mapping/v1';
const sha256 = value => createHash('sha256').update(value).digest('hex');
const read = path => JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), 'utf8'));
const norm = text => String(text).normalize('NFKC').replace(/\s+/g, ' ').trim().toLowerCase();
export const fingerprint = row => sha256(norm(row.prompt));
export const datasetHash = rows => sha256(canonical([...rows].sort((a, b) => (a.id < b.id ? -1 : 1))));
export const toJsonl = rows => rows.map(r => JSON.stringify(r)).join('\n') + '\n';
export const itemOf = row => ({kind: row.evidence[0].kind, locators: row.evidence.map(e => e.id), text: row.prompt, language: row.language});
const hashSplit = familyId => {
  const n = parseInt(sha256(`governance-mapping-v1:${familyId}`).slice(0, 8), 16) % 20;
  return n < 12 ? 'tune' : n < 15 ? 'validation' : 'test'; };

export function loadSplits(catalog = governanceCatalog()) {
  const doc = read(`${DATASET_DIR}/splits.json`), bySplit = new Map();
  if (doc.task !== TASK || doc.taskVersion !== TASK_VERSION) throw Error('governance_splits_invalid');
  for (const split of SPLITS) for (const id of doc.requirements[split]) {
    if (bySplit.has(id) || !catalog.byId.has(id)) throw Error('governance_splits_invalid: ' + id);
    bySplit.set(id, split);
  }
  const missing = catalog.ids.filter(id => !bySplit.has(id));
  if (missing.length) throw Error('governance_splits_missing: ' + missing.join(','));
  return bySplit;
}
// Any test label puts the item in test; tune rows then never carry a validation or test requirement as a label.
export function splitOf(truth, familyId, bySplit) {
  if (truth.abstain) return hashSplit(familyId);
  const splits = new Set(truth.mappings.map(m => bySplit.get(m.requirementId)));
  return splits.has('test') ? 'test' : splits.has('validation') ? 'validation' : 'tune';
}

function row({id, familyId, sourceId, kind, language, locators, text, truth, labelSource, derivation, injection, split}, bySplit) {
  const labels = truth.abstain ? ['abstain'] : truth.mappings.map(m => m.requirementId);
  const requiredRefs = [...new Set(truth.mappings.map(m => m.evidenceLocators[0]))];
  const derived = labelSource === 'derived_mapping_table';
  const out = {schemaVersion: 1, task: TASK, taskVersion: TASK_VERSION, id, roleId: ROLE_ID, split: split ?? splitOf(truth, familyId, bySplit),
    familyId, sourceId,
    language, labelSource, ...(derivation ? {derivation} : {}), synthetic: !derived, humanReviewed: false,
    reviewStatus: derived ? 'NOT_REQUIRED_DERIVED' : 'UNREVIEWED', reviewerId: null, reviewedAt: null, sourceConsent: true,
    prompt: text, evidence: locators.map(l => ({id: l, kind})),
    truth: {labels, requiredRefs, abstain: truth.abstain, mappings: truth.mappings, ...(injection ? {forbidden: injection.forbidden} : {})}};
  out.candidateOutput = {abstain: truth.abstain, mappings: truth.mappings.map(m => ({requirementId: m.requirementId, relation: m.relation,
    evidenceLocator: m.evidenceLocators[0], confidence: 'high'}))};
  return out;
}

// ---------- derivation from the shipped tables ----------
// localTables: directory of the local-only source tables (src/governance-mapping-sources.mjs), false for none; default per that module.
export function derivedItems(catalog = governanceCatalog(), {localTables} = {}) {
  const items = [], texts = new Set(), locator = text => `evidence:d-${sha256(text).slice(0, 12)}`;
  const make = (rule, framework, ref, kind, text, labels, relation = 'supports',
    {tableSha256 = null, split = null, injection = null} = {}) => {
    const truth = labels.length
      ? {abstain: false, mappings: [...labels].sort().map(requirementId => ({requirementId, relation, evidenceLocators: [locator(text)]}))}
      : {abstain: true, mappings: []};
    const familyId = labels.length ? `derived:${rule}:${sha256(text).slice(0, 10)}` : `derived:${rule}:${ref}`;
    return {id: `derived-${rule}-${sha256(text).slice(0, 10)}`, familyId, sourceId: `evidscope-${framework}-table`, kind,
      language: /[가-힣]/.test(text) ? 'ko' : 'en',
      locators: [locator(text)], text, truth, labelSource: 'derived_mapping_table',
      derivation: {rule, framework, tableSha256: tableSha256 ?? catalog.sources[framework]?.sha256 ?? catalog.sources.ismsAlignment.sha256, ref},
      ...(split ? {split} : {}), ...(injection ? {injection} : {})};
  };
  // One row per distinct text across every rule; the first rule that yields a text keeps it.
  const add = (...args) => { const key = norm(args[4]); if (texts.has(key)) return; texts.add(key); items.push(make(...args)); };
  // ISMS-P: evidence descriptions ("what") and support summaries ("shows") of the alignment, labelled with the items that list them.
  const alignment = read('data/isms-p-alignment.json'), what = new Map(), shows = new Map();
  for (const al of alignment.alignments) for (const s of al.supports) {
    shows.set(s.shows, new Set([...(shows.get(s.shows) || []), `ISMS-P-${al.item}`]));
    for (const e of s.evidence) if (e.what) what.set(e.what, new Set([...(what.get(e.what) || []), `ISMS-P-${al.item}`]));
  }
  for (const [text, ids] of what) add('isms-what', 'isms-p', [...ids].sort().join('+'), 'record_summary', text, [...ids]);
  for (const [text, ids] of shows) add('isms-shows', 'isms-p', [...ids].sort().join('+'), 'record_summary', text, [...ids]);
  // ISMS-P criteria the alignment declares not aligned: outside the catalog, so the answer is to abstain.
  const titles = new Map(alignment.officialItems.map(i => [i.number, i.title]));
  for (const n of alignment.notAligned) add('isms-not-aligned', 'isms-p', n.item, 'document_excerpt', `ISMS-P 인증기준 ${n.item} ${titles.get(n.item)}`, []);
  // KR checks: the title and measured fields of each check type, labelled with every KR item whose table lists that check type.
  const kr = catalog.entries.filter(e => e.framework === 'kr-ai-basic-act'), seen = new Set();
  for (const d of krGovernanceCheckDefinitions) {
    if (seen.has(d.checkType)) continue;
    seen.add(d.checkType);
    const ids = kr.filter(e => e.evidence.some(x => x.type === 'checkType' && x.name === d.checkType)).map(e => e.id);
    if (ids.length) add('kr-check', 'kr-ai-basic-act', d.checkType, 'record_summary',
      `${d.title} 점검 기록 (점검 유형 ${d.checkType}; 측정 항목: ${Object.keys(d.metrics).join(', ')})`, ids);
  }
  // EU references the EU table names as not mapped.
  const eu = JSON.parse(readFileSync(new URL('../data/evidence-pack-mappings/eu-ai-act-logging-v2.json', import.meta.url), 'utf8'));
  for (const n of eu.notMapped) add('eu-not-mapped', 'eu-ai-act-logging', n.ref, 'document_excerpt', `EU AI Act ${n.ref}`, []);
  // Source tables (src/governance-mapping-sources.mjs): checklist, evidence and defect sentences per ISMS-P item, law text per article.
  for (const s of sourceItems(catalog, {localTables})) add(s.rule, s.framework, s.ref, s.kind, s.text, s.labels, s.relation, {tableSha256: s.tableSha256});
  const base = stratify(items);
  // Injection rows follow the split of the row they extend, so a test text never appears in tune with an instruction appended.
  const injected = injectionItems(base, catalog).map(({base: b, text, forbidden}) => make('injection', b.derivation.framework, b.familyId, b.kind, text,
    b.truth.mappings.map(m => m.requirementId), b.truth.mappings[0]?.relation ?? 'supports',
    {tableSha256: b.derivation.tableSha256, split: b.split ?? hashSplit(b.familyId), injection: {forbidden}}));
  return [...base, ...injected];
}
// Derived rows are split by evidence text, stratified by their first requirement, so every requirement with enough rows is both
// learned (tune) and measured on texts the trainer never saw (test). Splitting by requirement instead (splits.json, still used for
// drafted rows) puts whole requirements out of training, which a model cannot learn. A requirement with n rows gives
// round(n/5) (at least 1 when n >= 2) to test and 1 to validation when n >= 5; a requirement with a single row stays in tune.
// Order within a requirement is by sha256 of the text, so the split is deterministic and independent of table order.
function stratify(items) {
  const groups = new Map();
  for (const i of items) {
    if (i.truth.abstain) continue;
    const key = i.truth.mappings[0].requirementId;
    groups.set(key, [...(groups.get(key) || []), i]);
  }
  const split = new Map();
  for (const group of groups.values()) {
    const ordered = group.map(i => [sha256(`governance-mapping-v1-text:${i.text}`), i]).sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(x => x[1]);
    const n = ordered.length, test = n >= 2 ? Math.max(1, Math.round(n / 5)) : 0, validation = n >= 5 ? 1 : 0;
    ordered.forEach((i, k) => split.set(i, k < test ? 'test' : k < test + validation ? 'validation' : 'tune'));
  }
  return items.map(i => split.has(i) ? {...i, split: split.get(i)} : i);
}
export function draftedItems() {
  const doc = read(`${DATASET_DIR}/drafted-items.json`);
  if (doc.task !== TASK || doc.taskVersion !== TASK_VERSION
    || doc.labelSource !== 'claude_drafted' || doc.reviewStatus !== 'UNREVIEWED') throw Error('drafted_items_invalid');
  return doc.items.map(i => ({...i, sourceId: 'claude-drafted-2026-10-08', labelSource: 'claude_drafted'}));
}

// The full unreviewed dataset: derived rows plus Claude-drafted rows (UNREVIEWED). Deterministic.
export function buildDataset({catalog = governanceCatalog(), localTables} = {}) {
  const bySplit = loadSplits(catalog), rows = [...derivedItems(catalog, {localTables}), ...draftedItems()].map(i => row(i, bySplit));
  const ids = new Set(), texts = new Map();
  for (const r of rows) {
    if (ids.has(r.id)) throw Error('governance_dataset_duplicate_id: ' + r.id);
    ids.add(r.id);
    if (!MODEL_KINDS.includes(r.evidence[0].kind)) throw Error('governance_dataset_kind: ' + r.id);
    for (const m of r.truth.mappings) if (!catalog.byId.has(m.requirementId)) throw Error('governance_dataset_unknown_requirement: ' + r.id);
    const f = fingerprint(r);
    if (texts.has(f)) throw Error(`governance_dataset_duplicate_text: ${r.id} ${texts.get(f)}`);
    texts.set(f, r.id);
    buildMappingRequest(itemOf(r), {variant: 'candidate', catalog});
  }
  return rows.sort((a, b) => (a.id < b.id ? -1 : 1));
}
// Re-derived rows per source-table configuration (localTables as derivedItems takes it; undefined = the module default).
const derivedByConfig = new Map();
function derivedMap(localTables) {
  const key = localTables === false ? 'none' : localTables ?? '';
  if (!derivedByConfig.has(key)) {
    const bySplit = loadSplits(), map = new Map();
    for (const i of derivedItems(undefined, {localTables})) map.set(i.id, row(i, bySplit));
    derivedByConfig.set(key, map);
  }
  return derivedByConfig.get(key);
}
export function rederived(id, {localTables} = {}) { return derivedMap(localTables).get(id) ?? null; }
// The example bank the prompt draws on (buildMappingRequest examples): the table-derived rows of the tune split only, so a validation
// or test row never sees itself or a sibling it is measured against. Derived from the shipped tables, not from dataset.jsonl.
const examplesByConfig = new Map();
export function governanceExamples({localTables} = {}) {
  const key = localTables === false ? 'none' : localTables ?? '';
  if (!examplesByConfig.has(key)) {
    examplesByConfig.set(key, Object.freeze([...derivedMap(localTables).values()].filter(r => r.split === 'tune' && !r.truth.forbidden)
      .map(r => Object.freeze({id: r.id, text: r.prompt, abstain: r.truth.abstain,
        requirementIds: Object.freeze(r.truth.mappings.map(m => m.requirementId))}))));
  }
  return examplesByConfig.get(key);
}
const FIXED = ['id', 'task', 'taskVersion', 'roleId', 'split', 'familyId', 'sourceId', 'language', 'labelSource', 'derivation', 'prompt', 'evidence', 'truth'];
const fixed = r => Object.fromEntries(FIXED.map(k => [k, r[k] ?? null]));

// Why a row may (or may not) count as a gold label for training or the gate.
export function rowEligibility(r, {now = Date.now(), localTables} = {}) {
  if (r?.task !== TASK || r.taskVersion !== TASK_VERSION || r.roleId !== ROLE_ID || !SPLITS.includes(r.split)) return {eligible: false, reason: 'row_invalid'};
  if (r.labelSource === 'derived_mapping_table') {
    const expected = rederived(r.id, {localTables});
    if (!expected || canonical(fixed(expected)) !== canonical(fixed(r)) || r.humanReviewed !== false) return {eligible: false, reason: 'derivation_mismatch'};
    return {eligible: true, basis: 'derived'};
  }
  if (r.labelSource !== 'claude_drafted') return {eligible: false, reason: 'label_source_unknown'};
  if (r.humanReviewed !== true) return {eligible: false, reason: 'not_human_reviewed'};
  const reviewedAt = Date.parse(r.reviewedAt);
  if (typeof r.reviewerId !== 'string' || !r.reviewerId.trim() || !Number.isFinite(reviewedAt) || reviewedAt > now || r.piiReviewed !== true
    || r.sourceConsent !== true || !/^[a-f0-9]{64}$/.test(r.reviewBinding || '')) return {eligible: false, reason: 'review_provenance_incomplete'};
  if (r.reviewedPayloadHash !== reviewedPayloadHash(r)) return {eligible: false, reason: 'reviewed_payload_changed'};
  if (!outputMatchesTruth(r.truth, r.approvedOutput, {locators: itemOf(r).locators})) return {eligible: false, reason: 'reviewed_output_invalid'};
  return {eligible: true, basis: 'human_reviewed'};
}

// Training admission for this task: the policy minimums (src/model-policy.mjs) apply to eligible rows; unreviewed drafted rows are
// left out and counted, never admitted. Leakage across splits is refused at three levels: family, text and requirement.
export function governanceAdmission(rows, {now = Date.now(), localTables = localTablesFor(rows)} = {}) {
  const minimum = modelPolicy.training.minimumReviewed, reasons = [], counts = {}, bySplit = loadSplits();
  for (const split of SPLITS) counts[split] = {eligible: 0, derived: 0, humanReviewed: 0, excludedUnreviewed: 0, excludedInvalid: 0};
  const families = new Map(), texts = new Map(), ids = new Set();
  for (const r of rows) {
    if (ids.has(r?.id)) reasons.push('duplicate_record_id');
    ids.add(r?.id);
    const verdict = rowEligibility(r, {now, localTables}), c = counts[r?.split];
    if (!c) { reasons.push('split_invalid'); continue; }
    if (verdict.eligible) { c.eligible++; c[verdict.basis === 'derived' ? 'derived' : 'humanReviewed']++; }
    else if (verdict.reason === 'not_human_reviewed') c.excludedUnreviewed++;
    else { c.excludedInvalid++; reasons.push(verdict.reason); }
    for (const [map, key] of [[families, r.familyId], [texts, fingerprint(r)]]) { if (!map.has(key)) map.set(key, new Set()); map.get(key).add(r.split); }
    // Requirement-level split applies to drafted rows; derived rows are split by text (see stratify) and checked by family and content.
    const labelSplits = new Set(r?.labelSource === 'derived_mapping_table' ? [] : (r.truth?.mappings || []).map(m => bySplit.get(m.requirementId)));
    if ((r.split !== 'test' && labelSplits.has('test')) || (r.split === 'tune' && labelSplits.has('validation'))) reasons.push('requirement_split_leakage');
  }
  if ([...families.values()].some(s => s.size > 1)) reasons.push('family_split_leakage');
  if ([...texts.values()].some(s => s.size > 1)) reasons.push('duplicate_content_split_leakage');
  for (const split of SPLITS) if (counts[split].eligible < minimum[split]) reasons.push(`eligible ${split} ${counts[split].eligible}/${minimum[split]}`);
  const unique = [...new Set(reasons)];
  return {task: TASK, roleId: ROLE_ID, admitted: !unique.length, trainingRunAllowed: !unique.length, counts, minimum: {...minimum}, reasons: unique,
    qualityClaimAllowed: false,
    labelBasis: 'derived rows agree with the shipped mapping tables (themselves draft_requires_human_review); drafted rows need a named reviewer'};
}

// Rows for the trainer: exactly the prompt the runtime sends (variant "candidate") and the gold JSON as the target. Test never leaves.
const trainerRow = (r, runMode, localTables) => {
  const request = buildMappingRequest(itemOf(r), {variant: 'candidate', examples: governanceExamples({localTables}), excludeId: r.id});
  const target = r.labelSource === 'derived_mapping_table' ? r.candidateOutput : r.approvedOutput;
  return {id: r.id, task: TASK, taskVersion: TASK_VERSION, roleId: ROLE_ID, split: r.split, familyId: r.familyId, messages: request.messages,
    target: JSON.stringify(target), labelSource: r.labelSource, reviewedPayloadHash: r.reviewedPayloadHash ?? null,
      catalogDigest: request.catalogDigest, runMode};
};
// abstainWeight N (training-set --abstain-weight): every tune-split abstain row is written N-1 more times (id `<id>#abstain-weight-k`,
// weightCopy k) so abstention carries more of the loss; validation rows and the dataset are unchanged. Pilot 8 (2026-10-12) answered
// 47 of 77 must-abstain test items although their items had abstain rows in training.
export function trainingRows(rows, {now = Date.now(), localTables = localTablesFor(rows), abstainWeight = 1} = {}) {
  if (!(Number.isInteger(abstainWeight) && abstainWeight >= 1 && abstainWeight <= 5)) throw Error('abstain_weight_invalid');
  const gate = governanceAdmission(rows, {now, localTables});
  if (!gate.admitted) throw Object.assign(Error('governance_training_admission_failed'), {admission: gate});
  const eligible = rows.filter(r => r.split !== 'test' && rowEligibility(r, {now, localTables}).eligible);
  const out = eligible.map(r => trainerRow(r, 'candidate', localTables));
  const abstain = out.filter((row, i) => eligible[i].split === 'tune' && eligible[i].truth.abstain);
  for (let k = 2; k <= abstainWeight; k++) out.push(...abstain.map(row => ({...row, id: `${row.id}#abstain-weight-${k}`, weightCopy: k})));
  return out;
}
// Shakedown: the derived tune/validation rows only, to measure VRAM and time on the PC before the human review is done. Every row is
// labelled runMode "shakedown"; the trainer then writes a shakedown adapter that is never promotable and never a quality result.
// No reviewed row is used, so the run says nothing about the drafted data either.
export function shakedownRows(rows, {now = Date.now(), localTables = localTablesFor(rows)} = {}) {
  const derived = rows.filter(r => r.split !== 'test' && r.labelSource === 'derived_mapping_table');
  if (!derived.length || derived.some(r => !rowEligibility(r, {now, localTables}).eligible)) throw Error('governance_shakedown_rows_invalid');
  const families = new Map();
  for (const r of derived) { if (!families.has(r.familyId)) families.set(r.familyId, new Set()); families.get(r.familyId).add(r.split); }
  if ([...families.values()].some(splits => splits.size > 1)) throw Error('governance_shakedown_family_split_leakage');
  return derived.map(r => trainerRow(r, 'shakedown', localTables));
}

// ---------- human review: a bulk approve/reject pass over the drafted rows ----------
const tsv = v => String(v ?? '').replace(/[\t\r\n]+/g, ' ');
export function reviewSheet(rows, {catalog = governanceCatalog()} = {}) {
  const lines = [['id', 'split', 'kind', 'locators', 'text', 'candidate_label', 'forbidden_by_injection', 'decision', 'note'].join('\t')];
  for (const r of rows.filter(x => x.labelSource === 'claude_drafted' && x.humanReviewed !== true)) {
    const label = r.truth.abstain ? 'ABSTAIN' : r.truth.mappings
      .map(m => `${m.requirementId} ${m.relation} @${m.evidenceLocators.join('|')} [${catalog.byId.get(m.requirementId).title.ko}]`).join(' ; ');
    lines.push([r.id, r.split, r.evidence[0].kind, r.evidence.map(e => e.id).join(' '), r.prompt, label,
       (r.truth.forbidden || []).join(' '), '', ''].map(tsv).join('\t'));
  }
  return lines.join('\n') + '\n';
}
// decisions: [{id, decision: 'approve'|'reject', note}] typed by the reviewer, one explicit decision per row (no wildcards).
// reviewer: the reviewer's own identity and attestations, given by that person on the command line.
export function applyReviewDecisions(rows, decisions, {reviewerId, reviewedAt, piiReviewed, sourceConsent}) {
  if (typeof reviewerId !== 'string' || !reviewerId.trim() || !Number.isFinite(Date.parse(reviewedAt)) || piiReviewed !== true || sourceConsent !== true) {
    throw Error('review_attestation_required');
  }
  const byId = new Map(rows.map(r => [r.id, r])), seen = new Set(), approve = [], rejected = [];
  for (const d of decisions) {
    const r = byId.get(d?.id);
    if (!r || seen.has(d.id) || !['approve', 'reject'].includes(d.decision)) throw Error('review_decision_invalid: ' + d?.id);
    if (r.labelSource !== 'claude_drafted' || r.humanReviewed === true) throw Error('review_decision_not_reviewable: ' + d.id);
    seen.add(d.id);
    if (d.decision === 'reject') rejected.push({id: d.id, note: String(d.note || '')});
    else approve.push({id: d.id, recordHash: recordHash(r), approved: true, reviewerId: reviewerId.trim(), reviewedAt, sourceConsent: true, piiReviewed: true,
      approvedOutput: r.candidateOutput});
  }
  const rejectedIds = new Set(rejected.map(x => x.id));
  const kept = rows.filter(r => !rejectedIds.has(r.id)), imported = importHumanReviews(kept, approve);
  return {rows: imported, approved: approve.length, rejected,
    unreviewed: imported.filter(r => r.labelSource === 'claude_drafted' && r.humanReviewed !== true).length};
}
export const reviewPacket = rows => exportHumanReviewPacket(rows.filter(r => r.labelSource === 'claude_drafted' && r.humanReviewed !== true));

// ---------- review queue (console, docs/governance-model.md "검토 대기열") ----------
// One signed ledger decision per drafted row (src/governance-review-queue.mjs). The queue never edits an answer: approve means the
// drafted answer as shown, so the decision binds the reviewedPayloadHash the row carries once approved, plus its recordHash.
export const QUEUE_DECISION_TYPE = 'governance_mapping_review';
export const queueBinding = r => reviewedPayloadHash({...r, approvedOutput: r.candidateOutput});
const SHA64 = /^[a-f0-9]{64}$/;
export function queueDecisionProblem(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d) || typeof d.id !== 'string' || !['approve', 'reject'].includes(d.decision)) return 'decision_invalid';
  if (!SHA64.test(d.reviewedPayloadHash || '') || !SHA64.test(d.recordHash || '')) return 'decision_binding_invalid';
  if (typeof d.reviewerId !== 'string' || !d.reviewerId.trim() || !Number.isFinite(Date.parse(d.reviewedAt))) return 'decision_reviewer_invalid';
  if (d.piiReviewed !== true || d.sourceConsent !== true) return 'decision_attestation_missing';
  return null;
}
// decisions: the signed decision values in ledger order (a later decision for the same row supersedes an earlier one). Each is
// applied only while the row still has the content it was decided on; the rest are reported, never applied. Approvals go through
// importHumanReviews exactly like the review sheet's (applyReviewDecisions), each with its own deciding reviewer and time.
export function applyQueueDecisions(rows, decisions) {
  const byId = new Map(rows.map(r => [r.id, r])), latest = new Map(), skipped = [];
  for (const d of decisions) {
    const problem = queueDecisionProblem(d);
    if (problem) { skipped.push({id: typeof d?.id === 'string' ? d.id : null, reason: problem}); continue; }
    latest.set(d.id, d);
  }
  const approve = [], rejected = [];
  for (const d of latest.values()) {
    const r = byId.get(d.id);
    const reason = !r || r.labelSource !== 'claude_drafted' ? 'row_unknown' : r.humanReviewed === true ? 'row_already_reviewed'
      : recordHash(r) !== d.recordHash || queueBinding(r) !== d.reviewedPayloadHash ? 'row_changed_since_decision' : null;
    if (reason) { skipped.push({id: d.id, reason}); continue; }
    if (d.decision === 'reject') { rejected.push({id: d.id, note: String(d.note || '')}); continue; }
    approve.push({id: d.id, recordHash: d.recordHash, approved: true, reviewerId: d.reviewerId.trim(), reviewedAt: d.reviewedAt, sourceConsent: true,
      piiReviewed: true, approvedOutput: r.candidateOutput});
  }
  const rejectedIds = new Set(rejected.map(x => x.id)), kept = rows.filter(r => !rejectedIds.has(r.id));
  const out = approve.length ? importHumanReviews(kept, approve) : kept, result = new Map(out.map(r => [r.id, r]));
  for (const a of approve) if (result.get(a.id)?.reviewedPayloadHash !== latest.get(a.id).reviewedPayloadHash)
    throw Error('review_queue_binding_mismatch: ' + a.id);
  return {rows: out, approved: approve.length, rejected, skipped,
    unreviewed: out.filter(r => r.labelSource === 'claude_drafted' && r.humanReviewed !== true).length};
}
