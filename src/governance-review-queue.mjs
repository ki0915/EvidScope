// Review queue of the governance-mapping dataset in the console (docs/governance-model.md, "검토 대기열"): one Claude-drafted row at a
// time, approve or reject only. Each decision is a signed ledger object (governance_mapping_review, id = row id) bound to the row's
// reviewedPayloadHash and recordHash, the deciding principal and the vault's time. A later decision for the same row must name the
// one it replaces. Nothing here marks a row reviewed: `export-reviewed` (scripts/governance-mapping.mjs) applies the signed decisions
// to the dataset through applyReviewDecisions/importHumanReviews, the same path as the review sheet.
import {readFileSync} from 'node:fs';
import {digest} from './crypto.mjs';
import {cleanText, fail} from './model.mjs';
import {TASK, TASK_VERSION, governanceCatalog} from './governance-mapping.mjs';
import {QUEUE_DECISION_TYPE, SPLITS, applyQueueDecisions, buildDataset, governanceAdmission, queueBinding} from './governance-mapping-data.mjs';
import {GATE} from './governance-mapping-eval.mjs';
import {recordHash} from '../scripts/model-training-data.mjs';

export const DATASET_ID = 'governance-mapping/v1';
const DECISION_FIELDS = new Set(['rowId', 'decision', 'reviewedPayloadHash', 'note', 'attestPiiReviewed', 'attestSourceConsent', 'supersedes']);
const SHA = /^[a-f0-9]{64}$/;
const DECIDERS = new Set(['reviewer', 'admin']);

// The repository dataset is deterministic (tests compare it with the committed file); it is built once per process.
let cached;
export const repositoryDataset = () => (cached ??= Object.freeze(buildDataset()));
export const draftedRows = rows => rows.filter(r => r.labelSource === 'claude_drafted');

// Review aids shown next to a row: what each requirement asks in plain Korean (the requirement catalog's own sentence for the AI
// Basic Act items, Claude-written summaries for the rest) and Korean reference translations of the non-Korean rows. They are display
// only: they are not part of the dataset, the row hashes or the decisions.
const json = name => JSON.parse(readFileSync(new URL(`../data/${name}`, import.meta.url), 'utf8'));
let aids;
export function reviewAids() {
  if (aids) return aids;
  const guide = json('governance-mapping/v1/review-guide.json'), catalogText = new Map(json('requirements.json').map(r => [r.id, r.requirement]));
  aids = Object.freeze({notice: guide.notice, plain: id => catalogText.get(id) ?? guide.requirements[id] ?? null,
    plainSource: id => catalogText.has(id) ? 'requirement_catalog' : guide.requirements[id] ? 'claude_summary' : null,
    translation: id => guide.translations[id] ?? null});
  return aids;
}
const requirement = (catalog, id) => {
  const e = catalog.byId.get(id), a = reviewAids();
  return e ? {requirementId: id, title: e.title.ko, titleEn: e.title.en, framework: e.framework, citation: e.citation, plain: a.plain(id),
    plainSource: a.plainSource(id)} : {requirementId: id, title: null};
};
// What the reviewer sees: the text, its locators, the drafted answer with requirement titles and plain explanations, and for an
// injection row the IDs the answer must not contain. The hashes are what a decision binds.
export function queueItem(r, catalog = governanceCatalog()) {
  return {id: r.id, split: r.split, kind: r.evidence[0].kind, language: r.language, familyId: r.familyId, labelSource: r.labelSource,
    synthetic: r.synthetic === true, reviewStatus: r.reviewStatus, text: r.prompt, locators: r.evidence.map(e => e.id),
    textKo: r.language === 'ko' ? null : reviewAids().translation(r.id), aidNotice: reviewAids().notice,
    draftedAnswer: {abstain: r.truth.abstain, mappings: r.truth.mappings.map(m => ({...requirement(catalog, m.requirementId), relation: m.relation,
      evidenceLocators: [...m.evidenceLocators]}))},
    injection: Array.isArray(r.truth.forbidden),
    forbidden: (r.truth.forbidden || []).map(f => ({id: f, ...requirement(catalog, f.split(':')[0])})),
    reviewedPayloadHash: queueBinding(r), recordHash: recordHash(r)};
}

// Progress per split against the training minimums (src/model-policy.mjs) and, for test, the gate's reviewed free-text minimum.
// Counts come from applying the signed decisions exactly as the export does, so the screen and the trainer's file agree.
export function queueProgress(rows, decisions, {now = Date.now()} = {}) {
  const applied = applyQueueDecisions(rows, decisions), admission = governanceAdmission(applied.rows, {now});
  const stale = new Set(applied.skipped.map(s => s.id)), state = new Map();
  for (const d of decisions) if (!stale.has(d.id)) state.set(d.id, d.decision);
  const splits = {};
  for (const split of SPLITS) {
    const drafted = draftedRows(rows).filter(r => r.split === split), c = admission.counts[split];
    const approved = drafted.filter(r => state.get(r.id) === 'approve').length, rejected = drafted.filter(r => state.get(r.id) === 'reject').length;
    const pending = drafted.length - approved - rejected, needed = Math.max(0, admission.minimum[split] - c.eligible);
    splits[split] = {drafted: drafted.length, approved, rejected, pending, derivedEligible: c.derived, humanReviewedEligible: c.humanReviewed,
      eligible: c.eligible, minimum: admission.minimum[split], neededApprovals: needed, reachable: pending >= needed};
  }
  const t = splits.test;
  t.gate = {humanReviewedFreeText: t.humanReviewedEligible, minimumHumanReviewedFreeText: GATE.minReviewedFreeText,
    neededApprovals: Math.max(0, GATE.minReviewedFreeText - t.humanReviewedEligible), gateItems: t.eligible, minimumGateItems: GATE.minItems};
  return {splits, trainingAdmitted: admission.admitted, admissionReasons: admission.reasons, staleDecisions: applied.skipped,
    decided: state.size, drafted: draftedRows(rows).length};
}

const withDecision = (item, decision) => ({...item, previousDecision: decision ?? null, previousDecisionHash: decision ? digest(decision) : null,
  previousDecisionStale: !!decision && decision.reviewedPayloadHash !== item.reviewedPayloadHash});
// HTTP: /api/governance-model/review[...]. policyObjects(p, type) is the service's verified read of signed objects.
export function createReviewQueue({store, policyObjects, human, dataset = repositoryDataset, now = () => Date.now()}) {
  const decisions = p => [...policyObjects(p, QUEUE_DECISION_TYPE).values()];
  const byId = () => new Map(draftedRows(dataset()).map(r => [r.id, r]));
  function view(p, url) {
    const split = url.searchParams.get('split') || 'all', after = url.searchParams.get('after') || '';
    if (split !== 'all' && !SPLITS.includes(split)) fail(400, '분할은 all, tune, validation, test 중 하나입니다');
    const values = decisions(p), decided = new Map(values.map(d => [d.id, d])), rows = dataset();
    const progress = queueProgress(rows, values, {now: now()}), stale = new Set(progress.staleDecisions.map(s => s.id));
    // Order: tune, validation, test (training needs tune first), then id. Stale decisions put their row back in the queue.
    const order = SPLITS.flatMap(s => draftedRows(rows).filter(r => r.split === s && (split === 'all' || split === s)));
    const position = new Map(order.map((r, i) => [r.id, i])), from = position.get(after) ?? -1;
    const open = order.filter(r => !decided.has(r.id) || stale.has(r.id)), next = open.find(r => position.get(r.id) > from) ?? open[0];
    return {datasetId: DATASET_ID, task: TASK, taskVersion: TASK_VERSION, split, progress, remaining: open.length,
      item: next ? withDecision(queueItem(next), decided.get(next.id)) : null,
      viewer: {id: p.id, role: p.role, mayDecide: DECIDERS.has(p.role)},
      shortcuts: {approve: 'a', reject: 'r', next: 'n', previous: 'p'}, qualityClaimAllowed: false};
  }
  function item(p, id) {
    const r = byId().get(id) || fail(404, '검토 대상 행이 없습니다');
    return {item: withDecision(queueItem(r), policyObjects(p, QUEUE_DECISION_TYPE).get(id))};
  }
  function decide(p, x) {
    if (!DECIDERS.has(p.role)) fail(403, '검토자 또는 관리자만 학습 데이터 행을 승인·거절할 수 있습니다');
    if (!x || typeof x !== 'object' || Array.isArray(x) || Object.keys(x).some(k => !DECISION_FIELDS.has(k))) fail(400, '지원하지 않는 검토 결정 필드');
    if (!['approve', 'reject'].includes(x.decision)) fail(400, '결정은 approve 또는 reject입니다 (답 수정은 지원하지 않습니다)');
    if (x.attestPiiReviewed !== true || x.attestSourceConsent !== true) fail(400, '개인정보 확인과 출처·사용 동의 확인이 필요합니다');
    const r = byId().get(x.rowId) || fail(404, '검토 대상 행이 없습니다');
    const binding = queueBinding(r);
    if (x.reviewedPayloadHash !== binding) fail(409, '화면에 표시된 행과 현재 데이터셋의 행이 다릅니다. 다시 불러와 확인하세요');
    const note = cleanText(x.note ?? '', 500).trim();
    if (x.supersedes !== undefined && x.supersedes !== null && !SHA.test(x.supersedes)) fail(400, 'supersedes는 이전 결정의 SHA-256입니다');
    return store.transaction(() => {
      const existing = policyObjects(p, QUEUE_DECISION_TYPE).get(r.id);
      if (existing ? x.supersedes !== digest(existing) : x.supersedes != null) {
        fail(409, existing ? '이미 결정된 행입니다. 바꾸려면 이전 결정의 해시를 supersedes로 보내세요' : '바꿀 이전 결정이 없습니다');
      }
      const value = {id: r.id, schemaVersion: 1, task: TASK, taskVersion: TASK_VERSION, datasetId: DATASET_ID, split: r.split, decision: x.decision,
        note, reviewedPayloadHash: binding, recordHash: recordHash(r), reviewerId: p.id, reviewerRole: p.role,
        authentication: p.authentication === 'oidc' ? 'oidc' : 'token', reviewedAt: new Date(now()).toISOString(), piiReviewed: true, sourceConsent: true,
        supersedes: existing ? digest(existing) : null, approvedOutput: x.decision === 'approve' ? 'drafted_answer_as_shown' : null};
      store.put(p, QUEUE_DECISION_TYPE, r.id, value);
      return {decision: value, decisionHash: digest(value), signed: true,
        notice: '결정은 서명된 원장 기록입니다. 학습 파일에는 export-reviewed가 이 결정을 적용한 행만 들어갑니다.'};
    });
  }
  function handle(p, method, url, x) {
    const path = url.pathname;
    if (!path.startsWith('/api/governance-model/review')) return undefined;
    human(p);
    if (path === '/api/governance-model/review' && method === 'GET') return store.transaction(() => view(p, url));
    if (path === '/api/governance-model/review/decisions' && method === 'GET') {
      return store.transaction(() => ({items: decisions(p).map(d => ({...d, decisionHash: digest(d)})), type: QUEUE_DECISION_TYPE}));
    }
    if (path === '/api/governance-model/review/decisions' && method === 'POST') return decide(p, x);
    const match = path.match(/^\/api\/governance-model\/review\/items\/([A-Za-z0-9._-]{1,120})$/);
    if (match && method === 'GET') return store.transaction(() => item(p, match[1]));
    fail(404, '경로 없음');
  }
  return {handle, view, decide};
}
