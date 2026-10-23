// The governance-mapping task inside the assistance flow (docs/governance-model.md, "연결").
// prepare: a reviewer adds one free-text item to a governance-assistant package; the package freezes the mode, the prompt variant
//          and the provenance from the status at that moment (model off → refused).
// runner:  one constrained inference; the output is checked against the catalog and the package's locators and becomes the
//          draft's `mappings`, each carrying the frozen provenance (source "model", model and adapter digests).
// review:  mappings stay advisory until a second person accepts them; an accepted edit may only drop mappings, never add or change one.
import {canonical} from './crypto.mjs';
import {LIMITS, MODEL_KINDS, buildMappingRequest, governanceCatalog, mappingError, normalizeMappingItem, parseModelContent,
  validateMappingOutput} from './governance-mapping.mjs';
import {provenanceOf} from './governance-model.mjs';
import {governanceExamples} from './governance-mapping-data.mjs';

const ACTIVE = new Set(['base_retrieval_constrained', 'promoted_adapter']);
const LOCATOR = /^[A-Za-z0-9._:@/#-]{1,190}$/;
const httpError = (status, message, code) => Object.assign(Error(message), {status, code});

// input: {kind, text}; evidence refs are the package's selected refs (the model may cite only those).
export function prepareMappingTask(input, {status, evidenceRefs}) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(k => !['kind', 'text'].includes(k))) {
    throw httpError(400, '지원하지 않는 매핑 입력 필드', 'mapping_input_fields');
  }
  if (!MODEL_KINDS.includes(input.kind)) throw httpError(400, '구조화 기록은 규칙 매핑으로 처리합니다. 모델 매핑은 자유 텍스트 종류만 받습니다', 'mapping_kind');
  if (!status || !ACTIVE.has(status.mode)) throw httpError(409, '거버넌스 매핑 모델이 꺼져 있습니다 (측정·승인 전)', 'governance_model_off');
  const refs = evidenceRefs.slice(0, LIMITS.locators);
  if (!refs.length || refs.some(ref => !LOCATOR.test(ref))) throw httpError(400, '매핑 증거 위치를 만들 수 없는 참조입니다', 'mapping_locator');
  let item;
  try { item = normalizeMappingItem({kind: input.kind, text: input.text, locators: refs.map(ref => `evidence:${ref}`)}); }
  catch (error) { throw httpError(400, '매핑 입력이 유효하지 않습니다', error.code || 'mapping_input_invalid'); }
  const promoted = status.mode === 'promoted_adapter', catalog = governanceCatalog();
  if (status.catalog?.digest !== catalog.digest) throw httpError(409, '매핑 catalog가 모델 상태와 다릅니다', 'mapping_catalog_mismatch');
  return {task: 'governance-mapping', taskVersion: 1, mode: status.mode, variant: promoted ? 'candidate' : 'retrieval_constrained', adapter: promoted,
    item, catalogDigest: catalog.digest, provenance: provenanceOf(status), humanConfirmationRequired: true};
}

// The runner side: the exact request the evaluation measured for this variant.
export function mappingRequestFor(task) {
  const request = buildMappingRequest(task.item, {variant: task.variant, examples: governanceExamples()});
  if (request.catalogDigest !== task.catalogDigest || request.adapter !== task.adapter) throw mappingError('mapping_catalog_mismatch');
  return request;
}

// Model content → advisory draft. Invalid output (unknown ID, foreign locator, schema break) fails the run; nothing is repaired.
export function mappingDraft(content, task) {
  const output = validateMappingOutput(parseModelContent(content), {locators: task.item.locators});
  const mappings = output.mappings.map(m => ({...m, provenance: task.provenance}));
  return {summary: output.abstain ? 'Model abstained: no catalog requirement is clearly evidenced by the supplied text.'
    : `Model proposed ${mappings.length} advisory requirement mapping(s) for human confirmation.`,
  findings: [], mappings,
  uncertainties: ['Model mappings are advisory and may be wrong; precision is measured only on the held-out test split.'],
  limitations: ['Mappings are not an applicability or compliance decision; a second person must confirm each one.'],
  recommendedFollowUps: mappings.length ? ['Confirm or remove each mapping against the cited evidence.'] : [], abstained: output.abstain};
}

// Server-side check of a submitted or edited draft's mappings.
export function validateDraftMappings(value, task) {
  if (!task) throw httpError(400, '이 package에는 매핑 작업이 없습니다', 'mapping_task_missing');
  if (!Array.isArray(value)) throw httpError(400, 'mappings 목록이 필요합니다', 'mapping_list');
  let checked;
  try {
    checked = validateMappingOutput({abstain: value.length === 0,
      mappings: value.map(m => { const {provenance, ...rest} = m || {}; return rest; })}, {locators: task.item.locators});
  } catch (error) { throw httpError(400, '매핑이 catalog 또는 증거 위치와 맞지 않습니다', error.code); }
  if (value.some(m => canonical(m?.provenance ?? null) !== canonical(task.provenance))) {
    throw httpError(400, '매핑 provenance가 package에 고정된 모델과 다릅니다', 'mapping_provenance_mismatch');
  }
  return checked.mappings.map(m => ({...m, provenance: structuredClone(task.provenance)}));
}

// Review: an edited draft may keep a subset of the model's mappings only; the accepting reviewer must be a second person.
export function reviewMappingsAllowed({original, edited, reviewerId, preparedBy, dispatchedBy, action}) {
  const before = original?.mappings || [];
  if (edited && (edited.mappings || []).some(m => !before.some(o => canonical(o) === canonical(m)))) {
    throw httpError(400, '검토 편집은 모델 매핑을 삭제만 할 수 있습니다', 'mapping_edit_not_subset');
  }
  if (action === 'accept' && before.length && (reviewerId === preparedBy || reviewerId === dispatchedBy)) {
    throw httpError(403, '모델 매핑 확인은 package 준비자·실행자가 아닌 다른 사람이 해야 합니다', 'mapping_four_eyes');
  }
}
