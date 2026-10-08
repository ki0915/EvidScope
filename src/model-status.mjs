// Which model the AI review room uses and whether it was trained (docs/feature-guide.md). Read-only facts from the repository
// model policy and role packages, the tenant's signed assistance profiles, the runtime observation and the repository record of
// training runs (data/training-runs.json). Nothing here starts, trains or promotes a model.
import {readFileSync} from 'node:fs';
import {modelPolicy} from './model-policy.mjs';
import {latestRoleProfiles} from './assistance.mjs';

const RUNS_FILE = new URL('../data/training-runs.json', import.meta.url);
const text = (v, max = 300) => typeof v === 'string' ? v.slice(0, max) : null;
const count = v => Number.isSafeInteger(v) && v >= 0 ? v : null;

// The repository record, re-read on each call (it is small) and reduced to known fields; unreadable means "no record".
export function trainingRuns(file = RUNS_FILE) {
  let data;
  try { data = JSON.parse(readFileSync(file, 'utf8')); } catch { return {available: false, runs: []}; }
  if (data?.format !== 'evidscope-training-runs-v1' || !Array.isArray(data.runs)) return {available: false, runs: []};
  const runs = data.runs.slice(0, 50).map(r => ({id: text(r.id, 120), evaluationId: text(r.evaluationId, 120), finishedOn: text(r.finishedOn, 40),
    baseModel: text(r.baseModel, 200), baseRevision: text(r.baseRevision, 80), method: text(r.method, 200), dataset: text(r.dataset, 300),
    adapterSha256: text(r.adapterSha256, 80),
    evaluation: r.evaluation && {items: count(r.evaluation.items), passed: count(r.evaluation.passed),
      baselineAdapterOff: count(r.evaluation.baselineAdapterOff), alwaysAbstainReference: count(r.evaluation.alwaysAbstainReference)},
    promoted: r.promoted === true, attachedToRuntime: r.attachedToRuntime === true, runtimeNote: text(r.runtimeNote, 300),
    sources: Array.isArray(r.sources) ? r.sources.slice(0, 10).map(s => text(s, 200)) : []}));
  return {available: true, notice: text(data.notice, 500), runs};
}

const modelFacts = m => ({id: m.id, model: m.model, provider: m.provider, artifactRepository: m.artifactRepository ?? null, revision: m.revision,
  quantization: m.quantization});

// signedProfiles: the verified assistance_profile values of the tenant; runtime: modelRuntimeStatus().
export function modelStatus({signedProfiles, runtime, runs = trainingRuns()}) {
  const roles = latestRoleProfiles(signedProfiles).map(r => ({id: r.id, profileVersion: r.version, model: r.modelPolicy?.model ?? null,
    provider: r.modelPolicy?.provider ?? null, upgradePending: r.upgradePending, upgradeTo: r.upgradePending ? r.approvedPolicy.model : null,
    adapter: r.rolePackage?.adapter ?? 'none', evalStatus: r.rolePackage?.evalStatus ?? 'UNREVIEWED', modelVersion: r.rolePackage?.modelVersion ?? null,
    packageVersion: r.rolePackage?.version ?? null}));
  const adapters = roles.filter(r => r.adapter !== 'none');
  return {
    generatedAt: new Date().toISOString(),
    reviewModel: modelFacts(modelPolicy.primary), classifier: modelFacts(modelPolicy.cipher),
    runtime: {enabledByDefault: runtime?.enabledByDefault === true, observationStatus: runtime?.observationStatus ?? 'unavailable',
      models: (runtime?.models || []).map(m => ({id: m.id, state: m.state, observedAt: m.observedAt ?? null}))},
    fineTuning: {attached: adapters.length > 0, roles: adapters.map(r => r.id),
      summary: adapters.length ? 'adapter_attached' : 'none_base_model_as_published'},
    roles,
    training: {enabledByDefault: modelPolicy.training.enabledByDefault === true, promotionAutomatic: false,
      vaultRecords: 'none_signed_by_this_vault', repository: runs,
      howTo: 'node scripts/training-run.mjs --data reviewed.jsonl --runtime-config runtime.json --check-only',
      promotion: 'node scripts/model-promote.mjs promote (사람의 승인 파일과 비교 평가 보고서가 필요합니다)'},
    limitations: ['검토실은 공개된 기본 모델을 그대로 씁니다. 역할 패키지에 미세조정 adapter가 연결돼 있지 않습니다.',
      '학습은 CLI로만 실행하며 이 볼트는 학습 기록을 서명하지 않습니다. 아래 학습 기록은 저장소 문서의 요약입니다.',
      '승격은 자동으로 일어나지 않습니다. 사람의 승인과 비교 평가 없이 런타임 모델이 바뀌지 않습니다.',
      '실행 상태는 Kubernetes 관측 영수증이 있을 때만 확인됩니다. 기본값은 비활성입니다.']};
}
