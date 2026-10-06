// Offline synthetic portfolio demo. Reuses the existing service boundary; no server or model starts.
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, randomBytes, randomUUID, verify} from 'node:crypto';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createService} from '../src/service.mjs';
import {canonical, digest, mac, verifyBundle} from '../src/crypto.mjs';
import {evaluateJob} from '../src/worker.mjs';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const requirements = JSON.parse(readFileSync(join(repository, 'data/requirements.json'), 'utf8'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const obligations = ['KR-34-RISK', 'KR-34-DOCUMENT', 'KR-34-OVERSIGHT'];
// Fixed, synthetic test reports, authenticated through the real ingest path.
// These values are not independent measurements of a live financial system.
const syntheticMeasurements = {
  risk: {riskPolicyRecorded: true, responsibleOrganisationRecorded: true, operatingReviewRecorded: true, mitigationTestPassed: true, residualRiskReviewed: true},
  publication: {measureDocumentInventoryRecorded: true, retentionYears: 5, accessControlTestPassed: true, restoreTestPassed: true, publishedSections: ['risk_management', 'explanation', 'user_protection', 'oversight_name_contact'], excludedSections: [], exclusionBasisRecorded: false, publicationTestPassed: true},
  oversight: {sections: ['responsibility', 'authority', 'competence', 'intervention', 'contact'], interventionExercisePassed: true},
};
const system = {
  id: 'portfolio-credit', name: '합성 대출 심사 보조', owner: '합성 검토팀',
  purpose: '대출 심사 보조', role: 'deployer', krRoles: ['deployer'], markets: ['KR'],
  domain: 'credit', generative: false, highImpact: 'candidate',
  supplierId: 'synthetic-supplier', modelId: 'synthetic-credit-model', modelVersion: 'v1',
  suppliedModelVersion: 'v1', suppliedPurpose: '대출 심사 보조',
  substantialModification: false, policyVersion: 'synthetic-policy-v1',
};
const document = (id, text) => {
  const bytes = Buffer.from(text);
  return {id, name: `${id}.txt`, sha256: sha(bytes), contentBase64: bytes.toString('base64')};
};
const supplier = () => ({
  id: 'portfolio-supplier', systemId: system.id, synthetic: true,
  supplierId: system.supplierId, modelId: system.modelId, modelVersion: 'v1',
  purpose: system.purpose, testScope: '합성 위험관리 문서 대조; 금융·법률 품질 평가 아님',
  measures: ['KR-34-RISK'], documents: [document('synthetic-risk', '합성 공급사 위험관리 기록 v1')],
});
const assessment = (requirementId, evidence) => ({
  systemId: system.id, requirementId, applicability: 'applicable', assessment: 'sufficient',
  legalReview: 'pending', evidence, control: '합성 검토자가 제출한 증거 연결',
  owner: '합성 검토팀', reason: '시험용 인간 평가 기록이며 실제 사람의 법률 판단이 아님',
  nextReviewAt: '2099-01-01T00:00:00.000Z',
});
const summary = report => Object.fromEntries(report.items.filter(item => obligations.includes(item.requirement.id))
  .map(item => [item.requirement.id, {status: item.status, technicalStatus: item.technicalStatus, legalStatus: item.legalStatus,
    supportsHumanAssessment: item.technicalEvidence.supportsHumanAssessment, missingChecks: item.technicalEvidence.missingChecks,
    reasons: item.technicalEvidence.reasons, matchedChecks: item.technicalEvidence.matchedChecks,
    measurementTrust: item.technicalEvidence.measurementTrust, automaticLegalVerdict: item.technicalEvidence.automaticLegalVerdict}]));
const complete = { 'KR-34-RISK': 'human_evidence_assessed', 'KR-34-DOCUMENT': 'human_evidence_assessed', 'KR-34-OVERSIGHT': 'human_evidence_assessed' };
const statuses = state => Object.fromEntries(Object.entries(state).map(([id, item]) => [id, item.status]));
const cases = [
  {id: 'baseline', name: '기준: 실제 보관 문서·합성 측정·감독 수행 기록 연결', expected: complete},
  {id: 'model-changed', name: '현재 모델 v2 변경', expected: Object.fromEntries(obligations.map(id => [id, 'review_required']))},
  {id: 'purpose-changed', name: '현재 공급사 목적이 같아도 최초 공급 목적 불일치', expected: Object.fromEntries(obligations.map(id => [id, 'review_required']))},
  {id: 'supplier-document-revised', name: '공급사 문서 개정: 연결된 위험관리 평가만 재검토', expected: {...complete, 'KR-34-RISK': 'review_required'}},
  {id: 'oversight-plan-revised', name: '감독 계획 개정: 문서·사람 감독 재검토', expected: {...complete, 'KR-34-DOCUMENT': 'review_required', 'KR-34-OVERSIGHT': 'review_required'}},
  {id: 'oversight-record-missing', name: '별도 누락 분기: 감독 수행 기록 없음', expected: {...complete, 'KR-34-OVERSIGHT': 'evidence_insufficient'}},
];

async function runCase(spec, root) {
  const directory = join(root, spec.id); mkdirSync(directory);
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  const principal = (id, role, kind) => ({id, role, kind, tenant: 'portfolio', token: randomBytes(32).toString('hex'), ...(role === 'source' ? {hmacSecret: randomBytes(32).toString('hex')} : {})});
  const reviewer = principal('synthetic-reviewer', 'reviewer');
  const worker = principal('synthetic-worker', 'worker');
  const authority = principal('synthetic-authority', 'source', 'authority');
  const tool = principal('synthetic-tool', 'source', 'tool');
  const telemetry = principal('synthetic-measurements', 'source', 'telemetry');
  const otherTenant = {...principal('synthetic-other-reviewer', 'reviewer'), tenant: 'other-portfolio'};
  const service = createService({dataDir: join(directory, 'vault'), key: privateKey, config: {principals: [reviewer, worker, authority, tool, telemetry, otherTenant]}, requirements});
  const call = (path, body, actor = reviewer) => service.handle(body === undefined ? 'GET' : 'POST', new URL(path, 'http://in-process.invalid'), {authorization: `Bearer ${actor.token}`}, body === undefined ? '' : JSON.stringify(body));
  const checks = [];
  const check = (name, actual, expected) => {assert.deepEqual(actual, expected, name); checks.push({name, passed: true, expected, actual});};
  const ingest = async (raw, actor) => {
    const body = JSON.stringify(raw), timestamp = String(Date.now()), nonce = randomUUID();
    const result = await service.handle('POST', new URL('/api/ingest', 'http://in-process.invalid'), {
      authorization: `Bearer ${actor.token}`, 'x-evid-timestamp': timestamp,
      'x-evid-nonce': nonce, 'x-evid-signature': mac(actor.hmacSecret, timestamp, nonce, body),
    }, body);
    assert.equal(result.accepted, true);
  };
  const plan = (text = '합성 조치·게시·감독 계획 v1: 위험관리 정책 및 시험 범위; 최종 결과·주요 기준·학습 데이터 설명 방안; 문의·이의·피해 대응 절차; 감독 담당 synthetic-human과 연락 synthetic-contact; 책임·권한·역량·중단 개입 절차. 5년 보관 정책·접근 통제·복구·게시 시험을 모사한 자료이며 실제 금융·법률 적합성 검토 아님') => call('/api/governance/documents', {...document('portfolio-oversight-plan', text), systemId: system.id, mediaType: 'text/plain'});
  let before, after;
  try {
    const savedSystem = await call('/api/governance/systems', system);
    await call('/api/governance/bundles', supplier());
    const riskDocument = await call('/api/governance/documents', {...document('portfolio-risk-measures', '합성 위험관리 시험 보고: 정책·담당 조직·운영 검토·위험 저감 시험·잔여 위험 검토. 실제 금융 환경을 측정한 자료가 아님.'), systemId: system.id, mediaType: 'text/plain'});
    const planDocument = await plan();
    const documentsBefore = await Promise.all(['portfolio-risk-measures', 'portfolio-oversight-plan'].map(id => call(`/api/governance/documents/${id}/export`)));
    const at = Date.now() - 60000, iso = offset => new Date(at + offset).toISOString();
    const common = {systemId: system.id, actionId: 'portfolio-action', traceId: 'portfolio-trace', requestId: 'portfolio-request', attemptId: 'attempt-1', modelId: system.modelId, modelVersion: 'v1', policyVersion: system.policyVersion, actor: 'synthetic-credit-agent', tool: 'credit-api', action: 'score', resource: 'synthetic-application', destination: 'internal', clockUncertaintyMs: 0};
    const scope = Object.fromEntries(['actor', 'tool', 'action', 'resource', 'destination'].map(field => [field, common[field]]));
    await call('/api/assets', {id: 'portfolio-policy', actor: common.actor, tool: common.tool, owner: '합성 정책팀', policyVersion: system.policyVersion, approvalRequired: true, validFrom: iso(-20000), destinations: ['internal']});
    await ingest({...common, id: 'grant', kind: 'grant', scope, occurredAt: iso(-10000), validFrom: iso(-20000), validUntil: iso(600000)}, authority);
    await ingest({...common, id: 'approval', kind: 'human_approval', reviewer: 'synthetic-human', scope, occurredAt: iso(-9000), validFrom: iso(-20000), validUntil: iso(600000)}, authority);
    await ingest({...common, id: 'execution', kind: 'execution', occurredAt: iso(0)}, tool);
    await ingest({...common, id: 'result', kind: 'result', status: 'success', occurredAt: iso(1000)}, tool);
    if (spec.id !== 'oversight-record-missing') await ingest({...common, id: 'oversight', kind: 'human_oversight_review', reviewer: 'synthetic-human', occurredAt: iso(2000)}, authority);
    const measure = async (requirementId, checkType, actualDocument, measurements) => {
      const id = `check-${requirementId}`;
      await ingest({...common, id, kind: 'governance_check', occurredAt: iso(3000), note: '합성 시험 결과 보고: 출처 인증은 측정 내용의 진실성 또는 법적 준수를 보증하지 않음',
        governanceCheck: {schemaVersion: 1, requirementId, checkType, result: 'pass', systemHash: digest(savedSystem), requirementHash: digest(requirements.find(item => item.id === requirementId)), documentHash: actualDocument.sha256, measurements}}, telemetry);
      return {type: 'event', ref: `${telemetry.id}/${id}`};
    };
    const riskCheck = await measure('KR-34-RISK', 'high_impact_risk_management', riskDocument, syntheticMeasurements.risk);
    const publicationCheck = await measure('KR-34-DOCUMENT', 'document_publication_retention', planDocument, syntheticMeasurements.publication);
    const oversightCheck = await measure('KR-34-OVERSIGHT', 'oversight_plan', planDocument, syntheticMeasurements.oversight);
    const badBody = JSON.stringify({...common, id: 'unauthenticated-measurement', kind: 'governance_check', occurredAt: iso(3000)});
    await assert.rejects(service.handle('POST', new URL('/api/ingest', 'http://in-process.invalid'), {
      authorization: `Bearer ${telemetry.token}`, 'x-evid-timestamp': String(Date.now()), 'x-evid-nonce': randomUUID(), 'x-evid-signature': '0'.repeat(64),
    }, badBody), error => error.status === 401);
    check('only_authenticated_measurements_received', (await call('/api/events?kind=governance_check')).total, 3);
    checks.push({name: 'invalid_measurement_hmac_rejected', passed: true});
    const claimed = await call('/internal/claim', {}, worker);
    check('one_action_claimed', claimed.jobs.length, 1);
    for (const job of claimed.jobs) {
      const result = evaluateJob(job); check('baseline_rule_findings', result.findings.length, 0);
      const committed = await call('/internal/complete', {leaseId: job.leaseId, result}, worker);
      check('analysis_backlog', committed.backlog, 0);
    }
    const supplierOnly = await call('/api/governance/assessments', assessment('KR-34-RISK', [{type: 'document', ref: 'supplier-bundle:portfolio-supplier'}]));
    const documentOnly = await call('/api/governance/assessments', assessment('KR-34-DOCUMENT', [{type: 'document', ref: 'governance-document:portfolio-oversight-plan'}]));
    const unsupported = summary(await call(`/api/governance/report?systemId=${system.id}`));
    check('supplier_only_risk_not_supported', {status: unsupported['KR-34-RISK'].status, missingChecks: unsupported['KR-34-RISK'].missingChecks}, {status: 'evidence_insufficient', missingChecks: ['high_impact_risk_management']});
    check('document_only_publication_not_supported', {status: unsupported['KR-34-DOCUMENT'].status, missingChecks: unsupported['KR-34-DOCUMENT'].missingChecks}, {status: 'evidence_insufficient', missingChecks: ['document_publication_retention']});
    check('submitted_human_conclusions_preserved', [supplierOnly.assessment, documentOnly.assessment], ['sufficient', 'sufficient']);
    const risk = await call('/api/governance/assessments', assessment('KR-34-RISK', [
      {type: 'document', ref: 'supplier-bundle:portfolio-supplier'}, {type: 'document', ref: 'governance-document:portfolio-risk-measures'}, riskCheck,
    ]));
    await call('/api/governance/assessments', assessment('KR-34-DOCUMENT', [{type: 'document', ref: 'governance-document:portfolio-oversight-plan'}, publicationCheck]));
    const oversight = await call('/api/governance/assessments', assessment('KR-34-OVERSIGHT', [
      {type: 'document', ref: 'governance-document:portfolio-oversight-plan'}, oversightCheck,
      ...(spec.id === 'oversight-record-missing' ? [] : [{type: 'event', ref: 'synthetic-authority/oversight'}]),
    ]));
    check('supplier_only_conclusion_history_preserved', (await call('/api/governance')).assessments.find(item => item.id === supplierOnly.id), supplierOnly);
    checks[checks.length - 1] = {name: 'supplier_only_conclusion_history_preserved', passed: true, actual: true, expected: true};
    check('typed_measurement_frozen_binding', risk.evidence[2].eventSnapshot.governanceCheck, {schemaVersion: 1, requirementId: 'KR-34-RISK', checkType: 'high_impact_risk_management', result: 'pass', systemHash: digest(savedSystem), requirementHash: digest(requirements.find(item => item.id === 'KR-34-RISK')), documentHash: riskDocument.sha256, measurements: syntheticMeasurements.risk});
    await assert.rejects(call('/api/governance/documents/portfolio-risk-measures/export', undefined, otherTenant), error => error.status === 404);
    await assert.rejects(call('/api/governance/assessments', assessment('KR-34-RISK', [riskCheck]), otherTenant), error => error.status === 404);
    check('other_tenant_has_no_portfolio_events', (await call('/api/events', undefined, otherTenant)).total, 0);
    checks.push({name: 'other_tenant_document_and_assessment_access_rejected', passed: true});
    before = await call('/api/governance/finance/report', {systemId: system.id});
    const earlierLedger = await call('/api/export');
    if (spec.id === 'model-changed') await call('/api/governance/systems', {...system, modelVersion: 'v2'});
    if (spec.id === 'purpose-changed') {
      const purpose = '고객 마케팅 분류';
      await call('/api/governance/systems', {...system, purpose});
      await call('/api/governance/bundles', {...supplier(), purpose});
    }
    if (spec.id === 'supplier-document-revised') await call('/api/governance/bundles', {...supplier(), documents: [document('synthetic-risk', '합성 공급사 위험관리 기록 v2') ]});
    if (spec.id === 'oversight-plan-revised') await plan('합성 감독 계획 v2: 담당자 변경');
    after = await call('/api/governance/finance/report', {systemId: system.id});
    const state = summary(after.snapshot.governance);
    check('obligation_states', statuses(state), spec.expected);
    check('legal_review_remains_pending', Object.values(state).every(item => ['pending', 'review_required'].includes(item.legalStatus)), true);
    check('automatic_legal_verdict', after.snapshot.automaticLegalVerdict, false);
    check('historical_signed_report_preserved', await call(`/api/governance/finance/reports/${before.id}`), before);
    // Keep the potentially large historical equality check compact in the public result.
    checks[checks.length - 1] = {name: 'historical_signed_report_preserved', passed: true, actual: true, expected: true};
    const issues = after.snapshot.bundles[0].verification.issues;
    if (spec.id === 'model-changed') check('model_mismatch_detected', issues.includes('MODEL_VERSION_MISMATCH'), true);
    if (spec.id === 'purpose-changed') {
      check('current_supplier_purpose_matches', issues.includes('PURPOSE_MISMATCH'), false);
      check('original_supplied_purpose_mismatch', issues.includes('SUPPLIED_PURPOSE_MISMATCH'), true);
    }
    if (['model-changed', 'purpose-changed'].includes(spec.id)) {
      await assert.rejects(call('/api/governance/assessments', assessment('KR-34-RISK', [{type: 'document', ref: 'supplier-bundle:portfolio-supplier'}])), error => error.status === 400);
      checks.push({name: 'mismatched_supplier_sufficient_assessment_rejected', passed: true});
    }
    if (spec.id === 'oversight-record-missing') {
      check('missing_oversight_record', {technicalStatus: state['KR-34-OVERSIGHT'].technicalStatus, missingChecks: state['KR-34-OVERSIGHT'].missingChecks}, {technicalStatus: 'typed_evidence_insufficient', missingChecks: ['human_oversight_review']});
      await assert.rejects(call(`/api/governance/tasks/${oversight.id}`, {status: 'closed', reason: '합성 종결 시도'}), error => error.status === 409);
      checks.push({name: 'unsupported_oversight_task_closure_rejected', passed: true});
    }
    if (spec.id === 'supplier-document-revised') check('supplier_revision_review_task', after.snapshot.tasks.some(task => task.bundleId === 'portfolio-supplier' && task.status === 'open'), true);
    if (spec.id === 'oversight-plan-revised') check('plan_revision_review_task', after.snapshot.tasks.some(task => task.documentId === 'portfolio-oversight-plan' && task.status === 'open'), true);
    check('financial_snapshot_signature', verify(null, Buffer.from(canonical(after.snapshot)), publicKey, Buffer.from(after.signature, 'base64')), true);
    const altered = structuredClone(after.snapshot); altered.system.modelVersion = 'tampered';
    check('altered_financial_snapshot_rejected', verify(null, Buffer.from(canonical(altered)), publicKey, Buffer.from(after.signature, 'base64')), false);
    check('full_integrity', (await call('/api/integrity')).valid, true);
    const ledger = await call('/api/export');
    // Capture the expected checkpoint from trusted fixture state, not the supplied bundle.
    // This is an in-process simulation of pinning, not an external trust service.
    const expectedCheckpoint = structuredClone(service.store.checkpoint('portfolio'));
    check('chain_with_fixture_pinned_checkpoint', verifyBundle(ledger, publicKey, expectedCheckpoint).rollbackChecked, true);
    assert.throws(() => verifyBundle(earlierLedger, publicKey, expectedCheckpoint), /External checkpoint mismatch/);
    checks.push({name: 'earlier_signed_export_rejected_by_current_checkpoint', passed: true});
    const alteredLedger = structuredClone(ledger); alteredLedger.records[0].payload.portfolioTampered = true;
    assert.throws(() => verifyBundle(alteredLedger, publicKey), /Record digest mismatch/);
    checks.push({name: 'altered_ledger_rejected', passed: true});
    // Public synthetic artifacts only. Never write the signing private key or credentials.
    writeFileSync(join(directory, 'public-key.pem'), publicKey.export({type: 'spki', format: 'pem'}));
    const measurementRecords = (await call('/api/events?kind=governance_check')).items;
    const documentsAfter = await Promise.all(['portfolio-risk-measures', 'portfolio-oversight-plan'].map(id => call(`/api/governance/documents/${id}/export`)));
    for (const [name, value] of [['finance-before.json', before], ['finance-after.json', after], ['ledger-export.json', ledger], ['checkpoint.json', expectedCheckpoint], ['supplier-export.json', await call('/api/governance/bundles/portfolio-supplier/export')], ['measurement-records.json', measurementRecords], ['governance-documents-before.json', documentsBefore], ['governance-documents-after.json', documentsAfter]]) writeFileSync(join(directory, name), JSON.stringify(value, null, 2) + '\n');
    return {id: spec.id, name: spec.name, passed: true, before: summary(before.snapshot.governance), after: state, supplierIssues: issues, checks, evidenceDirectory: directory};
  } catch (error) {
    return {id: spec.id, name: spec.name, passed: false, checks, error: {name: error.name, message: error.message, ...(error.status ? {status: error.status} : {})}, evidenceDirectory: directory};
  } finally { service.store.close(); }
}

export async function runPortfolioGovernanceDemo() {
  const root = mkdtempSync(join(tmpdir(), 'evidscope-portfolio-governance-'));
  const results = [];
  for (const spec of cases) results.push(await runCase(spec, root));
  const sources = ['scripts/portfolio-governance-demo.mjs', 'data/requirements.json', 'src/service.mjs', 'src/governance-policy.mjs', 'src/kr-governance-evidence.mjs', 'src/finance-evidence.mjs', 'src/governance-documents.mjs', 'src/model.mjs', 'src/worker.mjs', 'src/crypto.mjs', 'src/store.mjs'];
  return {
    schemaVersion: 1, createdAt: new Date().toISOString(), passed: results.every(item => item.passed),
    caseCount: results.length, passedCases: results.filter(item => item.passed).length,
    runtime: {node: process.version, platform: process.platform, arch: process.arch},
    transport: 'in_process_service_boundary_no_http_server', synthetic: true,
    modelCalls: 0, liveFinancialIntegration: false, humanReviewPerformed: false,
    measurementTrust: 'authenticated_synthetic_report_not_independent_truth',
    automaticLegalVerdict: false, competitiveSuperiorityProven: false,
    catalogHash: digest(requirements), sourceSha256: Object.fromEntries(sources.map(file => [file, sha(readFileSync(join(repository, file)))])),
    cases: results, artifactDirectory: root,
    limitations: [
      '합성 자격·문서·인간 평가 기록을 사용한 로컬 재현이며 실제 금융·법률 품질을 입증하지 않습니다.',
      'governance_check는 고정된 합성 시험 결과를 HMAC 인증 접수한 보고입니다. 측정 내용·문서 의미·법률 이행을 독립 실측하거나 인증한 결과가 아닙니다.',
      '공급사 증빙만으로 위험관리를 인정하지 않습니다. 실제 보관 문서와 조항별 측정의 현재 모델·정책·법령 해시를 대조하며 사람의 법률 검토는 pending으로 유지합니다.',
      '기존 HMAC 접수·SQLite·worker·거버넌스 경계를 같은 프로세스에서 호출합니다. HTTP/TLS·별도 호스트 경계는 시험하지 않습니다.',
      '감독 누락 사례는 처음부터 수행 기록을 제출하지 않는 별도 분기입니다. 기존 원본을 삭제하지 않습니다.',
      '서명키는 시험 시작 시 메모리에서 생성·고정한 합성 신뢰점입니다. 운영 외부 신뢰점·KMS·신뢰 시각 봉인이 아닙니다.',
      '금융 보고서·원장·공급사 원문은 여러 파일입니다. 독립 신뢰키 전달까지 포함한 단일 완결 증거 패키지가 아닙니다.',
      'temporaryDatabaseRetained: 합성 실행 폴더는 보존합니다. 개인 설정·기존 데이터·비밀 파일은 사용하지 않습니다.',
    ],
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--output')) throw Error('Usage: node scripts/portfolio-governance-demo.mjs [--output NEW_REPORT.json]');
  if (args.length && existsSync(resolve(args[1]))) throw Error('Refusing to overwrite an existing portfolio report');
  const result = await runPortfolioGovernanceDemo();
  if (args.length) writeFileSync(resolve(args[1]), JSON.stringify(result, null, 2) + '\n', {flag: 'wx'});
  console.log(JSON.stringify(args.length ? {passed: result.passed, caseCount: result.caseCount, passedCases: result.passedCases, artifactDirectory: result.artifactDirectory, report: resolve(args[1])} : result, null, 2));
  if (!result.passed) process.exitCode = 1;
}
