// Governance-mapping model console (docs/governance-model.md): the review queue's signed decisions, the export the trainer reads,
// and the signed factsheets. The reviewers here are the generated local test principals (alpha-reviewer, alpha-admin); nothing is
// written back to the repository dataset, whose drafted rows stay UNREVIEWED.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign as cryptoSign} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {keyFingerprint} from '../src/dsse.mjs';
import {QUEUE_DECISION_TYPE, applyReviewDecisions, buildDataset, queueBinding, rowEligibility, shakedownRows, toJsonl}
  from '../src/governance-mapping-data.mjs';
import {DECODING, PINNED_GGUF, baselineOutput, buildComparisonReport, hashOf, variantRequests} from '../src/governance-mapping-eval.mjs';
import {ROLE_DIR, promoteGovernanceCandidate} from '../src/governance-model.mjs';
import {buildFactsheet, evaluationFactsheetRequest, promotionFactsheetRequest, trainingFactsheetRequest} from '../src/governance-factsheets.mjs';
import {draftedRows, queueItem, repositoryDataset} from '../src/governance-review-queue.mjs';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const dataset = buildDataset(), drafted = dataset.filter(r => r.labelSource === 'claude_drafted');
const draftedTest = drafted.filter(r => r.split === 'test');
function service(t, options = {}) {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-console-')), config = initialize(dir);
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8'),
    requirements: JSON.parse(readFileSync('data/requirements.json', 'utf8')), governanceModelConsole: {reportsDir: join(dir, 'reports'), ...options}});
  t.after(() => s.store.close());
  const token = id => config.principals.find(p => p.id === id).token;
  const call = async (id, method, path, body) => s.handle(method, new URL('http://localhost' + path), {authorization: 'Bearer ' + token(id)},
    body === undefined ? '' : JSON.stringify(body));
  return {s, call, dir};
}
const status = code => error => error.status === code;
const decision = (row, decisionValue, extra = {}) => ({rowId: row.id, decision: decisionValue, reviewedPayloadHash: queueBinding(row),
  attestPiiReviewed: true, attestSourceConsent: true, ...extra});

test('queue: one drafted row at a time with its hashes; reviewer/admin decide, others read or are refused; decisions are signed', async t => {
  const {s, call} = service(t);
  const view = await call('alpha-reviewer', 'GET', '/api/governance-model/review?split=test');
  const row = draftedTest.find(r => r.id === view.item.id);
  assert.ok(row, 'the queue serves a drafted test row');
  assert.equal(view.item.reviewedPayloadHash, queueBinding(row));
  assert.equal(view.item.text, row.prompt);
  // Review aids: every non-Korean drafted row has a reference translation and every shown requirement a plain explanation; neither is
  // part of the row the decision binds.
  for (const r of draftedRows(repositoryDataset())) {
    const shown = queueItem(r);
    assert.equal(Boolean(shown.textKo), r.language !== 'ko', `${r.id} translation`);
    for (const m of [...shown.draftedAnswer.mappings, ...shown.forbidden]) assert.ok(m.plain, `${r.id} ${m.requirementId} explanation`);
    assert.equal(shown.reviewedPayloadHash, queueBinding(r));
  }
  assert.deepEqual(view.progress.splits.test, {...view.progress.splits.test, drafted: 57, approved: 0, rejected: 0, pending: 57, eligible: 59,
    minimum: 100, neededApprovals: 41});
  assert.equal(view.progress.splits.test.gate.neededApprovals, 30);
  assert.equal(view.progress.splits.tune.neededApprovals, 106);
  assert.equal((await call('alpha-auditor', 'GET', '/api/governance-model/review')).viewer.mayDecide, false);
  await assert.rejects(call('alpha-agent', 'GET', '/api/governance-model/review'), status(403));
  await assert.rejects(call('alpha-auditor', 'POST', '/api/governance-model/review/decisions', decision(row, 'approve')), status(403));
  await assert.rejects(call('alpha-agent', 'POST', '/api/governance-model/review/decisions', decision(row, 'approve')), status(403));
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions', decision(row, 'approve', {attestPiiReviewed: false})),
    status(400));
  // No editing: an answer, a reviewer identity or a time cannot be supplied.
  for (const extra of [{approvedOutput: {abstain: true, mappings: []}}, {reviewerId: 'someone-else'}, {reviewedAt: '2020-01-01T00:00:00.000Z'}]) {
    await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions', decision(row, 'approve', extra)), status(400));
  }
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions', decision(row, 'edit')), status(400));
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions',
    decision(row, 'approve', {reviewedPayloadHash: 'a'.repeat(64)})),
    status(409));
  const derived = dataset.find(r => r.labelSource === 'derived_mapping_table');
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions', decision(derived, 'approve')), status(404));

  const before = Date.now();
  const first = await call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions', decision(row, 'approve', {note: '맞음'}));
  assert.equal(first.decision.reviewerId, 'alpha-reviewer');
  assert.equal(first.decision.reviewerRole, 'reviewer');
  assert.equal(first.decision.reviewedPayloadHash, queueBinding(row));
  assert.ok(Date.parse(first.decision.reviewedAt) >= before - 1000);
  const ledger = s.store.ledgerObjects('alpha', QUEUE_DECISION_TYPE);
  assert.equal(ledger.length, 1);
  const record = s.store.rawBundle('alpha').records.find(r => r.type === QUEUE_DECISION_TYPE);
  assert.equal(record.principal, 'alpha-reviewer');
  // A second decision must name the one it replaces.
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions', decision(row, 'reject')), status(409));
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/review/decisions', decision(row, 'reject', {supersedes: 'b'.repeat(64)})),
    status(409));
  const second = await call('alpha-admin', 'POST', '/api/governance-model/review/decisions', decision(row, 'reject', {supersedes: first.decisionHash}));
  assert.equal(second.decision.supersedes, first.decisionHash);
  const after = await call('alpha-reviewer', 'GET', '/api/governance-model/review?split=test');
  assert.deepEqual([after.progress.splits.test.rejected, after.progress.splits.test.approved, after.progress.splits.test.pending], [1, 0, 56]);
  assert.notEqual(after.item.id, row.id);
  const item = await call('alpha-reviewer', 'GET', `/api/governance-model/review/items/${row.id}`);
  assert.equal(item.item.previousDecision.decision, 'reject');
  assert.equal(item.item.previousDecisionHash, second.decisionHash);
  assert.equal((await call('alpha-auditor', 'GET', '/api/governance-model/review/decisions')).items.length, 1);
  // The repository rows were not touched by any of this.
  assert.ok(repositoryDataset().filter(r => r.labelSource === 'claude_drafted').every(r => r.humanReviewed === false && r.reviewStatus === 'UNREVIEWED'));
});

test('export-reviewed: signed decisions from the verified vault export become reviewed rows through importHumanReviews', async t => {
  const {s, call, dir} = service(t);
  const [a, b, c, d] = draftedTest;
  for (const [who, row, value] of [['alpha-reviewer', a, 'approve'], ['alpha-reviewer', b, 'approve'],
    ['alpha-admin', c, 'approve'], ['alpha-reviewer', d, 'reject']]) {
    await call(who, 'POST', '/api/governance-model/review/decisions', decision(row, value));
  }
  const bundle = await call('alpha-admin', 'GET', '/api/export'), file = join(dir, 'export.json');
  writeFileSync(file, JSON.stringify(bundle));
  const out = join(dir, 'reviewed.jsonl'), args = ['--data', 'data/governance-mapping/v1/dataset.jsonl', '--bundle', file, '--trust-anchor',
    join(dir, 'trust-anchor.pem')];
  const result = runGovernanceMappingCommand(['export-reviewed', ...args, '--out', out]);
  assert.deepEqual([result.decisions, result.approved, result.rejected, result.skipped.length, result.stillUnreviewed], [4, 3, 1, 0, 215]);
  const rows = readFileSync(out, 'utf8').trim().split('\n').map(line => JSON.parse(line)), byId = new Map(rows.map(r => [r.id, r]));
  assert.equal(rows.length, dataset.length - 1);
  assert.equal(byId.has(d.id), false);
  for (const [row, who] of [[a, 'alpha-reviewer'], [c, 'alpha-admin']]) {
    const reviewed = byId.get(row.id);
    assert.deepEqual([reviewed.humanReviewed, reviewed.reviewStatus, reviewed.reviewerId], [true, 'HUMAN_REVIEWED', who]);
    assert.equal(reviewed.reviewedPayloadHash, queueBinding(row));
    assert.equal(rowEligibility(reviewed).basis, 'human_reviewed');
  }
  assert.equal(byId.get(draftedTest[4].id).humanReviewed, false);
  assert.equal(result.admission.counts.test.humanReviewed, 3);
  // A decision whose signed record was changed fails the export's chain check.
  const tampered = structuredClone(bundle), at = tampered.records.findIndex(r => r.type === QUEUE_DECISION_TYPE && r.payload.decision === 'reject');
  tampered.records[at].payload.decision = 'approve';
  writeFileSync(file, JSON.stringify(tampered));
  assert.throws(() => runGovernanceMappingCommand(['export-reviewed', ...args, '--out', join(dir, 'tampered.jsonl')]), /Record digest mismatch/);
  // A decision is applied only to the row content it was made on.
  writeFileSync(file, JSON.stringify(bundle));
  const changed = join(dir, 'changed.jsonl');
  writeFileSync(changed, toJsonl(dataset.map(r => (r.id === a.id ? {...r, prompt: r.prompt + ' (changed)'} : r))));
  const stale = runGovernanceMappingCommand(['export-reviewed', '--data', changed, ...args.slice(2), '--out', join(dir, 'stale.jsonl')]);
  assert.deepEqual(stale.skipped, [{id: a.id, reason: 'row_changed_since_decision'}]);
  assert.equal(stale.approved, 2);
  // Another vault's key does not verify the export.
  const other = generateKeyPairSync('ed25519').publicKey.export({format: 'pem', type: 'spki'}), otherFile = join(dir, 'other.pem');
  writeFileSync(otherFile, other);
  assert.throws(() => runGovernanceMappingCommand(['export-reviewed', '--data', 'data/governance-mapping/v1/dataset.jsonl', '--bundle', file,
    '--trust-anchor', otherFile, '--out', join(dir, 'other.jsonl')]));
  assert.ok(s.store);
});

// ---------- factsheets ----------
const reviewer = {reviewerId: 'test-reviewer', reviewedAt: '2026-10-01T00:00:00.000Z', piiReviewed: true, sourceConsent: true};
const reviewedRows = applyReviewDecisions(dataset, drafted.map(r => ({id: r.id, decision: 'approve'})), reviewer).rows;
const testRows = reviewedRows.filter(r => r.split === 'test');
const gold = row => JSON.stringify({abstain: row.truth.abstain, mappings: row.truth.mappings.map(m => ({requirementId: m.requirementId, relation: m.relation,
  evidenceLocator: m.evidenceLocators[0], confidence: 'high'}))});
const receipt = (variant, outputs, adapterSha256) => ({schemaVersion: 1, source: 'isolated_llama_cpp_batch', variant, operator: 'operator-a',
  modelFile: PINNED_GGUF.file, modelSha256: PINNED_GGUF.sha256, adapterFile: variant === 'candidate' ? 'lora.gguf' : null,
  adapterSha256: variant === 'candidate' ? adapterSha256 : null, server: {binarySha256: 'd'.repeat(64), buildInfo: 'test', contextTokens: 2048, gpuLayers: 99},
  isolation: {networkInterfaces: ['lo'], verified: true}, decoding: {...DECODING}, requestsSha256: hashOf(variantRequests(testRows, variant)),
  outputsSha256: hashOf(outputs), count: testRows.length, failures: 0, usage: {}, startedAt: 'x', finishedAt: 'y'});
export function measuredReport({adapterSha256 = 'c'.repeat(64), candidate = gold, withCandidate = true} = {}) {
  const variants = {};
  for (const v of ['always_abstain', 'rules_only']) variants[v] = {outputs: Object.fromEntries(testRows.map(r => [r.id, baselineOutput(v, r)]))};
  for (const v of ['zero_shot', 'retrieval', 'retrieval_constrained', ...(withCandidate ? ['candidate'] : [])]) {
    const outputs = Object.fromEntries(testRows.map(r => [r.id, v === 'candidate' ? candidate(r) : baselineOutput('rules_only', r)]));
    variants[v] = {outputs, receipt: receipt(v, outputs, adapterSha256)};
  }
  return buildComparisonReport(testRows, variants, {preparedBy: 'operator-a'});
}
const RECIPE = {rank: 8, alpha: 16, dropout: 0.05, targetModules: ['q_proj'], sequenceLength: 1536, batchSize: 1, gradientAccumulationSteps: 8, epochs: 2,
  learningRatePerMillion: 200, warmupStepsPer1000: 30, seed: 42, saveSteps: 5};
const trainingReceipt = (text, runMode) => ({schemaVersion: 2, status: runMode === 'shakedown' ? 'shakedown_not_promotable' : 'trained_candidate',
  identity: {task: 'governance-mapping', baseRepository: 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct', baseRevision: 'a'.repeat(40),
    baseArtifactLockSha256: 'b'.repeat(64), datasetSha256: sha256(Buffer.from(text)), trainerSha256: 'e'.repeat(64), image: 'sha256:' + 'f'.repeat(64),
    gpuMemoryFractionPercent: 65, runMode, ...RECIPE},
  globalStep: 54, trainingMetrics: {train_runtime: 1480.5, train_loss: 0.41, cudaPeakAllocatedMiB: 7123},
    timing: {loadSeconds: 95, trainSeconds: 1480, totalSeconds: 1590},
  trainingRunCompleted: true, heldOutTestUsedForTraining: false, qualityClaimAllowed: false, promotionAllowed: false});

test('factsheets: shakedown recorded as never promotable; evaluation numbers recomputed by the vault; listed in model status', async t => {
  const {call, dir} = service(t);
  const shakedownText = toJsonl(shakedownRows(dataset)), shakedownAdapter = '9'.repeat(64);
  const shakedown = trainingFactsheetRequest({receipt: trainingReceipt(shakedownText, 'shakedown'),
    trainingSet: shakedownText, adapterGgufSha256: shakedownAdapter});
  await assert.rejects(call('alpha-auditor', 'POST', '/api/governance-model/factsheets', shakedown), status(403));
  const recorded = (await call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', shakedown)).factsheet;
  assert.deepEqual([recorded.kind, recorded.runMode, recorded.label, recorded.promotable, recorded.qualityResult],
    ['training', 'shakedown', 'shakedown', false, false]);
  assert.equal(recorded.dataset.verification, 'reproduced_from_repository');
  assert.equal(recorded.dataset.byLabelSource.claude_drafted, 0);
  assert.equal(recorded.metrics.cudaPeakAllocatedMiB, 7123);
  assert.equal('train_loss' in recorded.metrics, false, 'a shakedown shows resource numbers only');
  assert.equal(recorded.operator.id, 'alpha-reviewer');
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', shakedown), status(409));
  // A shakedown receipt cannot be passed off as a candidate run, and its adapter cannot be claimed by a candidate run.
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/factsheets',
    {...shakedown, receipt: {...shakedown.receipt, status: 'trained_candidate'}}), status(400));
  const candidateText = toJsonl(shakedownRows(dataset).map(r => ({...r, runMode: 'candidate'})));
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', trainingFactsheetRequest({
    receipt: trainingReceipt(candidateText, 'candidate'), trainingSet: candidateText, adapterGgufSha256: shakedownAdapter})), status(409));
  const candidate = (await call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', trainingFactsheetRequest({
    receipt: trainingReceipt(candidateText, 'candidate'), trainingSet: candidateText}))).factsheet;
  assert.deepEqual([candidate.runMode, candidate.promotable, candidate.dataset.verification], ['candidate', true, 'operator_reported']);

  const passing = measuredReport();
  const evaluation = (await call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', evaluationFactsheetRequest(passing))).factsheet;
  assert.deepEqual([evaluation.label, evaluation.gate.eligible, evaluation.qualityResult], ['candidate_evaluation', true, true]);
  assert.equal(evaluation.metrics.candidate.precision, 1);
  assert.equal(evaluation.dataset.humanReviewedRows, 57);
  assert.equal(evaluation.dataset.withSignedQueueDecision, 0, 'test approvals here were not made in the queue');
  const forged = structuredClone(passing);
  forged.metrics.candidate.precision = 0.5;
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', evaluationFactsheetRequest(forged)), status(400));
  const ofShakedown = (await call('alpha-reviewer', 'POST', '/api/governance-model/factsheets',
    evaluationFactsheetRequest(measuredReport({adapterSha256: shakedownAdapter})))).factsheet;
  assert.deepEqual([ofShakedown.label, ofShakedown.promotable, ofShakedown.qualityResult, 'candidate' in ofShakedown.metrics, ofShakedown.gate.eligible],
    ['shakedown', false, false, false, false]);

  const runtime = await call('alpha-auditor', 'GET', '/api/model-runtime');
  assert.equal(runtime.factsheets.status, 'ok');
  assert.equal(runtime.factsheets.items.length, 4);
  const modelStatus = await call('alpha-auditor', 'GET', '/api/model-status');
  assert.deepEqual(modelStatus.factsheets.items.map(f => f.id).sort(), runtime.factsheets.items.map(f => f.id).sort());
  assert.equal(modelStatus.training.vaultRecords, 'governance_model_factsheets');
  // The experiment view: reports side by side, rows by label basis, shakedown evaluations without candidate numbers, history.
  mkdirSync(join(dir, 'reports'), {recursive: true});
  writeFileSync(join(dir, 'reports', 'candidate.json'), JSON.stringify(passing));
  writeFileSync(join(dir, 'reports', 'shakedown.json'), JSON.stringify(measuredReport({adapterSha256: shakedownAdapter})));
  writeFileSync(join(dir, 'reports', 'broken.json'), JSON.stringify({...passing, datasetSha256: 'f'.repeat(64)}));
  const view = await call('alpha-auditor', 'GET', '/api/governance-model/experiments');
  const byFile = Object.fromEntries(view.reports.map(r => [r.file, r]));
  assert.equal(byFile['broken.json'].status, 'unverified');
  assert.equal(byFile['candidate.json'].status, 'verified');
  assert.deepEqual(byFile['candidate.json'].variants, ['always_abstain', 'rules_only', 'zero_shot', 'retrieval', 'retrieval_constrained', 'candidate']);
  assert.deepEqual(byFile['candidate.json'].rowsByBasis, {human_reviewed: 57, derived: 59, not_eligible: 0});
  assert.equal(byFile['candidate.json'].variantsData.candidate.byBasis.human_reviewed.precision, 1);
  assert.ok(Object.keys(byFile['candidate.json'].variantsData.candidate.byFramework).length >= 2);
  assert.equal(byFile['candidate.json'].verdict.eligible, true);
  assert.equal(byFile['shakedown.json'].shakedown, true);
  assert.equal(byFile['shakedown.json'].variants.includes('candidate'), false);
  assert.equal(byFile['shakedown.json'].verdict.eligible, false);
  assert.ok(view.history.some(h => h.kind === 'factsheet_training' && h.label === 'shakedown' && h.promotable === false));
});

test('promotion factsheet: only a receipt signed by a trusted approver key, never for a shakedown adapter', async t => {
  mkdirSync('.test-runs', {recursive: true});
  const root = mkdtempSync(resolve('.test-runs', 'governance-trust-'));
  mkdirSync(join(root, ROLE_DIR), {recursive: true});
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  writeFileSync(join(root, ROLE_DIR, 'promotion-trust.json'), JSON.stringify({schemaVersion: 1, keys: [{reviewerId: 'approver-b',
    publicKeyPem: publicKey.export({format: 'pem', type: 'spki'})}]}));
  const signer = {keyid: keyFingerprint(publicKey), sign: m => cryptoSign(null, m, privateKey)}, passing = measuredReport();
  const approval = {reportSha256: hashOf(passing), approved: true, reviewerId: 'approver-b', reviewedAt: '2026-10-02T00:00:00.000Z',
    semanticGroundingReviewed: true, koreanQualityReviewed: true, privacyReviewed: true, injectionReviewed: true, mappingSampleReviewed: true};
  const envelope = await promoteGovernanceCandidate({report: passing, approval, signer, adapterFile: 'models/governance-mapping-lora.gguf'});
  // The repository trust list is empty: nothing can be recorded as promoted.
  assert.throws(() => buildFactsheet(promotionFactsheetRequest(envelope, passing), {principal: {id: 'x', role: 'reviewer'}, dataset: () => dataset}),
    e => e.code === 'promotion_trust_empty');
  const {call} = service(t, {root});
  const forged = {...envelope, signatures: [{keyid: 'k',
    sig: cryptoSign(null, Buffer.from('x'), generateKeyPairSync('ed25519').privateKey).toString('base64')}]};
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', promotionFactsheetRequest(forged)), status(409));
  const promoted = (await call('alpha-admin', 'POST', '/api/governance-model/factsheets', promotionFactsheetRequest(envelope, passing))).factsheet;
  assert.deepEqual([promoted.promoted, promoted.approver.reviewerId, promoted.operator.id, promoted.gate.verified],
    [true, 'approver-b', 'alpha-admin', 'report_reassessed']);
  assert.equal(promoted.adapter.ggufSha256, 'c'.repeat(64));
  // A shakedown adapter is never promotable, even with a signed receipt.
  const shakedownText = toJsonl(shakedownRows(dataset));
  const other = measuredReport({adapterSha256: '8'.repeat(64)});
  await call('alpha-reviewer', 'POST', '/api/governance-model/factsheets', trainingFactsheetRequest({receipt: trainingReceipt(shakedownText, 'shakedown'),
    trainingSet: shakedownText, adapterGgufSha256: '8'.repeat(64)}));
  const shakedownEnvelope = await promoteGovernanceCandidate({report: other, approval: {...approval, reportSha256: hashOf(other)}, signer,
    adapterFile: 'models/shakedown.gguf'});
  await assert.rejects(call('alpha-admin', 'POST', '/api/governance-model/factsheets', promotionFactsheetRequest(shakedownEnvelope, other)),
    e => e.status === 409 && /shakedown/.test(e.message));
});
