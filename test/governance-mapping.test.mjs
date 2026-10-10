import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {canonical} from '../src/crypto.mjs';
import {keyFingerprint} from '../src/dsse.mjs';
import {LIMITS, buildMappingRequest, governanceCatalog, mappingOutputSchema, outputMatchesTruth, resolveMapping, retrieveRequirements,
  ruleMapping, validateMappingOutput} from '../src/governance-mapping.mjs';
import {applyReviewDecisions, buildDataset, governanceAdmission, loadSplits, reviewSheet, rowEligibility, trainingRows}
  from '../src/governance-mapping-data.mjs';
import {DECODING, GATE, PINNED_GGUF, assessGovernanceReport, baselineOutput, beats, buildComparisonReport, evaluateOutputs, hashOf,
  variantRequests} from '../src/governance-mapping-eval.mjs';
import {ROLE_DIR, adapterField, governanceModelStatus, modelVersionField, promoteGovernanceCandidate, provenanceOf, verifyPromotion,
  createGovernanceMapper} from '../src/governance-model.mjs';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';
import {assessGovernanceReport as fromModelEvaluate} from '../scripts/model-evaluate.mjs';
import {promoteGovernanceCandidate as fromModelPromote} from '../scripts/model-promote.mjs';

const sha256 = text => createHash('sha256').update(text).digest('hex');
const committed = readFileSync('data/governance-mapping/v1/dataset.jsonl', 'utf8').trim().split('\n').map(line => JSON.parse(line));
const dataset = buildDataset();
const reviewer = {reviewerId: 'test-reviewer', reviewedAt: '2026-10-01T00:00:00.000Z', piiReviewed: true, sourceConsent: true};
// In-memory approvals for exercising the gate. Nothing here is written back: the committed drafted rows stay UNREVIEWED.
const approveAll = rows => applyReviewDecisions(rows,
  rows.filter(r => r.labelSource === 'claude_drafted').map(r => ({id: r.id, decision: 'approve'})), reviewer).rows;
const gold = row => JSON.stringify({abstain: row.truth.abstain, mappings: row.truth.mappings.map(m => ({requirementId: m.requirementId, relation: m.relation,
  evidenceLocator: m.evidenceLocators[0], confidence: 'high'}))});
const receipt = (rows, variant, outputs, extra = {}) => ({schemaVersion: 1, source: 'isolated_llama_cpp_batch', variant, operator: 'operator-a',
  modelFile: PINNED_GGUF.file, modelSha256: PINNED_GGUF.sha256, adapterFile: variant === 'candidate' ? 'governance-mapping-lora.gguf' : null,
  adapterSha256: variant === 'candidate' ? 'c'.repeat(64) : null, server: {binarySha256: 'd'.repeat(64), buildInfo: 'test', contextTokens: 2048, gpuLayers: 99},
  isolation: {networkInterfaces: ['lo'], verified: true}, decoding: {...DECODING}, requestsSha256: hashOf(variantRequests(rows, variant)),
  outputsSha256: hashOf(outputs), count: rows.length, failures: 0, usage: {}, startedAt: 'x', finishedAt: 'y', ...extra});
function report(rows, candidateOutput, {preparedBy = 'operator-a', receiptExtra = {}} = {}) {
  const variants = {};
  for (const v of ['always_abstain', 'rules_only']) variants[v] = {outputs: Object.fromEntries(rows.map(r => [r.id, baselineOutput(v, r)]))};
  for (const v of ['zero_shot', 'retrieval', 'retrieval_constrained', 'candidate']) {
    const outputs = Object.fromEntries(rows.map(r => [r.id, v === 'candidate' ? candidateOutput(r) : baselineOutput('rules_only', r)]));
    variants[v] = {outputs, receipt: receipt(rows, v, outputs, v === 'candidate' ? receiptExtra : {})};
  }
  return buildComparisonReport(rows, variants, {preparedBy});
}

test('catalog: 55 requirements from the shipped tables, schema enumerates exactly those IDs and the supplied locators', () => {
  const catalog = governanceCatalog();
  assert.equal(catalog.ids.length, 55);
  assert.deepEqual(Object.fromEntries(['eu-ai-act-logging', 'kr-ai-basic-act', 'isms-p'].map(f => [f, catalog.entries.filter(e => e.framework === f).length])),
    {'eu-ai-act-logging': 10, 'kr-ai-basic-act': 18, 'isms-p': 27});
  const schema = mappingOutputSchema({locators: ['doc:a#1']}), item = schema.properties.mappings.items.properties;
  assert.deepEqual(item.requirementId.enum, catalog.ids);
  assert.deepEqual(item.evidenceLocator.enum, ['doc:a#1']);
  assert.equal(schema.properties.mappings.maxItems, LIMITS.mappings);
  const ok = {abstain: false, mappings: [{requirementId: 'EU-AIA-12-1', relation: 'supports', evidenceLocator: 'doc:a#1', confidence: 'high'}]};
  assert.deepEqual(validateMappingOutput(ok, {locators: ['doc:a#1']}), ok);
  const bad = (change, code) => assert.throws(() => validateMappingOutput(change(structuredClone(ok)), {locators: ['doc:a#1']}), e => e.code === code);
  bad(o => { o.mappings[0].requirementId = 'EU-AIA-99'; return o; }, 'mapping_requirement_unknown');
  bad(o => { o.mappings[0].evidenceLocator = 'doc:other'; return o; }, 'mapping_locator_unknown');
  bad(o => { o.abstain = true; return o; }, 'mapping_abstain_conflict');
  bad(o => { o.mappings.push({...o.mappings[0]}); return o; }, 'mapping_duplicate');
  bad(o => { o.mappings[0].relation = 'complies'; return o; }, 'mapping_relation_invalid');
  bad(o => ({...o, note: 'x'}), 'mapping_output_fields');
});

test('rules decide structured evidence; a model answer for a rule item is refused', () => {
  const item = {kind: 'structured', locators: ['record:a'], evidence: {type: 'record', name: 'agent_stop_order'}};
  const rule = ruleMapping(item);
  assert.ok(rule.mappings.length > 0 && rule.mappings.every(m => m.evidenceLocator === 'record:a'));
  assert.equal(resolveMapping(item).provenance, 'rule');
  assert.throws(() => resolveMapping(item, {abstain: true, mappings: []}), e => e.code === 'rule_override_refused');
  assert.throws(() => buildMappingRequest(item, {variant: 'candidate'}), e => e.code === 'rule_determined_item');
});

test('dataset: deterministic, equal to the committed file, drafted rows never marked reviewed, no split leakage', () => {
  assert.equal(canonical(dataset), canonical([...committed].sort((a, b) => (a.id < b.id ? -1 : 1))));
  const derived = dataset.filter(r => r.labelSource === 'derived_mapping_table'), drafted = dataset.filter(r => r.labelSource === 'claude_drafted');
  assert.equal(derived.length, 288);
  assert.equal(drafted.length, 219);
  assert.ok(drafted.every(r => r.humanReviewed === false && r.reviewStatus === 'UNREVIEWED' && r.reviewerId === null && r.synthetic === true));
  assert.ok(derived.every(r => r.reviewStatus === 'NOT_REQUIRED_DERIVED' && r.humanReviewed === false && rowEligibility(r).basis === 'derived'));
  // Drafted rows are split by requirement (splits.json); derived rows by text, stratified so each test requirement is also learned.
  const splits = loadSplits();
  for (const r of drafted) for (const m of r.truth.mappings) {
    const s = splits.get(m.requirementId);
    if (s === 'test') assert.equal(r.split, 'test', r.id);
    if (s === 'validation') assert.notEqual(r.split, 'tune', r.id);
  }
  const tuned = new Set(derived.filter(r => r.split === 'tune').flatMap(r => r.truth.mappings.map(m => m.requirementId)));
  const tested = derived.filter(r => r.split === 'test' && !r.truth.abstain);
  assert.ok(tested.length >= 30);
  for (const r of tested) for (const m of r.truth.mappings) assert.ok(tuned.has(m.requirementId), `${r.id} ${m.requirementId} learned`);
  assert.equal(new Set(derived.map(r => r.familyId)).size, derived.length - derived.filter(r => r.truth.abstain).length
    + new Set(derived.filter(r => r.truth.abstain).map(r => r.familyId)).size);
  const admission = governanceAdmission(dataset);
  assert.equal(admission.admitted, false);
  assert.ok(!admission.reasons.some(x => /leakage/.test(x)));
  assert.deepEqual(Object.fromEntries(Object.entries(admission.counts).map(([s, c]) => [s, [c.eligible, c.excludedUnreviewed]])),
    {tune: [194, 147], validation: [35, 15], test: [59, 57]});
  assert.throws(() => trainingRows(dataset), /governance_training_admission_failed/);
});

test('review: explicit per-row decisions with the reviewer attestations; rejection drops, silence keeps a row unreviewed', () => {
  const rows = dataset.filter(r => r.labelSource === 'claude_drafted').slice(0, 3);
  assert.match(reviewSheet(rows).split('\n')[0], /^id\tsplit\tkind\tlocators\ttext\tcandidate_label\tforbidden_by_injection\tdecision\tnote$/);
  assert.throws(() => applyReviewDecisions(rows, [{id: rows[0].id, decision: 'approve'}], {...reviewer, piiReviewed: false}), /review_attestation_required/);
  assert.throws(() => applyReviewDecisions(rows, [{id: rows[0].id, decision: 'yes'}], reviewer), /review_decision_invalid/);
  const result = applyReviewDecisions(rows, [{id: rows[0].id, decision: 'approve'}, {id: rows[1].id, decision: 'reject', note: 'wrong article'}], reviewer);
  assert.equal(result.rows.length, 2);
  const [approved, untouched] = [result.rows.find(r => r.id === rows[0].id), result.rows.find(r => r.id === rows[2].id)];
  assert.equal(rowEligibility(approved).eligible, true);
  assert.equal(approved.reviewerId, 'test-reviewer');
  assert.equal(rowEligibility(untouched).reason, 'not_human_reviewed');
  assert.equal(rowEligibility({...approved, prompt: approved.prompt + ' changed'}).eligible, false);
  assert.equal(rowEligibility({...dataset.find(r => r.labelSource === 'derived_mapping_table'), truth: {abstain: true, mappings: []}}).reason,
    'derivation_mismatch');
});

test('training rows only after admission; the held-out test split never reaches the trainer', () => {
  const rows = trainingRows(approveAll(dataset));
  assert.ok(rows.length >= 350 && rows.every(r => r.split !== 'test'));
  for (const r of rows.slice(0, 20)) {
    assert.equal(r.messages.length, 2);
    const target = JSON.parse(r.target), request = JSON.parse(r.messages[1].content);
    assert.ok(target.mappings.every(m => request.evidence.locators.includes(m.evidenceLocator)));
  }
});

test('metrics on a hand-checked case: precision, recall, exact match, abstention, calibration', () => {
  const row = (id, mappings, extra = {}) => ({id, prompt: 'x', evidence: [{id: 'doc:a', kind: 'document_excerpt'}],
    truth: {abstain: mappings.length === 0, mappings: mappings.map(([requirementId, relation]) => ({requirementId, relation, evidenceLocators: ['doc:a']})),
      ...extra}});
  const rows = [row('r1', [['EU-AIA-12-1', 'supports'], ['KR-33', 'supports']]), row('r2', []),
    row('r3', [['KR-31-1', 'contradicts']], {forbidden: ['KR-33']})];
  const out = (...mappings) => JSON.stringify({abstain: !mappings.length, mappings: mappings.map(([requirementId, relation, confidence]) => ({requirementId,
    relation, evidenceLocator: 'doc:a', confidence}))});
  const m = evaluateOutputs(rows, {r1: out(['EU-AIA-12-1', 'supports', 'high']), r2: out(['ISMS-P-2.9.4', 'supports', 'low']),
    r3: out(['KR-31-1', 'supports', 'medium'], ['KR-33', 'supports', 'high'])});
  assert.deepEqual([m.tp, m.fp, m.fn], [1, 3, 2]);
  assert.equal(m.precision, 0.25);
  assert.equal(m.recall, 1 / 3);
  assert.equal(m.exactMatch, 0);
  assert.equal(m.abstention.mustAbstainCorrect, 0);
  assert.equal(m.safety.injectionResisted.rate, 0);
  assert.deepEqual([m.calibration.buckets.high.n, m.calibration.buckets.high.correct], [2, 1]);
  assert.ok(Math.abs(m.calibration.ece - (0.5 * 0.4 + 0.25 * 0.5 + 0.25 * 0.75)) < 1e-12);
  assert.equal(evaluateOutputs(rows, {r1: 'not json', r2: out(), r3: out()}).safety.schemaValid.rate, 2 / 3);
});

test('baselines: always-abstain abstains; rules-only maps literal table identifiers only', () => {
  const r = dataset.find(x => x.split === 'test');
  assert.deepEqual(JSON.parse(baselineOutput('always_abstain', r)), {abstain: true, mappings: []});
  const probe = {...r, prompt: 'the console writes agent_stop_order records', evidence: [{id: 'doc:p', kind: 'document_excerpt'}]};
  const mapped = JSON.parse(baselineOutput('rules_only', probe));
  assert.ok(mapped.mappings.length > 0 && mapped.mappings.every(m => m.evidenceLocator === 'doc:p'));
  assert.equal(JSON.parse(baselineOutput('rules_only', {...probe, prompt: 'an interaction was recorded'})).abstain, true);
  assert.equal(retrieveRequirements('로그 자동 기록 보관').length, LIMITS.candidates);
  assert.equal(beats({precision: 0.95, recall: 0.5}, {precision: 1, recall: 0.07}), false);
  assert.equal(beats({precision: 1, recall: 0.5}, {precision: 1, recall: 0.07}), true);
  assert.equal(beats({precision: 0.95, recall: 0.5}, {precision: null, recall: 0}), true);
  assert.equal(beats({precision: 0.95, recall: 0.4}, {precision: 0.9, recall: 0.5}), false);
});

const testRows = approveAll(dataset).filter(r => r.split === 'test');
const passing = report(testRows, gold);

test('gate: a measured candidate that beats every baseline passes; worse precision, lower coverage and unmeasured runs fail', () => {
  const verdict = assessGovernanceReport(passing);
  assert.deepEqual(verdict.reasons, []);
  assert.equal(verdict.eligible, true);
  assert.ok(verdict.gateItems >= GATE.minItems && verdict.reviewedFreeText >= GATE.minReviewedFreeText);
  assert.equal(fromModelEvaluate, assessGovernanceReport);
  // One wrong mapping on an item rules-only answered loses the matched comparison (docs/governance-model.md, gate rule 4).
  const rulesAnswered = testRows.find(r => JSON.parse(baselineOutput('rules_only', r)).mappings.length > 0 && rowEligibility(r).eligible);
  const wrongOnce = report(testRows, r => (r.id !== rulesAnswered.id ? gold(r)
    : JSON.stringify({abstain: false, mappings: [{requirementId: 'KR-33', relation: 'supports', evidenceLocator: r.evidence[0].id, confidence: 'high'}]})));
  assert.ok(assessGovernanceReport(wrongOnce).reasons.includes('does not beat rules_only on precision (matched_coverage: matched_precision_lower)'));
  const silent = report(testRows, () => JSON.stringify({abstain: true, mappings: []}));
  assert.equal(assessGovernanceReport(silent).eligible, false);
  assert.ok(assessGovernanceReport(report(testRows, gold, {receiptExtra: {isolation: {networkInterfaces: ['lo', 'eth0'], verified: false}}}))
    .reasons.includes('candidate: isolation_not_verified'));
  const tampered = structuredClone(passing);
  tampered.variants.candidate.outputs[testRows[0].id] = '{}';
  assert.throws(() => assessGovernanceReport(tampered), /governance_report_outputs_invalid/);
  const unreviewed = report(dataset.filter(r => r.split === 'test'), gold);
  assert.ok(assessGovernanceReport(unreviewed).reasons.some(x => /human-reviewed free-text items 0/.test(x)));
});

const {privateKey, publicKey} = generateKeyPairSync('ed25519');
const signer = {keyid: keyFingerprint(publicKey), sign: m => cryptoSign(null, m, privateKey)};
const approval = (extra = {}) => ({reportSha256: hashOf(passing), approved: true, reviewerId: 'approver-b', reviewedAt: '2026-10-02T00:00:00.000Z',
  semanticGroundingReviewed: true, koreanQualityReviewed: true, privacyReviewed: true, injectionReviewed: true, mappingSampleReviewed: true, ...extra});

test('promotion: independent signed human approval; the receipt sets the role fields; status follows the verified receipt only', async () => {
  assert.equal(fromModelPromote, promoteGovernanceCandidate);
  const promote = a => promoteGovernanceCandidate({report: passing, approval: a, signer, adapterFile: 'models/governance-mapping-lora.gguf'});
  await assert.rejects(promote(approval({reviewerId: 'operator-a'})), /approval_not_independent/);
  await assert.rejects(promote(approval({privacyReviewed: false})), /independent_human_approval_required/);
  await assert.rejects(promote(approval({reportSha256: 'e'.repeat(64)})), /independent_human_approval_required/);
  await assert.rejects(promoteGovernanceCandidate({report: report(testRows, () => JSON.stringify({abstain: true, mappings: []})), approval: approval(), signer,
    adapterFile: 'models/governance-mapping-lora.gguf'}), /candidate_evaluation_failed/);
  const envelope = await promote(approval());
  const adapterSha = 'c'.repeat(64);
  const roleFields = {adapter: adapterField(adapterSha), modelVersion: modelVersionField(adapterSha), evalStatus: 'PROMOTED_HUMAN_APPROVED'};
  const trust = [{reviewerId: 'approver-b', keyid: signer.keyid, verify: (m, s) => s.length === 64 && cryptoVerify(null, m, publicKey, s)}];
  assert.equal(verifyPromotion({envelope, report: passing, role: roleFields, trust}).approval.reviewerId, 'approver-b');
  assert.throws(() => verifyPromotion({envelope, report: passing, role: {...roleFields, evalStatus: 'UNREVIEWED'}, trust}),
    e => e.code === 'role_package_not_from_receipt');
  assert.throws(() => verifyPromotion({envelope, report: passing, role: roleFields, trust: [{...trust[0], reviewerId: 'someone-else'}]}),
    e => e.code === 'promotion_signer_not_approver');
  const other = generateKeyPairSync('ed25519');
  const untrusted = {...envelope, signatures: [{keyid: 'x', sig: cryptoSign(null, Buffer.from('x'), other.privateKey).toString('base64')}]};
  assert.throws(() => verifyPromotion({envelope: untrusted, report: passing, role: roleFields, trust}), /DSSE signature verification failed/);

  // Status reads only verified files under its root: a temporary repository copy of the role directory.
  mkdirSync('.test-runs', {recursive: true});
  const root = mkdtempSync(resolve('.test-runs', 'governance-model-')), dir = join(root, ROLE_DIR);
  mkdirSync(dir, {recursive: true});
  const role = JSON.parse(readFileSync(join(ROLE_DIR, 'role.json'), 'utf8'));
  const files = {receipt: JSON.stringify(envelope), report: JSON.stringify(passing)};
  writeFileSync(join(root, 'promotion.dsse.json'), files.receipt);
  writeFileSync(join(root, 'report.json'), files.report);
  writeFileSync(join(dir, 'promotion-trust.json'), JSON.stringify({schemaVersion: 1, keys: [{reviewerId: 'approver-b',
    publicKeyPem: publicKey.export({format: 'pem', type: 'spki'})}]}));
  const config = promotion => JSON.stringify({schemaVersion: 1, task: 'governance-mapping', taskVersion: 1, baselineReport: null, promotion});
  const promotionEntry = {receiptPath: 'promotion.dsse.json', receiptSha256: sha256(files.receipt),
    reportPath: 'report.json', reportSha256: sha256(files.report)};
  writeFileSync(join(dir, 'role.json'), JSON.stringify(role));
  writeFileSync(join(dir, 'governance-mapping.json'), config(null));
  assert.deepEqual([governanceModelStatus({root}).mode, governanceModelStatus({root}).reasons], ['off', ['no_measured_report']]);
  writeFileSync(join(dir, 'governance-mapping.json'), config(promotionEntry));
  assert.deepEqual(governanceModelStatus({root}).reasons, ['role_package_not_from_receipt']);
  writeFileSync(join(dir, 'role.json'), JSON.stringify({...role, ...roleFields}));
  const status = governanceModelStatus({root});
  assert.equal(status.mode, 'promoted_adapter');
  assert.equal(status.adapter.sha256, adapterSha);
  assert.equal(status.promotion.reviewerId, 'approver-b');
  assert.equal(status.humanConfirmationRequired, true);
  assert.equal(status.qualityClaimAllowed, false);
  writeFileSync(join(dir, 'governance-mapping.json'), config({...promotionEntry, reportSha256: 'f'.repeat(64)}));
  assert.deepEqual([governanceModelStatus({root}).mode, governanceModelStatus({root}).reasons], ['off', ['promotion_file_changed']]);
  writeFileSync(join(dir, 'governance-mapping.json'), config(null));
  assert.deepEqual(governanceModelStatus({root}).reasons, ['role_adapter_without_promotion']);
});
test('repository status is off until a measured report exists, and the mapper never runs the model when off', async () => {
  const status = governanceModelStatus();
  assert.equal(status.mode, 'off');
  assert.ok(status.reasons.includes('no_measured_report'));
  assert.equal(status.catalog.requirements, 55);
  assert.deepEqual(status.dataset.needsHumanReview, 219);
  assert.equal(runGovernanceMappingCommand(['status']).mode, 'off');
  let called = 0;
  const mapper = createGovernanceMapper({status, infer: async () => { called++; return {content: '{}'}; }});
  const off = await mapper({kind: 'document_excerpt', locators: ['doc:a'], text: '모든 도구 호출을 자동으로 기록한다'});
  assert.deepEqual([off.state, off.abstain, called], ['model_off', true, 0]);
  const rule = await mapper({kind: 'structured', locators: ['record:a'], evidence: {type: 'record', name: 'agent_stop_order'}});
  assert.equal(rule.provenance, 'rule');
  const on = createGovernanceMapper({status: {...status, mode: 'base_retrieval_constrained'}, infer: async q => {
    called++;
    assert.equal(q.adapter, false);
    assert.equal(q.schema.properties.mappings.items.properties.evidenceLocator.enum[0], 'doc:a');
    const mapping = {requirementId: 'EU-AIA-12-1', relation: 'supports', evidenceLocator: 'doc:a', confidence: 'high'};
    return {content: JSON.stringify({abstain: false, mappings: [mapping]})};
  }});
  const result = await on({kind: 'document_excerpt', locators: ['doc:a'], text: '모든 도구 호출을 자동으로 기록한다'});
  assert.equal(result.state, 'advisory_unconfirmed');
  assert.deepEqual(result.mappings[0].provenance, provenanceOf({...status, mode: 'base_retrieval_constrained'}));
  assert.equal(result.mappings[0].provenance.source, 'model');
  assert.ok(outputMatchesTruth({abstain: true}, {abstain: true, mappings: []}, {locators: ['doc:a']}));
});
