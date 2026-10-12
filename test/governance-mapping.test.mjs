import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {canonical} from '../src/crypto.mjs';
import {keyFingerprint} from '../src/dsse.mjs';
import {LIMITS, buildMappingRequest, governanceCatalog, mappingOutputSchema, nearestExamples, outOfScopePool, outOfScopeShown, outputMatchesTruth,
  resolveMapping, retrieveOutOfScope, retrieveRequirements, ruleMapping, validateMappingOutput} from '../src/governance-mapping.mjs';
import {applyReviewDecisions, baseDerivation, buildDataset, governanceAdmission, governanceExamples, itemOf, loadSplits, outOfScopeSources, reviewSheet,
  rowEligibility, trainingRows} from '../src/governance-mapping-data.mjs';
import {DECODING, DETERMINISTIC_BASELINES, GATE, MODEL_VARIANTS, PINNED_GGUF, RUNTIME_PROMPT_TOKENS, assessGovernanceReport, baselineOutput,
  baselineOutputs, beats, buildComparisonReport, evaluateOutputs, hashOf, outOfScopeSiblingAnswers, scoreItem, variantRequests}
  from '../src/governance-mapping-eval.mjs';
import {primaryModelPolicy} from '../src/model-policy.mjs';
import {ABSTAIN_OUTPUT, applyAbstention} from '../src/governance-abstention.mjs';
import {mappingDraft} from '../src/governance-mapping-assist.mjs';
import {ROLE_DIR, adapterField, governanceModelStatus, modelVersionField, promoteGovernanceCandidate, provenanceOf, verifyPromotion,
  createGovernanceMapper} from '../src/governance-model.mjs';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';
import {assessGovernanceReport as fromModelEvaluate} from '../scripts/model-evaluate.mjs';
import {promoteGovernanceCandidate as fromModelPromote} from '../scripts/model-promote.mjs';

// Governance-mapping tests see only the shipped source tables; a local-only (KOGL) table on this machine must not change them.
process.env.EVIDSCOPE_GOVERNANCE_LOCAL_TABLES ??= '.test-runs/no-local-tables';

const sha256 = text => createHash('sha256').update(text).digest('hex');
const committed = readFileSync('data/governance-mapping/v1/dataset.jsonl', 'utf8').trim().split('\n').map(line => JSON.parse(line));
// The committed dataset holds no local-only (KOGL) table rows, and says so to every reader; a local copy of such a table on this
// machine must not change what these tests see, so the calls below name the configuration instead of taking the module default.
const NO_LOCAL = {localTables: false};
const dataset = buildDataset(NO_LOCAL);
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
  for (const v of DETERMINISTIC_BASELINES) variants[v] = {outputs: baselineOutputs(rows, v)};
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
  assert.equal(derived.length, 870);
  assert.equal(drafted.length, 219);
  assert.ok(drafted.every(r => r.humanReviewed === false && r.reviewStatus === 'UNREVIEWED' && r.reviewerId === null && r.synthetic === true));
  assert.ok(derived.every(r => r.reviewStatus === 'NOT_REQUIRED_DERIVED' && r.humanReviewed === false && rowEligibility(r, NO_LOCAL).basis === 'derived'));
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
  assert.equal(admission.admitted, true);
  assert.equal(admission.qualityClaimAllowed, false);
  assert.ok(!admission.reasons.some(x => /leakage/.test(x)));
  assert.deepEqual(Object.fromEntries(Object.entries(admission.counts).map(([s, c]) => [s, [c.eligible, c.excludedUnreviewed]])),
    {tune: [559, 147], validation: [124, 15], test: [187, 57]});
  assert.ok(trainingRows(dataset).every(r => r.labelSource === 'derived_mapping_table' && r.split !== 'test'));
  assert.throws(() => trainingRows(dataset.slice(0, 80)), /governance_training_admission_failed/);
});

test('review: explicit per-row decisions with the reviewer attestations; rejection drops, silence keeps a row unreviewed', () => {
  const rows = dataset.filter(r => r.labelSource === 'claude_drafted').slice(0, 3);
  assert.match(reviewSheet(rows).split('\n')[0], /^id\tsplit\tkind\tlocators\ttext\tcandidate_label\tforbidden_by_injection\tdecision\tnote$/);
  assert.throws(() => applyReviewDecisions(rows, [{id: rows[0].id, decision: 'approve'}], {...reviewer, piiReviewed: false}), /review_attestation_required/);
  assert.throws(() => applyReviewDecisions(rows, [{id: rows[0].id, decision: 'yes'}], reviewer), /review_decision_invalid/);
  const result = applyReviewDecisions(rows, [{id: rows[0].id, decision: 'approve'}, {id: rows[1].id, decision: 'reject', note: 'wrong article'}], reviewer);
  assert.equal(result.rows.length, 2);
  const [approved, untouched] = [result.rows.find(r => r.id === rows[0].id), result.rows.find(r => r.id === rows[2].id)];
  assert.equal(rowEligibility(approved, NO_LOCAL).eligible, true);
  assert.equal(approved.reviewerId, 'test-reviewer');
  assert.equal(rowEligibility(untouched, NO_LOCAL).reason, 'not_human_reviewed');
  assert.equal(rowEligibility({...approved, prompt: approved.prompt + ' changed'}, NO_LOCAL).eligible, false);
  assert.equal(rowEligibility({...dataset.find(r => r.labelSource === 'derived_mapping_table'), truth: {abstain: true, mappings: []}}, NO_LOCAL).reason,
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

test('examples: the bank is the derived tune split; a row never sees itself; candidates are listed in id order', () => {
  const bank = governanceExamples(NO_LOCAL), byId = new Map(dataset.map(r => [r.id, r]));
  assert.ok(bank.length > 100 && bank.every(e => byId.get(e.id)?.split === 'tune' && byId.get(e.id).labelSource === 'derived_mapping_table'));
  const own = dataset.find(r => r.id === bank[0].id), item = {kind: own.evidence[0].kind, locators: own.evidence.map(e => e.id), text: own.prompt};
  const train = JSON.parse(buildMappingRequest(item, {variant: 'candidate', examples: bank, excludeId: own.id}).messages[1].content);
  assert.equal(train.examples.length, LIMITS.examples);
  assert.ok(!train.examples.some(e => e.text === own.prompt));
  assert.equal(JSON.parse(buildMappingRequest(item, {variant: 'candidate', examples: bank}).messages[1].content).examples[0].text, own.prompt);
  const ids = train.candidates.map(c => c.id);
  assert.deepEqual(ids, [...ids].sort());
  for (const e of train.examples) if (Array.isArray(e.answer)) for (const id of e.answer) assert.ok(ids.includes(id));
  const r = dataset.find(x => x.split === 'test' && !x.truth.abstain && x.labelSource === 'derived_mapping_table');
  const sent = JSON.parse(variantRequests([r], 'retrieval_constrained')[0].messages[1].content);
  assert.ok(sent.examples.every(e => bank.some(b => b.text.startsWith(e.text.replace(/…$/, '')))));
  const copied = JSON.parse(baselineOutput('nearest_example', r, undefined, NO_LOCAL));
  assert.deepEqual(copied.mappings.map(m => m.requirementId), [...nearestExamples(r.prompt, bank, {k: 1})[0].example.requirementIds].sort());
});

test('out of scope: the not-aligned ISMS-P criteria, Korean title in the prompt and Prowler English name for retrieval only', () => {
  const pool = outOfScopePool(NO_LOCAL), catalog = governanceCatalog();
  const alignment = JSON.parse(readFileSync('data/isms-p-alignment.json', 'utf8'));
  const prowler = new Map(JSON.parse(readFileSync('data/governance-mapping/sources/prowler/kisa_isms_p_2023_aws.json', 'utf8')).Requirements
    .map(r => [r.Id, r]));
  assert.equal(pool.entries.length, 74);
  assert.deepEqual(pool.ids, alignment.notAligned.map(n => `ISMS-P-${n.item}`));
  assert.ok(pool.ids.every(id => /^ISMS-P-\d+\.\d+\.\d+$/.test(id) && !catalog.byId.has(id)), 'never a catalog id');
  assert.ok(!mappingOutputSchema({locators: ['doc:a']}).properties.mappings.items.properties.requirementId.enum.some(id => pool.byId.has(id)));
  for (const e of pool.entries) {
    const official = alignment.officialItems.find(i => i.number === e.number), en = prowler.get(e.number);
    assert.equal(e.title, official.title);
    assert.equal(e.alias, en.Name);
    assert.equal(e.text, `ISMS-P ${e.number} ${e.title} ${en.Name}. ${en.Description.replace(/\s+/g, ' ').trim()}`);
    // The Prowler sentences that are dataset rows never enter the retrieval text.
    for (const s of en.Attributes.flatMap(a => [...(a.AuditChecklist ?? []), ...(a.AuditEvidence ?? [])])) assert.ok(!e.text.includes(s), e.id);
    // The prompt shows the number in the label form and the title: no id key, never the catalog's id form a grammar could complete.
    const shown = outOfScopeShown(e);
    assert.deepEqual(shown, {criterion: `ISMS-P ${e.number}`, title: e.title});
    assert.doesNotMatch(JSON.stringify(shown), /ISMS-P-/);
  }
  assert.match(pool.digest, /^[a-f0-9]{64}$/);
  assert.equal(pool.sources.kisaGuide, undefined);
  // Korean evidence finds the criterion by its title, English evidence by the Prowler name.
  assert.equal(retrieveOutOfScope('ISMS-P 인증기준 2.2.4 인식제고 및 교육훈련', {embeddings: null, ...NO_LOCAL})[0].id, 'ISMS-P-2.2.4');
  assert.ok(retrieveOutOfScope(prowler.get('2.4.1').Name, {embeddings: null, ...NO_LOCAL}).some(x => x.id === 'ISMS-P-2.4.1'));
  assert.equal(retrieveOutOfScope('정보보호 교육 계획', {embeddings: null, ...NO_LOCAL}).length, LIMITS.outOfScope);
});

test('out of scope: with the local KISA guide the retrieval text also carries the Korean criterion sentence, never the prompt', () => {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-oos-guide-'));
  // A stand-in for the KOGL guide (not its text): one criterion sentence that shares no words with the title or the Prowler entry.
  const criterion = '분기마다 모의 피싱 메일 대응 훈련을 실시하고   그 결과를 기록하여야 한다.';
  const bytes = JSON.stringify({schemaVersion: 1, id: 'kisa-isms-p-guide-2023-11', items: [{number: '2.2.4', title: '인식제고 및 교육훈련', criterion},
    {number: '2.2.2', title: '직무 분리', criterion: '카탈로그에 있는 항목의 문장은 쓰이지 않는다.'}, {number: '9.9.9', criterion: 7}]});
  writeFileSync(join(dir, 'kisa-isms-p-guide-2023-11.json'), bytes);
  const plainPool = outOfScopePool(NO_LOCAL), guided = outOfScopePool({localTables: dir});
  assert.equal(outOfScopePool({localTables: dir}), guided, 'cached per guide hash');
  assert.deepEqual(guided.sources.kisaGuide, {id: 'kisa-isms-p-guide-2023-11', sha256: sha256(bytes)});
  assert.notEqual(guided.digest, plainPool.digest);
  assert.deepEqual(guided.ids, plainPool.ids);
  for (const e of guided.entries) {
    const before = plainPool.byId.get(e.id);
    const added = e.id === 'ISMS-P-2.2.4' ? ' 분기마다 모의 피싱 메일 대응 훈련을 실시하고 그 결과를 기록하여야 한다.' : '';
    assert.equal(e.text, before.text + added, 'the whitespace-normalized criterion follows the shipped retrieval text');
    assert.deepEqual(outOfScopeShown(e), outOfScopeShown(before), 'the prompt shows the same entry either way');
  }
  const query = '모의 피싱 메일 대응 결과';
  assert.equal(retrieveOutOfScope(query, {embeddings: null, localTables: dir})[0].id, 'ISMS-P-2.2.4');
  assert.ok(!retrieveOutOfScope(query, {embeddings: null, k: 8, ...NO_LOCAL}).some(x => x.id === 'ISMS-P-2.2.4'), 'the title alone misses it');
  const item = {kind: 'document_excerpt', text: query, locators: ['doc:1']};
  const guidedRequest = buildMappingRequest(item, {variant: 'retrieval', embeddings: null, localTables: dir});
  assert.ok(guidedRequest.outOfScope.includes('ISMS-P-2.2.4'));
  assert.ok(!guidedRequest.messages[1].content.includes('기록하여야'), 'the criterion sentence never enters the prompt');
  assert.deepEqual(buildMappingRequest(item, {variant: 'retrieval', embeddings: null, ...NO_LOCAL}).candidates, guidedRequest.candidates);
});

test('out of scope: listed after the 12 catalog candidates, marked, explained; the source criterion annotates abstain examples', () => {
  const bank = governanceExamples(NO_LOCAL), pool = outOfScopePool(NO_LOCAL);
  // Source criteria of must-abstain rows: from the rule's ref, an injection row from the row it extends; nothing for other rows.
  const bySource = rows => rows.filter(r => outOfScopeSources(r).length);
  assert.equal(bySource(dataset).length, 184);
  assert.equal(bySource(dataset.filter(r => r.split === 'test')).length, 46);
  for (const r of dataset) {
    const sources = outOfScopeSources(r), rule = r.derivation?.rule;
    if (r.truth.abstain && /^(isms-not-aligned|prowler-(check|evidence|defect))$/.test(rule ?? '')) assert.ok(sources.length > 0, r.id);
    if (!r.truth.abstain || r.labelSource !== 'derived_mapping_table' || /^(kr|eu)-/.test(rule)) assert.deepEqual(sources, [], r.id);
    if (rule === 'isms-not-aligned') assert.deepEqual(sources, [`ISMS-P-${r.derivation.ref}`]);
  }
  const injected = dataset.find(r => r.derivation?.rule === 'injection' && r.truth.abstain && r.derivation.ref.startsWith('derived:prowler-'));
  assert.deepEqual(outOfScopeSources(injected), [`ISMS-P-${injected.derivation.ref.split(':').at(-1)}`]);
  assert.deepEqual(baseDerivation(injected).rule, injected.derivation.ref.split(':')[1]);
  assert.ok(bank.every(e => (e.outOfScope === null) || (e.abstain && pool.byId.has(e.outOfScope))));
  assert.ok(bank.filter(e => e.outOfScope).length > 100);

  const row = dataset.find(r => r.split === 'test' && r.derivation?.rule === 'isms-not-aligned'), [own] = outOfScopeSources(row);
  const shownOwn = outOfScopeShown(pool.byId.get(own)), idOf = shown => `ISMS-P-${shown.criterion.slice('ISMS-P '.length)}`;
  // zero_shot carries no outOfScope list and keeps the system prompt it was measured with; the other three explain the list.
  const zeroShot = buildMappingRequest(itemOf(row), {variant: 'zero_shot'});
  assert.doesNotMatch(zeroShot.messages[0].content, /outOfScope/);
  assert.equal(JSON.parse(zeroShot.messages[1].content).outOfScope, undefined);
  const system = buildMappingRequest(itemOf(row), {variant: 'retrieval', ...NO_LOCAL}).messages[0].content;
  assert.match(system, /outOfScope lists ISMS-P criteria that are not in the catalog/);
  assert.match(system, /never a requirementId, and evidence of one of them is answered with abstain/);
  assert.equal(system.replace(/ outOfScope lists [^]*?determines a candidate\./, ''), zeroShot.messages[0].content);
  for (const variant of ['retrieval', 'retrieval_constrained', 'candidate']) {
    const q = buildMappingRequest(itemOf(row), {variant, examples: bank, excludeId: row.id, ...NO_LOCAL}), user = JSON.parse(q.messages[1].content);
    assert.equal(q.messages[0].content, system, 'one system prompt for the variants that list outOfScope');
    assert.deepEqual(Object.keys(user), ['evidence', 'candidates', 'outOfScope', 'examples']);
    assert.equal(user.candidates.length, LIMITS.candidates);
    assert.ok(user.candidates.every(c => governanceCatalog().byId.has(c.id)), 'the catalog candidates are untouched');
    assert.ok(user.outOfScope.every(o => canonical(Object.keys(o)) === canonical(['criterion', 'title'])));
    assert.doesNotMatch(JSON.stringify(user.outOfScope), /ISMS-P-/, 'nothing in the list has the form of a requirementId');
    assert.deepEqual(user.outOfScope.map(idOf), q.outOfScope);
    assert.deepEqual(q.outOfScope, [...q.outOfScope].sort());
    assert.ok(q.outOfScope.length <= LIMITS.outOfScope && q.outOfScope.includes(own), 'the row names its own criterion');
    assert.deepEqual(user.outOfScope.find(o => o.criterion === shownOwn.criterion), shownOwn);
    if (q.responseFormat.type === 'json_schema') {
      assert.ok(!q.responseFormat.schema.properties.mappings.items.properties.requirementId.enum.some(id => pool.byId.has(id)));
    }
    const notes = user.examples.filter(e => e.outOfScope);
    assert.ok(notes.length > 0);
    for (const e of user.examples) {
      assert.ok([...e.text].length <= LIMITS.exampleChars);
      const source = bank.find(b => b.text === e.text || b.text.startsWith(e.text.replace(/…$/, '')));
      if (e.outOfScope) {
        assert.equal(e.answer, 'abstain');
        assert.deepEqual(e.outOfScope, outOfScopeShown(pool.byId.get(source.outOfScope)));
      } else assert.ok(!source || source.outOfScope === null);
    }
  }
  // Training rows carry the same prompt; the target of a must-abstain row stays an abstention.
  const trained = trainingRows(dataset, NO_LOCAL).filter(t => outOfScopeSources(dataset.find(r => r.id === t.id)).length);
  assert.ok(trained.length > 50);
  for (const t of trained) {
    assert.deepEqual(JSON.parse(t.target), {abstain: true, mappings: []});
    assert.ok(JSON.parse(t.messages[1].content).outOfScope.length > 0);
  }
});

test('out of scope: never a mapping target; scored as a wrong mapping, refused at runtime, dropped by the abstention policy', async () => {
  const row = dataset.find(r => r.split === 'test' && r.derivation?.rule === 'isms-not-aligned'), [own] = outOfScopeSources(row);
  const locator = row.evidence[0].id, shownOwn = outOfScopeShown(outOfScopePool(NO_LOCAL).byId.get(own));
  const content = JSON.stringify({abstain: false, mappings: [{requirementId: own, relation: 'supports', evidenceLocator: locator, confidence: 'high'}]});
  const scored = scoreItem(row, content);
  assert.deepEqual([scored.tp, scored.fp, scored.abstained, scored.exact], [0, 1, false, false]);
  assert.deepEqual(scored.checks, {schemaValid: false, onlyCatalogIds: false, onlySuppliedLocators: true, injectionResisted: null, mustAbstainCorrect: false});
  const answerable = dataset.find(r => r.split === 'test' && !r.truth.abstain && r.labelSource === 'derived_mapping_table');
  const g = answerable.truth.mappings[0], both = JSON.stringify({abstain: false, mappings: [
    {requirementId: g.requirementId, relation: g.relation, evidenceLocator: g.evidenceLocators[0], confidence: 'high'},
    {requirementId: own, relation: 'supports', evidenceLocator: g.evidenceLocators[0], confidence: 'high'}]});
  assert.deepEqual([scoreItem(answerable, both).tp, scoreItem(answerable, both).fp, scoreItem(answerable, both).checks.onlyCatalogIds], [1, 1, false]);
  assert.throws(() => validateMappingOutput(JSON.parse(content), {locators: [locator]}), e => e.code === 'mapping_requirement_out_of_scope');
  const spaced = JSON.parse(content.replace(own, shownOwn.criterion));
  assert.throws(() => validateMappingOutput(spaced, {locators: [locator]}), e => e.code === 'mapping_requirement_out_of_scope', 'the shown form');
  assert.throws(() => resolveMapping(itemOf(row), JSON.parse(content)), e => e.code === 'mapping_requirement_out_of_scope');
  assert.equal(outputMatchesTruth(row.truth, JSON.parse(content), {locators: [locator]}), false);
  assert.throws(() => mappingDraft(content, {item: itemOf(row), provenance: {source: 'model'}}), e => e.code === 'mapping_requirement_out_of_scope');
  // The runtime mapper never surfaces it: the request lists it as out of scope, the schema cannot name it, a reply naming it fails.
  const status = {...governanceModelStatus(), mode: 'base_retrieval_constrained'};
  const mapper = createGovernanceMapper({status, infer: async q => {
    assert.ok(JSON.parse(q.messages[1].content).outOfScope.some(o => o.criterion === shownOwn.criterion));
    assert.ok(!q.schema.properties.mappings.items.properties.requirementId.enum.includes(own));
    return {content};
  }});
  await assert.rejects(mapper(itemOf(row)), e => e.code === 'mapping_requirement_out_of_scope');
  // The abstention policy keeps listed catalog candidates only: an out-of-scope id is dropped even at a passing score.
  const request = buildMappingRequest(itemOf(row), {variant: 'candidate', examples: governanceExamples(NO_LOCAL), excludeId: row.id, ...NO_LOCAL});
  const policy = applyAbstention(content, [[content, 0]], {threshold: -1, candidates: request.candidates});
  assert.deepEqual([policy.content, policy.dropped.map(d => d.why)], [ABSTAIN_OUTPUT, ['not_candidate']]);
});

test('out of scope: the report command counts must-abstain answers beside a listed criterion (same section, or the criterion itself)', () => {
  const rows = dataset.filter(r => r.split === 'test'), catalog = governanceCatalog(), requests = variantRequests(rows, 'candidate');
  const byId = new Map(requests.map(q => [q.id, q]));
  const abstain = JSON.stringify({abstain: true, mappings: []}), outputs = Object.fromEntries(rows.map(r => [r.id, abstain]));
  // A must-abstain row whose listed criterion has an aligned sibling in the catalog, the shape a grammar-completed copy takes.
  let sibling, copied;
  for (const r of rows.filter(x => x.truth.abstain)) {
    const listed = buildMappingRequest(itemOf(r), {variant: 'candidate', examples: governanceExamples(NO_LOCAL), excludeId: r.id, ...NO_LOCAL}).outOfScope;
    const pair = listed.map(id => [id, catalog.ids.find(c => c.startsWith(id.slice(0, id.lastIndexOf('.') + 1)))]).find(([, c]) => c);
    if (!sibling && pair) sibling = {row: r, id: pair[1]};
    else if (sibling && !copied && listed.length) copied = {row: r, id: listed[0]};
  }
  assert.ok(sibling && copied && JSON.parse(byId.get(sibling.row.id).messages[1].content).outOfScope.length);
  const answer = (r, id) => JSON.stringify({abstain: false, mappings: [{requirementId: id, relation: 'supports', evidenceLocator: r.evidence[0].id,
    confidence: 'high'}]});
  outputs[sibling.row.id] = answer(sibling.row, sibling.id);
  outputs[copied.row.id] = answer(copied.row, copied.id);
  const answerable = rows.find(r => !r.truth.abstain);
  outputs[answerable.id] = answer(answerable, sibling.id);
  const mustAbstain = rows.filter(r => r.truth.abstain).length;
  const counts = outOfScopeSiblingAnswers(rows, outputs, requests);
  assert.deepEqual(counts, {mustAbstain, listing: counts.listing, rowsWithSibling: 1, siblingMappings: 1, outOfScopeMappings: 1});
  assert.ok(counts.listing > mustAbstain / 2 && counts.listing <= mustAbstain);
  // A copy in the form the prompt shows ("ISMS-P 2.2.4", unconstrained variants) names the criterion as well.
  outputs[copied.row.id] = answer(copied.row, copied.id.replace(/^ISMS-P-/, 'ISMS-P '));
  assert.deepEqual(outOfScopeSiblingAnswers(rows, outputs, requests), counts);
  assert.deepEqual(outOfScopeSiblingAnswers(rows, outputs, variantRequests(rows, 'zero_shot')),
    {mustAbstain, listing: 0, rowsWithSibling: 0, siblingMappings: 0, outOfScopeMappings: 0}, 'zero_shot lists nothing');
});

test('requests: only the outOfScope additions changed, and zero_shot not at all; every dataset request fits the runtime budget', () => {
  // Hashes of the test-split requests (committed dataset, TF-IDF) as built before the outOfScope field and system sentence. Taking
  // the additions out again (the system sentence, the user outOfScope list, the examples' outOfScope notes) gives those bytes back:
  // candidates, examples and evidence are unchanged. zero_shot never had any of them.
  const before = {zero_shot: '58f9d8047e76332276c1ba2de9cd2bcf3f1b1acafa1297a2fe5e3e8f4ad4e207',
    retrieval: '6c7466207b71e6879d70c4357c935bf1ff6d55f71941e3cf0d44e2a89dc994f4',
    retrieval_constrained: 'c1ee9d5dd0f6d0182bf3ddba5d1c5dc2c300fd67943a3213a4d25ac71b17cb08',
    candidate: 'aad49a0edddb1d1504afb92a3e9569c4344f72bb175b3c0390aa9f8a97af0fd3'};
  const withoutOutOfScope = q => {
    const user = JSON.parse(q.messages[1].content);
    delete user.outOfScope;
    for (const e of user.examples ?? []) delete e.outOfScope;
    return {...q, messages: [{...q.messages[0], content: q.messages[0].content.replace(/ outOfScope lists [^]*?determines a candidate\./, '')},
      {...q.messages[1], content: JSON.stringify(user)}]};
  };
  const rows = dataset.filter(r => r.split === 'test');
  for (const v of MODEL_VARIANTS) {
    const requests = variantRequests(rows, v);
    if (v === 'zero_shot') assert.equal(hashOf(requests), before[v], 'zero_shot requests are byte-identical');
    else assert.notEqual(hashOf(requests), before[v], v);
    assert.equal(hashOf(requests.map(withoutOutOfScope)), before[v], v);
  }
  // The runtime refuses a prompt with more than numCtx - numPredict tokens (src/isolated-inference-client.mjs) and more than
  // maxPromptBytes bytes. Calibration, 2026-10-12: the Llama 3 tokenizer with the Llama 3.1 chat template over every request of the
  // shipped dataset and of a build with the local KISA guide, all four variants, gave at most 0.353 prompt tokens per byte of the
  // JSON messages (zero_shot's id list; 0.293 for the retrieval prompts) and a longest prompt of 1,639 tokens (6,380 bytes), which
  // the 2048-token context of before (1,536 for the prompt) did not hold. A request of B bytes is taken as at most 0.36 B tokens.
  const {numCtx, numPredict, maxPromptBytes} = primaryModelPolicy().generation, TOKENS_PER_BYTE = 0.36;
  for (const v of MODEL_VARIANTS) {
    const longest = Math.max(...variantRequests(dataset, v).map(q => Buffer.byteLength(JSON.stringify(q.messages))));
    assert.ok(longest <= maxPromptBytes, `${v}: ${longest} bytes`);
    assert.ok(Math.ceil(longest * TOKENS_PER_BYTE) + numPredict <= numCtx, `${v}: ${longest} bytes may exceed the runtime prompt budget`);
  }
  assert.equal(RUNTIME_PROMPT_TOKENS, numCtx - numPredict);
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
  const rulesAnswered = testRows.find(r => JSON.parse(baselineOutput('rules_only', r)).mappings.length > 0 && rowEligibility(r, NO_LOCAL).eligible);
  const wrongOnce = report(testRows, r => (r.id !== rulesAnswered.id ? gold(r)
    : JSON.stringify({abstain: false, mappings: [{requirementId: 'KR-33', relation: 'supports', evidenceLocator: r.evidence[0].id, confidence: 'high'}]})));
  assert.ok(assessGovernanceReport(wrongOnce).reasons.includes('does not beat rules_only on precision (matched_coverage: matched_precision_lower)'));
  const silent = report(testRows, () => JSON.stringify({abstain: true, mappings: []}));
  assert.equal(assessGovernanceReport(silent).eligible, false);
  assert.ok(assessGovernanceReport(report(testRows, gold, {receiptExtra: {isolation: {networkInterfaces: ['lo', 'eth0'], verified: false}}}))
    .reasons.includes('candidate: isolation_not_verified'));
  // A run that scored a prompt longer than the runtime serves (numCtx - numPredict) does not describe the product.
  const longest = n => assessGovernanceReport(report(testRows, gold, {receiptExtra: {usage: {maxPromptTokens: n}}})).reasons;
  assert.ok(longest(RUNTIME_PROMPT_TOKENS + 1).includes('candidate: prompt_over_runtime_budget'));
  assert.ok(!longest(RUNTIME_PROMPT_TOKENS).some(x => /prompt_over_runtime_budget/.test(x)));
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
