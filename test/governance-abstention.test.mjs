// Abstention calibration (docs/governance-model.md "보류 보정"): requirement-id log-probability scores, the keep-or-abstain policy, the
// threshold chosen on validation rows, and the comparison report that carries, re-verifies and judges the calibrated candidate.
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {ABSTAIN_OUTPUT, LOGPROB_SCALE, MIN_KEPT, applyAbstention, calibrateAbstention, calibrationSummary, mappingScores, policyOutputs,
  thresholdProbability} from '../src/governance-abstention.mjs';
import {buildDataset, rowEligibility, toJsonl} from '../src/governance-mapping-data.mjs';
import {CALIBRATED, DECODING, DETERMINISTIC_BASELINES, GATE, PINNED_GGUF, assessGovernanceReport, baselineOutput, baselineOutputs,
  buildComparisonReport, evaluateOutputs, hashOf, measurementProblem, variantRequests, verifyGovernanceReport} from '../src/governance-mapping-eval.mjs';
import {experimentOf} from '../src/governance-experiments.mjs';
import {governanceCatalog} from '../src/governance-mapping.mjs';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';

// Governance-mapping tests see only the shipped source tables; a local-only (KOGL) table on this machine must not change them.
process.env.EVIDSCOPE_GOVERNANCE_LOCAL_TABLES ??= '.test-runs/no-local-tables';

const NO_LOCAL = {localTables: false};
const dataset = buildDataset(NO_LOCAL), catalog = governanceCatalog();
const testRows = dataset.filter(r => r.split === 'test'), validationRows = dataset.filter(r => r.split === 'validation');
const eligible = rows => rows.filter(r => rowEligibility(r, NO_LOCAL).eligible);
const out = (r, mappings) => JSON.stringify({abstain: !mappings.length, mappings: mappings.map(([requirementId, relation = 'supports']) =>
  ({requirementId, relation, evidenceLocator: r.evidence[0].id, confidence: 'high'}))});
const gold = r => out(r, r.truth.mappings.map(m => [m.requirementId, m.relation]));
// A wrong answer for an answerable row: a catalog id the row's truth does not name.
const wrong = r => out(r, [[catalog.ids.find(id => !r.truth.mappings.some(m => m.requirementId === id))]]);
// Tokens that spell the output: each requirement id value is one token with the given micro-nat score, everything else scores 0.
function tokensFor(content, scoreOf) {
  const tokens = [];
  let at = 0;
  for (const m of content.matchAll(/"requirementId":"([^"]+)"/g)) {
    const from = m.index + '"requirementId":"'.length, to = from + m[1].length;
    tokens.push([content.slice(at, from), 0], [content.slice(from, to), scoreOf(m[1])]);
    at = to;
  }
  if (at < content.length) tokens.push([content.slice(at), 0]);
  return tokens;
}
const HIGH = -100000, LOW = -1500000; // p(id) ≈ 0.90 and ≈ 0.22

// Synthetic candidate behaviour: every fourth answerable row gets a wrong id at a low score, the others the gold mapping at a high score
// that decreases a little per row (so the threshold is a real choice), must-abstain rows abstain.
function synthetic(rows, {wrongEvery = 4, allWrong = false} = {}) {
  const outputs = {}, logprobs = {};
  let i = 0;
  for (const r of rows) {
    if (r.truth.abstain) { outputs[r.id] = ABSTAIN_OUTPUT; logprobs[r.id] = [[ABSTAIN_OUTPUT, 0]]; continue; }
    const bad = allWrong || i % wrongEvery === wrongEvery - 1;
    outputs[r.id] = bad ? wrong(r) : gold(r);
    logprobs[r.id] = tokensFor(outputs[r.id], () => (bad ? LOW - i * 10 : HIGH - i * 10));
    i++;
  }
  return {outputs, logprobs};
}
const receipt = (v, rows, outputs, extra = {}) => ({schemaVersion: 1, source: 'isolated_llama_cpp_batch', variant: v, operator: 'operator-a',
  modelFile: PINNED_GGUF.file, modelSha256: PINNED_GGUF.sha256, adapterFile: v === 'candidate' ? 'a.gguf' : null,
  adapterSha256: v === 'candidate' ? 'c'.repeat(64) : null, server: {binarySha256: 'd'.repeat(64), buildInfo: 't', contextTokens: 2048, gpuLayers: 99},
  isolation: {networkInterfaces: ['lo'], verified: true}, decoding: {...DECODING}, requestsSha256: hashOf(variantRequests(rows, v)),
  outputsSha256: hashOf(outputs), count: rows.length, failures: 0, usage: {}, startedAt: 'x', finishedAt: 'y', ...extra});
const rules = r => baselineOutput('rules_only', r);
// variants for a report: baselines, the three base-model variants answering as rules-only, and the synthetic candidate.
function variantsFor(candidate) {
  const variants = {};
  for (const v of DETERMINISTIC_BASELINES) variants[v] = {outputs: baselineOutputs(testRows, v)};
  for (const v of ['zero_shot', 'retrieval', 'retrieval_constrained']) {
    const outputs = Object.fromEntries(testRows.map(r => [r.id, rules(r)]));
    variants[v] = {outputs, receipt: receipt(v, testRows, outputs)};
  }
  variants.candidate = {outputs: candidate.outputs, receipt: receipt('candidate', testRows, candidate.outputs, {logprobsSha256: hashOf(candidate.logprobs)})};
  return variants;
}
function calibratedReport({validation = synthetic(validationRows), candidate = synthetic(testRows), minKept} = {}) {
  const calibration = {validation: {rows: validationRows, outputs: validation.outputs, logprobs: validation.logprobs,
    receipt: receipt('candidate', validationRows, validation.outputs, {logprobsSha256: hashOf(validation.logprobs)})}, logprobs: candidate.logprobs,
  ...(minKept ? {minKept} : {})};
  return buildComparisonReport(testRows, variantsFor(candidate), {preparedBy: 'operator-a', calibration});
}

test('scores: the tokens overlapping a requirement id add up per mapping; tokens that do not spell the output score nothing', () => {
  const head = '{"abstain":false,"mappings":[{"requirementId":', mid = ',"relation":"supports","evidenceLocator":"e:1","confidence":"high"},{"requirementId":"';
  const tail = '","relation":"contradicts","evidenceLocator":"e:1","confidence":"high"}]}';
  const tokens = [[head, 0], ['"ISMS', -100000], ['-P-2', -200000], ['.9.4"', -50000], [mid, 0], ['KR', -700000], ['-31-1', -300000], [tail, 0]];
  const content = tokens.map(t => t[0]).join('');
  assert.deepEqual([...mappingScores(content, tokens)], [['ISMS-P-2.9.4', -350000], ['KR-31-1', -1000000]]);
  assert.deepEqual([...mappingScores(content, [[content, -5]])], [['ISMS-P-2.9.4', -5], ['KR-31-1', -5]]);
  assert.equal(mappingScores(content, [...tokens.slice(0, 7), [tail + ' ', 0]]), null);
  assert.equal(mappingScores(content, [[content, -1.5]]), null);
  assert.equal(mappingScores(content, null), null);
  const both = ['ISMS-P-2.9.4', 'KR-31-1'];
  const a = applyAbstention(content, tokens, {threshold: -400000, candidates: both});
  assert.equal(a.kept, 1);
  assert.deepEqual(JSON.parse(a.content).mappings.map(m => m.requirementId), ['ISMS-P-2.9.4']);
  assert.deepEqual(a.dropped, [{requirementId: 'KR-31-1', score: -1000000, why: 'below_threshold'}]);
  const b = applyAbstention(content, tokens, {threshold: -1000000, candidates: ['KR-31-1']});
  assert.deepEqual([JSON.parse(b.content).mappings.map(m => m.requirementId), b.dropped[0].why], [['KR-31-1'], 'not_candidate']);
  const c = applyAbstention(content, tokens, {threshold: -2000000});
  assert.equal(c.content, JSON.stringify({abstain: false, mappings: JSON.parse(content).mappings}));
  assert.equal(applyAbstention(content, tokens, {threshold: -1, candidates: both}).content, ABSTAIN_OUTPUT);
  assert.deepEqual(applyAbstention(content, [[content + 'x', 0]], {threshold: -9, candidates: both}).dropped.map(d => d.why), ['unscored', 'unscored']);
  assert.equal(applyAbstention(content, tokens, {threshold: null}).content, ABSTAIN_OUTPUT);
  assert.deepEqual(applyAbstention('not json', [['not json', 0]], {threshold: -9}), {content: ABSTAIN_OUTPUT, kept: 0, dropped: []});
  assert.equal(applyAbstention(ABSTAIN_OUTPUT, [[ABSTAIN_OUTPUT, 0]], {threshold: -9}).content, ABSTAIN_OUTPUT);
  assert.equal(thresholdProbability(-100000), Math.exp(-0.1));
  assert.equal(thresholdProbability(null), null);
  assert.equal(LOGPROB_SCALE, 1e6);
});

test('calibration: the most permissive score at which validation precision reaches the gate minimum with enough mappings kept', () => {
  const rows = eligible(validationRows), {outputs, logprobs} = synthetic(rows), none = Object.fromEntries(rows.map(r => [r.id, null]));
  const evaluate = (r, o) => evaluateOutputs(r, o, catalog);
  const cal = calibrateAbstention(rows, outputs, logprobs, none, evaluate, {minPrecision: GATE.minPrecision});
  const goldScores = rows.flatMap(r => (logprobs[r.id] ?? []).map(t => t[1]).filter(s => s <= HIGH && s > LOW));
  assert.equal(cal.reached, true);
  assert.equal(cal.threshold, Math.min(...goldScores));
  assert.deepEqual([cal.method, cal.filter, cal.minPrecision, cal.minKept, cal.rows], ['id_logprob_threshold', 'candidates', 0.9, MIN_KEPT, rows.length]);
  assert.equal(cal.mappings, rows.reduce((n, r) => n + JSON.parse(outputs[r.id]).mappings.length, 0));
  assert.equal(cal.unscored, 0);
  assert.deepEqual([cal.chosen.precision, cal.chosen.kept], [1, goldScores.length]);
  assert.ok(cal.chosen.recall > 0.5 && cal.chosen.recall < 1);
  assert.deepEqual(cal.curve.map(e => e.threshold), [...new Set(cal.curve.map(e => e.threshold))].sort((a, b) => b - a));
  const permissive = cal.curve.at(-1);
  assert.ok(permissive.precision < cal.chosen.precision && permissive.recall === cal.chosen.recall && permissive.kept > cal.chosen.kept,
    'keeping everything adds only the wrong low-score mappings');
  assert.equal(policyOutputs(rows, outputs, logprobs, none, cal.threshold)[rows.find(r => !r.truth.abstain).id], outputs[rows.find(r => !r.truth.abstain).id]);
  // Candidates filter: an id outside the row's candidate list is dropped whatever its score.
  const only = Object.fromEntries(rows.map(r => [r.id, ['EU-AIA-12-1']]));
  const filtered = calibrateAbstention(rows, outputs, logprobs, only, evaluate, {minPrecision: GATE.minPrecision});
  assert.ok(filtered.curve.length < cal.curve.length);
  // Nothing reaches the minimum: the most precise threshold is reported with reached: false; with no mappings there is no threshold.
  const bad = synthetic(rows, {allWrong: true});
  const failed = calibrateAbstention(rows, bad.outputs, bad.logprobs, none, evaluate, {minPrecision: GATE.minPrecision});
  assert.deepEqual([failed.reached, failed.chosen.precision, failed.threshold === null], [false, 0, false]);
  const silent = calibrateAbstention(rows, Object.fromEntries(rows.map(r => [r.id, ABSTAIN_OUTPUT])), {}, none, evaluate, {minPrecision: 0.9});
  assert.deepEqual([silent.reached, silent.threshold, silent.chosen, silent.curve], [false, null, null, []]);
  assert.throws(() => calibrateAbstention(rows, outputs, logprobs, none, evaluate, {minPrecision: 0}), e => e.code === 'calibration_min_precision_invalid');
});

test('report: carries the calibration and the calibrated candidate, re-verifies both, and judges the calibrated variant', () => {
  const report = calibratedReport();
  assert.ok(report.variants[CALIBRATED] && report.calibration.reached === true);
  assert.equal(report.variants[CALIBRATED].outputsSha256, hashOf(report.variants[CALIBRATED].outputs));
  assert.equal(report.calibration.validation.gateItems, eligible(validationRows).length);
  assert.ok(report.metrics.candidate.precision < 1 && report.metrics[CALIBRATED].precision === 1, 'the policy drops the low-score wrong answers');
  assert.ok(report.metrics[CALIBRATED].recall <= report.metrics.candidate.recall);
  assert.equal(report.metrics[CALIBRATED].abstention.mustAbstainCorrect, 1);
  const verified = verifyGovernanceReport(report);
  assert.ok(verified.metrics[CALIBRATED]);
  const verdict = assessGovernanceReport(report);
  assert.equal(verdict.underTest, CALIBRATED);
  assert.equal(measurementProblem(report, CALIBRATED), null);
  assert.deepEqual([verdict.calibration.reached, verdict.calibration.threshold, verdict.candidate.precision],
    [true, report.calibration.threshold, report.metrics[CALIBRATED].precision]);
  assert.ok(!verdict.reasons.some(x => /calibration/.test(x)), verdict.reasons.join('; '));
  const summary = calibrationSummary(report);
  assert.equal(summary.thresholdProbability, Math.exp(report.calibration.threshold / LOGPROB_SCALE));
  const experiment = experimentOf(report);
  assert.ok(experiment.variants.includes(CALIBRATED) && experiment.variantsData[CALIBRATED].measurement.problem === null);
  assert.equal(experiment.calibration.reached, true);
  // Tampering: a changed threshold, changed calibrated outputs, or a missing half of the pair is refused.
  const tampered = structuredClone(report);
  tampered.calibration.threshold -= 1;
  assert.throws(() => verifyGovernanceReport(tampered), e => e.code === 'governance_report_calibration_changed');
  const edited = structuredClone(report), id = testRows.find(r => !r.truth.abstain).id;
  edited.variants[CALIBRATED].outputs[id] = ABSTAIN_OUTPUT;
  edited.variants[CALIBRATED].outputsSha256 = hashOf(edited.variants[CALIBRATED].outputs);
  assert.throws(() => verifyGovernanceReport(edited), e => e.code === 'governance_report_calibrated_outputs_changed');
  const half = structuredClone(report);
  delete half.calibration;
  assert.throws(() => verifyGovernanceReport(half), e => e.code === 'governance_report_calibration_invalid');
  const other = structuredClone(report);
  delete other.variants[CALIBRATED];
  assert.throws(() => verifyGovernanceReport(other), e => e.code === 'governance_report_calibration_invalid');
  const moved = structuredClone(report);
  moved.calibration.validation.rows[0] = {...moved.calibration.validation.rows[0], prompt: moved.calibration.validation.rows[0].prompt + ' '};
  assert.throws(() => verifyGovernanceReport(moved), e => e.code === 'governance_report_calibration_rows_invalid');
  // Measurement: the validation run must bind the same model and adapter, and the candidate receipt the test log-probabilities.
  const unbound = structuredClone(report);
  delete unbound.variants.candidate.receipt.logprobsSha256;
  assert.equal(measurementProblem(unbound, CALIBRATED), 'logprobs_binding_mismatch');
  const swapped = structuredClone(report);
  swapped.calibration.validation.receipt.adapterSha256 = 'e'.repeat(64);
  assert.equal(measurementProblem(swapped, CALIBRATED), 'calibration_model_mismatch');
  assert.ok(assessGovernanceReport(swapped).reasons.includes(`${CALIBRATED}: calibration_model_mismatch`));
  const unmeasured = structuredClone(report);
  unmeasured.calibration.validation.receipt = null;
  assert.equal(measurementProblem(unmeasured, CALIBRATED), 'measured_isolated_inference_required');
  // A calibration that did not reach the minimum on validation fails the gate whatever the test rows say.
  const weak = calibratedReport({validation: synthetic(validationRows, {allWrong: true})});
  assert.equal(weak.calibration.reached, false);
  assert.ok(assessGovernanceReport(weak).reasons.includes(`calibration did not reach precision ${GATE.minPrecision} on validation`));
  assert.throws(() => buildComparisonReport(testRows, variantsFor(synthetic(testRows)), {preparedBy: 'operator-a', calibration: {validation: {}}}),
    e => e.code === 'report_calibration_invalid');
  const plain = buildComparisonReport(testRows, variantsFor(synthetic(testRows)), {preparedBy: 'operator-a'});
  assert.equal(plain.variants[CALIBRATED], undefined);
  assert.equal(assessGovernanceReport(plain).underTest, 'candidate');
});

test('cli: validation requests and report --validation-runs round-trip the batch runner files into a verified calibrated report', () => {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-calibration-')), runs = join(dir, 'runs'), vdir = join(runs, 'validation');
  const data = join(dir, 'dataset.jsonl');
  mkdirSync(vdir, {recursive: true});
  writeFileSync(data, toJsonl(dataset));
  const requested = runGovernanceMappingCommand(['requests', '--data', data, '--variant', 'candidate', '--split', 'validation', '--out',
    join(vdir, 'candidate.requests.jsonl')]);
  assert.deepEqual(requested, {requests: validationRows.length, variant: 'candidate', split: 'validation'});
  const lines = readFileSync(join(vdir, 'candidate.requests.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.deepEqual(lines.map(l => l.id), validationRows.map(r => r.id));
  assert.throws(() => runGovernanceMappingCommand(['requests', '--data', data, '--variant', 'retrieval', '--split', 'validation', '--out', join(dir, 'x')]),
    /only made for the candidate/);
  const candidate = synthetic(testRows), validation = synthetic(validationRows), variants = variantsFor(candidate);
  const json = (file, value) => writeFileSync(file, JSON.stringify(value) + '\n');
  for (const v of ['zero_shot', 'retrieval', 'retrieval_constrained', 'candidate']) {
    json(join(runs, `${v}.outputs.json`), variants[v].outputs);
    json(join(runs, `${v}.receipt.json`), variants[v].receipt);
  }
  json(join(runs, 'candidate.logprobs.json'), candidate.logprobs);
  json(join(vdir, 'candidate.outputs.json'), validation.outputs);
  json(join(vdir, 'candidate.logprobs.json'), validation.logprobs);
  json(join(vdir, 'candidate.receipt.json'), receipt('candidate', validationRows, validation.outputs, {logprobsSha256: hashOf(validation.logprobs)}));
  const result = runGovernanceMappingCommand(['report', '--data', data, '--runs', runs, '--validation-runs', vdir, '--prepared-by', 'operator-a',
    '--out', join(dir, 'report.json')]);
  assert.ok(result.variants.includes(CALIBRATED));
  assert.equal(result.calibration.reached, true);
  // Informational, per model variant: must-abstain answers beside a criterion the prompt listed as out of scope (zero_shot lists none).
  const siblings = result.outOfScopeSiblings, mustAbstain = testRows.filter(r => r.truth.abstain).length;
  assert.deepEqual(Object.keys(siblings), ['zero_shot', 'retrieval', 'retrieval_constrained', 'candidate', CALIBRATED]);
  assert.ok(Object.values(siblings).every(x => x.mustAbstain === mustAbstain && x.listing <= mustAbstain));
  assert.deepEqual([siblings.zero_shot.listing, siblings.candidate.listing > 0], [0, true]);
  assert.equal(result.gate.underTest, CALIBRATED);
  const written = JSON.parse(readFileSync(join(dir, 'report.json'), 'utf8'));
  assert.equal(measurementProblem(written, CALIBRATED), null);
  assert.deepEqual(runGovernanceMappingCommand(['gate', '--report', join(dir, 'report.json')]).calibration.threshold, written.calibration.threshold);
  assert.equal(calibrationSummary(written).reached, true);
});
