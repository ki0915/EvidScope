// The promotion gate's default precision comparison (matched coverage) and the shakedown training mode
// (docs/governance-model.md "승격 게이트", docs/governance-model-runbook.md "셰이크다운").
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {applyReviewDecisions, buildDataset, rowEligibility, shakedownRows, toJsonl, trainingRows} from '../src/governance-mapping-data.mjs';
import {DECODING, DETERMINISTIC_BASELINES, GATE, PINNED_GGUF, assessGovernanceReport, baselineOutput, beats, buildComparisonReport, compareWithBaseline,
  hashOf, variantRequests}
  from '../src/governance-mapping-eval.mjs';
import {assessBaselineMode} from '../src/governance-model.mjs';
import {RUN_DIRS, dockerCreateArgs, trainingSpec} from '../src/governance-training.mjs';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';

const dataset = buildDataset();
const reviewer = {reviewerId: 'test-reviewer', reviewedAt: '2026-10-01T00:00:00.000Z', piiReviewed: true, sourceConsent: true};
const testRows = applyReviewDecisions(dataset, dataset.filter(r => r.labelSource === 'claude_drafted').map(r => ({id: r.id, decision: 'approve'})),
  reviewer).rows.filter(r => r.split === 'test');
const out = (r, mappings) => JSON.stringify({abstain: !mappings.length, mappings: mappings.map(([requirementId, relation = 'supports']) => ({requirementId,
  relation, evidenceLocator: r.evidence[0].id, confidence: 'high'}))});
const gold = r => out(r, r.truth.mappings.map(m => [m.requirementId, m.relation]));
const rulesAnswered = r => JSON.parse(baselineOutput('rules_only', r)).mappings.length > 0;
function report(variantsOutput) {
  const receipt = (v, outputs) => ({schemaVersion: 1, source: 'isolated_llama_cpp_batch', variant: v, operator: 'operator-a', modelFile: PINNED_GGUF.file,
    modelSha256: PINNED_GGUF.sha256, adapterFile: v === 'candidate' ? 'a.gguf' : null, adapterSha256: v === 'candidate' ? 'c'.repeat(64) : null,
    server: {binarySha256: 'd'.repeat(64), buildInfo: 't', contextTokens: 2048, gpuLayers: 99}, isolation: {networkInterfaces: ['lo'], verified: true},
    decoding: {...DECODING}, requestsSha256: hashOf(variantRequests(testRows, v)), outputsSha256: hashOf(outputs), count: testRows.length, failures: 0,
    usage: {}, startedAt: 'x', finishedAt: 'y'});
  const variants = {};
  for (const v of DETERMINISTIC_BASELINES) variants[v] = {outputs: Object.fromEntries(testRows.map(r => [r.id, baselineOutput(v, r)]))};
  for (const v of ['zero_shot', 'retrieval', 'retrieval_constrained', 'candidate']) {
    if (!variantsOutput[v]) continue;
    const outputs = Object.fromEntries(testRows.map(r => [r.id, variantsOutput[v](r)]));
    variants[v] = {outputs, receipt: receipt(v, outputs)};
  }
  return buildComparisonReport(testRows, variants, {preparedBy: 'operator-a'});
}
const rules = r => baselineOutput('rules_only', r);
const models = candidate => ({zero_shot: rules, retrieval: rules, retrieval_constrained: rules, candidate});

test('gate default: matched coverage; a few errors where rules-only did not answer no longer fail; strict keeps the literal rule', () => {
  assert.equal(GATE.comparison, 'matched_coverage');
  const answerable = testRows.filter(r => !r.truth.abstain && !rulesAnswered(r) && rowEligibility(r).eligible);
  const wrong = new Set(answerable.slice(0, 2).map(r => r.id));
  // Gold everywhere plus one extra wrong mapping on two items rules-only did not answer: precision < 1 but >= 0.9.
  const twoErrors = report(models(r => (wrong.has(r.id) ? out(r, [...r.truth.mappings.map(m => [m.requirementId, m.relation]), ['KR-33']]) : gold(r))));
  const verdict = assessGovernanceReport(twoErrors);
  assert.ok(verdict.candidate.precision < 1 && verdict.candidate.precision >= GATE.minPrecision);
  assert.deepEqual(verdict.reasons, []);
  assert.equal(verdict.comparisons.rules_only.matched.candidatePrecision, 1);
  assert.equal(verdict.thresholds.comparison, 'matched_coverage');
  const strict = assessGovernanceReport(twoErrors, {comparison: 'strict'});
  // Strict compares overall precision at no lower coverage; against an exact baseline only an exact candidate that covers more wins.
  const r = strict.comparisons.rules_only;
  assert.equal(r.rule, 'strict');
  assert.equal(r.beats, beats({precision: r.precision.candidate, recall: r.recall.candidate}, {precision: r.precision.baseline, recall: r.recall.baseline}));
  assert.equal(beats({precision: verdict.candidate.precision, recall: 1}, {precision: 1, recall: 0.1}), false);
  assert.throws(() => assessGovernanceReport(twoErrors, {comparison: 'lenient'}), /gate_comparison_unknown/);

  // Abstaining on the items rules-only answered loses the matched comparison even with gold elsewhere.
  const skipsRules = report(models(r => (rulesAnswered(r) ? out(r, []) : gold(r))));
  assert.ok(assessGovernanceReport(skipsRules).reasons.includes(
    'does not beat rules_only on precision (matched_coverage: no_candidate_mappings_where_baseline_answered)'));
  // Overall precision below the minimum fails although the matched items are right.
  const noisy = report(models(r => (r.truth.abstain || rulesAnswered(r) ? gold(r)
    : out(r, [...r.truth.mappings.map(m => [m.requirementId, m.relation]), ['KR-33'], ['KR-31-1']]))));
  assert.ok(assessGovernanceReport(noisy).reasons.includes(`candidate precision below ${GATE.minPrecision}`));
});

test('compareWithBaseline: lower coverage passes only with higher precision; matched precision must not drop', () => {
  const row = (id, ids) => ({id, prompt: 'x', evidence: [{id: 'doc:a', kind: 'document_excerpt'}],
    truth: {abstain: !ids.length, mappings: ids.map(requirementId => ({requirementId, relation: 'supports', evidenceLocators: ['doc:a']}))}});
  const rows = [row('r1', ['KR-33']), row('r2', ['KR-31-1']), row('r3', ['EU-AIA-12-1']), row('r4', ['ISMS-P-2.9.4'])];
  const o = (...ids) => JSON.stringify({abstain: !ids.length, mappings: ids.map(requirementId => ({requirementId, relation: 'supports',
    evidenceLocator: 'doc:a', confidence: 'high'}))});
  // The baseline answers everything: 3 right, r4 wrong (precision 0.75, coverage 0.75).
  const baseline = {r1: o('KR-33'), r2: o('KR-31-1'), r3: o('EU-AIA-12-1'), r4: o('KR-33')};
  const verdict = candidate => compareWithBaseline(rows, {candidate, baseline}, 'baseline');
  // Exact on r1, r2 only: coverage 0.5 < 0.75 but precision 1 > 0.75 on everything and on the matched items.
  assert.equal(verdict({r1: o('KR-33'), r2: o('KR-31-1'), r3: o(), r4: o()}).beats, true);
  // Lower coverage at no higher precision: one error out of three mappings (0.67 < 0.75).
  assert.equal(verdict({r1: o('KR-33'), r2: o('KR-33'), r3: o('EU-AIA-12-1'), r4: o()}).why, 'matched_precision_lower');
  const sameCoverage = verdict({r1: o('KR-33'), r2: o('KR-31-1'), r3: o('EU-AIA-12-1'), r4: o('KR-33')});
  assert.deepEqual([sameCoverage.beats, sameCoverage.matched.items], [true, 4], 'equal precision at equal coverage is not a loss');
  const lowerCoverage = compareWithBaseline(rows, {candidate: {r1: o('KR-33'), r2: o(), r3: o(), r4: o('KR-33')},
    baseline: {...baseline, r4: o('ISMS-P-2.9.4')}},
    'baseline');
  assert.equal(lowerCoverage.why, 'matched_precision_lower');
  const exactBaseline = {r1: o('KR-33'), r2: o('KR-31-1'), r3: o(), r4: o()};
  assert.equal(compareWithBaseline(rows, {candidate: {r1: o('KR-33'), r2: o(), r3: o(), r4: o()}, baseline: exactBaseline}, 'baseline').why,
    'lower_coverage_without_higher_precision');
  assert.equal(compareWithBaseline(rows, {candidate: {r1: o(), r2: o(), r3: o('EU-AIA-12-1'), r4: o()}, baseline: exactBaseline}, 'baseline').why,
    'no_candidate_mappings_where_baseline_answered');
  const never = Object.fromEntries(rows.map(r => [r.id, o()]));
  assert.equal(compareWithBaseline(rows, {candidate: {...never, r1: o('KR-33')}, baseline: never}, 'baseline').beats, true);
});

test('base mode needs the minimum precision as well as the rules-only comparison', () => {
  const sloppy = report({zero_shot: rules, retrieval: rules, retrieval_constrained: r => (r.truth.abstain || rulesAnswered(r) ? gold(r)
    : out(r, [...r.truth.mappings.map(m => [m.requirementId, m.relation]), ['KR-33'], ['KR-31-1']]))});
  const verdict = assessBaselineMode(sloppy);
  assert.equal(verdict.allowed, false);
  assert.ok(verdict.reasons.includes('baseline_precision_below_minimum'));
  assert.deepEqual(assessBaselineMode(report({zero_shot: rules, retrieval: rules, retrieval_constrained: gold})).reasons, []);
});

test('shakedown: derived rows only, labelled shakedown, refused by the candidate trainer and the other way round', () => {
  const rows = shakedownRows(dataset);
  assert.equal(rows.length, 194 + 35);
  assert.ok(rows.every(r => r.runMode === 'shakedown' && r.labelSource === 'derived_mapping_table' && r.split !== 'test'));
  assert.throws(() => shakedownRows(dataset.map(r => (r.labelSource === 'derived_mapping_table' ? {...r, truth: {...r.truth, abstain: !r.truth.abstain}} : r))),
    /governance_shakedown_rows_invalid/);
  const reviewed = applyReviewDecisions(dataset, dataset.filter(r => r.labelSource === 'claude_drafted')
    .map(r => ({id: r.id, decision: 'approve'})), reviewer).rows;
  assert.ok(trainingRows(reviewed).every(r => r.runMode === 'candidate'));
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-shakedown-')), file = join(dir, 'shakedown.jsonl');
  const written = runGovernanceMappingCommand(['training-set', '--data', 'data/governance-mapping/v1/dataset.jsonl', '--shakedown', '--out', file]);
  assert.deepEqual([written.rows, written.runMode], [229, 'shakedown']);
  assert.equal(readFileSync(file, 'utf8'), toJsonl(rows));
  assert.throws(() => runGovernanceMappingCommand(['training-set', '--data', 'data/governance-mapping/v1/dataset.jsonl', '--out', join(dir, 'x.jsonl')]),
    /governance_training_admission_failed/);

  // The Docker launcher: its own output directory and the --shakedown flag; the data file's run mode must match.
  const base = join(dir, 'base'), work = join(dir, 'work'), ckpt = join(dir, 'ckpt');
  for (const d of [base, work, ckpt]) mkdirSync(d);
  writeFileSync(join(base, 'artifact-lock.json'), JSON.stringify({repository: 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct', revision: 'a'.repeat(40), files: []}));
  const options = {image: 'sha256:' + 'b'.repeat(64), baseDir: base, baseRevision: 'a'.repeat(40), dataFile: file, checkpointsDir: ckpt,
    scriptsDir: resolve('scripts'), workDir: work};
  assert.throws(() => trainingSpec(options), /training_set_run_mode_mismatch/);
  const spec = trainingSpec({...options, runMode: 'shakedown'});
  const args = dockerCreateArgs(spec, 'evidscope-governance-train-00000000-0000-0000-0000-000000000000');
  assert.equal(args[args.indexOf('--output') + 1], `/checkpoints/${RUN_DIRS.shakedown}`);
  assert.ok(args.includes('--shakedown'));
  assert.throws(() => trainingSpec({...options, runMode: 'shakedown', resumeCheckpoint: 'governance-mapping/run/checkpoint-5'}), /checkpoint_path_invalid/);
  assert.equal(trainingSpec({...options, runMode: 'shakedown', resumeCheckpoint: 'governance-mapping/shakedown/checkpoint-5'}).resumeCheckpoint,
    'governance-mapping/shakedown/checkpoint-5');

  // The Python trainer's own admission re-checks the run mode.
  const bundled = resolve('.local/python/python.exe'), python = process.env.EVIDSCOPE_PYTHON || (existsSync(bundled) ? bundled : 'python3');
  const candidateFile = join(dir, 'candidate.jsonl');
  writeFileSync(candidateFile, toJsonl(trainingRows(reviewed)));
  const mixed = join(dir, 'mixed.jsonl');
  writeFileSync(mixed, toJsonl([...rows.slice(0, 3), ...trainingRows(reviewed).filter(r => r.labelSource === 'claude_drafted').slice(0, 1)
    .map(r => ({...r, runMode: 'shakedown'}))]));
  const code = `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
print(json.dumps({name: t.admission(path, shakedown=flag)[1] for name, path, flag in [("shakedown", sys.argv[1], True), ("asCandidate", sys.argv[1], False),
  ("candidate", sys.argv[2], False), ("candidateAsShakedown", sys.argv[2], True), ("mixed", sys.argv[3], True)]}))
`;
  const r = spawnSync(python, ['-I', '-B', '-c', code, file, candidateFile, mixed], {encoding: 'utf8', timeout: 120000});
  assert.equal(r.status, 0, r.stderr);
  const gates = JSON.parse(r.stdout.trim().split('\n').at(-1));
  assert.deepEqual([gates.shakedown.admitted, gates.shakedown.promotable, gates.shakedown.counts], [true, false, {tune: 194, validation: 35}]);
  assert.ok(gates.asCandidate.reasons.includes('shakedown_rows_in_candidate_run'));
  assert.deepEqual([gates.candidate.admitted, gates.candidate.promotable], [true, true]);
  assert.ok(gates.candidateAsShakedown.reasons.includes('shakedown_requires_derived_shakedown_rows'));
  assert.ok(gates.mixed.reasons.includes('shakedown_requires_derived_shakedown_rows'));
  const check = spawnSync(python, ['-I', '-B', 'scripts/train-governance-mapping-lora.py', '--data', file, '--check-only', '--shakedown'], {encoding: 'utf8'});
  assert.equal(check.status, 0, check.stderr);
});
