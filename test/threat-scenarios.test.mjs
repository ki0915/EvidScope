// The "채점 답안" machinery: the scenario catalog builds synthetic intent records that feed the real risk and sequence rules, and
// the scorer measures the rules+sequence baseline the session-inference model must beat. No Store/SQLite, so this runs on any node.
import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog, buildScenarioEvents, scoreScenario, scoreCatalog} from '../src/threat-scenarios.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = loadRules(join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalog = loadCatalog(join(root, 'data/threat-scenarios/v1/catalog.json'));

test('every scenario step becomes one ordered intent record', () => {
  const s = catalog.scenarios.find(x => x.id === 'exfil-ssh-then-send');
  const ev = buildScenarioEvents(s);
  assert.equal(ev.length, s.steps.length);
  assert.ok(ev.every(e => e.kind === 'intent' && e.traceId === s.id && e.tool === 'claude-code'));
  assert.deepEqual(ev.map(e => e.seq), [1, 2]);
});

test('rules+sequence baseline catches every threat gold step, chain, verdict and type', () => {
  const r = scoreCatalog(catalog, rules);
  assert.equal(r.threat.goldStepRecall, 1);
  assert.equal(r.threat.seqRecall, 1);
  assert.equal(r.threat.verdictAccuracy, 1);
  assert.equal(r.threat.typeAccuracy, 1);
  assert.deepEqual(r.threat.misses, []);
});

test('no false positives on truly-clean negatives', () => {
  const r = scoreCatalog(catalog, rules);
  assert.equal(r.cleanTrue.falsePositiveRate, 0);
  assert.deepEqual(r.cleanTrue.falsePositives, []);
});

test('known rule gaps fire as violations (the session model must clear these)', () => {
  const r = scoreCatalog(catalog, rules);
  assert.equal(r.knownRuleGaps.count, 3);
  assert.ok(r.knownRuleGaps.fired.every(g => g.verdict === 'violation' && g.codes.length));
});

test('a loopback transfer is not outbound', () => {
  const res = scoreScenario(catalog.scenarios.find(x => x.id === 'neg-curl-localhost'), rules);
  assert.equal(res.verdict, 'clean');
  assert.deepEqual(res.codes, []);
});

test('sequence chain fires only when a step belongs to the evaluated action', () => {
  const res = scoreScenario(catalog.scenarios.find(x => x.id === 'bulk-cred-read'), rules);
  assert.ok(res.codes.includes('SEQ_BULK_SENSITIVE'));
  assert.equal(res.inferredType, 'bulk_collection');
});
