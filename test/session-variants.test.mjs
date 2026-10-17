// 변형 생성: 골드(설계 라벨)가 보존되고, 위협 단계는 유지되며, 각 변형이 베이스를 familyId로 묶어 계열 분할에 안전한지.
import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog} from '../src/threat-scenarios.mjs';
import {buildVariantCatalog} from '../src/session-variants.mjs';
import {sessionGold, scoreSessions, baselinePredict, familyOf} from '../src/session-inference.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = loadRules(join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalog = loadCatalog(join(root, 'data/threat-scenarios/v1/catalog.json'));

test('every kept variant preserves its base label, and nothing is dropped for the shipped catalog', () => {
  const v = buildVariantCatalog(catalog, rules, {perThreat: 8, perBenign: 8});
  assert.equal(v.droppedVariantCount, 0);
  const baseOf = id => catalog.scenarios.find(b => id.startsWith(b.id + '#'));
  for (const s of v.scenarios) {
    const base = baseOf(s.id);
    assert.ok(base, s.id);
    const g = sessionGold(s, rules);
    assert.equal(g.verdict, base.label.verdict);
    assert.equal(g.type, base.label.type || null);
    assert.equal(familyOf(s), base.id);
  }
});

test('augmentation keeps full threat recall while benign noise makes the baseline over-fire (the model target)', () => {
  const v = buildVariantCatalog(catalog, rules, {perThreat: 8, perBenign: 8});
  const r = scoreSessions(v.scenarios, rules, s => baselinePredict(s, rules, {withSequence: true}));
  assert.equal(r.threatRecall, 1);
  assert.ok(r.hardNegativeFalsePositiveRate > 0);
  assert.ok(r.verdict.precision < 1);
});

test('variant ids are unique and families equal the base count', () => {
  const v = buildVariantCatalog(catalog, rules, {perThreat: 5, perBenign: 5});
  assert.equal(new Set(v.scenarios.map(s => s.id)).size, v.scenarios.length);
  assert.equal(new Set(v.scenarios.map(s => s.familyId)).size, catalog.scenarios.length);
});
