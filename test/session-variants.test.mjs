// 변형 생성: 섞은 뒤에도 연쇄 경보·골드가 베이스와 같고, 중복이 없고, 잡음 풀이 평가·검증 계열을 끌어오지 않으며(적대적 감사 2026-10-17),
// 각 변형이 베이스를 familyId로 묶어 계열 분할에 안전한지.
import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog} from '../src/threat-scenarios.mjs';
import {buildVariantCatalog} from '../src/session-variants.mjs';
import {sessionGold, sessionInput, scoreSessions, baselinePredict, familyOf} from '../src/session-inference.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = loadRules(join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalog = loadCatalog(join(root, 'data/threat-scenarios/v1/catalog.json'));

const seqSet = s => [...new Set(sessionInput(s, rules).actions.flatMap(a => a.findings.map(f => f.code)).filter(c => c.startsWith('SEQ_')))].sort();
const stepId = st => JSON.stringify([st.toolName, st.command ?? null, st.filePath ?? null, st.url ?? null]);

test('kept variants keep the base chain alerts and gold; drifted and duplicate variants are dropped, not kept', () => {
  const v = buildVariantCatalog(catalog, rules, {perThreat: 30, perBenign: 30});
  // 예전 k=0·9·18·27은 잡음 0개로 원본과 같았다(적대적 감사). 이제 중복은 버리고 다음 k로 채운다.
  assert.ok(v.dropped.duplicate > 0);
  const baseOf = id => catalog.scenarios.find(b => id.startsWith(b.id + '#'));
  for (const s of v.scenarios) {
    const base = baseOf(s.id);
    assert.ok(base, s.id);
    assert.equal(familyOf(s), base.id);
    assert.deepEqual(seqSet(s), seqSet(base), s.id);
    const g = sessionGold(s, rules), bg = sessionGold(base, rules);
    assert.equal(g.verdict, bg.verdict);
    assert.equal(g.type, bg.type);
    assert.deepEqual(g.requirementIds, bg.requirementIds);
  }
  // 정상 세션에 위험 연쇄 경보가 붙은 변형은 남지 않는다(예전엔 정상 정답으로 학습됐다).
  assert.ok(v.scenarios.filter(s => s.label.verdict === 'clean').every(s => seqSet(s).length === 0));
});

test('no two variants of a base share the same steps', () => {
  const v = buildVariantCatalog(catalog, rules, {perThreat: 30, perBenign: 30});
  const keys = v.scenarios.map(s => s.familyId + '|' + s.steps.map(st => stepId(st) + st.delayMs).join('|'));
  assert.equal(new Set(keys).size, keys.length);
});

test('the noise pool never draws from excluded (held-out or validation) families', () => {
  const excluded = ['neg-read-claude-settings', 'neg-ls-build'];
  const v = buildVariantCatalog(catalog, rules, {perThreat: 12, perBenign: 12, poolExclude: excluded});
  assert.ok(excluded.every(f => !v.poolFamilies.includes(f)));
  const banned = new Set(catalog.scenarios.filter(s => excluded.includes(s.id)).flatMap(s => s.steps.map(stepId)));
  assert.ok(v.scenarios.filter(s => !excluded.includes(s.familyId)).every(s => s.steps.every(st => !banned.has(stepId(st)))));
  assert.ok(v.scenarios.filter(s => !excluded.includes(s.familyId)).some(s => s.steps.some(st => st.filler)));
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
