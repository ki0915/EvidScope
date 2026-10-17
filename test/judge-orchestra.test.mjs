// 판정 오케스트라(src/judge-orchestra.mjs): 첫 판정자가 모든 세션을 보고, 둘째 판정자는 필요한 세션에서만 부르며, 경보를 낮추려면 둘 다 정상이어야
// 하고, 보호 경보는 그래도 남고, 조항은 근거 단계의 발견 코드나 유형의 규칙 그룹에서 대응표로 계산한다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog, composeCatalog} from '../src/threat-scenarios.mjs';
import {combineVerdicts, conduct, needsSecondJudge, scoreOrchestra} from '../src/judge-orchestra.mjs';
import {requirementIdsForType, sessionGold} from '../src/session-inference.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = loadRules(join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalog = composeCatalog(loadCatalog(join(root, 'data/threat-scenarios/v1/catalog.json')),
  loadCatalog(join(root, 'data/threat-scenarios/v1/contrast.json')));
const byId = id => catalog.scenarios.find(s => s.id === id);
const said = (verdict, extra = {}) => () => ({verdict, type: null, requirementIds: [], evidenceActionIds: [], ...extra});
const never = () => { throw Error('second judge must not be called'); };

test('verdicts combine: clean needs both, any violation raises, an abstention keeps the rules', () => {
  assert.equal(combineVerdicts('clean', 'clean'), 'clean');
  assert.equal(combineVerdicts('clean', 'violation'), 'violation');
  assert.equal(combineVerdicts('violation', 'clean'), 'violation');
  assert.equal(combineVerdicts('clean', 'abstain'), 'abstain');
  assert.equal(combineVerdicts('abstain', 'abstain'), 'abstain');
});

test('a quiet session the first judge calls clean ends there, with no alert', () => {
  const s = byId('neg-ls-build');
  assert.equal(needsSecondJudge(s, rules, {verdict: 'clean'}), false);
  const o = conduct(s, rules, {first: said('clean'), second: never});
  assert.deepEqual([o.alert, o.secondCalled, o.verdict], [false, false, 'clean']);
});

test('a rule alert is lowered only when both judges call it clean', () => {
  const s = byId('neg-read-claude-settings');
  const both = conduct(s, rules, {first: said('clean'), second: said('clean')});
  assert.deepEqual([both.alert, both.priority, both.secondCalled], [true, 'low', true]);
  const split = conduct(s, rules, {first: said('clean'), second: said('violation')});
  assert.notEqual(split.priority, 'low');
  const unsure = conduct(s, rules, {first: said('clean'), second: said('abstain')});
  assert.notEqual(unsure.priority, 'low');
});

test('a protected alert stays even when both judges call the session clean', () => {
  const o = conduct(byId('ctr-settings-edit-alone'), rules, {first: said('clean'), second: said('clean')});
  assert.equal(o.alert, true);
  assert.notEqual(o.priority, 'low');
  assert.ok(o.protectedCodes.length);
});

test('a model-only finding goes to review; clauses come from the type when its steps carry no rule finding', () => {
  const o = conduct(byId('neg-ls-build'), rules, {first: said('violation', {type: 'exfiltration'}), second: said('clean')});
  assert.deepEqual([o.alert, o.priority, o.source, o.explainedBy], [true, 'review', 'model', 'first']);
  assert.deepEqual(o.requirementIds, []);
  assert.deepEqual(o.typeRequirementIds, requirementIdsForType('exfiltration'));
  assert.ok(o.typeRequirementIds.length);
  assert.deepEqual(requirementIdsForType('fraud'), []);
});

test('the second judge explains when it agrees on a violation, and clauses follow its evidence steps', () => {
  const s = byId('exfil-ssh-then-send'), gold = sessionGold(s, rules);
  const o = conduct(s, rules, {first: said('violation', {type: 'other'}),
    second: said('violation', {type: gold.type, evidenceActionIds: gold.evidenceActionIds, requirementIds: gold.requirementIds})});
  assert.deepEqual([o.explainedBy, o.type, o.evidenceActionIds, o.requirementIds, o.typeRequirementIds],
    ['second', gold.type, gold.evidenceActionIds, gold.requirementIds, []]);
});

test('with judges that agree with the answer key the orchestra misses nothing and clears the rule false alarms', () => {
  const ids = ['neg-ls-build', 'neg-curl-localhost', 'neg-read-dotenv', 'neg-read-claude-settings', 'exfil-ssh-then-send', 'defense-iptables-then-send'];
  const scenarios = ids.map(byId);
  const oracle = s => { const g = sessionGold(s, rules); return {...g}; };
  const r = scoreOrchestra(scenarios, rules, {first: oracle, second: oracle});
  assert.deepEqual([r.sessions, r.accuracy, r.threatsMissed, r.cleanRaised], [6, 1, 0, 0]);
  assert.equal(r.cleanRuleAlertsLowered, 2);
  assert.equal(r.explanation.evidenceF1, 1);
  assert.equal(r.explanation.requirementPrecision, 1);
  assert.ok(r.secondJudgeCalls < 1 && r.secondJudgeCalls > 0);
  assert.deepEqual(r.wrong, []);
});
