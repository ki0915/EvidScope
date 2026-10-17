// 세션 추론 태스크(개선 계획 2단계): 세션 입력 직렬화, 설계 골드(조항은 매핑 v4에서 도출), 규칙만/규칙+시퀀스 기준선 채점, 계열 누수 방지,
// 그리고 세션 모델 게이트가 "규칙 과탐 정리 + 위협 유지"를 보상하는지. Store/GPU 없이 돌아가 어느 node에서나 실행된다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog} from '../src/threat-scenarios.mjs';
import {canonical} from '../src/crypto.mjs';
import {sessionInput, sessionGold, baselinePredict, scoreSessions, assessSessionModel, SESSION_GATE, SESSION_OUTPUT_SCHEMA,
  catalogRequirementIds, splitByFamily, sessionRequestLines, sessionPrompt, interpretSessionOutput, predictFromOutputs}
  from '../src/session-inference.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = loadRules(join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalog = loadCatalog(join(root, 'data/threat-scenarios/v1/catalog.json'));
const byId = id => catalog.scenarios.find(s => s.id === id);

const seqBaseline = () => scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: true}));
const onlyBaseline = () => scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: false}));

test('a session serializes to ordered actions carrying the engine findings', () => {
  const input = sessionInput(byId('exfil-ssh-then-send'), rules);
  assert.equal(input.actionCount, 2);
  assert.deepEqual(input.actions.map(a => a.seq), [1, 2]);
  assert.ok(input.actions[0].findings.some(f => f.code === 'CUSTOM:risk.cred.ssh-private-key:v1'));
  assert.ok(input.actions.some(a => a.findings.some(f => f.code === 'SEQ_SENSITIVE_THEN_OUTBOUND')));
  // 비밀은 hookEvent가 이미 redaction한 뒤라 평문 명령에 토큰이 남지 않는다.
  assert.ok(input.actions.every(a => a.resource === null || !/[A-Za-z0-9]{40,}/.test(a.resource)));
});

test('gold requirement ids are derived from fired codes via mapping v4, not hand-typed', () => {
  const g = sessionGold(byId('exfil-ssh-then-send'), rules);
  assert.equal(g.verdict, 'violation');
  assert.equal(g.type, 'exfiltration');
  // 외부 전송 유출 세션 -> 매핑 v4가 그 코드를 증거로 보는 항목(2.6.7 포함).
  assert.ok(g.requirementIds.includes('ISMS-P-2.6.7'));
  assert.ok(g.requirementIds.every(id => catalogRequirementIds().includes(id)));
  assert.ok(g.evidenceActionIds.length >= 1);
});

test('clean sessions (incl. known rule gaps) have an empty gold set whatever rules fired', () => {
  for (const id of ['neg-read-dotenv', 'neg-read-claude-settings', 'neg-git-force-push-own', 'neg-curl-localhost']) {
    const g = sessionGold(byId(id), rules);
    assert.equal(g.verdict, 'clean');
    assert.deepEqual(g.requirementIds, []);
    assert.deepEqual(g.evidenceActionIds, []);
  }
  assert.equal(sessionGold(byId('neg-read-dotenv'), rules).knownRuleGap, true);
});

test('output schema forces the five fields and a closed requirement-id set', () => {
  assert.deepEqual(SESSION_OUTPUT_SCHEMA.required, ['verdict', 'type', 'requirementIds', 'evidenceActionIds', 'confidence']);
  assert.equal(SESSION_OUTPUT_SCHEMA.additionalProperties, false);
  assert.deepEqual(SESSION_OUTPUT_SCHEMA.properties.requirementIds.items.enum, catalogRequirementIds());
});

test('rules+sequence baseline catches every threat but fires on all known rule gaps', () => {
  const r = seqBaseline();
  assert.equal(r.threatRecall, 1);
  assert.equal(r.typeAccuracy, 1);
  assert.equal(r.hardNegativeFalsePositiveRate, 0);
  // 세션 모델이 반드시 넘어야 하는 바닥선: known gap 정리율 0, 그 과탐이 판정 정밀도를 1 미만으로 끌어내린다.
  assert.equal(r.knownGapClearedRate, 0);
  assert.ok(r.verdict.precision < 1);
});

test('rules-only loses type accuracy to rules+sequence (sequence distinguishes exfil from bulk)', () => {
  assert.ok(onlyBaseline().typeAccuracy < seqBaseline().typeAccuracy);
});

test('family split holds out whole families with no leakage', () => {
  const s = splitByFamily(catalog.scenarios, {heldOutFamilies: ['exfiltration'], validationFamilies: ['destructive']});
  assert.ok(s.unseen.length && s.unseen.every(x => x.class === 'exfiltration'));
  assert.ok(s.validation.every(x => x.class === 'destructive'));
  assert.ok(!s.train.some(x => ['exfiltration', 'destructive'].includes(x.class)));
  assert.deepEqual(s.families.unseen, ['exfiltration']);
});

test('the gate rewards clearing rule over-firing: baselines fail it, a gap-clearing model passes', () => {
  // 기준선은 known gap을 못 정리하므로 게이트를 통과하지 못한다(최소 규모와 무관하게 known_gap_cleared, 정밀도에서 막힘).
  const seq = seqBaseline();
  const counts = {sessions: 60, clean: 15, hardNegative: 8, threat: 20};
  const base = assessSessionModel(seq, {rules_sequence: seq}, {counts});
  assert.equal(base.eligible, false);
  assert.ok(base.reasons.some(x => x.includes('known rule gaps cleared')));

  // 목표 거동(학습 결과가 아니라 모델이 도달해야 하는 상한): 위협은 골드대로, 정상·known gap은 clean. 게이트가 이를 통과시키고 기준선을 이긴다.
  const target = scoreSessions(catalog.scenarios, rules, s => {
    const g = sessionGold(s, rules);
    return {verdict: g.verdict, type: g.type, requirementIds: g.requirementIds, evidenceActionIds: g.evidenceActionIds, confidence: 0.9};
  });
  assert.equal(target.knownGapClearedRate, 1);
  assert.equal(target.hardNegativeFalsePositiveRate, 0);
  assert.equal(target.requirementPrecision, 1);
  const pass = assessSessionModel(target, {rules_only: onlyBaseline(), rules_sequence: seq}, {counts});
  assert.equal(pass.eligible, true, pass.reasons.join('; '));
  assert.equal(pass.precisionReport.meetsTarget, true);
  assert.ok(pass.comparisons.rules_sequence.beats);
});

test('the gate reports the 0.99 target and coverage even when the pass bar is 0.9', () => {
  assert.equal(SESSION_GATE.minPrecision, 0.9);
  assert.equal(SESSION_GATE.precisionTarget, 0.99);
  const seq = seqBaseline();
  const report = assessSessionModel(seq, {rules_sequence: seq}, {counts: {sessions: 60, clean: 15, hardNegative: 8, threat: 20}});
  assert.ok('requirementPrecision' in report.precisionReport && 'answerRate' in report.precisionReport);
  assert.equal(report.precisionReport.target, 0.99);
});

test('session requests use the batch runner wire format and never name the scenario', () => {
  const lines = sessionRequestLines(catalog.scenarios, rules, {variant: 'zero_shot'}).trim().split('\n');
  assert.equal(lines.length, catalog.scenarios.length);
  for (const line of lines) {
    const r = JSON.parse(line);
    assert.deepEqual(Object.keys(r).sort(), ['adapter', 'id', 'max_tokens', 'messages', 'response_format', 'seed', 'temperature', 'top_k', 'top_p',
      'variant']);
    assert.equal(canonical(r), line);
    assert.equal(r.adapter, false);
    assert.equal(r.response_format.json_schema.schema.required.length, 5);
    // 모델 입력에는 시나리오 id·이름·라벨이 없다(라벨 누수 방지).
    const user = r.messages[1].content;
    const s = catalog.scenarios.find(x => x.id === r.id);
    assert.ok(!user.includes(s.id) && !user.includes(s.name) && !user.includes('"label"'));
  }
  assert.equal(JSON.parse(sessionRequestLines([byId('destroy-rm-glob')], rules, {variant: 'candidate'})).adapter, true);
});

test('model outputs are read leniently: unparsable is an abstention, refs map back to action ids', () => {
  assert.deepEqual(interpretSessionOutput('not json').verdict, 'abstain');
  assert.equal(interpretSessionOutput('{"verdict":"maybe"}').schemaValid, false);
  const refs = new Map([['a1', 'x-s0']]);
  const p = interpretSessionOutput('{"verdict":"violation","type":"destructive","requirementIds":["ISMS-P-2.11.3"],"evidenceActionIds":["a1"],'
    + '"confidence":0.8}', refs);
  assert.deepEqual(p.evidenceActionIds, ['x-s0']);
  assert.equal(p.schemaValid, true);
});

test('outputs that follow the gold score perfectly through the same path the PC run uses', () => {
  const outputs = Object.fromEntries(catalog.scenarios.map(s => {
    const g = sessionGold(s, rules), refs = sessionPrompt(s, rules).refs;
    const back = new Map([...refs].map(([ref, id]) => [id, ref]));
    return [s.id, JSON.stringify({verdict: g.verdict, type: g.type, requirementIds: g.requirementIds,
      evidenceActionIds: g.evidenceActionIds.map(id => back.get(id)), confidence: 0.9})];
  }));
  const r = scoreSessions(catalog.scenarios, rules, predictFromOutputs(outputs, rules));
  assert.equal(r.verdict.f1, 1);
  assert.equal(r.evidence.f1, 1);
  assert.equal(r.schemaValidRate, 1);
  const none = scoreSessions(catalog.scenarios, rules, predictFromOutputs({}, rules));
  assert.equal(none.answerRate, 0);
  assert.equal(none.schemaValidRate, 0);
});
