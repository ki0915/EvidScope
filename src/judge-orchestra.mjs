// 판정 오케스트라(2026-10-17, "판정은 JEV, 이유는 Qwen"): 규칙·시퀀스가 먼저 소견을 내고, 첫 판정자(JEV-9B)가 모든 세션을 판정한다. 둘째
// 판정자(Qwen3-4B)는 필요한 세션에서만 부른다: 첫 판정자가 위반이라 했을 때(어느 단계가 근거인지 짚는다), 기권했을 때, 규칙 소견이 있는데
// 정상이라 했을 때(경보를 낮추려면 두 판정자가 모두 정상이어야 한다). 최종 처리는 session-disposition의 원칙 그대로다: 모델은 경보를 지우지
// 못하고, 보호 경보는 낮추지도 못하며, 규칙이 못 본 모델 발견은 review로 사람에게 간다. 조항은 모델이 쓰지 않는다. 근거 단계의 발견 코드를
// 서명된 대응표에 넣어 계산하고, 규칙 소견이 없는 모델 발견에는 그 유형의 규칙 그룹이 걸리는 조항을 유형 수준 후보로만 붙인다.
import {disposition} from './session-disposition.mjs';
import {requirementIdsForType, scoreSession, sessionGold, sessionInput} from './session-inference.mjs';

const hasFindings = (scenario, rules) => sessionInput(scenario, rules).actions.some(a => a.findings.length);

// 둘째 판정자를 불러야 하는지. 첫 판정만으로 끝나는 세션은 규칙 소견이 없고 첫 판정자가 정상이라고 한 세션뿐이다.
export function needsSecondJudge(scenario, rules, first) {
  return first?.verdict !== 'clean' || hasFindings(scenario, rules);
}

// 두 판정의 합의: 둘 다 정상일 때만 정상, 하나라도 위반이면 위반, 나머지(기권이 섞인 경우)는 기권이라 규칙 경보가 그대로 남는다.
export function combineVerdicts(a, b) {
  if (a === 'clean' && b === 'clean') return 'clean';
  return a === 'violation' || b === 'violation' ? 'violation' : 'abstain';
}

// 한 세션의 최종 결과. first·second는 (scenario) => 예측(interpretSessionOutput 형식). 설명(유형·근거 단계·조항)은 둘째 판정자가 위반이라
// 했으면 그쪽, 아니면 첫 판정자 것을 쓴다.
export function conduct(scenario, rules, {first, second}) {
  const a = first(scenario);
  const secondCalled = needsSecondJudge(scenario, rules, a);
  const b = secondCalled ? second(scenario) : null;
  const verdict = secondCalled ? combineVerdicts(a.verdict, b.verdict) : a.verdict;
  const {alert, priority, source, protectedCodes, instructionsInRecords} = disposition(scenario, rules, {verdict});
  const explainer = verdict !== 'violation' ? null : b?.verdict === 'violation' ? b : a.verdict === 'violation' ? a : null;
  const requirementIds = explainer?.requirementIds ?? [];
  return {verdict, alert, priority, source, protectedCodes, instructionsInRecords, judges: {first: a.verdict, second: b?.verdict ?? null}, secondCalled,
    explainedBy: explainer === null ? null : explainer === b ? 'second' : 'first', type: explainer?.type ?? null,
    evidenceActionIds: explainer?.evidenceActionIds ?? [], requirementIds,
    typeRequirementIds: !requirementIds.length && explainer?.type ? requirementIdsForType(explainer.type) : []};
}

const rate = (num, den) => (den ? +(num / den).toFixed(4) : null);
const f1 = (tp, fp, fn) => (2 * tp + fp + fn ? +((2 * tp) / (2 * tp + fp + fn)).toFixed(4) : null);

// 설계 정답이 있는 세션 묶음에서 오케스트라 전체를 채점한다. 맞음: 위협은 경보가 남고 low로 낮아지지 않음, 정상은 경보가 없거나 low.
export function scoreOrchestra(scenarios, rules, judges) {
  const rows = scenarios.map(s => {
    const gold = sessionGold(s, rules), o = conduct(s, rules, judges);
    const raised = o.alert && o.priority !== 'low';
    return {id: s.id, gold, o, correct: gold.verdict === 'violation' ? raised : !raised, raised, explained: scoreSession(o, gold)};
  });
  const threats = rows.filter(r => r.gold.verdict === 'violation'), clean = rows.filter(r => r.gold.verdict !== 'violation');
  const alerted = threats.filter(r => r.raised && r.o.verdict === 'violation');
  const sum = f => alerted.reduce((n, r) => n + f(r.explained), 0);
  const typed = alerted.filter(r => r.explained.typeApplicable);
  return {
    sessions: rows.length, accuracy: rate(rows.filter(r => r.correct).length, rows.length),
    secondJudgeCalls: rate(rows.filter(r => r.o.secondCalled).length, rows.length),
    threats: threats.length, threatsMissed: threats.filter(r => !r.raised).length,
    clean: clean.length, cleanRaised: clean.filter(r => r.raised).length,
    cleanRuleAlertsLowered: clean.filter(r => r.o.alert && r.o.priority === 'low').length,
    reviews: rows.filter(r => r.o.priority === 'review').length,
    keptByProtection: rows.filter(r => r.o.verdict === 'clean' && r.o.protectedCodes.length).length,
    explanation: {typeAccuracy: rate(typed.filter(r => r.explained.typeCorrect).length, typed.length),
      evidenceF1: f1(sum(e => e.ev.tp), sum(e => e.ev.fp), sum(e => e.ev.fn)),
      requirementPrecision: rate(sum(e => e.requirementCorrect), sum(e => e.requirementMappings)),
      byFirst: alerted.filter(r => r.o.explainedBy === 'first').length, bySecond: alerted.filter(r => r.o.explainedBy === 'second').length,
      typeLevelOnly: alerted.filter(r => r.o.typeRequirementIds.length).length},
    wrong: rows.filter(r => !r.correct).map(r => ({id: r.id, gold: r.gold.verdict, verdict: r.o.verdict, priority: r.o.priority, judges: r.o.judges})),
  };
}
