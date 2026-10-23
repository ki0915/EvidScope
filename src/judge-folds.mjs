// 판정 6~9회차의 교차 검증 요약(2026-10-18). 한 분할의 "처음 보는 유형" 점수는 어떤 유형을 뺐느냐에 달려 있어서, 빼는 유형을 바꿔 가며 돌린
// 회차들의 summary.json(scripts/judge-round.mjs score)과 orchestra.json을 한 표로 모으고, 판정자마다 회차 평균과 최저를 낸다. 숫자만 다룬다.

const pick = (o, keys) => Object.fromEntries(keys.map(k => [k, o?.[k] ?? null]));
const GATED = ['answerRate', 'answeredAccuracy', 'threatClearedRate', 'knownGapClearedRate', 'typeAccuracy', 'evidenceF1'];

// 한 회차, 한 판정자의 줄. 없는 세트는 null로 남긴다(예: 4회차 이전 요약에는 safeFlagged가 없다).
export function foldRow(summary, judge) {
  const j = summary?.judges?.[judge];
  if (!j) return null;
  const raw = set => j.sets?.[set]?.model_without_abstain?.answeredAccuracy ?? null;
  const rj = j.sets?.rjudge?.model_without_abstain;
  return {
    gate: j.gate ? {eligible: j.gate.eligible, reasons: j.gate.reasons} : null,
    unseen: pick(j.sets?.unseen?.model, GATED),
    raw: {unseen: raw('unseen'), mask: raw('unseen.mask'), strip: raw('unseen.strip')},
    rjudge: rj ? {accuracy: rj.answeredAccuracy ?? null, safeFlagged: rj.safeFlagged ?? null, safe: rj.safe ?? null} : null,
    assebenchTest: j.sets?.['assebench-test']?.model_without_abstain?.answeredAccuracy ?? null,
  };
}

// 숫자 경로들의 회차 평균·최저. null인 회차는 빼고, 모두 null이면 null.
function aggregate(rows, paths) {
  const out = {};
  for (const path of paths) {
    const values = rows.map(r => path.split('.').reduce((o, k) => o?.[k], r)).filter(v => typeof v === 'number');
    out[path] = values.length ? {mean: +(values.reduce((a, b) => a + b, 0) / values.length).toFixed(4), min: Math.min(...values), rounds: values.length}
      : null;
  }
  return out;
}

const PATHS = [...GATED.map(k => `unseen.${k}`), 'raw.unseen', 'raw.mask', 'raw.strip', 'rjudge.accuracy', 'rjudge.safeFlagged', 'assebenchTest'];

// rounds: [{name, held, unseenCounts, summary, orchestra}]. orchestra는 scripts/judge-round.mjs orchestra가 쓴 파일(없어도 된다).
export function summarizeFolds(rounds, {judges = ['jev-cand', 'qwen-cand']} = {}) {
  const perJudge = {};
  for (const judge of judges) {
    const rows = rounds.map(r => ({round: r.name, ...foldRow(r.summary, judge)})).filter(r => r.unseen);
    perJudge[judge] = {rounds: rows, across: aggregate(rows, PATHS), gatePassed: rows.filter(r => r.gate?.eligible).length};
  }
  const orchestra = rounds.filter(r => r.orchestra?.sets?.unseen).map(r => ({round: r.name,
    ...pick(r.orchestra.sets.unseen, ['sessions', 'accuracy', 'secondJudgeCalls', 'threatsMissed', 'cleanRaised', 'reviews'])}));
  return {rounds: rounds.map(r => ({name: r.name, held: r.held?.length ?? null, unseen: r.unseenCounts ?? null})), judges: perJudge,
    orchestra: {rounds: orchestra, across: aggregate(orchestra, ['accuracy', 'secondJudgeCalls', 'threatsMissed'])}};
}
