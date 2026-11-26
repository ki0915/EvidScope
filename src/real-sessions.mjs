// 실제 기록으로 판정 오케스트라 돌리기(2026-11-26). 설계 시나리오가 아니라 PC의 Claude Code·Codex가 디스크에 남긴 대화 기록
// (src/agent-history.mjs)을 라이브 훅과 같은 기록으로 바꾸고, 세션(traceId)마다 규칙·시퀀스 소견을 세션 전체에서 계산한 뒤, 학습 분포
// (세션당 1~16 행동)에 맞게 비슷한 크기의 구간(기본 12 행동 이하)으로 나눠 두 판정자에게 보낸다. 판정·처리는 설계 세트와 같은 코드다:
// 첫 판정자는 모든 구간, 둘째 판정자는 needsSecondJudge 구간만, 합의는 combineVerdicts, 경보 처리는 session-disposition의 원칙(모델은 경보를
// 지우지 못하고, 보호 경보·지시문 신호가 있는 구간은 낮추지도 못하며, 규칙이 못 본 모델 발견은 review).
// 실제 기록에는 정답이 없으므로 정확도가 아니라 운영 수치를 낸다: 규칙 경보 구간 중 두 판정자 합의로 low가 된 수, 보호·지시문·불일치로 남은 수,
// 모델 단독 발견(review) 수, 코드별 수. 기록 원문(명령·경로)이 들어 있는 요청·구간 파일은 *.local.* 로 PC에만 남고, 요약에는 숫자와 규칙
// 코드 이름만 들어간다.
import {createHash} from 'node:crypto';
import {readAgentHistory} from './agent-history.mjs';
import {combineVerdicts, needsSecondJudgeForInput} from './judge-orchestra.mjs';
import {dispositionFromInput} from './session-disposition.mjs';
import {SEQUENCE} from './sequence-rules.mjs';
import {predictInput, requestFromInput, sessionInputFromEvents} from './session-inference.mjs';

export const REAL_WINDOW = 12;
// 설계 시나리오(src/threat-scenarios.mjs buildScenarioEvents)와 같은 기록 껍데기: 같은 평가 경로를 탄다.
const TENANT = 'alpha', SOURCE = 'alpha-agent';
const NOW_OFFSET = 2 * 3600 * 1000;
const shortHash = s => createHash('sha256').update(s).digest('hex').slice(0, 16);

// readAgentHistory의 호출들 -> 세션별 기록. 한 에이전트의 모든 기록이 시간 순서(같은 시각이면 읽은 순서)로 하나의 seq를 받는다: 세션을
// 넘는 연쇄를 볼 때도 순서가 맞는다. collection 표시는 뺀다: 학습 시나리오의 기록과 같은 모양이 되고, 위험·시퀀스 규칙은 이 필드를 보지 않는다.
export function sessionsFromCalls(calls, {agent}) {
  const records = calls.flatMap(call => call.records).map((record, i) => [record, i])
    .sort(([a, i], [b, j]) => Date.parse(a.occurredAt) - Date.parse(b.occurredAt) || i - j);
  const bySession = new Map();
  let seq = 0;
  for (const [{collection, ...e}] of records) {
    const event = {...e, seq: ++seq, tenant: TENANT, source: SOURCE, sourceKind: 'agent', receivedAt: e.occurredAt};
    if (!bySession.has(event.traceId)) bySession.set(event.traceId, []);
    bySession.get(event.traceId).push(event);
  }
  return [...bySession].map(([traceId, events]) => ({agent, traceId, events}));
}

// 각 세션과 같은 시간대(세션 앞뒤 연쇄 창 SEQUENCE.windowMs 안)의 다른 세션 기록. 저장소는 같은 행위자의 연쇄를 세션을 가리지 않고 잡으므로,
// 동시에 돌던 세션의 단계도 소견 계산에 넣는다(행동 목록에는 넣지 않는다).
export function withContext(sessions) {
  const all = sessions.flatMap(s => s.events.map(e => ({e, t: Date.parse(e.occurredAt), trace: s.traceId}))).sort((a, b) => a.t - b.t);
  const firstAtOrAfter = t => { let lo = 0, hi = all.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (all[mid].t < t) lo = mid + 1; else hi = mid; } return lo; };
  return sessions.map(s => {
    if (!s.events.length) return {...s, context: []};
    const times = s.events.map(e => Date.parse(e.occurredAt)), from = Math.min(...times) - SEQUENCE.windowMs, to = Math.max(...times) + SEQUENCE.windowMs;
    const context = [];
    for (let i = firstAtOrAfter(from); i < all.length && all[i].t <= to; i++) if (all[i].trace !== s.traceId) context.push(all[i].e);
    return {...s, context: context.sort((a, b) => a.seq - b.seq)};
  });
}

// n개 행동을 size 이하의 비슷한 크기 구간 [from, to)로. 13개 -> 7+6, 25개 -> 9+9+7 (꼬리에 1~2개짜리 구간이 생기지 않게).
export function windowBounds(n, size = REAL_WINDOW) {
  if (!(n > 0)) return [];
  if (!(Number.isInteger(size) && size > 0)) throw RangeError('window size is a positive integer');
  const step = Math.ceil(n / Math.ceil(n / size)), bounds = [];
  for (let from = 0; from < n; from += step) bounds.push([from, Math.min(n, from + step)]);
  return bounds;
}

// 한 세션 -> 판정 구간들. 소견은 세션 전체 기록(과 같은 시간대 다른 세션의 context)으로 계산하고(구간 경계를 넘는 연쇄도 잡힌다) 나서 나눈다. 구간 id는 에이전트·세션·시작
// 위치의 해시라 모델 프롬프트에 세션 id가 들어가지 않는다. from/to(시각)와 traceId는 PC에만 남는 색인용이다.
export function sessionWindows(session, rules, {window = REAL_WINDOW} = {}) {
  if (!session.events.length) return [];
  const last = session.events.reduce((t, e) => Math.max(t, Date.parse(e.occurredAt)), 0);
  const input = sessionInputFromEvents(session.events, rules, {tool: session.agent, now: last + NOW_OFFSET, context: session.context ?? []});
  const at = new Map();
  for (const e of session.events) if (!at.has(e.actionId)) at.set(e.actionId, e.occurredAt);
  return windowBounds(input.actions.length, window).map(([from, to], index, all) => {
    const actions = input.actions.slice(from, to), ids = new Set(actions.map(a => a.actionId));
    return {id: `rw-${shortHash(`${session.agent}|${session.traceId}|${from}`)}`, agent: session.agent, traceId: session.traceId, index, of: all.length,
      from: at.get(actions[0].actionId), to: at.get(actions.at(-1).actionId),
      input: {tool: input.tool, actionCount: actions.length, actions, instructionsInRecords: input.instructionsInRecords.filter(id => ids.has(id))}};
  });
}

// 에이전트 기록 폴더들 -> 세션·구간. agents: [{agent, dir}]. 기본은 하위 에이전트(sidechain) 호출도 넣는다: 라이브 훅도 그 호출을 같은
// 세션으로 받는다.
export async function realWindows(agents, rules, {since, until, window = REAL_WINDOW, sidechains = true} = {}) {
  const out = {windows: [], stats: {}};
  for (const {agent, dir} of agents) {
    const {calls, stats} = await readAgentHistory({agent, dir, since, until, sidechains, actor: `${agent}@pc`});
    const sessions = withContext(sessionsFromCalls(calls, {agent}));
    const windows = sessions.flatMap(s => sessionWindows(s, rules, {window}));
    out.windows.push(...windows);
    out.stats[agent] = {files: stats.files, unreadableFiles: stats.unreadableFiles, calls: calls.length, sessions: sessions.length, windows: windows.length,
      skipped: {noTime: stats.skipped.noTime, outOfRange: stats.skipped.outOfRange, repeated: stats.skipped.repeated}};
  }
  return out;
}

// 배치 요청(학습된 판정자용 candidate 변형). 두 판정자 모두 같은 요청을 읽는다(JEV는 사용자 메시지만, Qwen은 메시지 전체).
export const windowRequest = w => requestFromInput(w.id, w.input, {variant: 'candidate'});

// 기록된 출력({id: content})과 logprobs로 구간 예측. threshold(마이크로냇 정수)가 있으면 그 아래 판정은 기권으로 바꾼다(설계 세트와 같은 규칙).
export const windowPredict = (outputs, {logprobs, threshold} = {}) => w => predictInput(w.id, w.input, outputs, {logprobs, threshold});

// 첫 판정 결과를 보고 둘째 판정자가 필요한 구간만.
export const secondJudgeWindows = (windows, first) => windows.filter(w => needsSecondJudgeForInput(w.input, first(w)));

// 한 구간의 최종 결과(src/judge-orchestra.mjs conduct와 같은 흐름). 둘째 판정이 필요한데 출력이 없으면 secondMissing으로 센다(그 구간은
// 기권으로 합쳐져 규칙 경보가 그대로 남는다).
export function conductWindow(w, {first, second}) {
  const a = first(w);
  const secondCalled = needsSecondJudgeForInput(w.input, a);
  const b = secondCalled ? second(w) : null;
  const verdict = secondCalled ? combineVerdicts(a.verdict, b.verdict) : a.verdict;
  const d = dispositionFromInput(w.input, {verdict});
  const explainer = verdict !== 'violation' ? null : b?.verdict === 'violation' ? b : a;
  return {verdict, alert: d.alert, priority: d.priority, source: d.source, protectedCodes: d.protectedCodes, instructionsInRecords: d.instructionsInRecords,
    judges: {first: a.verdict, second: b?.verdict ?? null}, firstValid: a.schemaValid, secondCalled, secondValid: b ? b.schemaValid : null,
    type: explainer?.type ?? null};
}

const bump = (o, k, n = 1) => { o[k] = (o[k] || 0) + n; return o; };
const sorted = o => Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

// 숫자만 담은 요약. 규칙 경보 구간(소견이 있는 구간)이 어떻게 처리됐는지, 모델 단독 발견, 판정자별 분포, 세션 수준 결과, 코드별 수.
export function summarizeReal(windows, results) {
  const rows = windows.map((w, i) => ({w, r: results[i], codes: [...new Set(w.input.actions.flatMap(a => a.findings.map(f => f.code)))]}));
  const flagged = rows.filter(x => x.codes.length);
  const verdicts = pick => rows.reduce((o, x) => (pick(x) === null ? o : bump(o, pick(x))), {violation: 0, clean: 0, abstain: 0});
  const sessions = new Map();
  for (const x of rows) {
    const key = `${x.w.agent}|${x.w.traceId}`;
    if (!sessions.has(key)) sessions.set(key, {agent: x.w.agent, rows: []});
    sessions.get(key).rows.push(x);
  }
  const sessionRows = [...sessions.values()], flaggedSessions = sessionRows.filter(s => s.rows.some(x => x.codes.length));
  const codes = {};
  for (const x of flagged) for (const code of x.codes) {
    const c = codes[code] ??= {windows: 0, lowered: 0, kept: 0, protected: 0};
    c.windows++;
    if (x.r.priority === 'low') c.lowered++; else c.kept++;
    if (x.r.protectedCodes.includes(code)) c.protected++;
  }
  const kept = flagged.filter(x => x.r.priority !== 'low');
  return {
    sessions: sessionRows.length, sessionsByAgent: sorted(sessionRows.reduce((o, s) => bump(o, s.agent), {})),
    windows: rows.length, actions: rows.reduce((n, x) => n + x.w.input.actionCount, 0),
    windowsPerSession: {max: Math.max(0, ...sessionRows.map(s => s.rows.length)), single: sessionRows.filter(s => s.rows.length === 1).length},
    judges: {first: verdicts(x => x.r.judges.first), firstInvalid: rows.filter(x => !x.r.firstValid).length,
      secondCalled: rows.filter(x => x.r.secondCalled).length, second: verdicts(x => x.r.judges.second),
      secondInvalid: rows.filter(x => x.r.secondCalled && !x.r.secondValid).length,
      agreeWhenBoth: rows.filter(x => x.r.secondCalled && x.r.judges.first === x.r.judges.second).length, combined: verdicts(x => x.r.verdict)},
    priority: sorted(rows.reduce((o, x) => bump(o, x.r.priority ?? 'none'), {})),
    ruleAlerts: {windows: flagged.length, high: flagged.filter(x => x.w.input.actions.some(a => a.findings.some(f => f.severity === 'high'))).length,
      loweredToLow: flagged.length - kept.length,
      kept: kept.length, keptHigh: kept.filter(x => x.r.priority === 'high').length,
      keptByProtection: kept.filter(x => x.r.verdict === 'clean' && x.r.protectedCodes.length).length,
      keptByInstructions: kept.filter(x => x.r.verdict === 'clean' && !x.r.protectedCodes.length && x.r.instructionsInRecords.length).length,
      keptModelViolation: kept.filter(x => x.r.verdict === 'violation').length, keptModelAbstain: kept.filter(x => x.r.verdict === 'abstain').length},
    modelOnlyReviews: rows.filter(x => x.r.priority === 'review').length,
    violationTypes: sorted(rows.filter(x => x.r.verdict === 'violation' && x.r.type).reduce((o, x) => bump(o, x.r.type), {})),
    sessionLevel: {flagged: flaggedSessions.length,
      allRuleAlertsLowered: flaggedSessions.filter(s => s.rows.every(x => !x.codes.length || x.r.priority === 'low')).length,
      anyKeptHigh: sessionRows.filter(s => s.rows.some(x => x.r.priority === 'high')).length,
      anyReview: sessionRows.filter(s => s.rows.some(x => x.r.priority === 'review')).length},
    codes: sorted(codes),
  };
}

// PC에만 남는 확인 목록: 경보가 남았거나(low 아님) review가 된 구간의 id·세션·구간 위치·코드·판정. 명령·경로 원문은 넣지 않는다.
export function reviewList(windows, results) {
  return windows.map((w, i) => ({w, r: results[i]})).filter(({r}) => r.alert && r.priority !== 'low')
    .map(({w, r}) => ({id: w.id, agent: w.agent, traceId: w.traceId, window: `${w.index + 1}/${w.of}`, from: w.from, to: w.to, priority: r.priority,
      verdict: r.verdict, judges: r.judges, type: r.type, protectedCodes: r.protectedCodes, instructions: r.instructionsInRecords.length,
      codes: [...new Set(w.input.actions.flatMap(a => a.findings.map(f => f.code)))].sort()}));
}
