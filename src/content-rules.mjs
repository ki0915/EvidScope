// LLM security findings of AI coding agents (docs/agent-monitoring.md, evaluation engine v9). The hook screens the text the model
// reads, the user's prompt and each tool's answer, and sends a content record of the signals it found (src/agent-content-signals.mjs:
// labels, counts and a hash, never the text). This module turns those signals into findings for the action that read the text, and
// links an instruction-changing phrase to the risky calls the same session makes after it: a planted instruction in a web page, file
// or MCP answer, then a credential read, a transfer out, a destructive command or a change to defences or monitoring. Pure, like
// src/sequence-rules.mjs: the vault (src/store.mjs) and the offline replay (src/policy-replay.mjs) build the input with
// contentSignalInput. These are findings for review; the evaluation blocks nothing (the hook's guard, src/agent-hook-guard.mjs, is apart).
// v9 also reads the scope the hook records on each intent (src/agent-hook-events.mjs hookScope): a risky call made while the agent ran
// with its approval prompts or sandbox off, and a file edit outside the working folder.
import {recordContent} from './agent-content-signals.mjs';
import {CONTENT_TOOLS, HOOK_AGENTS, SCOPE_OUTSIDE} from './agent-hook-events.mjs';
import {SEQUENCE, classOf, isStep, loopback, stepRules} from './sequence-rules.mjs';

// Every code this module emits; evidence-pack mapping version 5 names each one.
export const CONTENT_CODES = Object.freeze(['LLM_INDIRECT_INJECTION', 'LLM_PROMPT_OVERRIDE', 'LLM_HIDDEN_TEXT', 'LLM_SECRET_IN_PROMPT',
  'LLM_SECRET_IN_CONTEXT', 'LLM_PERSONAL_DATA_IN_PROMPT', 'LLM_PERSONAL_DATA_IN_CONTEXT', 'SEQ_INJECTION_THEN_ACTION']);
// The scope codes of engine v9; evidence-pack mapping version 5 names each one too.
export const SCOPE_CODES = Object.freeze(['AGENT_RISK_WITHOUT_OVERSIGHT', 'AGENT_WRITE_OUTSIDE_WORKSPACE']);
// The modes in which nobody approves a call: Claude Code's bypassPermissions, a Codex run without a sandbox.
const OVERSIGHT_OFF = Object.freeze(['agent-mode:bypasspermissions', 'agent-sandbox:danger-full-access']);

// A content record of an AI coding agent or of the local model proxy (agent source, CONTENT_TOOLS, the content_screen self_report), as
// {source, signals, hash}, or null.
export function contentOf(e) {
  if (e?.sourceKind !== 'agent' || !CONTENT_TOOLS.includes(e.tool) || e.kind !== 'self_report' || e.action !== 'content_screen') return null;
  return recordContent(e);
}
const signalled = e => { const c = contentOf(e); return c && Object.keys(c.signals).length ? c : null; };
const injected = e => !!signalled(e)?.signals.injection_cue;
const time = e => Date.parse(e.occurredAt);
// The classes of a risky step (src/sequence-rules.mjs), without the outbound class for a transfer to the machine itself.
const riskyClasses = (e, ids) => {
  const classes = new Set(ids.flatMap(id => classOf(id.replace(/:v\d+$/, ''))));
  if (loopback(e.destination)) classes.delete('outbound');
  return classes;
};
const sameSession = (a, b) => a.traceId === b.traceId && a.actor === b.actor;
const categories = e => Array.isArray(e.dataCategories) ? e.dataCategories : [];
const hookIntent = e => isStep(e) && e.sourceKind === 'agent' && HOOK_AGENTS.includes(e.tool);
const oversightOff = e => hookIntent(e) && categories(e).find(c => OVERSIGHT_OFF.includes(c));
const outsideEdit = e => hookIntent(e) && e.action === 'file_write' && categories(e).includes(SCOPE_OUTSIDE);
// An intent whose scope makes a finding: a risky call with approvals off, or an edit outside the working folder.
const scoped = (e, ids) => !!(oversightOff(e) && riskyClasses(e, ids).size || outsideEdit(e));

// Snapshot input: the ledger seqs of this action's content records with a signal and of its intents with a scope finding (own), and
// summaries of other actions' records of
// the same session within the window (related): content records with an injection signal before this action's risky steps, and
// risky steps after this action's injection signals, in ledger order (the latest SEQUENCE.related). Undefined when this action has
// neither a signalled content record nor a risky step with an injection signal before it, so every other snapshot stays as it was.
export function contentSignalInput(actionEvents, retained, rules, matches) {
  const active = stepRules(rules);
  const named = e => active.filter(r => matches(r, e)).map(r => `${r.id}:v${r.version}`);
  const own = actionEvents.filter(e => signalled(e) || scoped(e, named(e)));
  const steps = actionEvents.filter(e => isStep(e) && riskyClasses(e, named(e)).size);
  if (!own.length && !steps.length) return undefined;
  const actionId = (own[0] || steps[0]).actionId, sources = own.filter(injected), related = [];
  for (const e of retained) {
    if (e.actionId === actionId) continue;
    const t = time(e);
    if (steps.length && injected(e) && steps.some(s => sameSession(s, e) && t <= time(s) && time(s) - t <= SEQUENCE.windowMs)) {
      const c = contentOf(e);
      related.push({seq: e.seq, source: e.source, id: e.id, actionId: e.actionId, traceId: e.traceId, actor: e.actor, occurredAt: e.occurredAt,
        content: {source: c.source, signals: c.signals}});
    } else if (sources.length && isStep(e) && sources.some(c => sameSession(c, e) && time(c) <= t && t - time(c) <= SEQUENCE.windowMs)) {
      const ids = named(e);
      if (!riskyClasses(e, ids).size) continue;
      related.push({seq: e.seq, source: e.source, id: e.id, actionId: e.actionId, traceId: e.traceId, actor: e.actor, occurredAt: e.occurredAt,
        ...(typeof e.resource === 'string' ? {resource: e.resource} : {}), ...(typeof e.destination === 'string' ? {destination: e.destination} : {}),
        rules: ids});
    }
  }
  if (!own.length && !related.length) return undefined;
  return {own: own.map(e => e.seq).sort((a, b) => a - b), related: related.sort((a, b) => a.seq - b.seq).slice(-SEQUENCE.related)};
}

const WINDOW = SEQUENCE.windowMs / 60000;
const where = source => source === 'prompt' ? '사용자 프롬프트' : 'AI가 읽은 도구 결과(웹 페이지·파일·MCP 응답·명령 출력)';
const personal = s => [s.unique_id ? `주민·외국인등록번호·운전면허번호 ${s.unique_id}개` : '', s.card_number ? `카드번호 ${s.card_number}개` : '',
  s.contact_bulk ? `서로 다른 연락처 ${s.contact_bulk}개` : ''].filter(Boolean).join(', ');

// The findings of engine v9 for this action's content records and risky steps (contentSignalInput). Like the sequence findings, a
// finding cites only this action's records and counts the other actions in the pattern.
export function contentFindings(events, input, {add, rules, matches}) {
  if (input === undefined) return;
  const active = stepRules(rules), mine = events.filter(e => input.own.includes(e.seq));
  const own = mine.map(e => ({e, ...signalled(e)})).filter(c => c.signals);
  for (const {e, source, signals: s} of own) {
    const prompt = source === 'prompt';
    if (s.injection_cue) add(prompt ? 'LLM_PROMPT_OVERRIDE' : 'LLM_INDIRECT_INJECTION', 'medium', prompt
      ? `사용자 프롬프트에 AI의 기존 지시·안전 규칙을 무시하거나 숨기게 하는 문구가 ${s.injection_cue}곳 있습니다. 탈옥·오용 시도인지 검토하세요`
      : `${where(source)}에 AI의 지시를 바꾸거나 사용자에게 숨기게 하는 문구가 ${s.injection_cue}곳 있습니다. 간접 프롬프트 주입인지 검토하세요`, [e]);
    else if (s.role_marker) add(prompt ? 'LLM_PROMPT_OVERRIDE' : 'LLM_INDIRECT_INJECTION', 'low',
      `${where(source)}에 대화 역할 표식(시스템·어시스턴트 구분 기호)이 ${s.role_marker}곳 있습니다. 모델 개발 자료가 아니라면 주입 시도인지 확인하세요`, [e]);
    if (s.hidden_text) add('LLM_HIDDEN_TEXT', 'low',
      `${where(source)}에 보이지 않는 문자(태그 문자·방향 제어 문자·연속된 폭 없는 문자)가 ${s.hidden_text}개 있습니다. 숨긴 지시인지 확인하세요`, [e]);
    if (s.secret_value) add(prompt ? 'LLM_SECRET_IN_PROMPT' : 'LLM_SECRET_IN_CONTEXT', prompt ? 'high' : 'medium', prompt
      ? `사용자 프롬프트에 API 키·개인키 같은 비밀 값 형태가 ${s.secret_value}개 있어 AI 서비스로 전송되었습니다. 키를 폐기·교체할지 검토하세요`
      : `${where(source)}에 API 키·개인키 같은 비밀 값 형태가 ${s.secret_value}개 있어 AI 서비스로 전송되었습니다. 필요한 접근이었는지 검토하세요`, [e]);
    if (s.unique_id || s.card_number || s.contact_bulk) add(prompt ? 'LLM_PERSONAL_DATA_IN_PROMPT' : 'LLM_PERSONAL_DATA_IN_CONTEXT',
      s.unique_id || s.card_number ? 'high' : 'medium',
      `${where(source)}에 개인정보(${personal(s)})가 있어 AI 서비스로 전송되었습니다. 처리 근거와 국외 이전 여부를 검토하세요`, [e]);
  }
  for (const e of mine.filter(isStep)) {
    const mode = oversightOff(e), ids = active.filter(r => matches(r, e)).map(r => r.id);
    if (mode && riskyClasses(e, ids).size) add('AGENT_RISK_WITHOUT_OVERSIGHT', 'medium', `AI가 승인 확인을 끈 모드(${mode.split(':')[1]})에서 `
      + '위험 규칙에 걸린 행동을 했습니다. 사람이 승인하지 않은 실행이니 의도한 작업인지 검토하세요', [e]);
    if (outsideEdit(e)) add('AGENT_WRITE_OUTSIDE_WORKSPACE', 'medium',
      'AI가 작업 폴더 밖의 파일을 고치려 했습니다. 다른 프로젝트, 시스템 설정이나 다른 에이전트의 설정을 건드린 것인지 검토하세요', [e]);
  }
  // The chain: an injection signal, then (no later, within the window) a risky step of the same session; this action's part is the
  // risky step (then), the injection signal (first), or both.
  const steps = events.filter(isStep).map(e => ({e, classes: riskyClasses(e, active.filter(r => matches(r, e)).map(r => r.id))})).filter(s => s.classes.size);
  const sources = own.filter(c => c.signals.injection_cue);
  const before = input.related.filter(r => r.content?.signals?.injection_cue)
    .filter(r => steps.some(s => sameSession(s.e, r) && time(r) <= time(s.e) && time(s.e) - time(r) <= SEQUENCE.windowMs));
  const after = input.related.filter(r => Array.isArray(r.rules) && riskyClasses(r, r.rules).size)
    .filter(r => sources.some(c => sameSession(c.e, r) && time(c.e) <= time(r) && time(r) - time(c.e) <= SEQUENCE.windowMs));
  const thenSteps = steps.filter(s => before.some(r => sameSession(s.e, r) && time(r) <= time(s.e) && time(s.e) - time(r) <= SEQUENCE.windowMs));
  const firstSources = sources.filter(c => after.some(r => sameSession(c.e, r) && time(c.e) <= time(r) && time(r) - time(c.e) <= SEQUENCE.windowMs));
  if (!thenSteps.length && !firstSources.length) return;
  const n = new Set([...before, ...after].map(r => r.actionId)).size;
  const from = [...new Set([...before.map(r => r.content.source), ...firstSources.map(c => c.source)])];
  const origin = from.length === 1 ? where(from[0]) : '사용자 프롬프트와 AI가 읽은 도구 결과';
  const message = thenSteps.length && firstSources.length
    ? `같은 세션에서 ${origin}에 지시를 바꾸려는 문구가 있었고 ${WINDOW}분 안에 위험 행동이 이어졌으며 이 행동이 그 일부입니다(다른 행동 ${n}건). 주입된 지시를 따른 것인지 검토하세요`
    : thenSteps.length
      ? `이 위험 행동 앞 ${WINDOW}분 안에 같은 세션의 ${origin}에 지시를 바꾸려는 문구가 있었습니다(다른 행동 ${n}건). 주입된 지시를 따른 행동인지 검토하세요`
      : `이 행동에서 ${origin}에 지시를 바꾸려는 문구가 있었고 그 뒤 ${WINDOW}분 안에 같은 세션에서 AI가 위험 행동을 했습니다(다른 행동 ${n}건). `
        + '주입된 지시를 따른 것인지 검토하세요';
  add('SEQ_INJECTION_THEN_ACTION', 'high', message, [...thenSteps.map(s => s.e), ...firstSources.map(c => c.e)]);
}
