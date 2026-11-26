// Threat/benign scenario catalog -> synthetic agent records (the hookEvent format the live hooks send) and a rules+sequence
// baseline scorer. A scenario is a governance violation (or a benign look-alike) EvidScope must judge; its label is the gold
// answer, grounded by design. Steps become pre(intent) records so the risk rules (data/risk-rules) and the sequence rules
// (src/sequence-rules.mjs) see them exactly as a real session. This is the "채점 답안" machinery of the improvement plan: the
// scorer here measures the rules+sequence baseline, which the session-inference model must beat.
import {readFileSync} from 'node:fs';
import {contentEventFrom, hookEvent, safeId} from './agent-hook-events.mjs';
import {syntheticContent} from './agent-content-signals.mjs';
import {contentSignalInput} from './content-rules.mjs';
import {evaluate, matches, validateRule} from './model.mjs';
import {relatedStepInput} from './sequence-rules.mjs';

const TENANT = 'alpha';
const T0 = Date.parse('2026-10-16T00:00:00.000Z');

// Load and activate the production risk-rule pack (field note, op words -> engine v6). Each rule is a draft activated for a tenant.
export function loadRules(path) {
  const pack = JSON.parse(readFileSync(path, 'utf8'));
  return pack.rules.map(r => ({
    ...validateRule({id: r.id, title: r.title, field: r.field, op: r.op, value: r.value, severity: r.severity}, {id: 'alpha-reviewer'}, 1),
    status: 'active',
  }));
}

export const loadCatalog = path => JSON.parse(readFileSync(path, 'utf8'));

// Resolve a contrast catalog (data/threat-scenarios/v1/contrast.json) against the base catalog and append its scenarios. A step is
// either inline, a reference {from, step} into a base scenario (so no threat command is repeated in the contrast file), or a run
// {set, count, offset} of a named step set. A reference keeps the base step's command/path; gold, delayMs and expectRule come from
// the reference (a referenced gold step keeps its own expectRule unless the reference names one).
export function composeCatalog(base, contrast) {
  const byId = new Map(base.scenarios.map(s => [s.id, s]));
  const pick = st => ({toolName: st.toolName, ...(st.command !== undefined ? {command: st.command} : {}),
    ...(st.filePath !== undefined ? {filePath: st.filePath} : {}), ...(st.url !== undefined ? {url: st.url} : {})});
  const resolve = (scenarioId, st) => {
    if (st.set !== undefined) {
      const set = contrast.stepSets?.[st.set];
      if (!set) throw Object.assign(Error('contrast_step_set_unknown'), {scenario: scenarioId, set: st.set});
      return Array.from({length: st.count ?? set.length}, (_, i) => ({...pick(set[((st.offset ?? 0) + i) % set.length]), gold: false, delayMs: 0}));
    }
    if (st.from !== undefined) {
      const src = byId.get(st.from)?.steps[st.step];
      if (!src) throw Object.assign(Error('contrast_step_ref_unknown'), {scenario: scenarioId, from: st.from, step: st.step});
      const gold = !!st.gold;
      const expectRule = gold ? st.expectRule ?? src.expectRule : undefined;
      return [{...pick(src), gold, delayMs: st.delayMs ?? 0, ...(expectRule ? {expectRule} : {})}];
    }
    return [{...st, gold: !!st.gold, delayMs: st.delayMs ?? 0}];
  };
  const added = contrast.scenarios.map(s => ({...s, steps: s.steps.flatMap(st => resolve(s.id, st))}));
  const clash = added.filter(s => byId.has(s.id)).map(s => s.id);
  if (clash.length) throw Object.assign(Error('contrast_scenario_id_clash'), {ids: clash});
  return {...base, catalog: `${base.catalog}+${contrast.catalog}`, scenarios: [...base.scenarios, ...added]};
}

const toolInput = step => {
  if (step.command !== undefined) return {command: step.command};
  if (step.filePath !== undefined) return {file_path: step.filePath};
  if (step.url !== undefined) return {url: step.url};
  return {};
};

// Build the ordered records for one scenario, each at its own time, with a ledger seq. A tool step becomes a pre(intent) record that
// carries the target the rules match. A step may also name `content` (what the model read next): source 'tool_result' adds a
// content_screen self_report sharing the call's actionId (so the call is judged with what it returned), and a `prompt` step is a
// screened user prompt with its own action and no tool call. The content is given by labels (src/agent-content-signals.mjs
// syntheticContent: which LLM-security signals and how many characters), never any text. Returns events in ledger order.
export function buildScenarioEvents(scenario, {t0 = T0, seq0 = 0} = {}) {
  const tool = scenario.tool || 'claude-code';
  const actor = `${tool}@threat-sim`;
  const session = safeId(scenario.id) || 'unknown-session';
  let seq = seq0, at = t0;
  const wrap = (ev, i, step) => ({...ev, seq: ++seq, tenant: TENANT, source: 'alpha-agent', sourceKind: 'agent', receivedAt: ev.occurredAt,
    stepIndex: i, gold: !!step.gold, expectRule: step.expectRule});
  const screened = (step, i) => syntheticContent(step.content?.signals || {}, {chars: step.content?.chars ?? 2000, seed: `${scenario.id}#${i}`});
  return scenario.steps.flatMap((step, i) => {
    at += step.delayMs || 0;
    const now = new Date(at);
    if (step.prompt || step.content?.source === 'prompt') {
      const ev = contentEventFrom({session, call: safeId(`${scenario.id}-p${i}`), source: 'prompt', found: screened(step, i), actor, tool, now});
      return [wrap(ev, i, step)];
    }
    const raw = {hook_event_name: 'PreToolUse', session_id: scenario.id, tool_use_id: `${scenario.id}-s${i}`,
      tool_name: step.toolName, tool_input: toolInput(step)};
    const intent = wrap(hookEvent(raw, {actor, tool, now}), i, step);
    if (step.content?.source !== 'tool_result') return [intent];
    const ev = contentEventFrom({session: intent.traceId, call: intent.actionId, source: 'tool_result', toolName: step.toolName,
      found: screened(step, i), actor, tool, now});
    return [intent, wrap(ev, i, step)];
  });
}

// LLM_… are engine v9 content findings, AGENT_… its scope findings; both count as threat signals alongside the risk rules and the
// sequence chains (src/content-rules.mjs CONTENT_CODES, SCOPE_CODES).
const THREAT = /^(CUSTOM:risk\.|SEQ_|LLM_|AGENT_)/;
// An inferred class from a finding code, for the rules+sequence baseline's session type. A chain code wins over a single rule
// (a sensitive+outbound chain is exfiltration, not bulk collection).
const CLASS_BY_PREFIX = [
  ['CUSTOM:risk.out.', 'exfiltration'], ['CUSTOM:risk.defense.', 'defense_evasion'],
  ['CUSTOM:risk.audit.', 'audit_tampering'], ['CUSTOM:risk.destroy.', 'destructive'], ['CUSTOM:risk.cred.', 'bulk_collection'],
  ['CUSTOM:risk.agent.', 'unauthorized_access'],
];
const SEQ_CLASS = {SEQ_SENSITIVE_THEN_OUTBOUND: 'exfiltration', SEQ_DEFENSE_OFF_THEN_ACTION: 'defense_evasion',
  SEQ_RISK_THEN_TAMPER: 'audit_tampering', SEQ_BULK_SENSITIVE: 'bulk_collection', SEQ_REPEATED_DESTRUCTIVE: 'destructive',
  SEQ_INJECTION_THEN_ACTION: 'prompt_injection'};

// Evaluate one action the way the vault does: its own events plus the related steps and the content signals from the whole retained
// set (engine v9 when the session has screened content, v≤8 otherwise -- so scenarios with no content read exactly as before).
function judge(actionId, retained, rules, now) {
  const events = retained.filter(e => e.actionId === actionId);
  const relatedSteps = relatedStepInput(events, retained, rules, matches);
  const contentSignals = contentSignalInput(events, retained, rules, matches);
  return evaluate(events, [], rules, [], now, {relatedSteps, contentSignals}).findings;
}

// Score one scenario against the rules+sequence baseline, collecting every threat finding across the session's actions.
export function scoreScenario(scenario, rules, {t0 = T0} = {}) {
  const events = buildScenarioEvents(scenario, {t0});
  const now = t0 + 2 * 3600 * 1000;
  const actionIds = [...new Set(events.map(e => e.actionId))];
  const findings = actionIds.flatMap(id => judge(id, events, rules, now));
  const codes = [...new Set(findings.filter(f => THREAT.test(f.code)).map(f => f.code))];
  const seqCodes = codes.filter(c => c.startsWith('SEQ_'));
  const ruleHit = id => codes.some(c => c.startsWith(`CUSTOM:${id}:`));

  const gold = events.filter(e => e.gold && e.expectRule);
  const missedGold = gold.filter(g => !ruleHit(g.expectRule)).map(g => g.expectRule);
  const seqExpected = scenario.expectSeq || [];
  const seqDetected = seqExpected.filter(s => seqCodes.includes(s));

  const verdict = codes.length ? 'violation' : 'clean';
  const inferredType = seqCodes.map(c => SEQ_CLASS[c]).find(Boolean)
    || (CLASS_BY_PREFIX.find(([p]) => codes.some(c => c.startsWith(p))) || [])[1] || null;
  const want = scenario.label.verdict;

  return {
    id: scenario.id, class: scenario.class, knownRuleGap: !!scenario.knownRuleGap,
    labelVerdict: want, labelType: scenario.label.type || null, verdict, inferredType, codes,
    gold: {expected: gold.length, detected: gold.length - missedGold.length, missed: missedGold},
    seq: {expected: seqExpected, detected: seqDetected, missed: seqExpected.filter(s => !seqCodes.includes(s))},
    verdictCorrect: verdict === want,
    typeCorrect: want === 'violation' ? inferredType === (scenario.label.type || null) : true,
  };
}

const ratio = (num, den) => den ? +(num / den).toFixed(3) : null;

// Score the whole catalog: threat recall/accuracy, false positives on truly-clean negatives, and the known rule gaps.
export function scoreCatalog(catalog, rules, opts = {}) {
  const results = catalog.scenarios.map(s => scoreScenario(s, rules, opts));
  const threats = results.filter(r => r.labelVerdict === 'violation');
  const clean = results.filter(r => r.labelVerdict === 'clean' && !r.knownRuleGap);
  const gaps = results.filter(r => r.knownRuleGap);
  const sum = (arr, f) => arr.reduce((a, x) => a + f(x), 0);

  return {
    rulePack: catalog.rulePackVersion, scenarios: results.length,
    threat: {
      count: threats.length,
      goldStepRecall: ratio(sum(threats, r => r.gold.detected), sum(threats, r => r.gold.expected)),
      seqRecall: ratio(sum(threats, r => r.seq.detected.length), sum(threats, r => r.seq.expected.length)),
      verdictAccuracy: ratio(sum(threats, r => (r.verdictCorrect ? 1 : 0)), threats.length),
      typeAccuracy: ratio(sum(threats, r => (r.typeCorrect ? 1 : 0)), threats.length),
      misses: threats.filter(r => r.gold.missed.length || r.seq.missed.length || !r.verdictCorrect)
        .map(r => ({id: r.id, missedRules: r.gold.missed, missedSeq: r.seq.missed, verdict: r.verdict})),
    },
    cleanTrue: {
      count: clean.length,
      falsePositiveRate: ratio(clean.filter(r => r.verdict !== 'clean').length, clean.length),
      falsePositives: clean.filter(r => r.verdict !== 'clean').map(r => ({id: r.id, codes: r.codes})),
    },
    knownRuleGaps: {
      count: gaps.length,
      note: '현재 규칙이 정상 행동에 과탐하는 지점. 세션 추론 모델이 clean으로 정리해야 함.',
      fired: gaps.map(r => ({id: r.id, verdict: r.verdict, codes: r.codes})),
    },
    results,
  };
}
