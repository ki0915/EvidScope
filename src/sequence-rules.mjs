// Multi-action anomaly rules for AI coding agents (docs/agent-monitoring.md, evaluation engine v5). Each tool call of an agent is
// one action, and the risk rules (data/risk-rules/ai-agent-baseline.json) flag a call on its own. These rules also read the risky
// calls of the same actor around an action, so steps that are each only a signal show the pattern they make together: reading a
// credential file and then sending data out, disabling a defence and then acting, acting and then clearing logs. A step is an
// intent whose fields an active rule of the agent risk pack matches; the rule id gives its class (risk.cred.*, risk.out.*, ...).
// Pure: src/model.mjs passes its rule matcher; the vault (src/store.mjs) and the offline replay (src/policy-replay.mjs) build the
// input with relatedStepInput. EvidScope blocks nothing: these are findings for review.

// Engine constants (a change is a new evaluation engine): the window of a chain, how many related steps a snapshot carries, and
// the window and threshold of the two count rules (distinct credential targets, destructive commands).
export const SEQUENCE = Object.freeze({windowMs: 30 * 60 * 1000, related: 50,
  bulk: Object.freeze({windowMs: 10 * 60 * 1000, threshold: 5}), destructive: Object.freeze({windowMs: 10 * 60 * 1000, threshold: 3})});
// Step classes by rule id prefix; a rule can fall in more than one class.
export const STEP_CLASSES = Object.freeze({
  sensitive: ['risk.cred.'], outbound: ['risk.out.'], destroy: ['risk.destroy.'],
  defenseOff: ['risk.defense.defender', 'risk.defense.firewall', 'risk.defense.iptables-flush', 'risk.defense.selinux-off'],
  tamper: ['risk.defense.clear-eventlog', 'risk.defense.history-clear', 'risk.audit.'], weaken: ['risk.defense.chmod-777'],
});
const classOf = id => Object.keys(STEP_CLASSES).filter(name => STEP_CLASSES[name].some(prefix => id.startsWith(prefix)));
const stepRules = rules => rules.filter(r => typeof r.id === 'string' && classOf(r.id).length);
const isStep = e => e?.kind === 'intent' && typeof e.actor === 'string' && e.actor !== '';
const time = e => Date.parse(e.occurredAt);
// A transfer to the machine itself (curl to a local API under test) is not data leaving it.
const LOOPBACK = /^(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|::1|\[::1\])$/;
const loopback = destination => typeof destination === 'string' && LOOPBACK.test(destination.toLowerCase());

// Snapshot input: the risky steps of other actions by the same actors within the window around this action's own risky steps, as
// summaries in ledger order (the latest `related`), each with the id and version of every rule of the pack that matches it.
// Undefined when this action has no risky step (or the tenant no rule of the pack), so every other snapshot stays as it was.
export function relatedStepInput(actionEvents, retained, rules, matches) {
  const active = stepRules(rules);
  if (!active.length) return undefined;
  const named = e => active.filter(r => matches(r, e)).map(r => `${r.id}:v${r.version}`);
  const here = actionEvents.filter(e => isStep(e) && named(e).length);
  if (!here.length) return undefined;
  const actionId = here[0].actionId, range = new Map();
  for (const e of here) {const t = time(e), r = range.get(e.actor);range.set(e.actor, r ? [Math.min(r[0], t), Math.max(r[1], t)] : [t, t]);}
  const related = [];
  for (const e of retained) {
    if (!isStep(e) || e.actionId === actionId || !range.has(e.actor)) continue;
    const t = time(e), [from, to] = range.get(e.actor);
    if (!(t >= from - SEQUENCE.windowMs && t <= to + SEQUENCE.windowMs)) continue;
    const ids = named(e);
    if (!ids.length) continue;
    related.push({seq: e.seq, source: e.source, id: e.id, actionId: e.actionId, actor: e.actor, occurredAt: e.occurredAt,
      ...(typeof e.resource === 'string' ? {resource: e.resource} : {}), ...(typeof e.destination === 'string' ? {destination: e.destination} : {}),
      rules: ids});
  }
  return related.sort((a, b) => a.seq - b.seq).slice(-SEQUENCE.related);
}

const WINDOW = SEQUENCE.windowMs / 60000, NEAR = SEQUENCE.bulk.windowMs / 60000, NEAR_DESTROY = SEQUENCE.destructive.windowMs / 60000;
// Chain rules: a step of a first class, then (no later, and at most the window after it) a step of a then class by the same actor.
// The messages name this action's part: then (it completes the chain), first (it starts one), same (one command holds both) or both.
const CHAINS = [
  {code: 'SEQ_SENSITIVE_THEN_OUTBOUND', first: ['sensitive'], then: ['outbound'], message: {
    same: '한 명령 안에 자격증명·비밀 파일 접근과 외부 전송이 함께 있습니다. 유출 시도인지 검토하세요',
    then: n => `이 외부 전송 앞 ${WINDOW}분 안에 같은 AI가 자격증명·비밀 파일에 접근했습니다(다른 행동 ${n}건). 유출 시도인지 검토하세요`,
    first: n => `이 자격증명·비밀 파일 접근 뒤 ${WINDOW}분 안에 같은 AI가 외부 전송을 시도했습니다(다른 행동 ${n}건). 유출 시도인지 검토하세요`,
    both: n => `같은 AI가 ${WINDOW}분 안에 자격증명·비밀 파일 접근과 외부 전송을 이어서 했고 이 행동이 그 일부입니다(다른 행동 ${n}건). `
      + '유출 시도인지 검토하세요'}},
  {code: 'SEQ_DEFENSE_OFF_THEN_ACTION', first: ['defenseOff'], then: ['sensitive', 'outbound', 'destroy'], message: {
    same: '한 명령 안에 보안 기능 해제와 위험 행동이 함께 있습니다. 방어를 끄고 한 행동인지 검토하세요',
    then: n => `이 행동 앞 ${WINDOW}분 안에 같은 AI가 보안 기능(백신·방화벽 등)을 껐습니다(다른 행동 ${n}건). 방어를 끄고 한 행동인지 검토하세요`,
    first: n => `이 보안 기능 해제 뒤 ${WINDOW}분 안에 같은 AI가 위험 행동을 시도했습니다(다른 행동 ${n}건). 방어를 끄고 한 행동인지 검토하세요`,
    both: n => `같은 AI가 ${WINDOW}분 안에 보안 기능 해제와 위험 행동을 이어서 했고 이 행동이 그 일부입니다(다른 행동 ${n}건). `
      + '방어를 끄고 한 행동인지 검토하세요'}},
  {code: 'SEQ_RISK_THEN_TAMPER', first: ['sensitive', 'outbound', 'destroy', 'defenseOff', 'weaken'], then: ['tamper'], message: {
    same: '한 명령 안에 위험 행동과 기록 삭제·감시 설정 접근이 함께 있습니다. 흔적을 지우려 한 것인지 검토하세요',
    then: n => `이 기록 삭제·감시 설정 접근 앞 ${WINDOW}분 안에 같은 AI가 위험 행동을 했습니다(다른 행동 ${n}건). 흔적을 지우려 한 것인지 검토하세요`,
    first: n => `이 위험 행동 뒤 ${WINDOW}분 안에 같은 AI가 기록 삭제나 감시 설정 접근을 시도했습니다(다른 행동 ${n}건). 흔적을 지우려 한 것인지 검토하세요`,
    both: n => `같은 AI가 ${WINDOW}분 안에 위험 행동과 기록 삭제·감시 설정 접근을 이어서 했고 이 행동이 그 일부입니다(다른 행동 ${n}건). `
      + '흔적을 지우려 한 것인지 검토하세요'}},
];
// Every code these rules emit (the chains, then the two count rules); evidence-pack mapping version 4 names each one.
export const SEQUENCE_CODES = Object.freeze([...CHAINS.map(chain => chain.code), 'SEQ_BULK_SENSITIVE', 'SEQ_REPEATED_DESTRUCTIVE']);

// The findings of engine v5 for this action's own risky steps against the related steps (relatedStepInput). A finding cites only
// this action's steps (the related ones are other actions' evidence, which the vault does not let a finding cite) and counts the
// other actions in the pattern. Nothing runs without the input, so engine v5 returns the earlier output for every other snapshot.
export function sequenceFindings(events, related, {add, rules, matches}) {
  if (related === undefined) return;
  const active = stepRules(rules);
  const step = (e, ids, here) => {
    const classes = new Set(ids.flatMap(classOf));
    if (loopback(e.destination)) classes.delete('outbound');
    return {e, here, seq: e.seq, actionId: e.actionId, actor: e.actor, at: time(e), resource: e.resource, classes};
  };
  const own = events.filter(isStep).map(e => step(e, active.filter(r => matches(r, e)).map(r => r.id), true)).filter(s => s.classes.size);
  if (!own.length) return;
  const others = related.map(s => step(s, s.rules.map(id => id.replace(/:v\d+$/, '')), false)).filter(s => s.classes.size);
  const all = [...own, ...others], has = (s, names) => names.some(name => s.classes.has(name));
  const before = (a, b) => a === b || a.at < b.at || (a.at === b.at && a.seq < b.seq);
  for (const chain of CHAINS) {
    const firsts = all.filter(s => has(s, chain.first)), thens = all.filter(s => has(s, chain.then)), pairs = [];
    for (const a of firsts) for (const b of thens) {
      if ((a.here || b.here) && a.actor === b.actor && before(a, b) && b.at - a.at <= SEQUENCE.windowMs) pairs.push([a, b]);
    }
    if (!pairs.length) continue;
    const linked = pairs.filter(([a, b]) => a !== b), n = new Set(linked.flatMap(p => p.filter(s => !s.here).map(s => s.actionId))).size;
    const part = !linked.length ? 'same' : linked.every(([a, b]) => b.here && !a.here) ? 'then'
      : linked.every(([a, b]) => a.here && !b.here) ? 'first' : 'both';
    const message = part === 'same' ? chain.message.same : chain.message[part](n);
    add(chain.code, 'high', message, [...new Set(pairs.flatMap(p => p.filter(s => s.here).map(s => s.e)))]);
  }
  // Count rules, around each of this action's steps of the class: distinct credential targets, and actions with a destructive command.
  const near = (cls, windowMs, key) => {
    let best = 0;
    for (const s of own.filter(x => x.classes.has(cls))) {
      const around = all.filter(x => x.classes.has(cls) && x.actor === s.actor && Math.abs(x.at - s.at) <= windowMs);
      best = Math.max(best, new Set(around.map(key)).size);
    }
    return best;
  };
  const targets = near('sensitive', SEQUENCE.bulk.windowMs, s => s.resource ?? '');
  if (targets >= SEQUENCE.bulk.threshold) add('SEQ_BULK_SENSITIVE', 'medium',
    `이 행동 앞뒤 ${NEAR}분 안에 같은 AI가 서로 다른 자격증명·비밀 대상 ${targets}곳에 접근했습니다(이 행동 포함). 대량 수집인지 검토하세요`,
    own.filter(s => s.classes.has('sensitive')).map(s => s.e));
  const destructive = near('destroy', SEQUENCE.destructive.windowMs, s => s.actionId);
  if (destructive >= SEQUENCE.destructive.threshold) add('SEQ_REPEATED_DESTRUCTIVE', 'medium',
    `이 행동 앞뒤 ${NEAR_DESTROY}분 안에 같은 AI가 파괴적 명령을 ${destructive}번 시도했습니다(이 행동 포함). 의도한 작업인지 확인하세요`,
    own.filter(s => s.classes.has('destroy')).map(s => s.e));
}
