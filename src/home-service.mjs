// The console home (docs/feature-guide.md): which agents have recorded activity now, what needs attention (threats, items
// waiting for a person, evidence present per framework) and the review model's status. Every value is derived from records
// already in the vault; nothing here appends to the ledger (the access log records the read like any other GET).
// "Active" means activity recorded in the window, never a heartbeat: a quiet agent may still run, an active one may have stopped.
import {canonical} from './crypto.mjs';
import {fail} from './model.mjs';
import {isDecision} from './decision-rules.mjs';
import {FRAMEWORKS, frameworkMapping} from './evidence-pack-frameworks.mjs';
import {NOT_CARRIED, inPeriod} from './evidence-inventory.mjs';
import {modelStatus} from './model-status.mjs';

export const AGENT_WINDOWS = Object.freeze({'5m': 300000, '15m': 900000, '1h': 3600000, '24h': 86400000});
export const HOME_PERIODS = Object.freeze({'7d': 7 * 86400000, '30d': 30 * 86400000, '90d': 90 * 86400000});
// The running-agents read is one index range over events(tenant, received), newest first, cut at these bounds.
export const GOVERNANCE_TTL_MS = 60000;
export const WINDOW_LIMITS = Object.freeze({events: 20000, bytes: 32 * 1024 * 1024, items: 200, quiet: 100});
const STOP_CODES = new Set(['STOP_UNCONFIRMED', 'EXECUTION_AFTER_STOP_REQUEST', 'STOP_ORDER_NOT_HELD', 'STOP_PROPAGATION_MISSING',
  'STOP_PROPAGATION_TIME_UNCERTAIN']);
const UNPROPAGATED = new Set(['overdue', 'activated_late', 'pending', 'no_enforcement_point']);
const DECIDERS = new Set(['reviewer', 'admin']);
const iso = t => new Date(t).toISOString();
const ACTIVE_DEFINITION = '활동 = 선택한 기간 안에 이 에이전트의 기록이 볼트에 수신됨(receivedAt 기준). 생존 신호(heartbeat)가 아닙니다. '
  + '기록이 없다고 멈춘 것이 아니며, 기록이 있다고 지금 실행 중이라는 뜻도 아닙니다.';

function sinceParam(params) {
  const since = params.get('since');
  if (since === null || since === '') return null;
  if (since.length > 40 || !Number.isFinite(Date.parse(since))) fail(400, 'since는 ISO 8601 시각입니다');
  return iso(Date.parse(since));
}
// One section of the home: a failure (a faulted projection, a limit) is shown in its place instead of failing the page.
function section(fn) {
  try { return {status: 'ok', ...fn()}; }
  catch (error) { return {status: 'unavailable', httpStatus: error?.status ?? 500, reason: String(error?.message || error).slice(0, 300)}; }
}
// Presence of each mapped evidence kind in the period, by the rules of measure() in src/evidence-inventory.mjs (the package
// counts): true present, false none recorded, null a kind not counted here (API responses, files, the online ledger check).
export function presence(rows, disclosures, period) {
  const types = new Set(), kinds = new Map(), checks = new Set(), codes = new Set(), latest = new Map();
  const opened = new Map(disclosures.map(d => [d.seq, d.event]));
  for (const row of rows) {
    if (!inPeriod(period, row.recordedAt)) continue;
    types.add(row.type);
    if (row.type === 'evaluation' && typeof row.payload?.actionId === 'string') latest.set(row.payload.actionId, row.payload);
    if (row.type !== 'event') continue;
    const sealed = String(row.payload?.format).startsWith('evidscope-encrypted-event'), event = opened.get(row.seq) ?? (sealed ? null : row.payload);
    if (!event || typeof event !== 'object') continue;
    if (!kinds.has(event.kind)) kinds.set(event.kind, new Set());kinds.get(event.kind).add(event.sourceKind);
    if (event.kind === 'governance_check' && event.governanceCheck?.checkType) checks.add(event.governanceCheck.checkType);
  }
  for (const v of latest.values()) for (const f of Array.isArray(v.findings) ? v.findings : []) if (f?.code) codes.add(f.code);
  return e => {
    if (e.type === 'integrityCheck' || NOT_CARRIED[e.type]) return null;
    if (e.type === 'record') return types.has(e.name);
    if (e.type === 'eventKind') return [e.source, ...(e.alsoAllowed || [])].some(k => kinds.get(e.name)?.has(k));
    if (e.type === 'checkType') return checks.has(e.name);
    if (e.type === 'finding') return codes.has(e.code);
    return null;
  };
}
let mappings = null;
const frameworkMappings = () => (mappings ??= FRAMEWORKS.map(id => frameworkMapping(id)));

// factsheets(p): the signed governance-model factsheets ({status, items}); src/governance-model-service.mjs.
export function createHome({store, policyObjects, verifiedEvents, approvals, registry, legalReviewState, runtimeStatus, now = () => Date.now(),
  factsheets = () => ({status: 'unavailable', reason: 'not_configured', items: []})}) {
  const values = (p, type) => [...policyObjects(p, type).values()];

  // Events received in [since, now], newest first, as one indexed range; cut at WINDOW_LIMITS (then counts are lower bounds).
  function windowEvents(p, since) {
    verifiedEvents(p);
    const events = [];let bytes = 0, truncated = false;
    const query = store.db.prepare('SELECT body FROM events WHERE tenant=? AND received>=? ORDER BY received DESC LIMIT ?');
    for (const row of query.iterate(p.tenant, iso(since), WINDOW_LIMITS.events + 1)) {
      if (events.length >= WINDOW_LIMITS.events || (bytes += row.body.length) > WINDOW_LIMITS.bytes) { truncated = true; break; }
      events.push(JSON.parse(row.body));
    }
    return {events, truncated};
  }
  // Latest signed evaluation of each action in `actionIds`: open (unsuppressed) findings by severity. null when not readable.
  function openFindings(p, actionIds) {
    const result = new Map();if (!actionIds.size) return result;
    const ok = store.eachEvaluationNewestFirst(p.tenant, v => {
      if (!actionIds.has(v.actionId) || result.has(v.actionId)) return;
      result.set(v.actionId, (v.findings || []).filter(f => !f.suppressedBy).map(f => ({code: f.code, severity: f.severity || 'unknown'})));
      if (result.size === actionIds.size) return false;
    });
    if (!ok) fail(413, '평가 기록이 조회 한도를 넘어 발견 수를 셀 수 없습니다');
    return result;
  }

  function runningAgents(p, window) {
    if (!Object.hasOwn(AGENT_WINDOWS, window)) fail(400, '기간은 5m, 15m, 1h, 24h 중 하나입니다');
    const until = now(), since = until - AGENT_WINDOWS[window], {events, truncated} = windowEvents(p, since);
    const entries = values(p, 'agent_registry'), live = entries.filter(v => v.state !== 'retired');
    const bySource = new Map(), byActor = new Map();
    // Live entries attribute first; a retired entry still names activity that continues after retirement.
    for (const v of [...entries.filter(v => v.state === 'retired'), ...live]) {
      for (const s of v.sources || []) bySource.set(s, v);
      for (const a of v.actors || []) byActor.set(a, v);
    }
    const groups = new Map(), agentActors = new Map();let unattributed = 0;
    const group = (key, base) => {
      if (!groups.has(key)) groups.set(key, {key, ...base, lastActivity: null, firstActivity: null, events: 0, actions: new Set(), decisions: 0, denies: 0,
        kinds: {}, sources: new Set(), sourceKinds: new Set(), models: new Set(), tools: new Set()});
      return groups.get(key);
    };
    const actorOf = e => e.actor && e.actor !== 'unknown' ? e.actor : null;
    const add = (g, e) => {
      g.events++;if (e.actionId) g.actions.add(e.actionId);g.kinds[e.kind] = (g.kinds[e.kind] || 0) + 1;g.sources.add(e.source);g.sourceKinds.add(e.sourceKind);
      if (e.model && g.models.size < 20) g.models.add(e.model);if (e.tool && g.tools.size < 20) g.tools.add(e.tool);
      if (isDecision(e)) { g.decisions++;if (e.decision === 'deny') g.denies++; }
      if (!g.lastActivity || e.receivedAt > g.lastActivity) g.lastActivity = e.receivedAt;
      if (!g.firstActivity || e.receivedAt < g.firstActivity) g.firstActivity = e.receivedAt;
    };
    const registered = e => bySource.get(e.source) || (actorOf(e) && byActor.get(actorOf(e)));
    // Agent and OTLP sources report the agent itself; tool and enforcement records name it as actor and join its group.
    for (const e of events) {
      const entry = registered(e);
      if (entry) { add(group('registry:' + entry.id, {registered: true, entry}), e);continue; }
      if (!['agent', 'otlp'].includes(e.sourceKind)) continue;
      const actor = actorOf(e), key = canonical(['unregistered', e.source, actor]);
      add(group(key, {registered: false, source: e.source, actor}), e);if (actor && !agentActors.has(actor)) agentActors.set(actor, key);
    }
    for (const e of events) {
      if (registered(e) || ['agent', 'otlp'].includes(e.sourceKind)) continue;
      const actor = actorOf(e);
      if (!actor || !['tool', 'enforcement'].includes(e.sourceKind)) { unattributed++;continue; }
      const own = agentActors.has(actor) ? groups.get(agentActors.get(actor)) : null;
      add(own || group(canonical(['unregistered', null, actor]), {registered: false, source: null, actor}), e);
    }
    const actionIds = new Set([...groups.values()].flatMap(g => [...g.actions]));
    let findings = null, findingsError = null;
    try { findings = openFindings(p, actionIds); } catch (error) { findingsError = String(error?.message || error).slice(0, 200); }
    const stops = values(p, 'agent_stop_order').filter(o => o.status === 'active');
    const pendingTransitions = values(p, 'agent_transition').filter(t => t.status === 'pending');
    let pending = [], approvalsError = null;
    try { pending = approvals.pending(p); } catch (error) { approvalsError = String(error?.message || error).slice(0, 200); }
    const items = [...groups.values()].map(g => {
      const entry = g.entry, actors = entry ? entry.actors || [] : g.actor ? [g.actor] : [];
      const orders = entry ? stops.filter(o => o.agentId === entry.id) : [];
      const open = findings ? [...g.actions].flatMap(id => findings.get(id) || []) : null, bySeverity = {};
      for (const f of open || []) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      const waiting = pending.filter(v => actors.includes(v.target?.actor));
      const flags = [];
      if (!g.registered) flags.push('not_registered');
      if (orders.some(o => o.scope === 'agent' && g.lastActivity > o.issuedAt)) flags.push('active_after_stop_order');
      if (entry?.state === 'suspended' && g.lastActivity > entry.effectiveFrom) flags.push('active_while_suspended');
      if (entry?.state === 'retired' && g.lastActivity > entry.effectiveFrom) flags.push('active_after_retirement');
      return {id: g.registered ? g.key : 'unregistered:' + Buffer.from(g.key).toString('base64url').slice(0, 120), registered: g.registered,
        registryId: entry?.id ?? null, name: entry?.name ?? g.actor ?? g.source, state: entry?.state ?? 'not_registered', owner: entry?.owner ?? null,
        source: g.registered ? null : g.source, actor: g.registered ? null : g.actor, sources: [...g.sources].sort(), sourceKinds: [...g.sourceKinds].sort(),
        lastActivity: g.lastActivity, firstActivity: g.firstActivity,
        counts: {events: g.events, actions: g.actions.size, decisions: g.decisions, denies: g.denies}, kinds: g.kinds,
        models: [...g.models].sort(), tools: [...g.tools].sort(),
        openFindings: open ? {total: open.length, bySeverity} : null,
        stopOrders: {active: orders.length, scopes: [...new Set(orders.map(o => o.scope))].sort(), ids: orders.map(o => o.id).slice(0, 5)},
        pendingApprovals: approvalsError ? null : waiting.length, pendingTransition: entry ? !!pendingTransitions.find(t => t.agentId === entry.id) : false,
        flags};
    }).sort((a, b) => b.lastActivity.localeCompare(a.lastActivity) || a.id.localeCompare(b.id));
    // Registered production/approved entries without activity in the window, with the last receipt of their sources (index lookups).
    const active = new Set(items.map(i => i.registryId).filter(Boolean));
    const lastOf = store.db.prepare('SELECT MAX(received) at FROM events WHERE tenant=? AND source=?');
    const quiet = live.filter(v => ['production', 'approved'].includes(v.state) && !active.has(v.id)).slice(0, WINDOW_LIMITS.quiet).map(v => ({registryId: v.id,
      name: v.name, state: v.state, lastSourceActivity: (v.sources || []).map(s => lastOf.get(p.tenant, s).at).filter(Boolean).sort().at(-1) ?? null,
      activeStopOrders: stops.filter(o => o.agentId === v.id).length}));
    const summary = {active: items.length, registered: items.filter(i => i.registered).length, unregistered: items.filter(i => !i.registered).length,
      flagged: items.filter(i => i.flags.some(f => f !== 'not_registered')).length, withOpenFindings: items.filter(i => i.openFindings?.total).length,
      withPendingApprovals: items.filter(i => i.pendingApprovals).length, quietRegistered: quiet.length, unattributedEvents: unattributed};
    return {generatedAt: iso(until), tenant: p.tenant, window: {id: window, since: iso(since), until: iso(until), basis: 'receivedAt'},
      definition: ACTIVE_DEFINITION, summary, items: items.slice(0, WINDOW_LIMITS.items), total: items.length, quiet,
      scanned: {events: events.length, truncated, limit: WINDOW_LIMITS.events},
      ...(findingsError ? {findingsError} : {}), ...(approvalsError ? {approvalsError} : {}),
      limitations: ['등록 항목의 출처 자격·행위자 이름으로 묶습니다. 미등록 행위자 이름은 출처의 자기 보고입니다.',
        '도구·집행 지점 기록은 행위자 이름이 있을 때만 에이전트에 붙입니다. 행위자 없는 기록은 unattributedEvents로 셉니다.',
        ...(truncated ? [`기간 안의 기록이 ${WINDOW_LIMITS.events}건을 넘어 최신 기록만 셌습니다. 수치는 하한입니다.`] : [])]};
  }

  function threats(p, since) {
    const findings = section(() => {
      const bySeverity = {}, seen = new Set();let open = 0, actions = 0, fresh = 0, stop = 0, partial = 0;
      const ok = store.eachEvaluationNewestFirst(p.tenant, v => {
        if (seen.has(v.actionId)) return;seen.add(v.actionId);
        const list = (v.findings || []).filter(f => !f.suppressedBy);if (!list.length) return;
        actions++;if (v.coverage?.truncated) partial++;
        for (const f of list) {
          open++;bySeverity[f.severity || 'unknown'] = (bySeverity[f.severity || 'unknown'] || 0) + 1;if (STOP_CODES.has(f.code)) stop++;
          if (since && v.createdAt > since) fresh++;
        }
      });
      if (!ok) fail(413, '평가 기록이 조회 한도를 넘어 발견 수를 셀 수 없습니다');
      return {open, actions, bySeverity, stopRelated: stop, partialEvaluations: partial, newSince: since ? {since, count: fresh} : null};
    });
    const stopOrders = section(() => {
      verifiedEvents(p);
      const views = registry.stopPropagation(p).filter(v => v.status === 'active'), entries = policyObjects(p, 'agent_registry');
      const after = store.db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=? AND source=? AND received>?');
      const orders = views.map(v => {
        const entry = entries.get(v.agentId), sources = v.scope === 'agent' ? entry?.sources || [] : [];
        return {id: v.orderId, agentId: v.agentId, scope: v.scope, issuedAt: v.issuedAt, deadline: v.deadline, propagation: v.propagation,
          eventsAfterIssue: sources.reduce((n, s) => n + after.get(p.tenant, s, v.issuedAt).n, 0)};
      });
      return {active: orders.length, notPropagated: orders.filter(o => UNPROPAGATED.has(o.propagation)), notHeld: orders.filter(o => o.eventsAfterIssue > 0),
        basis: '전체 에이전트 정지 명령 이후 그 에이전트 출처 자격으로 수신된 기록 수입니다. 도구 기록의 위반은 발견(EXECUTION_AFTER_STOP_REQUEST)으로 셉니다.'};
    });
    return {findings, stopOrders};
  }
  // Integrity alarms after the other sections read the verified state: faulted projections, quarantine, verification age.
  function integrity(p) {
    return section(() => {
      const state = store.verifiedStateStatus(p.tenant);
      return {quarantine: store.quarantine ? String(store.quarantine.reason || 'quarantined') : null, faults: state.faults || [], cached: state.cached,
        verifiedAt: state.verifiedAt ?? null, count: state.count ?? null};
    });
  }

  function review(p) {
    const approvalSection = section(() => {
      const list = approvals.pending(p);
      return {pending: list.length, mayAnswer: list.filter(v => v.mayAnswer?.allowed).length,
        soonest: list.slice(0, 5).map(v => ({id: v.id, actor: v.target?.actor ?? null, tool: v.target?.tool ?? null, action: v.target?.action ?? null,
          remainingSeconds: v.remainingSeconds, expiresAt: v.expiresAt, approvalsNeeded: v.approvalsNeeded, mayAnswer: v.mayAnswer?.allowed === true}))};
    });
    const cases = section(() => {
      const list = values(p, 'case'), waiting = list.filter(c => c.status !== 'closed');
      return {open: list.filter(c => c.status === 'open').length, inReview: list.filter(c => c.status === 'in_review').length,
        oldestOpenSince: waiting.map(c => c.history?.[0]?.at).filter(Boolean).sort()[0] ?? null};
    });
    const registryChanges = section(() => {
      const entries = policyObjects(p, 'agent_registry'), list = values(p, 'agent_transition').filter(t => t.status === 'pending');
      const may = t => { const e = entries.get(t.agentId);return DECIDERS.has(p.role) && !!e && ![e.registeredBy, e.editedBy, t.requestedBy].includes(p.id); };
      const lifts = values(p, 'agent_stop_order').filter(o => o.status === 'active' && o.liftRequest);
      return {pendingTransitions: list.length, mayDecide: list.filter(may).length, pendingStopLifts: lifts.length,
        mayDecideLifts: DECIDERS.has(p.role) ? lifts.filter(o => o.liftRequest.by !== p.id).length : 0};
    });
    const governance = section(() => {
      const tasks = values(p, 'governance_task').filter(t => t.status !== 'closed'), reviews = values(p, 'governance_legal_review');
      const assessments = values(p, 'assessment').filter(a => a.legalReview !== undefined || String(a.requirementId || '').startsWith('KR-'));
      return {openTasks: tasks.length, pendingLegalReviews: assessments.filter(a => legalReviewState(a, reviews).status === 'pending').length};
    });
    return {approvals: approvalSection, cases, registryChanges, governance};
  }

  // Evidence present per mapped item in the period: the mapping of evidence packages read against the ledger range of the period.
  // The range read costs about 10 µs per record (parse and hash check), so a computed summary is reused for GOVERNANCE_TTL_MS.
  const governanceCache = new Map();
  function governanceSupport(p, period) {
    const key = canonical([p.tenant, period]), hit = governanceCache.get(key);
    if (hit && now() - hit.at < GOVERNANCE_TTL_MS) return {...hit.value, reused: true};
    const value = section(() => {
      const until = now(), from = iso(until - HOME_PERIODS[period]), to = iso(until + 1);
      const range = store.ledgerSince(p.tenant, from);
      if (range.tooMany) fail(413, `기간 기록이 ${range.count - range.first + 1}건으로 요약 한도를 넘습니다. 증거 패키지 CLI로 확인하세요`);
      const present = presence(range.rows, range.disclosures, {from, to});
      const frameworks = frameworkMappings().map(m => {
        const items = m.items.map(item => {
          const statuses = item.evidence.map(present);
          const status = statuses.includes(true) ? 'evidence_present' : statuses.includes(false) ? 'no_evidence_recorded' : 'not_counted_here';
          return {id: item.id, title: item.title.ko, citation: item.citation, status};
        });
        const tally = s => items.filter(i => i.status === s).length;
        return {id: m.id, title: m.title.ko, mappingVersion: m.version, items: items.length, evidencePresent: tally('evidence_present'),
          noEvidence: tally('no_evidence_recorded'), notCountedHere: tally('not_counted_here'), list: items};
      });
      return {period: {id: period, from, to: iso(until), basis: 'recordedAt'}, recordsInPeriod: range.rows.length, frameworks,
        pack: {command: 'node scripts/evidence-pack.mjs build', framework: FRAMEWORKS, tenant: p.tenant, from, to: iso(until)},
        notice: '“증거 있음”은 매핑된 기록 종류가 기간 안에 있다는 뜻입니다. 요구사항 충족이나 준수 판정이 아닙니다. '
          + 'API 응답·저장소 파일·온라인 점검 같은 종류는 여기서 세지 않습니다.'};
    });
    if (value.status === 'ok') {
      if (governanceCache.size > 1000) governanceCache.clear();
      governanceCache.set(key, {at: now(), value: {...value, computedAt: iso(now())}});
    }
    return {...value, computedAt: iso(now()), reused: false};
  }

  function homeSummary(p, params) {
    const since = sinceParam(params);
    const agents = section(() => { const r = runningAgents(p, '15m');return {window: r.window, summary: r.summary, definition: r.definition}; });
    const result = {generatedAt: iso(now()), tenant: p.tenant, viewer: {id: p.id, role: p.role, mayDecide: DECIDERS.has(p.role)}, agents,
      threats: threats(p, since), review: review(p), model: section(() => compactModel(p))};
    result.threats.integrity = integrity(p);
    return result;
  }
  const status = p => modelStatus({signedProfiles: values(p, 'assistance_profile'), runtime: runtimeStatus(), factsheets: factsheets(p)});
  function compactModel(p) {
    const s = status(p), latest = s.training.repository.runs.at(-1);
    return {reviewModel: s.reviewModel.model, revision: s.reviewModel.revision, quantization: s.reviewModel.quantization,
      runtimeEnabled: s.runtime.enabledByDefault, observationStatus: s.runtime.observationStatus, fineTuning: s.fineTuning.summary,
      upgradePending: s.roles.filter(r => r.upgradePending).length, evalStatuses: [...new Set(s.roles.map(r => r.evalStatus))],
      trainingRuns: s.training.repository.runs.length, latestRun: latest ? {id: latest.id, passed: latest.evaluation?.passed ?? null,
        items: latest.evaluation?.items ?? null, alwaysAbstainReference: latest.evaluation?.alwaysAbstainReference ?? null, promoted: latest.promoted} : null,
      promotionAutomatic: false};
  }

  function handle(p, method, url) {
    const path = url.pathname;
    if (!['/api/home', '/api/home/agents', '/api/home/governance', '/api/model-status'].includes(path)) return undefined;
    if (method !== 'GET') fail(405, '허용되지 않은 메서드');
    const period = url.searchParams.get('period') || '7d';
    if (path === '/api/home/governance' && !Object.hasOwn(HOME_PERIODS, period)) fail(400, '기간은 7d, 30d, 90d 중 하나입니다');
    // The governance summary reads the period's ledger range, so the console loads it after the rest of the home.
    return store.transaction(() => path === '/api/home' ? homeSummary(p, url.searchParams) : path === '/api/home/governance' ? governanceSupport(p, period)
      : path === '/api/model-status' ? status(p) : runningAgents(p, url.searchParams.get('window') || '15m'));
  }
  return {handle, runningAgents};
}
