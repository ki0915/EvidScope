// Log explorer, live tail and operations dashboard of the console (docs/feature-guide.md). Read-only views over the verified
// event projection and the latest signed evaluations: every record is classified (shell, file, web, git, package, secret,
// delete, ...), searched, counted per facet and per time bucket. Classification is a reading aid computed at query time from
// the record's reported tool, action and command words; it is never stored, signed or used by the evaluation engines.
import {fail} from './model.mjs';

export const SEVERITY_RANK = Object.freeze({info: 1, low: 2, medium: 3, high: 4, critical: 5});
export const RANGES = Object.freeze({'15m': 900e3, '1h': 3600e3, '4h': 4 * 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3});
// Bucket widths that give 30-60 bars per range.
const BUCKETS = Object.freeze({'15m': 30e3, '1h': 60e3, '4h': 300e3, '24h': 1800e3, '7d': 4 * 3600e3, '30d': 86400e3});
export const FACETS = Object.freeze(['agent', 'category', 'kind', 'status', 'risk', 'collection', 'data', 'actor']);
const MAX_SCAN = 200000,
  MAX_OFFSET = 10000;

// Command words, checked in this order: the first match names the category, every match is a tag.
// words(start, ...alternatives): one case-insensitive pattern, kept as separate strings so each line stays readable.
const words = (start, ...alternatives) => new RegExp(`${start}(${alternatives.join('|')})`, 'i');
const CMD = String.raw`(^|[\s;&|(])`;
const SHELL_CLASSES = [
  ['secret', words(String.raw`(^|[\s"'/\\=])`, String.raw`\.env\b`, String.raw`\.aws[\\/]`, String.raw`\.ssh[\\/]`, 'id_rsa', 'id_ed25519',
    String.raw`credentials?\b`, String.raw`\.netrc`, String.raw`\.pgpass`, String.raw`\.npmrc`, String.raw`secrets?\b`, String.raw`passwords?\b`,
    String.raw`api[_-]?keys?\b`, String.raw`tokens?\b`, 'Login Data', String.raw`key4\.db`, String.raw`logins\.json`)],
  ['delete', new RegExp(String.raw`(^|[\s;&|(])(rm|rmdir|del|erase|rd|Remove-Item|ri|shred|unlink)(\s|$)|git\s+(clean|reset\s+--hard)|--force\b|` +
    String.raw`\bDROP\s+(TABLE|DATABASE)\b|truncate\s`, 'i')],
  ['network', /(^|[\s;&|(])(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|ssh|scp|sftp|rsync|nc|ncat|ftp|telnet|Send-MailMessage)(\s|$)|https?:\/\//i],
  ['package', words(CMD, String.raw`(npm|pnpm|yarn|bun)\s+(i|install|add|ci)\b`, String.raw`npx\s`, String.raw`pip3?\s+install`, String.raw`uv\s+(pip|add)`,
    String.raw`cargo\s+(install|add)`, String.raw`go\s+(get|install)`, String.raw`winget\s+install`, String.raw`choco\s+install`,
    String.raw`apt(-get)?\s+install`, String.raw`brew\s+install`, String.raw`gem\s+install`)],
  ['git', /(^|[\s;&|(])git\s/i],
  ['build', words(CMD, String.raw`(npm|pnpm|yarn|bun)\s+(run|test|t)\b`, String.raw`node\s`, String.raw`python3?\s`,
    String.raw`py\s`, 'pytest', String.raw`tsc\b`, String.raw`vite\b`, String.raw`next\s`, String.raw`make\b`,
    String.raw`cargo\s+(build|test|run)`, String.raw`go\s+(build|test|run)`, String.raw`dotnet\s`,
    String.raw`mvn\s`, 'gradle')],
  ['system', words(CMD, 'Set-ItemProperty', String.raw`reg\s+(add|delete)`, 'netsh', 'Set-MpPreference', 'schtasks', String.raw`sc\s+(stop|config|delete)`,
    'systemctl', 'launchctl', 'crontab', String.raw`chmod\s+[0-7]*7`, 'chown', 'sudo', 'runas',
    'Set-ExecutionPolicy', 'Stop-Process', 'taskkill', String.raw`kill\s`)],
];
const ACTION_CATEGORIES = Object.freeze({
  file_read: 'file_read',
  file_write: 'file_write',
  file_search: 'file_search',
  web_fetch: 'web',
  web_search: 'web',
  subagent: 'subagent',
  mcp_call: 'mcp',
});
const KIND_CATEGORIES = Object.freeze({
  grant: 'authority',
  revoke: 'authority',
  human_approval: 'authority',
  automated_review: 'authority',
  delegation: 'authority',
  gap: 'collection_gap',
  execution: 'tool_record',
  result: 'tool_record',
});

const agentRecord = e => e.sourceKind === 'agent' && typeof e.note === 'string';
// "[Bash] git status" -> "Bash"
export const toolName = e => (typeof e.note === 'string' && /^\[([^\]]{1,80})\]/.exec(e.note)?.[1]) || null;

export function classify(e) {
  const tags = [];
  if (agentRecord(e)) {
    const text = `${e.note} ${e.resource || ''}`;
    if (e.action === 'shell_exec') {
      for (const [name, pattern] of SHELL_CLASSES) if (pattern.test(text)) tags.push(name);
    } else if (['file_read', 'file_write'].includes(e.action) && SHELL_CLASSES[0][1].test(text)) tags.push('secret');
    const base = ACTION_CATEGORIES[e.action] || (e.action === 'shell_exec' ? 'shell' : 'tool_call');
    if (e.destination && e.action === 'shell_exec' && !tags.includes('network')) tags.push('network');
    return {category: tags[0] || base, tags: [...new Set([base, ...tags])]};
  }
  if (e.sourceKind === 'otlp') return {category: 'telemetry', tags: ['telemetry']};
  const category = KIND_CATEGORIES[e.kind] || (e.sourceKind === 'enforcement' ? 'enforcement' : 'other');
  return {category, tags: [category]};
}

// Free text: every word must occur (case-insensitive) in the record's searchable text; "-word" must not; "quoted phrases" stay
// whole; field:value restricts one field (agent, tool, category, actor, kind, status, action, trace, id).
export function parseQuery(q) {
  const terms = [],
    text = String(q || '').slice(0, 300);
  for (const match of text.matchAll(/(-?)(?:(\w+):)?(?:"([^"]*)"|(\S+))/g)) {
    const [, not, field, quoted, bare] = match,
      value = (quoted ?? bare ?? '').toLowerCase();
    if (!value) continue;
    terms.push({not: !!not, field: field ? field.toLowerCase() : null, value});
  }
  return terms;
}
const FIELD_VALUES = {
  agent: e => e.tool,
  tool: e => e.toolName,
  category: e => `${e.category} ${e.tags.join(' ')}`,
  actor: e => e.actor,
  kind: e => e.kind,
  status: e => e.status,
  action: e => e.action,
  trace: e => e.traceId,
  id: e => `${e.id} ${e.actionId}`,
};
function matchesQuery(item, terms) {
  if (!terms.length) return true;
  const all = [
    item.note,
    item.resource,
    item.destination,
    item.actor,
    item.tool,
    item.toolName,
    item.action,
    item.actionId,
    item.traceId,
    item.id,
    item.category,
    ...item.tags,
    ...(item.findings || []),
  ]
    .filter(Boolean)
    .join('\n')
    .toLowerCase();
  return terms.every(t => {
    const hay = t.field && FIELD_VALUES[t.field] ? String(FIELD_VALUES[t.field](item) ?? '').toLowerCase() : all;
    return hay.includes(t.value) !== t.not;
  });
}

function timeWindow(params, now) {
  const from = params.get('from'),
    to = params.get('to'),
    range = params.get('range') || '24h';
  if (from || to) {
    const start = from ? Date.parse(from) : now - RANGES['24h'],
      end = to ? Date.parse(to) : now;
    if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) fail(400, '조회 기간(from/to)이 올바르지 않습니다');
    const span = end - start,
      key = Object.keys(RANGES).find(k => RANGES[k] >= span) || '30d';
    return {start, end, range: 'custom', bucketMs: Math.max(BUCKETS[key], Math.ceil(span / 60 / 1000) * 1000)};
  }
  if (range === 'all') return {start: null, end: now, range, bucketMs: null};
  if (!Object.hasOwn(RANGES, range)) fail(400, '조회 기간은 15m, 1h, 4h, 24h, 7d, 30d, all 중 하나입니다');
  return {start: now - RANGES[range], end: now, range, bucketMs: BUCKETS[range]};
}
const listParam = (params, name) => {
  const raw = params.get(name);
  return raw
    ? raw
        .split(',')
        .map(v => v.trim())
        .filter(Boolean)
        .slice(0, 20)
    : [];
};

// One readable row per record: the reported fields the console shows, the classification, the time used on the axis (the
// reported occurredAt; imported history is placed at the time it happened, not when it arrived) and its action's risk.
function row(e, risk, synthetic) {
  const {category, tags} = classify(e),
    at = Date.parse(e.occurredAt),
    received = Date.parse(e.receivedAt);
  return {
    seq: e.seq,
    id: e.id,
    source: e.source,
    sourceKind: e.sourceKind,
    kind: e.kind,
    occurredAt: e.occurredAt,
    receivedAt: e.receivedAt,
    at: Number.isFinite(at) && at <= received + 300000 ? at : received,
    actor: e.actor ?? null,
    tool: e.tool ?? null,
    toolName: toolName(e),
    action: e.action ?? null,
    category,
    tags,
    status: e.status ?? null,
    note: e.note ?? null,
    resource: e.resource ?? null,
    destination: e.destination ?? null,
    actionId: e.actionId ?? null,
    traceId: e.traceId ?? null,
    risk: risk?.severity ?? 'none',
    findings: risk?.codes || [],
    collection: e.collection === 'history_import' ? 'history_import' : 'live',
    late: e.late === true,
    assurance: e.assurance ?? null,
    data: synthetic ? 'synthetic' : 'real',
  };
}
const facetValue = {
  agent: r => r.tool || r.sourceKind || 'unknown',
  category: r => r.category,
  kind: r => r.kind,
  status: r => r.status || 'none',
  risk: r => r.risk,
  collection: r => r.collection,
  data: r => r.data,
  actor: r => r.actor || 'unknown',
};

// risks: actionId -> {severity, codes} from the latest evaluation (open findings only). synthetic: Set of synthetic action ids.
export function exploreLogs(events, {params, risks = new Map(), synthetic = new Set(), now = Date.now()}) {
  const window = timeWindow(params, now),
    terms = parseQuery(params.get('q')),
    after = params.get('after');
  const afterSeq = after === null ? null : Number(after);
  if (afterSeq !== null && !Number.isSafeInteger(afterSeq)) fail(400, '실시간 보기 기준(after)은 정수여야 합니다');
  const limit = Number(params.get('limit') || 100),
    offset = Number(params.get('offset') || 0);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) fail(400, '한 번에 보는 기록 수는 1~500');
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > MAX_OFFSET) fail(400, `건너뛸 기록 수는 0~${MAX_OFFSET}`);
  const filters = Object.fromEntries(FACETS.map(name => [name, listParam(params, name)]));
  const rows = [];
  let latestSeq = 0;
  for (const e of events) {
    if (Number.isSafeInteger(e.seq) && e.seq > latestSeq) latestSeq = e.seq;
    if (afterSeq !== null && !(e.seq > afterSeq)) continue;
    const r = row(e, risks.get(e.actionId), synthetic.has(e.actionId));
    if (afterSeq === null && ((window.start !== null && r.at < window.start) || r.at > window.end)) continue;
    if (!matchesQuery(r, terms)) continue;
    rows.push(r);
  }
  const passes = (r, skip) => FACETS.every(name => name === skip || !filters[name].length || filters[name].includes(facetValue[name](r)));
  const facets = Object.fromEntries(
    FACETS.map(name => {
      const counts = {};
      for (const r of rows)
        if (passes(r, name)) {
          const v = facetValue[name](r);
          counts[v] = (counts[v] || 0) + 1;
        }
      return [
        name,
        Object.entries(counts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 30)
          .map(([value, count]) => ({value, count, selected: filters[name].includes(value)})),
      ];
    }),
  );
  const chosen = rows.filter(r => passes(r)).sort((a, b) => b.at - a.at || b.seq - a.seq);
  return {
    range: window.range,
    from: window.start === null ? null : new Date(window.start).toISOString(),
    to: new Date(window.end).toISOString(),
    query: params.get('q') || '',
    filters,
    total: chosen.length,
    offset,
    limit,
    items: chosen.slice(offset, offset + limit),
    latestSeq,
    facets,
    histogram: histogram(chosen, window),
    scope: 'retained_event_projection',
    timeAxis: 'occurredAt_reported_capped_at_receipt',
    limitations: [
      '분류는 보고된 도구·명령 단어로 화면에서 계산한 읽기 도구입니다. 서명되지 않으며 탐지 규칙이나 판정이 아닙니다',
      '시간 축은 보고된 발생 시각입니다(접수보다 5분 넘게 미래인 값은 접수 시각). 사후 수집 기록은 실제 발생 시각에 놓입니다',
      '위험은 그 행동의 최신 평가에서 열린 발견의 가장 높은 중요도입니다',
      '파기된 기록과 수집되지 않은 행동은 보이지 않습니다',
    ],
  };
}

function histogram(rows, window) {
  if (!rows.length && window.start === null) return {bucketMs: null, points: []};
  const start = window.start ?? Math.min(...rows.map(r => r.at)),
    end = window.end;
  const bucketMs = window.bucketMs ?? Math.max(60e3, Math.ceil((end - start) / 60 / 60e3) * 60e3);
  const first = Math.floor(start / bucketMs) * bucketMs,
    count = Math.min(400, Math.max(1, Math.ceil((end - first) / bucketMs)));
  const points = Array.from({length: count}, (_, i) => ({
    at: new Date(first + i * bucketMs).toISOString(),
    total: 0,
    risky: 0,
    failures: 0,
    ok: 0,
    byAgent: {},
  }));
  for (const r of rows) {
    const i = Math.floor((r.at - first) / bucketMs);
    if (i < 0 || i >= count) continue;
    // risky, failures (failed calls without an open finding) and ok split total, so they stack.
    const p = points[i];
    p.total++;
    if (r.risk !== 'none') p.risky++;
    else if (r.status === 'failure') p.failures++;
    else p.ok++;
    const agent = facetValue.agent(r);
    p.byAgent[agent] = (p.byAgent[agent] || 0) + 1;
  }
  return {bucketMs, points};
}

// The operations dashboard: activity and risk over the window, by agent, category and rule, plus the newest risky records.
export function dashboardView(events, {params, risks = new Map(), synthetic = new Set(), findings = [], now = Date.now()}) {
  const window = timeWindow(params, now);
  const rows = [];
  for (const e of events) {
    const r = row(e, risks.get(e.actionId), synthetic.has(e.actionId));
    if ((window.start !== null && r.at < window.start) || r.at > window.end) continue;
    rows.push(r);
  }
  const real = rows.filter(r => r.data === 'real'),
    agents = real.filter(r => r.sourceKind === 'agent');
  const distinct = (list, key) => new Set(list.map(key).filter(Boolean)).size;
  const actionTimes = new Map();
  for (const r of real) if (r.actionId && !(actionTimes.get(r.actionId) <= r.at)) actionTimes.set(r.actionId, r.at);
  const inWindow = findings.filter(f => actionTimes.has(f.actionId) && !f.synthetic && f.state === 'open');
  const bySeverity = {};
  for (const f of inWindow) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const rules = new Map();
  for (const f of inWindow) {
    const rule = rules.get(f.code) || {code: f.code, message: f.message, severity: f.severity, count: 0, actions: new Set()};
    rule.count++;
    rule.actions.add(f.actionId);
    rules.set(f.code, rule);
  }
  const categories = {};
  for (const r of agents) {
    const c = categories[r.category] || (categories[r.category] = {category: r.category, count: 0, risky: 0});
    c.count++;
    if (r.risk !== 'none') c.risky++;
  }
  const sessions = new Map();
  for (const r of agents) {
    if (!r.traceId) continue;
    const s = sessions.get(r.traceId) || {traceId: r.traceId, actor: r.actor, tool: r.tool, events: 0, risky: 0, firstAt: r.at, lastAt: r.at};
    s.events++;
    if (r.risk !== 'none') s.risky++;
    s.firstAt = Math.min(s.firstAt, r.at);
    s.lastAt = Math.max(s.lastAt, r.at);
    sessions.set(r.traceId, s);
  }
  const iso = ms => new Date(ms).toISOString();
  const signals = inWindow
    .map(f => ({
      ...f,
      at: iso(actionTimes.get(f.actionId)),
      note: real.find(r => r.actionId === f.actionId && r.note)?.note ?? null,
      actor: real.find(r => r.actionId === f.actionId)?.actor ?? null,
    }))
    .sort((a, b) => b.at.localeCompare(a.at))
    .slice(0, 12);
  return {
    range: window.range,
    from: window.start === null ? null : iso(window.start),
    to: iso(window.end),
    stats: {
      events: real.length,
      agentEvents: agents.length,
      actions: actionTimes.size,
      sessions: sessions.size,
      actors: distinct(real, r => r.actor),
      riskyActions: new Set(inWindow.map(f => f.actionId)).size,
      alerts: inWindow.length,
      bySeverity,
      failures: real.filter(r => r.status === 'failure').length,
      historyImports: real.filter(r => r.collection === 'history_import').length,
      syntheticEvents: rows.length - real.length,
    },
    histogram: histogram(real, window),
    rules: [...rules.values()]
      .map(r => ({...r, actions: r.actions.size}))
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count)
      .slice(0, 10),
    categories: Object.values(categories).sort((a, b) => b.count - a.count),
    sessions: [...sessions.values()]
      .sort((a, b) => b.lastAt - a.lastAt)
      .slice(0, 8)
      .map(s => ({...s, firstAt: iso(s.firstAt), lastAt: iso(s.lastAt)})),
    signals,
    limitations: [
      '합성(데모·시험) 기록은 숫자와 그래프에서 뺐습니다',
      '경보 수는 기간 안에 처음 기록된 행동의 열린 발견입니다',
      '분류는 보고된 도구·명령 단어로 계산한 읽기 도구이며 판정이 아닙니다',
      '수집되지 않은 행동은 0으로 보입니다. 미관측은 안전이 아닙니다',
    ],
  };
}

// What the agent read or searched earlier in the same session (same traceId, an agent source): the files, searches and web pages
// it reported before this action. These are the agent's own reports of what it looked at, not proof it used them.
export function sessionReferences(sessionEvents, actionEvents, limit = 40) {
  const own = actionEvents.filter(e => e.sourceKind === 'agent' && e.traceId);
  if (!own.length) return null;
  const startAt = Math.min(...own.map(e => Date.parse(e.occurredAt)).filter(Number.isFinite)),
    ids = new Set(own.map(e => e.actionId));
  const reads = sessionEvents
    .filter(
      e =>
        e.sourceKind === 'agent' &&
        e.kind === 'intent' &&
        !ids.has(e.actionId) &&
        ['file_read', 'file_search', 'web_fetch', 'web_search', 'mcp_call'].includes(e.action) &&
        Date.parse(e.occurredAt) <= startAt,
    )
    .sort((a, b) => Date.parse(b.occurredAt) - Date.parse(a.occurredAt));
  return {
    traceId: own[0].traceId,
    total: reads.length,
    items: reads
      .slice(0, limit)
      .map(e => ({
        eventId: e.id,
        actionId: e.actionId,
        occurredAt: e.occurredAt,
        toolName: toolName(e),
        action: e.action,
        target: e.destination ? `${e.destination} ${e.resource || ''}`.trim() : e.resource || e.note,
        verification: 'self_reported_session_activity',
      })),
    scope: '같은 세션에서 이 행동보다 먼저 에이전트가 읽거나 검색했다고 보고한 파일·웹·도구입니다. 실제로 판단에 사용했는지는 확인하지 않습니다',
  };
}
