// Who runs an agent and who answers for it (docs/agent-registry.md, "실행자와 책임자"). Pure functions shared by the vault, the
// console API and the evidence package: the executor fields an agent hook reports (OS account, PC, repository, git user), the
// owner map that turns those into a team and an accountable owner, the ownership status of a registry entry and the
// accountability report of an export. No I/O.
//
// The status of an owner is one of three, and only a person moves it to the last one:
//  - unknown: no owner recorded and no map rule matches what the agent was seen running as;
//  - inferred: a map rule matched (or a catalog document named an owner). A guess with its basis, never an approval;
//  - confirmed: a reviewer entered or confirmed the owner (POST /api/registry/:id/owner, or an edit that sets owner).
// An inference that finds two different owners for one agent is a conflict, not a choice.
import {canonical} from './crypto.mjs';

export const OWNER_MAP_TYPE = 'agent_owner_map';
// The principal that writes auto-registered entries (registry policy autoRegister). Never a human: an entry it registered has
// no owner until a person confirms one.
export const AUTO_DISCOVERY_PRINCIPAL = 'registry-auto-discovery';
export const EXECUTOR_FIELDS = Object.freeze(['account', 'host', 'repository', 'gitUser']);
// What an owner map rule can look at: the executor fields, and the actor name and source principal of the record.
export const OWNER_MATCH_FIELDS = Object.freeze([...EXECUTOR_FIELDS, 'actor', 'source']);
export const OWNER_MATCH_OPS = Object.freeze(['eq', 'prefix', 'suffix']);
export const OWNER_STATUSES = Object.freeze(['unknown', 'inferred', 'conflict', 'confirmed']);
export const OWNER_MAP_LIMITS = Object.freeze({rules: 200, value: 256, label: 200});

const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const text = v => typeof v === 'string' && v ? v : null;
// The executor of a record as it was stored: only the known fields, only strings. Null when the record names none.
export function executorOf(event) {
  const x = plain(event?.executor) ? event.executor : null;
  if (!x) return null;
  const out = {};
  for (const k of EXECUTOR_FIELDS) if (text(x[k])) out[k] = x[k];
  return Object.keys(out).length ? out : null;
}

function ruleMatches(rule, values) {
  const v = values[rule.field];
  if (typeof v !== 'string' || !v) return false;
  const a = v.toLowerCase(), b = rule.value.toLowerCase();
  return rule.op === 'eq' ? a === b : rule.op === 'prefix' ? a.startsWith(b) : a.endsWith(b);
}
// The first rule (map order is priority) that matches one observation: {executor, actor, source}.
export function matchOwner(map, observation) {
  const values = {...(observation.executor || {}), actor: observation.actor || undefined, source: observation.source || undefined};
  const rule = (map?.rules || []).find(r => ruleMatches(r, values));
  return rule ? {owner: rule.owner, team: rule.team || null, ruleId: rule.id, field: rule.field, value: values[rule.field], mapVersion: map.version ?? null} : null;
}

// Executors seen for one agent, grouped: [{executor, actor, source, events, lastSeen}], most recent first, at most `limit`.
export function groupExecutors(observations, limit = 20) {
  const groups = new Map();
  for (const o of observations) {
    const key = canonical([o.executor || null, o.actor || null, o.source || null]);
    const g = groups.get(key) || {executor: o.executor || null, actor: o.actor || null, source: o.source || null, events: 0, lastSeen: null};
    g.events++;
    if (o.at && (!g.lastSeen || o.at > g.lastSeen)) g.lastSeen = o.at;
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || '') || b.events - a.events
    || canonical([a.executor, a.actor, a.source]).localeCompare(canonical([b.executor, b.actor, b.source]))).slice(0, limit);
}

// The owner the map infers from the executors an agent was seen with: one owner (inferred), several (conflict) or none.
export function inferOwner(map, executors) {
  const matches = [];
  for (const g of executors) { const m = matchOwner(map, g); if (m) matches.push({...m, events: g.events}); }
  const owners = [...new Set(matches.map(m => m.owner))].sort();
  if (!owners.length) return {status: 'unknown', owner: null, team: null, basis: null};
  if (owners.length > 1) return {status: 'conflict', owner: null, team: null, candidates: owners.map(owner => {
    const for_ = matches.filter(m => m.owner === owner);
    return {owner, team: for_[0].team, ruleIds: [...new Set(for_.map(m => m.ruleId))].sort(), events: for_.reduce((n, m) => n + m.events, 0)};
  }), basis: 'owner_map'};
  const first = matches[0], teams = [...new Set(matches.filter(m => m.team).map(m => m.team))];
  return {status: 'inferred', owner: first.owner, team: teams.length === 1 ? teams[0] : null, basis: 'owner_map',
    rule: {id: first.ruleId, field: first.field, value: first.value, mapVersion: first.mapVersion}};
}

// Ownership of a registry entry: a reviewer's confirmation of the current owner, a legacy owner a person typed at registration or
// edit, a catalog document's owner (inferred), or the map inference over the executors seen.
export function ownershipOf(entry, inference = null) {
  const o = plain(entry?.ownership) ? entry.ownership : null, owner = text(entry?.owner);
  if (owner && o?.status === 'confirmed' && o.owner === owner)
    return {status: 'confirmed', owner, team: o.team ?? null, confirmedBy: o.by, confirmedAt: o.at, basis: o.basis ?? 'reviewer'};
  if (owner && !entry.catalog && entry.registeredBy !== AUTO_DISCOVERY_PRINCIPAL)
    return {status: 'confirmed', owner, team: null, confirmedBy: entry.editedBy ?? entry.registeredBy ?? null, confirmedAt: entry.editedAt ?? null,
      basis: 'entered_at_registration'};
  if (owner && entry.catalog) return {status: 'inferred', owner, team: null, basis: 'catalog_document'};
  return inference ? {...inference} : {status: 'unknown', owner: null, team: null, basis: null};
}

// Whether a record belongs to an entry: the authenticated source or reported actor the entry names, or (for an entry registered from
// a candidate) the source and actor it was discovered from.
export function belongsTo(entry, event) {
  if ((entry.sources || []).includes(event.source) || event.actor && (entry.actors || []).includes(event.actor)) return true;
  const d = plain(entry.discoveredFrom) ? entry.discoveredFrom : null;
  if (!d || !d.source && !d.actor) return false;
  return (!d.source || d.source === event.source) && (!d.actor || d.actor === event.actor);
}
const ACTIVITY_KINDS = ['intent', 'execution', 'self_report', 'result', 'delegation'];
export const agentActivity = e => ACTIVITY_KINDS.includes(e?.kind) && ['agent', 'otlp', 'tool'].includes(e.sourceKind);
// The live entry a record belongs to (a retired one only when no live one claims it); ids sorted so the choice is stable.
export function entryFor(entries, event) {
  const matching = entries.filter(v => belongsTo(v, event)).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return matching.find(v => v.state !== 'retired') || matching[0] || null;
}

// Accountability of one record: the agent entry, the executor and the owner, as an alert or a case shows them.
export function recordAccountability(entries, map, event, executorsByEntry = new Map()) {
  const entry = entryFor(entries, event), executor = executorOf(event);
  const inference = entry ? inferOwner(map, executorsByEntry.get(entry.id) || [{executor, actor: event.actor, source: event.source, events: 1}])
    : inferOwner(map, [{executor, actor: event.actor, source: event.source, events: 1}]);
  return {agent: entry ? {id: entry.id, name: entry.name, state: entry.state} : null, actor: event.actor || null, source: event.source || null,
    executor, owner: entry ? ownershipOf(entry, inference) : inference};
}

// ---------- accountability report of an export (evidence package file accountability.json) ----------
export const ACCOUNTABILITY_FORMAT = 'evidscope-accountability-v1';
const NOTICE = {ko: '실행자는 에이전트 훅의 자기 보고입니다. 추정 책임자는 매핑 표의 결과일 뿐이며, 확정은 검토자가 기록한 것만입니다.',
  en: 'Executors are self-reported by the agent hook. An inferred owner is only the owner map\'s result; only an owner a reviewer recorded is confirmed.'};
// From the records of a verified export (ledger order) and its disclosures: the last version of every registry entry and of the owner
// map, and the agent records (sealed ones only through their disclosure). Same records, same report.
export function accountabilityReport(records, disclosures = []) {
  const entries = new Map(), disclosed = new Map(disclosures.map(d => [d.seq, d.event])), events = [];
  let map = null;
  for (const row of records) {
    if (row.type === 'agent_registry' && plain(row.payload) && typeof row.payload.id === 'string') entries.set(row.payload.id, row.payload);
    else if (row.type === OWNER_MAP_TYPE && plain(row.payload)) map = row.payload;
    else if (row.type === 'event') {
      const sealed = String(row.payload?.format).startsWith('evidscope-encrypted-event'), e = disclosed.get(row.seq) ?? (sealed ? null : row.payload);
      if (plain(e) && agentActivity(e)) events.push({e, seq: row.seq, at: row.recordedAt});
    }
  }
  const live = [...entries.values()], byEntry = new Map(), unattributed = new Map();
  for (const {e, at} of events) {
    const entry = entryFor(live, e), o = {executor: executorOf(e), actor: e.actor || null, source: e.source || null, at};
    if (entry) { if (!byEntry.has(entry.id)) byEntry.set(entry.id, []); byEntry.get(entry.id).push(o); }
    else { const key = canonical([o.source, o.actor]); if (!unattributed.has(key)) unattributed.set(key, []); unattributed.get(key).push(o); }
  }
  const agents = live.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0).map(entry => {
    const executors = groupExecutors(byEntry.get(entry.id) || []);
    return {id: entry.id, name: entry.name ?? entry.id, state: entry.state, version: entry.version, registeredBy: entry.registeredBy,
      autoRegistered: entry.registeredBy === AUTO_DISCOVERY_PRINCIPAL, owner: ownershipOf(entry, inferOwner(map, executors)),
      events: (byEntry.get(entry.id) || []).length, executors};
  });
  const others = [...unattributed.values()].map(list => {
    const executors = groupExecutors(list);
    return {source: list[0].source, actor: list[0].actor, events: list.length, owner: inferOwner(map, executors), executors};
  }).sort((a, b) => canonical([a.source, a.actor]).localeCompare(canonical([b.source, b.actor])));
  const tally = s => agents.filter(a => a.owner.status === s).length;
  return {format: ACCOUNTABILITY_FORMAT, notice: NOTICE, ownerMap: map ? {version: map.version, rules: (map.rules || []).length} : null,
    counts: {agents: agents.length, confirmed: tally('confirmed'), inferred: tally('inferred'), conflict: tally('conflict'), unknown: tally('unknown'),
      unregisteredAgents: others.length, agentRecords: events.length, recordsWithExecutor: events.filter(x => executorOf(x.e)).length},
    agents, unregistered: others};
}
// Whether an export has anything for the report: registry entries, an owner map or an agent record naming its executor.
export const hasAccountability = (records, disclosures = []) => records.some(r => r.type === 'agent_registry' || r.type === OWNER_MAP_TYPE)
  || records.some(r => r.type === 'event' && executorOf(r.payload)) || disclosures.some(d => executorOf(d.event));
