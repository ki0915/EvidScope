// OCSF Detection Finding (class_uid 2004) output for existing SIEMs (differentiator D5). EvidScope stays the source of
// truth: every event carries unmapped.evidscope references (tenant, action, evaluation ledger seq/hash, signed checkpoint)
// so an analyst can return to the export and re-verify with scripts/verify.mjs and scripts/replay-findings.mjs.
// 1.3.0 is the default because Amazon Security Lake custom sources accept only OCSF <= 1.3; 1.9.0 adds ai_agent
// evidence and a record_integrity attestation.
import {createHash, createPublicKey, KeyObject} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {isEncryptedEvent, verifyBundle} from './crypto.mjs';
import {fail} from './model.mjs';
import {tenantLogId} from './tlog.mjs';

export const OCSF_VERSIONS = Object.freeze(['1.3.0', '1.9.0']);
export const OCSF_DEFAULT_VERSION = '1.3.0';
export const SPLUNK_SOURCETYPE = 'ocsf:evidscope:detection_finding';
const CATEGORY = {uid: 2, name: 'Findings'}, CLASS = {uid: 2004, name: 'Detection Finding'}, CREATE = {id: 1, name: 'Create'};
const SEVERITY = {low: [2, 'Low'], medium: [3, 'Medium'], high: [4, 'High']};
const LEDGER_SERIALIZATION = 'EvidScope ledger record without hash, canonical JSON with sorted keys (src/crypto.mjs canonical)';
const PRODUCT_VERSION = (() => {
  try { return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version; } catch { return 'unknown'; }
})();

export function signingKeyId(publicKey) {
  const key = publicKey instanceof KeyObject && publicKey.type === 'public' ? publicKey : createPublicKey(publicKey);
  return createHash('sha256').update(key.export({type: 'spki', format: 'der'})).digest('hex');
}

const sha256 = (value, serialization = LEDGER_SERIALIZATION) => ({algorithm_id: 3, algorithm: 'SHA-256', value, encoding_id: 1, encoding: 'Hex',
  serialization_id: 99, serialization});
const unique = values => [...new Set(values.filter(value => typeof value === 'string' && value))];
const times = (events, field) => events.map(e => Date.parse(e[field])).filter(Number.isFinite);

// Target resources: the event's own resource; an OTLP model call has none, so its destination host (correlates with
// proxy and firewall logs) or else its model stands in, typed so a SIEM rule can tell them apart.
function targets(events) {
  const seen = new Map();
  for (const e of events) {
    const r = typeof e.resource === 'string' && e.resource ? {name: e.resource}
      : typeof e.destination === 'string' && e.destination ? {name: e.destination, type: 'Network endpoint'}
      : typeof e.model === 'string' && e.model ? {name: e.model, type: 'AI model'} : null;
    if (r) seen.set(`${r.type || ''}\0${r.name}`, r);
  }
  return [...seen.values()];
}
function evidence(ref, event, v19) {
  const item = {data: event ? {ref, kind: event.kind, sourceKind: event.sourceKind, occurredAt: event.occurredAt, seq: event.seq} : {ref, retained: false}};
  // Authority, safety and telemetry records name the agent they concern; only agent/tool records are its activity.
  const activity = ['agent', 'tool', 'otlp'].includes(event?.sourceKind);
  if (activity && event.actor) item.actor = {app_name: event.actor};
  if (activity && event.tool && event.action) item.api = {operation: event.action, service: {name: event.tool}};
  if (v19) {
    item.uid = ref;
    if (event?.kind) item.name = event.kind;
    if (activity && event.actor) {
      const observation = event.aiObservation, model = observation?.model;
      item.ai_agent = {name: event.actor, type_id: 0, type: 'Unknown',
        ...(model && model !== 'unknown' ? {ai_model: {name: model, ai_provider: observation.provider || 'unknown'}} : {})};
    }
  }
  return item;
}

function attestation(tenant, ledger, keyId, chainUid) {
  // The fingerprint is the EvidScope ledger record hash, not a hash of this OCSF event: serialization_id 99 names the
  // record serialization. prev_event links the previous ledger record by position (evidscope:<tenant>:<seq>).
  // With the transparency log on, chain_uid is the tenant's C2SP origin and this hash is leaf seq-1 of that tree.
  return {
    uid: `evidscope:${tenant}:${ledger.seq}`,
    chain_uid: chainUid || `evidscope-ledger-v1:${tenant}`,
    ...(keyId ? {authority_uid: `ed25519-spki-sha256:${keyId}`} : {}),
    fingerprint: sha256(ledger.hash),
    ...(ledger.seq > 1 ? {prev_event: {uid: `evidscope:${tenant}:${ledger.seq - 1}`, fingerprint: sha256(ledger.previous)}} : {}),
  };
}

function findingEvent({tenant, ledger, finding, index, events, version, checkpoint, keyId, chainUid}) {
  const v19 = version === '1.9.0', evaluation = ledger.payload, uid = `${evaluation.id}:${index}`, time = Date.parse(evaluation.createdAt);
  const [severityId, severity] = SEVERITY[finding.severity] || [0, 'Unknown'], suppressed = typeof finding.suppressedBy === 'string';
  const refs = Array.isArray(finding.evidence) ? finding.evidence : [], found = refs.map(ref => events.get(ref)).filter(Boolean);
  const custom = /^CUSTOM:(.+):v(\d+)$/.exec(finding.code), engine = evaluation.replay?.engine || 'unrecorded';
  const firstSeen = times(found, 'occurredAt'), resources = targets(found);
  return {
    activity_id: CREATE.id, activity_name: CREATE.name, category_uid: CATEGORY.uid, category_name: CATEGORY.name,
    class_uid: CLASS.uid, class_name: CLASS.name, type_uid: CLASS.uid * 100 + CREATE.id, type_name: `${CLASS.name}: ${CREATE.name}`,
    severity_id: severityId, severity, time, timezone_offset: 0, message: finding.message,
    status_id: suppressed ? 3 : 1, status: suppressed ? 'Suppressed' : 'New',
    status_detail: suppressed ? `Suppressed by approved time-limited exception ${finding.suppressedBy}; source evidence is unchanged`
      : 'Open in the latest signed evaluation of this action',
    metadata: {
      version, uid, tenant_uid: tenant, log_name: 'evidscope.evaluations', log_provider: 'EvidScope evidence ledger',
      original_time: evaluation.createdAt, product: {name: 'EvidScope', vendor_name: 'EvidScope', version: PRODUCT_VERSION},
      ...(v19 ? {profiles: ['record_integrity']} : {}),
    },
    finding_info: {
      uid, title: `EvidScope ${finding.code}`, desc: finding.message, types: [finding.code], created_time: time, data_sources: ['evidscope-ledger'],
      analytic: {type_id: 1, type: 'Rule', name: finding.code, uid: custom ? custom[1] : finding.code, version: custom ? custom[2] : engine},
      ...(firstSeen.length ? {first_seen_time: Math.min(...firstSeen), last_seen_time: Math.max(...firstSeen)} : {}),
    },
    evidences: refs.slice(0, 50).map(ref => evidence(ref, events.get(ref), v19)),
    ...(resources.length ? {resources: resources.map(r => ({...r, ...(v19 ? {role_id: 1, role: 'Target'} : {})}))} : {}),
    ...(v19 ? {is_alert: !suppressed, attestation_list: [attestation(tenant, ledger, keyId, chainUid)]} : {}),
    unmapped: {evidscope: {
      format: 'evidscope-ocsf-reference-v1', tenant, actionId: evaluation.actionId, evaluationId: evaluation.id, evaluationVersion: evaluation.version,
      findingIndex: index, code: finding.code, evidence: refs, ...(suppressed ? {suppressedBy: finding.suppressedBy} : {}), engine,
      analysisTime: evaluation.analysisTime ?? null, snapshotHash: evaluation.snapshotHash ?? null,
      aiAgents: unique(found.map(e => e.actor)),
      ledger: {seq: ledger.seq, hash: ledger.hash, previous: ledger.previous, serialization: LEDGER_SERIALIZATION},
      checkpoint: checkpoint ? {format: checkpoint.format, tenant: checkpoint.tenant, count: checkpoint.count, head: checkpoint.head,
        signature: checkpoint.signature} : null,
      ...(keyId ? {signingKeySha256: keyId} : {}),
      verify: 'GET /api/export; node scripts/verify.mjs EXPORT.json TRUST_ANCHOR.pem; node scripts/replay-findings.mjs EXPORT.json TRUST_ANCHOR.pem',
    }},
  };
}

// evaluations: [{seq, hash, previous, payload}] of authenticated evaluation ledger records in ledger order.
// eventsFor(actionId) returns that action's retained (verified) events. Only each action's latest evaluation is mapped.
export function ocsfFindings({tenant, evaluations, eventsFor = () => [], checkpoint = null, publicKey, version, chainUid}) {
  const selected = version ?? OCSF_DEFAULT_VERSION;
  if (!OCSF_VERSIONS.includes(selected)) fail(400, `지원하지 않는 OCSF 버전입니다 (${OCSF_VERSIONS.join(' 또는 ')})`);
  const keyId = publicKey ? signingKeyId(publicKey) : null, latest = new Map();
  for (const ledger of evaluations) latest.set(ledger.payload.actionId, ledger);
  return [...latest.values()].sort((a, b) => a.seq - b.seq).flatMap(ledger => {
    const findings = Array.isArray(ledger.payload.findings) ? ledger.payload.findings : [];
    if (!findings.length) return [];
    const events = new Map(eventsFor(ledger.payload.actionId).map(e => [`${e.source}/${e.id}`, e]));
    return findings.map((finding, index) => findingEvent({tenant, ledger, finding, index, events, version: selected, checkpoint, keyId, chainUid}));
  });
}

// Pair signed evaluation payloads (already authenticated through the checkpoint in this transaction, e.g. by the
// service's verifiedEvaluations) with their ledger positions. Call inside the same Store transaction.
export function evaluationLedgerRows(db, tenant, signedEvaluations) {
  const rows = db.prepare(`SELECT seq,hash,json_extract(body,'$.previous') AS previous,json_extract(body,'$.payload.id') AS id
   FROM ledger WHERE tenant=? AND json_extract(body,'$.type')='evaluation' ORDER BY seq`).all(tenant);
  if (rows.length !== signedEvaluations.length || rows.some((row, index) => row.id !== signedEvaluations[index]?.id)) {
    fail(409, '분석 조회 사본이 서명 원장과 일치하지 않습니다');
  }
  return rows.map((row, index) => ({seq: row.seq, hash: row.hash, previous: row.previous, payload: signedEvaluations[index]}));
}

// Offline path: verify an export bundle with a trusted key, then map its latest evaluations.
export function ocsfFromBundle(bundle, publicKey, {version, expectedCheckpoint} = {}) {
  verifyBundle(bundle, publicKey, expectedCheckpoint);
  const disclosures = new Map((bundle.disclosures || []).map(d => [d.seq, d.event])), byAction = new Map();
  for (const row of bundle.records) {
    if (row.type !== 'event') continue;
    const event = isEncryptedEvent(row.payload) ? disclosures.get(row.seq) : row.payload;
    if (!event) continue;
    if (!byAction.has(event.actionId)) byAction.set(event.actionId, []);
    byAction.get(event.actionId).push({...event, seq: row.seq, hash: row.hash});
  }
  const evaluations = bundle.records.filter(row => row.type === 'evaluation')
    .map(row => ({seq: row.seq, hash: row.hash, previous: row.previous, payload: row.payload}));
  // A transparency origin is only a label here; it is used when it names this tenant's log.
  const tenant = bundle.checkpoint.tenant, origin = bundle.transparency?.origin;
  const chainUid = typeof origin === 'string' && origin.endsWith('/t/' + tenantLogId(tenant)) ? origin : undefined;
  return ocsfFindings({tenant, evaluations, eventsFor: actionId => byAction.get(actionId) || [], checkpoint: bundle.checkpoint, publicKey, version,
    chainUid});
}

// Splunk HTTP Event Collector envelopes (sourcetype picked up by the Splunk OCSF-CIM add-on's ocsf:* convention).
export function hecEnvelope(event, {sourcetype = SPLUNK_SOURCETYPE, index} = {}) {
  return {time: event.time / 1000, source: 'evidscope', sourcetype, ...(index ? {index} : {}), event};
}
