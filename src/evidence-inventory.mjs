// Counts the evidence kinds named by a mapping (data/isms-p-alignment.json, src/evidence-pack-frameworks.mjs) in an export
// that verifyBundle has accepted. Shared by scripts/isms-p-report.mjs and evidence packages (docs/evidence-pack.md), and
// published with the offline verifier. The presence of evidence is never a finding that a requirement is met.
export const NOT_CARRIED = {api: 'api_response_not_carried_by_exports', file: 'repository_file_not_carried_by_exports',
  integrityCheck: 'online_check_result_not_carried_by_exports'};
export const EVIDENCE_TYPES = ['record', 'eventKind', 'checkType', 'finding', 'integrityCheck', 'api', 'file'];

// The identifying fields of one evidence entry of a mapping.
export const evidenceName = e => e.type === 'api' ? {method: e.method, path: e.path, ...(e.mode ? {mode: e.mode} : {}), ...(e.field ? {field: e.field} : {})}
  : e.type === 'finding' ? (e.codePrefix !== undefined ? {codePrefix: e.codePrefix} : {code: e.code}) : e.type === 'file' ? {path: e.path}
    : {name: e.name, ...(e.source ? {source: e.source} : {}), ...(e.alsoAllowed ? {alsoAllowed: e.alsoAllowed} : {})};

export function timeRange(values) {
  const times = values.filter(v => typeof v === 'string' && /^\d{4}-\d\d-\d\dT/.test(v) && Number.isFinite(Date.parse(v)))
    .sort((a, b) => Date.parse(a) - Date.parse(b));
  if (!times.length) return null;
  return {from: times[0], to: times.at(-1), ...(times.length < values.length ? {unparsed: values.length - times.length} : {})};
}
const counted = (count, extra = {}) => count ? {status: 'present', count, ...extra} : {status: 'none_recorded', count: 0};
// period {from, to}: half-open [from, to) on the vault's signed recordedAt; null keeps every record.
export const inPeriod = (period, recordedAt) => !period
  || (Date.parse(recordedAt) >= Date.parse(period.from) && Date.parse(recordedAt) < Date.parse(period.to));

// Reads only a bundle that verifyBundle has accepted: every retained encrypted event then has a disclosure whose digest
// matches the signed payloadHash, and erased events have none.
export function inventory(bundle, replay, {period = null, locators = false} = {}) {
  const records = new Map(), disclosures = new Map((bundle.disclosures || []).map(d => [d.seq, d.event])), events = [], latest = new Map();
  for (const row of bundle.records) {
    if (!inPeriod(period, row.recordedAt)) continue;
    if (!records.has(row.type)) records.set(row.type, []);
    records.get(row.type).push({seq: row.seq, recordedAt: row.recordedAt});
    if (row.type === 'event') {
      // A sealed event is read only from its verified disclosure; an erased one has none and is not classified.
      const disclosed = disclosures.get(row.seq), sealed = String(row.payload?.format).startsWith('evidscope-encrypted-event');
      const event = disclosed ?? (sealed ? null : row.payload);
      if (event && typeof event === 'object') events.push({event, seq: row.seq, recordedAt: row.recordedAt, encrypted: disclosed !== undefined});
    }
    if (row.type === 'evaluation' && typeof row.payload?.actionId === 'string') latest.set(row.payload.actionId, row);
  }
  const replayed = replay ? new Map(replay.evaluations.map(e => [e.seq, e.status])) : null;
  return {records, events, latest, replayed, locators};
}

const seqList = (data, seqs) => (data.locators ? {seqs: [...seqs].sort((a, b) => a - b)} : {});
// Whether a finding entry of a mapping names this finding: one code, or (mapping version 3) every code with a prefix.
export const findingMatches = (e, f) => typeof f?.code === 'string' && (e.codePrefix !== undefined ? f.code.startsWith(e.codePrefix) : f.code === e.code);
// verifiedStatus names the integrity check this caller has just performed (a report, or a package).
export function measure(e, data, verification, verifiedStatus = 'verified_by_this_report') {
  if (e.type === 'integrityCheck' && e.name === 'signed_ledger') {
    return {status: verifiedStatus, count: verification.count, basis: 'offline_signature_and_hash_chain_verification',
      ...(data.locators ? {} : {rollbackChecked: verification.rollbackChecked})};
  }
  if (NOT_CARRIED[e.type]) return {status: 'not_in_export', reason: NOT_CARRIED[e.type]};
  if (e.type === 'record') {
    const rows = data.records.get(e.name) || [];
    return counted(rows.length, {recordedAt: timeRange(rows.map(r => r.recordedAt)), verification: 'signed_hash_chain',
      ...seqList(data, rows.map(r => r.seq))});
  }
  if (e.type === 'eventKind' || e.type === 'checkType') {
    const allowed = e.type === 'eventKind' ? new Set([e.source, ...(e.alsoAllowed || [])]) : null;
    const hits = data.events.filter(({event}) => e.type === 'eventKind' ? event.kind === e.name && allowed.has(event.sourceKind)
      : event.kind === 'governance_check' && event.governanceCheck?.checkType === e.name);
    const bySource = Object.create(null);
    for (const {event} of hits) bySource[event.sourceKind] = (bySource[event.sourceKind] || 0) + 1;
    return counted(hits.length, {sourceKinds: bySource, recordedAt: timeRange(hits.map(h => h.recordedAt)),
      sourceClaimedOccurredAt: timeRange(hits.map(h => h.event.occurredAt)), disclosureVerified: hits.filter(h => h.encrypted).length,
      verification: 'signed_hash_chain_and_disclosure_digest', ...seqList(data, hits.map(h => h.seq))});
  }
  if (e.type === 'finding') {
    let actions = 0, occurrences = 0, suppressed = 0;
    const times = [], seqs = [], replay = data.replayed ? {replayed: 0, notReplayable: 0} : 'not_requested';
    for (const row of data.latest.values()) {
      const hits = (Array.isArray(row.payload.findings) ? row.payload.findings : []).filter(f => findingMatches(e, f));
      if (!hits.length) continue;
      actions++; occurrences += hits.length; suppressed += hits.filter(f => f.suppressedBy !== undefined).length;
      times.push(row.recordedAt); seqs.push(row.seq);
      if (data.replayed) replay[data.replayed.get(row.seq) === 'replayed' ? 'replayed' : 'notReplayable']++;
    }
    return counted(occurrences, {actions, suppressed, recordedAt: timeRange(times), replay, verification: 'signed_evaluation', ...seqList(data, seqs)});
  }
  throw Error('Unknown evidence type in alignment: ' + e.type);
}
