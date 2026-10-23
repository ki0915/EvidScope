// Vault route POST /api/ingest/otlp: accepts the minimized event batch produced by the OTLP
// receiver (src/otlp-http.mjs), re-validates every event and commits the batch in one transaction.
// Decision candidates (src/otlp.mjs mapDecisionSpan) become policy_decision records only for an `enforcement` source whose
// credential opts in with `otlpDecisions`; an `otlp` source never stores one (docs/agent-registry.md).
import {fail, validateEvent} from './model.mjs';
import {OTLP_BATCH_FORMAT, OTLP_DECISION_MAPPING, OTLP_MAPPING_VERSION, otlpDecisionInvariant, otlpEventInvariant} from './otlp.mjs';
import {appendSourceEvent, assertBatchAnalysisCapacity, receiptMatch} from './event-ingest.mjs';

export const OTLP_BATCH_MAX_EVENTS = 2048;
const POINT = /^[a-zA-Z0-9._:@/-]{1,120}$/, ENGINE = /^[A-Za-z0-9._:-]{1,64}$/;
const DECISION_NOTE = JSON.stringify({adapter: OTLP_DECISION_MAPPING, attributesRetained: 'allowlist', recordedBeforeExecution: 'not_reported'});
const plainObject = v => !!v && typeof v === 'object' && !Array.isArray(v);

// otlpDecisions: {enforcementPointId, engine?, clockUncertaintyMs?} on an enforcement source credential.
function validDecisionOptions(p) {
  const o = p.otlpDecisions;
  if (p.role !== 'source' || p.kind !== 'enforcement' || !plainObject(o)) return false;
  if (Object.keys(o).some(k => !['enforcementPointId', 'engine', 'clockUncertaintyMs'].includes(k))) return false;
  const clock = o.clockUncertaintyMs;
  return POINT.test(o.enforcementPointId ?? '') && (o.engine === undefined || ENGINE.test(o.engine))
    && (clock === undefined || clock === 'unknown' || (Number.isSafeInteger(clock) && clock >= 0 && clock <= 300000));
}
// OTLP sources authenticate with a bearer token only; an HMAC secret would blur the two auth models. An enforcement source that
// reports decisions over OTLP keeps its HMAC secret for /api/ingest; the OTLP route takes its bearer token, as the OPA status route does.
export function validateOtlpPrincipals(principals) {
  if (principals.some(p => p.kind === 'otlp' && (p.role !== 'source' || p.hmacSecret !== undefined))) throw Error('Invalid credential configuration');
  if (principals.some(p => p.otlpDecisions !== undefined && !validDecisionOptions(p))) throw Error('Invalid credential configuration');
}
export const otlpSource = p => p.role === 'source' && (p.kind === 'otlp' || (p.kind === 'enforcement' && p.otlpDecisions !== undefined));

export function createOtlpIngest({store, principals, verifiedActions}) {
  validateOtlpPrincipals(principals);
  return function ingestOtlp(p, body) {
    if (!otlpSource(p)) fail(403, 'OTLP 수집 출처 자격이 필요합니다');
    let batch;
    try { batch = JSON.parse(body); } catch { fail(400, 'JSON 형식 오류'); }
    if (!plainObject(batch) || Object.keys(batch).some(k => !['format', 'mapping', 'events', 'decisions'].includes(k))
      || batch.format !== OTLP_BATCH_FORMAT || batch.mapping !== OTLP_MAPPING_VERSION || !Array.isArray(batch.events)
      || (batch.decisions !== undefined && !Array.isArray(batch.decisions))) fail(400, 'OTLP 수집 묶음 형식 오류');
    const candidates = batch.decisions ?? [];
    if (batch.events.length + candidates.length > OTLP_BATCH_MAX_EVENTS) fail(413, `OTLP 수집 묶음 한도 ${OTLP_BATCH_MAX_EVENTS}건 초과`);
    const reasons = {}, reject = reason => { reasons[reason] = (reasons[reason] || 0) + 1; };
    const valid = [];
    if (p.kind === 'otlp') {
      for (const raw of batch.events) {
        try {
          if (!otlpEventInvariant(raw)) { reject('invalid_event'); continue; }
          valid.push(validateEvent(raw, p));
        } catch { reject('invalid_event'); }
      }
      // The span of a companion candidate is stored (or counted) through its GenAI event.
      for (const raw of candidates) if (raw?.companion !== true) reject('decision_needs_enforcement_source');
    } else {
      const options = p.otlpDecisions, spans = new Set();
      for (const raw of candidates) {
        if (raw?.companion === true && typeof raw.id === 'string') spans.add(raw.id.replace(/^otel-decision:/, 'otel:'));
        try {
          if (!otlpDecisionInvariant(raw)) { reject('invalid_event'); continue; }
          const decision = {...raw}; delete decision.companion;
          valid.push(validateEvent({...decision, enforcementPointId: options.enforcementPointId, engine: options.engine ?? 'otel',
            clockUncertaintyMs: options.clockUncertaintyMs ?? 'unknown', note: DECISION_NOTE}, p));
        } catch { reject('invalid_event'); }
      }
      for (const raw of batch.events) if (!spans.has(raw?.id)) reject('not_decision_span');
    }
    const result = (accepted, duplicates) => ({accepted, duplicates, rejected: Object.values(reasons).reduce((n, v) => n + v, 0), reasons,
      durability: 'sqlite_full_commit', analysis: 'asynchronous', externalSeal: false});
    if (!valid.length) return result(0, 0);
    return store.transaction(() => {
      verifiedActions(p);
      let accepted = 0, duplicates = 0;
      const fresh = [], seen = new Map();
      for (const e of valid) {
        // Earlier in this batch: raw digests; stored: keyed receipt tags. A destroyed key epoch cannot confirm a retry.
        const prev = seen.has(e.id) ? (seen.get(e.id) === e.fingerprint ? 'same' : 'different') : receiptMatch(store, p.tenant, p.id, e.id, e.fingerprint);
        if (prev) {
          if (prev !== 'same') { reject('id_conflict'); continue; }
          duplicates++; store.count('duplicates'); continue;
        }
        seen.set(e.id, e.fingerprint); fresh.push(e);
      }
      assertBatchAnalysisCapacity(store, p.tenant, fresh.map(e => e.actionId));
      for (const e of fresh) { appendSourceEvent(store, p, e); accepted++; }
      store.count('accepted', fresh.length);
      return result(accepted, duplicates);
    });
  };
}
