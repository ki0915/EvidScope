// Vault route POST /api/ingest/otlp: accepts the minimized event batch produced by the OTLP
// receiver (src/otlp-http.mjs), re-validates every event and commits the batch in one transaction.
import {fail, validateEvent} from './model.mjs';
import {OTLP_BATCH_FORMAT, OTLP_MAPPING_VERSION, otlpEventInvariant} from './otlp.mjs';
import {appendSourceEvent, assertBatchAnalysisCapacity} from './event-ingest.mjs';

export const OTLP_BATCH_MAX_EVENTS = 2048;

// OTLP sources authenticate with a bearer token only; an HMAC secret would blur the two auth models.
export function validateOtlpPrincipals(principals) {
  if (principals.some(p => p.kind === 'otlp' && (p.role !== 'source' || p.hmacSecret !== undefined))) throw Error('Invalid credential configuration');
}

export function createOtlpIngest({store, principals, verifiedActions}) {
  validateOtlpPrincipals(principals);
  return function ingestOtlp(p, body) {
    if (p.role !== 'source' || p.kind !== 'otlp') fail(403, 'OTLP 수집 출처 자격이 필요합니다');
    let batch;
    try { batch = JSON.parse(body); } catch { fail(400, 'JSON 형식 오류'); }
    if (!batch || typeof batch !== 'object' || Array.isArray(batch) || Object.keys(batch).some(k => !['format', 'mapping', 'events'].includes(k))
      || batch.format !== OTLP_BATCH_FORMAT || batch.mapping !== OTLP_MAPPING_VERSION || !Array.isArray(batch.events)) fail(400, 'OTLP 수집 묶음 형식 오류');
    if (batch.events.length > OTLP_BATCH_MAX_EVENTS) fail(413, `OTLP 수집 묶음 한도 ${OTLP_BATCH_MAX_EVENTS}건 초과`);
    const reasons = {}, reject = reason => { reasons[reason] = (reasons[reason] || 0) + 1; };
    const valid = [];
    for (const raw of batch.events) {
      try {
        if (!otlpEventInvariant(raw)) { reject('invalid_event'); continue; }
        valid.push(validateEvent(raw, p));
      } catch { reject('invalid_event'); }
    }
    const result = (accepted, duplicates) => ({accepted, duplicates, rejected: Object.values(reasons).reduce((n, v) => n + v, 0), reasons,
      durability: 'sqlite_full_commit', analysis: 'asynchronous', externalSeal: false});
    if (!valid.length) return result(0, 0);
    return store.transaction(() => {
      verifiedActions(p);
      let accepted = 0, duplicates = 0;
      const fresh = [], seen = new Map(), receipt = store.db.prepare('SELECT fingerprint FROM receipts WHERE tenant=? AND source=? AND id=?');
      for (const e of valid) {
        const prev = seen.get(e.id) ?? receipt.get(p.tenant, p.id, e.id)?.fingerprint;
        if (prev !== undefined) {
          if (prev !== e.fingerprint) { reject('id_conflict'); continue; }
          duplicates++; store.count('duplicates'); continue;
        }
        seen.set(e.id, e.fingerprint); fresh.push(e);
      }
      assertBatchAnalysisCapacity(store, p.tenant, fresh.map(e => e.actionId));
      for (const e of fresh) { appendSourceEvent(store, p, e); accepted++; store.count('accepted'); }
      return result(accepted, duplicates);
    });
  };
}
