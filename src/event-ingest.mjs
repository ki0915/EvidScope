import {fail} from './model.mjs';

// Per-tenant analysis backlog gate (audit S7): one busy tenant must not refuse every tenant's writes.
// ANALYSIS_BACKLOG_LIMIT_PER_TENANT overrides the default for load tests and small deployments.
export function analysisBacklogLimit() {
  const value = Number(process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT);
  return Number.isSafeInteger(value) && value > 0 ? value : 10000;
}
export function tenantBacklog(store, tenant) {
  return store.cachedStatement('SELECT COUNT(*) n FROM actions WHERE tenant=? AND analyzed<version').get(tenant).n;
}
// Single events (POST /api/ingest, grouped by src/ingest-batch.mjs): the backlog is counted once per batch and tenant, then kept
// current per event (an event adds to it only for an action that was not pending), so each event sees what it saw when every
// event had its own transaction. Call inside the write transaction, before appending; returns whether the event adds to it.
function assertBatchedCapacity(store, tenantState, tenant, actionId) {
  tenantState.backlog ??= tenantBacklog(store, tenant);
  if (tenantState.backlog > analysisBacklogLimit()) fail(503, '분석 적체: 유한 재시도 후 로컬 손실 지표를 기록하세요');
  return !store.cachedStatement('SELECT analyzed<version AS pending FROM actions WHERE tenant=? AND id=?').get(tenant, actionId)?.pending;
}
// Batch variant: counts the actions the batch would newly make pending, so one batch cannot carry a tenant far past the
// limit. A batch is still admitted into an empty backlog even when it alone exceeds the limit, or it could never be stored.
export function assertBatchAnalysisCapacity(store, tenant, actionIds) {
  const backlog = tenantBacklog(store, tenant), state = store.db.prepare('SELECT analyzed<version AS pending FROM actions WHERE tenant=? AND id=?');
  let added = 0;
  for (const id of new Set(actionIds)) if (!state.get(tenant, id)?.pending) added++;
  if (backlog > 0 && backlog + added > analysisBacklogLimit()) fail(503, '분석 적체: 유한 재시도 후 로컬 손실 지표를 기록하세요');
}

// The four writes every accepted source event needs. Projection checks fail if any is missing. e.fingerprint is the raw-body
// digest from validateEvent; what is stored and signed is the keyed tag under the event's key epoch (round 2, audit S3).
export function appendSourceEvent(store, p, raw) {
  const e = store.sealEventFingerprint(p.tenant, raw), record = store.append(p.tenant, 'event', e, p.id);
  store.append(p.tenant, 'event_receipt', {format: 'evidscope-event-receipt-v1', basis: 'source_ingest', source: e.source, id: e.id,
    fingerprint: e.fingerprint, eventSeq: record.seq, eventHash: record.hash}, p.id);
  store.project({...e, seq: record.seq, hash: record.hash});
  store.projectionMutation(() => store.projectionStatement('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) '
    + 'ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(p.tenant, e.actionId));
  return record;
}
// Duplicate check of a source retry against its stored receipt: 'same' | 'different' | 'unverifiable' (key epoch destroyed).
export function receiptMatch(store, tenant, source, id, rawDigest) {
  const prev = store.cachedStatement('SELECT fingerprint FROM receipts WHERE tenant=? AND source=? AND id=?').get(tenant, source, id);
  return prev ? store.compareEventFingerprint(tenant, prev.fingerprint, rawDigest) : null;
}

// Start of one ingest batch, inside its transaction: expired nonces go once, and each tenant's projections are checked once
// (verify throws the HTTP error). A tenant whose check fails refuses only its own events, as separate transactions would.
export function beginIngestBatch(store, sources, verify) {
  store.cachedStatement('DELETE FROM nonces WHERE expires<?').run(Date.now());
  const tenants = new Map();
  for (const p of sources) if (!tenants.has(p.tenant)) {
    let error = null;
    try { verify(p); } catch (caught) { error = caught; }
    tenants.set(p.tenant, {error, backlog: undefined});
  }
  return {tenants};
}
const ACCEPTED = Object.freeze({durability: 'sqlite_full_commit', analysis: 'asynchronous', externalSeal: false});
// One authenticated, validated source event inside its batch savepoint (POST /api/ingest).
export function ingestSourceEvent(store, context, p, nonce, e) {
  const tenantState = context.tenants.get(p.tenant);
  if (tenantState.error) throw tenantState.error;
  if (store.cachedStatement('SELECT 1 FROM nonces WHERE source=? AND nonce=?').get(p.id, nonce)) fail(409, '이미 사용한 nonce입니다');
  store.cachedStatement('INSERT INTO nonces VALUES(?,?,?)').run(p.id, nonce, Date.now() + 600000);
  const prev = receiptMatch(store, p.tenant, p.id, e.id, e.fingerprint);
  if (prev) {
    if (prev === 'unverifiable') fail(409, '동일 출처 이벤트 ID의 이전 접수 지문 키가 파기되어 내용을 비교할 수 없습니다');
    if (prev !== 'same') fail(409, '동일 출처 이벤트 ID의 내용 충돌');
    store.count('duplicates'); return {accepted: true, duplicate: true, ...ACCEPTED};
  }
  const adds = assertBatchedCapacity(store, tenantState, p.tenant, e.actionId);
  appendSourceEvent(store, p, e); store.count('accepted');
  if (adds) tenantState.backlog++;
  return {accepted: true, duplicate: false, ...ACCEPTED};
}
