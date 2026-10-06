import {fail} from './model.mjs';

// Per-tenant analysis backlog gate (audit S7): one busy tenant must not refuse every tenant's writes.
// ANALYSIS_BACKLOG_LIMIT_PER_TENANT overrides the default for load tests and small deployments.
export function analysisBacklogLimit() {
  const value = Number(process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT);
  return Number.isSafeInteger(value) && value > 0 ? value : 10000;
}
export function tenantBacklog(store, tenant) {
  return store.db.prepare('SELECT COUNT(*) n FROM actions WHERE tenant=? AND analyzed<version').get(tenant).n;
}
// Call inside the write transaction, before appending.
export function assertAnalysisCapacity(store, tenant) {
  if (tenantBacklog(store, tenant) > analysisBacklogLimit()) fail(503, '분석 적체: 유한 재시도 후 로컬 손실 지표를 기록하세요');
}
// Batch variant: counts the actions the batch would newly make pending, so one batch cannot carry a tenant far past the
// limit. A batch is still admitted into an empty backlog even when it alone exceeds the limit, or it could never be stored.
export function assertBatchAnalysisCapacity(store, tenant, actionIds) {
  const backlog = tenantBacklog(store, tenant), state = store.db.prepare('SELECT analyzed<version AS pending FROM actions WHERE tenant=? AND id=?');
  let added = 0;
  for (const id of new Set(actionIds)) if (!state.get(tenant, id)?.pending) added++;
  if (backlog > 0 && backlog + added > analysisBacklogLimit()) fail(503, '분석 적체: 유한 재시도 후 로컬 손실 지표를 기록하세요');
}

// The four writes every accepted source event needs. Projection checks fail if any is missing.
export function appendSourceEvent(store, p, e) {
  const record = store.append(p.tenant, 'event', e, p.id);
  store.append(p.tenant, 'event_receipt', {format: 'evidscope-event-receipt-v1', basis: 'source_ingest', source: e.source, id: e.id,
    fingerprint: e.fingerprint, eventSeq: record.seq, eventHash: record.hash}, p.id);
  store.project({...e, seq: record.seq, hash: record.hash});
  store.projectionMutation(() => store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) '
    + 'ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(p.tenant, e.actionId));
  return record;
}
