// HTTP routes of the governance-mapping model console (docs/governance-model.md): the review queue, the experiment comparison and the
// signed factsheets. Reads go through the service's verified signed-object reads; nothing here starts, trains or promotes a model.
//   GET  /api/governance-model/review?split=&after=     next drafted row, its hashes and the progress per split
//   GET  /api/governance-model/review/items/<id>         one row with its current decision
//   GET  /api/governance-model/review/decisions          the signed decisions
//   POST /api/governance-model/review/decisions          approve or reject one row (reviewer/admin)
//   GET  /api/governance-model/experiments               reports side by side and the run history
//   GET  /api/governance-model/factsheets                signed factsheets, newest first
//   POST /api/governance-model/factsheets                record one factsheet (reviewer/admin)
import {fail} from './model.mjs';
import {QUEUE_DECISION_TYPE} from './governance-mapping-data.mjs';
import {createReviewQueue, repositoryDataset} from './governance-review-queue.mjs';
import {FACTSHEET_TYPE, buildFactsheet, listFactsheets} from './governance-factsheets.mjs';
import {REPORTS_DIR, experimentsView} from './governance-experiments.mjs';

export const FACTSHEETS_PATH = '/api/governance-model/factsheets';
export const FACTSHEET_MAX_BYTES = 2 * 1024 * 1024;

export function createGovernanceModelService({store, policyObjects, human, reviewer, reportsDir = REPORTS_DIR, root, dataset = repositoryDataset,
  now = () => Date.now()}) {
  const queue = createReviewQueue({store, policyObjects, human, dataset, now});
  const values = (p, type) => [...policyObjects(p, type).values()];
  // For /api/model-runtime and /api/model-status: a faulted ledger read is shown in place, the rest of the status still renders.
  function factsheets(p) {
    try { return {status: 'ok', items: store.transaction(() => listFactsheets(values(p, FACTSHEET_TYPE)))}; }
    catch (error) { return {status: 'unavailable', reason: error.message, items: []}; }
  }
  function record(p, x) {
    reviewer(p);
    // The checks (report re-verification, training-file reproduction) run outside the write transaction; the write re-checks identity.
    const [decisions, recorded] = store.transaction(() => [values(p, QUEUE_DECISION_TYPE), values(p, FACTSHEET_TYPE)]);
    let built;
    try { built = buildFactsheet(x, {principal: p, decisions, factsheets: recorded, dataset, now: now(), root}); }
    catch (error) { if (error.code && error.status) fail(error.status, error.code); throw error; }
    return store.transaction(() => {
      const current = policyObjects(p, FACTSHEET_TYPE);
      if (current.has(built.id)) fail(409, 'factsheet_already_recorded');
      // A shakedown recorded meanwhile must still stop a candidate claim on its adapter.
      const shakedown = [...current.values()].some(f => f.kind === 'training' && f.runMode === 'shakedown' && f.adapter?.ggufSha256
        && f.adapter.ggufSha256 === built.adapter?.ggufSha256);
      if (shakedown && built.runMode !== 'shakedown' && built.kind !== 'evaluation') fail(409, 'factsheet_adapter_is_shakedown');
      store.put(p, FACTSHEET_TYPE, built.id, built);
      return {factsheet: built, signed: true};
    });
  }
  function handle(p, method, url, x) {
    const path = url.pathname;
    if (path.startsWith('/api/governance-model/review')) return queue.handle(p, method, url, x);
    if (path === '/api/governance-model/experiments' && method === 'GET') {
      human(p);
      const recorded = store.transaction(() => listFactsheets(values(p, FACTSHEET_TYPE)));
      return experimentsView({reportsDir, factsheets: recorded, now: now()});
    }
    if (path === FACTSHEETS_PATH && method === 'GET') { human(p); return {items: store.transaction(() => listFactsheets(values(p, FACTSHEET_TYPE)))}; }
    if (path === FACTSHEETS_PATH && method === 'POST') return record(p, x);
    if (path.startsWith('/api/governance-model/')) fail(404, '경로 없음');
    return undefined;
  }
  return {handle, factsheets, queue};
}
