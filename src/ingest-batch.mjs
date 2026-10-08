// Group commit for source ingest (round 5, docs/performance.md). Requests that arrive close together share one SQLite
// transaction: one BEGIN IMMEDIATE, one projection check per tenant, one v1 checkpoint signature per tenant over the new chain
// head, one tlog note and one fsync. Every event keeps its own ledger rows (event, event_receipt), its own hash-chain position
// and its own receipt, so exports, checkpoints and both verifiers are unchanged. Each event runs in its own savepoint: a
// refused event (replayed nonce, content conflict, backlog) rolls back alone. A request is answered only after the COMMIT
// that holds its event returned (synchronous=FULL), so 202 still means durable; if the batch fails, no event of it is stored
// and every request in it gets the error. Store.transaction stays synchronous: batching happens before it.
export const INGEST_BATCH_DEFAULTS = Object.freeze({maxWaitMs: 0, maxEvents: 256});

// INGEST_BATCH_MAX_WAIT_MS (0-1000): how long the first queued event may wait for others; 0 commits at the end of the current
// event-loop turn, so a batch holds what arrived while the previous commit ran and a lone event waits for nothing.
// INGEST_BATCH_MAX_EVENTS (1-4096): a full batch commits at once; 1 restores one transaction per event.
export function ingestBatchOptions(env = process.env) {
  const read = (name, min, max, fallback) => {
    if (env[name] === undefined || env[name] === '') return fallback;
    const value = Number(env[name]);
    if (!Number.isSafeInteger(value) || value < min || value > max) throw Error('Invalid ' + name);
    return value;
  };
  return {maxWaitMs: read('INGEST_BATCH_MAX_WAIT_MS', 0, 1000, INGEST_BATCH_DEFAULTS.maxWaitMs),
    maxEvents: read('INGEST_BATCH_MAX_EVENTS', 1, 4096, INGEST_BATCH_DEFAULTS.maxEvents)};
}

// begin(items) runs first inside the batch transaction and returns the context handed to every item's work(context); if it
// throws, the whole batch fails. end(context, values), when given, runs after the last item, still inside the transaction, with the
// return values of the items whose savepoints were kept. work runs in a savepoint; its return value resolves that item's promise after COMMIT.
// onCommit({size, committed, failed, waitedMs}) is called after each batch; stats sums them (process-wide, never served per tenant).
export function createGroupCommit({store, begin = () => ({}), end, maxWaitMs = INGEST_BATCH_DEFAULTS.maxWaitMs,
  maxEvents = INGEST_BATCH_DEFAULTS.maxEvents, onCommit} = {}) {
  if (!Number.isSafeInteger(maxWaitMs) || maxWaitMs < 0 || !Number.isSafeInteger(maxEvents) || maxEvents < 1) throw TypeError('Invalid group commit bounds');
  let queue = [], timer = null, immediate = null;
  const stats = {batches: 0, events: 0, committed: 0, failedBatches: 0, largest: 0, maxWaitedMs: 0};
  const schedule = () => {
    if (immediate || !queue.length) return;
    if (queue.length >= maxEvents || maxWaitMs === 0) { clearTimeout(timer); timer = null; immediate = setImmediate(flush); return; }
    // Bounded by the oldest queued event, not reset by later arrivals.
    if (!timer) timer = setTimeout(() => { timer = null; if (!immediate) immediate = setImmediate(flush); }, Math.max(0, queue[0].at + maxWaitMs - Date.now()));
  };
  function flush() {
    immediate = null; clearTimeout(timer); timer = null;
    const batch = queue.splice(0, maxEvents), outcomes = new Array(batch.length);
    schedule();
    if (!batch.length) return;
    let failure = null;
    try {
      store.transaction(() => {
        const context = begin(batch.map(item => item.input));
        for (let i = 0; i < batch.length; i++) {
          try { outcomes[i] = {value: store.transaction(() => batch[i].work(context))}; } catch (error) { outcomes[i] = {error}; }
        }
        if (end) end(context, outcomes.filter(outcome => !outcome.error).map(outcome => outcome.value));
      });
    } catch (error) { failure = error; }
    let committed = 0;
    for (let i = 0; i < batch.length; i++) {
      const item = batch[i], outcome = outcomes[i];
      // A failed batch stored nothing: an event's own refusal stays its answer, every other event gets the batch error.
      if (outcome?.error) item.reject(outcome.error);
      else if (failure) item.reject(failure);
      else { committed++; item.resolve(outcome.value); }
    }
    const waitedMs = Date.now() - batch[0].at;
    stats.batches++; stats.events += batch.length; stats.committed += committed; if (failure) stats.failedBatches++;
    stats.largest = Math.max(stats.largest, batch.length); stats.maxWaitedMs = Math.max(stats.maxWaitedMs, waitedMs);
    if (onCommit) try { onCommit({size: batch.length, committed, failed: !!failure, waitedMs}); } catch {}
  }
  return {
    get pending() { return queue.length; },
    get stats() { return {...stats, maxWaitMs, maxEvents}; },
    // input is handed to begin(); work(context) is the synchronous per-event write.
    submit(input, work) {
      if (typeof work !== 'function') throw TypeError('Group commit work must be a function');
      return new Promise((resolve, reject) => { queue.push({input, work, resolve, reject, at: Date.now()}); schedule(); });
    },
  };
}
