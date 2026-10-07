// Deterministic offline policy replay (differentiator D2). Re-runs every signed evaluation in an export bundle using
// only ledger records that precede it (seq < evaluation seq) and compares the recomputed findings with the recorded ones.
// Dependency-free: node:crypto via src/crypto.mjs plus the evaluation engine in src/model.mjs.
//
// The prefix state mirrors Store._applyActionStateRow / Store.cachedAnalysisSnapshot: events of the action that were not
// erased before the evaluation, every asset registration in log order, the latest record of each rule (active versions)
// and of each exception. Recorded snapshotHash = digest(snapshot) proves that the reconstruction is the exact input.
import {EVALUATION_ENGINE, boundedEvaluation} from './model.mjs';
import {canonical, digest, isEncryptedEvent, verifyBundle} from './crypto.mjs';

export const POLICY_REPLAY_FORMAT = 'evidscope-policy-replay-v1';
// Limits in force before evaluations recorded them (src/analysis.mjs analysisLimits for engine evidscope-evaluate-v1).
export const LEGACY_ANALYSIS_LIMITS = Object.freeze({
  events: 1000, assets: 5000, rules: 100, exceptions: 5000, snapshotBytes: 10 * 1024 * 1024, findings: 100, resultBytes: 1024 * 1024,
});
const AUTHORITY_KINDS = ['grant', 'human_approval', 'automated_review', 'revoke'];
const bytes = value => Buffer.byteLength(JSON.stringify(value));
const ref = event => `${event.source}/${event.id}`;
// Same comparator as the vault's snapshot (locale-aware; the vault and the replayer must share ICU collation).
const eventOrder = (a, b) => a.receivedAt.localeCompare(b.receivedAt) || a.source.localeCompare(b.source) || a.id.localeCompare(b.id);
const findingKey = finding => `${finding.code}|${(finding.evidence || []).join(',')}`;

function emptyState() {
  return {events: new Map(), byAction: new Map(), unavailable: new Map(), keyEvents: new Map(), assets: new Map(), rules: new Map(),
    exceptions: new Map()};
}

function addEvent(state, event) {
  state.events.set(event.seq, event);
  if (!state.byAction.has(event.actionId)) state.byAction.set(event.actionId, new Map());
  state.byAction.get(event.actionId).set(event.seq, event);
}

function removeEvent(state, seq) {
  const event = state.events.get(seq);
  if (event) { state.events.delete(seq); state.byAction.get(event.actionId)?.delete(seq); }
  state.unavailable.delete(seq);
}

function apply(state, row, disclosures) {
  const payload = row.payload || {};
  if (row.type === 'event') {
    if (isEncryptedEvent(payload)) {
      state.keyEvents.set(payload.keyId, row.seq);
      const event = disclosures.get(row.seq);
      if (event) addEvent(state, {...event, seq: row.seq, hash: row.hash});
      // Envelopes written before actionId was bound in the clear cannot be attributed to an action.
      else state.unavailable.set(row.seq, {seq: row.seq, actionId: typeof payload.actionId === 'string' ? payload.actionId : null});
    } else addEvent(state, {...payload, seq: row.seq, hash: row.hash});
  } else if (row.type === 'retention_disposition') {
    for (const keyId of payload.keyIds || []) if (state.keyEvents.has(keyId)) removeEvent(state, state.keyEvents.get(keyId));
  } else if (row.type === 'asset' && payload.id) state.assets.set(`${payload.id}:${row.seq}`, payload);
  else if (row.type === 'rule' && payload.id) state.rules.set(payload.id, payload);
  else if (row.type === 'exception' && payload.id) state.exceptions.set(payload.id, payload);
}

function snapshot(state, actionId) {
  return {
    events: [...(state.byAction.get(actionId)?.values() || [])].sort(eventOrder),
    assets: [...state.assets.values()],
    rules: [...state.rules.values()].flatMap(rule => (rule.versions || []).filter(version => version.status === 'active')),
    exceptions: [...state.exceptions.values()],
  };
}

// Mirrors Store.cachedAnalysisSnapshot resource checks followed by the claim-time size check in src/analysis.mjs.
function quarantineReason(data, limits) {
  const used = 100 + [...data.events, ...data.assets, ...data.rules, ...data.exceptions].reduce((total, value) => total + bytes(value) + 1, 0);
  const reasons = ['events', 'assets', 'rules', 'exceptions'].filter(name => data[name].length > limits[name]);
  if (used > limits.snapshotBytes - 4096) reasons.push('snapshotBytes');
  const size = reasons.length ? used : bytes(data);
  if (size > limits.snapshotBytes - 4096) reasons.push('snapshotBytes');
  return reasons.length ? `resource_limit:${reasons.join(',')}` : null;
}

function compare(recorded, replayed) {
  const diff = {};
  for (const field of ['authority', 'effect', 'limitations', 'coverage']) {
    if (canonical(recorded[field] ?? null) !== canonical(replayed[field])) diff[field] = {recorded: recorded[field] ?? null, replayed: replayed[field]};
  }
  const before = Array.isArray(recorded.findings) ? recorded.findings : [], after = replayed.findings;
  if (canonical(before) !== canonical(after)) {
    const a = new Map(before.map(f => [findingKey(f), f])), b = new Map(after.map(f => [findingKey(f), f]));
    const brief = f => ({code: f.code, severity: f.severity, evidence: f.evidence, ...(f.suppressedBy ? {suppressedBy: f.suppressedBy} : {})});
    const changed = [...a.keys()].filter(key => b.has(key) && canonical(a.get(key)) !== canonical(b.get(key)));
    diff.findings = {
      recordedOnly: [...a.keys()].filter(key => !b.has(key)).map(key => brief(a.get(key))),
      replayedOnly: [...b.keys()].filter(key => !a.has(key)).map(key => brief(b.get(key))),
      changed: changed.map(key => ({recorded: a.get(key), replayed: b.get(key)})),
    };
    if (!diff.findings.recordedOnly.length && !diff.findings.replayedOnly.length && !changed.length) diff.findings.orderOnly = true;
  }
  return Object.keys(diff).length ? diff : null;
}

// Authority evidence relative to each independent tool record, by ledger position (not by source-claimed time).
function ordering(events) {
  const authority = events.filter(e => e.sourceKind === 'authority' && AUTHORITY_KINDS.includes(e.kind));
  const brief = e => ({seq: e.seq, kind: e.kind, ref: ref(e)});
  return events.filter(e => e.sourceKind === 'tool' && ['execution', 'result'].includes(e.kind)).map(e => ({
    seq: e.seq, kind: e.kind, ref: ref(e),
    authorityRecordedBefore: authority.filter(a => a.seq < e.seq).map(brief),
    authorityRecordedAfter: authority.filter(a => a.seq > e.seq).map(brief),
  }));
}

function inputSummary(data, matches) {
  return {events: data.events.map(e => e.seq), assets: data.assets.length, rules: data.rules.map(r => ({id: r.id, version: r.version})),
    exceptions: data.exceptions.length, snapshotHash: matches ? 'matches_record' : 'differs_from_record'};
}

function replayOne(state, row, engine) {
  const evaluation = row.payload || {}, recordedEngine = evaluation.replay?.engine;
  const base = {seq: row.seq, id: evaluation.id ?? null, actionId: evaluation.actionId ?? null, version: evaluation.version ?? null,
    evaluationStatus: evaluation.status ?? null, engine: recordedEngine ?? 'unrecorded'};
  const notReplayable = (reason, extra = {}) => ({...base, status: 'not_replayable', reason, ...extra});
  if (typeof evaluation.actionId !== 'string') return notReplayable('invalid_record');
  if (recordedEngine !== undefined && recordedEngine !== engine) return notReplayable('engine_unavailable');
  const data = snapshot(state, evaluation.actionId);
  const hidden = [...state.unavailable.values()].filter(u => u.actionId === null || u.actionId === evaluation.actionId).map(u => u.seq);
  const recordedSeqs = Array.isArray(evaluation.replay?.inputs?.events) ? evaluation.replay.inputs.events : null;
  const erased = recordedSeqs ? recordedSeqs.filter(seq => hidden.includes(seq)) : hidden;
  if (evaluation.status === 'quarantined_resource_limit') {
    if (erased.length) return notReplayable('erased_input', {erasedEvents: erased});
    const expected = quarantineReason(data, {...LEGACY_ANALYSIS_LIMITS, ...evaluation.replay?.limits});
    if (expected === evaluation.coverage?.reason) return notReplayable('resource_limit', {quarantineConfirmed: true, coverage: evaluation.coverage});
    return {...base, status: 'mismatch', diff: {quarantine: {recorded: evaluation.coverage?.reason ?? null, replayed: expected}}};
  }
  if (evaluation.status !== 'evaluated') return notReplayable('unknown_status');
  if (typeof evaluation.snapshotHash !== 'string' || !Number.isFinite(Date.parse(evaluation.analysisTime))) {
    return notReplayable('legacy_record_lacks_inputs');
  }
  const matches = digest(data) === evaluation.snapshotHash;
  if (!matches && erased.length) return notReplayable('erased_input', {erasedEvents: erased});
  const limits = {...LEGACY_ANALYSIS_LIMITS, ...evaluation.replay?.limits};
  const replayed = boundedEvaluation({...data, analysisTime: Date.parse(evaluation.analysisTime)}, limits);
  const diff = compare(evaluation, replayed);
  const order = ordering(data.events);
  const report = {...base, inputs: inputSummary(data, matches), ordering: order,
    approvalRecordedAfterExecution: order.some(o => o.authorityRecordedAfter.some(a => a.kind === 'human_approval'))};
  if (matches) {
    const basis = evaluation.replay ? 'recorded_inputs' : 'snapshot_hash_engine_assumed';
    return diff ? {...report, status: 'mismatch', basis, diff} : {...report, status: 'replayed', basis, findings: replayed.findings.length};
  }
  if (evaluation.replay) {
    const reconstructed = data.events.map(e => e.seq);
    const inputs = recordedSeqs ? {recordedOnly: recordedSeqs.filter(s => !reconstructed.includes(s)),
      reconstructedOnly: reconstructed.filter(s => !recordedSeqs.includes(s))} : {};
    return {...report, status: 'mismatch', basis: 'recorded_inputs', diff: {...diff, inputs: {snapshotHash: 'differs_from_record', ...inputs}}};
  }
  // Pre-replay records whose snapshot cannot be reconstructed: findings that still agree are best effort only.
  return diff ? notReplayable('legacy_inputs_unverifiable', {inputs: report.inputs, diff})
    : {...report, status: 'replayed', basis: 'best_effort', findings: replayed.findings.length};
}

// Call only on a bundle that passed verifyBundle(bundle, trustedKey) with disclosures (not chainOnly).
export function replayEvaluations(bundle, {engine = EVALUATION_ENGINE} = {}) {
  if (!bundle || !Array.isArray(bundle.records)) throw TypeError('An export bundle with records is required');
  const disclosures = new Map((bundle.disclosures || []).map(d => [d.seq, d.event]));
  const state = emptyState(), evaluations = [];
  for (const row of bundle.records) {
    if (row.type === 'evaluation') evaluations.push(replayOne(state, row, engine));
    apply(state, row, disclosures);
  }
  const count = status => evaluations.filter(e => e.status === status).length;
  const reasons = {};
  for (const e of evaluations) if (e.status === 'not_replayable') reasons[e.reason] = (reasons[e.reason] || 0) + 1;
  const summary = {evaluations: evaluations.length, replayed: count('replayed'), mismatch: count('mismatch'), notReplayable: count('not_replayable'),
    notReplayableReasons: reasons, approvalRecordedAfterExecution: evaluations.filter(e => e.approvalRecordedAfterExecution).length};
  return {
    format: POLICY_REPLAY_FORMAT, engine, tenant: bundle.checkpoint?.tenant ?? null,
    checkpoint: bundle.checkpoint ? {count: bundle.checkpoint.count, head: bundle.checkpoint.head} : null,
    valid: summary.mismatch === 0, summary, evaluations,
    limitations: [
      'Each evaluation is recomputed only from signed records that precede it in the ledger; this does not establish that source claims are true.',
      'Ordering is by ledger sequence under the signed checkpoint; without a pinned or witnessed checkpoint, rollback is not excluded.',
      'Evaluations whose input events were later erased under an authorized disposition cannot be re-examined (not_replayable).',
      'Results are compared exactly, messages included; records from another evaluation engine are not_replayable, never silently accepted.',
    ],
  };
}

export function verifyAndReplay(bundle, publicKey, expectedCheckpoint, options = {}) {
  const verification = verifyBundle(bundle, publicKey, expectedCheckpoint, options);
  return {verification, ...replayEvaluations(bundle)};
}
