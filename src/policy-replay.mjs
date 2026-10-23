// Deterministic offline policy replay (differentiator D2). Re-runs every signed evaluation in an export bundle using
// only ledger records that precede it (seq < evaluation seq) and compares the recomputed findings with the recorded ones.
// Dependency-free: node:crypto via src/crypto.mjs plus the evaluation engine in src/model.mjs.
//
// The prefix state mirrors Store._applyActionStateRow / Store.cachedAnalysisSnapshot: events of the action that were not
// erased before the evaluation, every asset registration in log order, the latest record of each rule (active versions)
// and of each exception. Recorded snapshotHash = digest(snapshot) proves that the reconstruction is the exact input.
// Engine v2 adds the registry input (every agent_registry / agent_registry_policy version) and the related deny decisions of
// other actions; both are present only when the prefix holds them, exactly as in the vault's snapshot. Engine v3 adds the
// action's approval requests (latest version of each, in the order they were opened under the action; src/approvals.mjs).
// Engine v4 adds the stop orders with the first activation per order and covering enforcement point (src/stop-orders.mjs).
// Engine v5 adds the risky steps of the same actor in other actions (src/sequence-rules.mjs). They come from records every engine
// read (intents and tenant rules), so the input is rebuilt only for evaluations that name v5; once a v5 evaluation is in the ledger,
// an earlier engine named for an action with a risky step is a mismatch (the vault builds the input for every such action).
// Engine v7 likewise reads AI coding agent commands without their code markup (agentCommandInput): the input is rebuilt only for
// evaluations that name v7, and once one is in the ledger an earlier engine named for an action with such a command is a mismatch.
// Engine v8 likewise reads agent records imported later from the agent's transcript (historyImportInput): the input is rebuilt only for
// evaluations that name v8 or later, and once one is in the ledger an earlier engine named for an action with such a record is a mismatch.
// Engine v9 likewise reads the LLM security signals of agent content records (contentSignalInput, src/content-rules.mjs): the input is
// rebuilt only for evaluations that name v9, and once one is in the ledger an earlier engine named for an action with such input is a
// mismatch.
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V5, EVALUATION_ENGINE_V6, EVALUATION_ENGINE_V7, EVALUATION_ENGINE_V8, EVALUATION_ENGINE_V9, EVALUATION_ENGINES,
  agentCommandInput, boundedEvaluation, evaluationEngine, historyImportInput, matches as ruleMatches} from './model.mjs';
import {contentSignalInput} from './content-rules.mjs';
import {canonical, digest, isEncryptedEvent, verifyBundle} from './crypto.mjs';
import {REGISTRY_INPUT_TYPES, registryAnalysisInput} from './agent-registry.mjs';
import {relatedDenyInput} from './decision-rules.mjs';
import {relatedStepInput} from './sequence-rules.mjs';
import {STOP_ORDER_TYPE, stopOrderAnalysisInput} from './stop-orders.mjs';
import {APPROVAL_TYPE, approvalAnalysisInput} from './approvals.mjs';

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

// The engines whose snapshots carry the related risky steps of the same actor (src/sequence-rules.mjs).
const STEP_ENGINES = [EVALUATION_ENGINE_V5, EVALUATION_ENGINE_V6, EVALUATION_ENGINE_V7, EVALUATION_ENGINE_V8, EVALUATION_ENGINE_V9];
// The engines whose snapshots carry the AI coding agent commands read without their markup (agentCommandInput).
const COMMAND_ENGINES = [EVALUATION_ENGINE_V7, EVALUATION_ENGINE_V8, EVALUATION_ENGINE_V9];
// The engines whose snapshots carry the agent records imported from transcripts (historyImportInput).
const IMPORT_ENGINES = [EVALUATION_ENGINE_V8, EVALUATION_ENGINE_V9];

function emptyState() {
  return {events: new Map(), byAction: new Map(), unavailable: new Map(), keyEvents: new Map(), assets: new Map(), rules: new Map(),
    exceptions: new Map(), registry: [], registryRows: [], approvals: new Map(), approvalActions: new Map(), stepsSince: undefined,
    replaySince: undefined, commandsSince: undefined, importsSince: undefined, contentSince: undefined};
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
  else if (REGISTRY_INPUT_TYPES.includes(row.type)) state.registry.push({type: row.type, payload});
  else if (row.type === APPROVAL_TYPE && typeof payload.id === 'string' && payload.id) {
    state.approvals.set(payload.id, payload);
    if (typeof payload.actionId === 'string') {
      const ids = state.approvalActions.get(payload.actionId) || [];
      if (!ids.includes(payload.id)) state.approvalActions.set(payload.actionId, [...ids, payload.id]);
    }
  }
  if (row.type === 'evaluation' && STEP_ENGINES.includes(payload.replay?.engine)) state.stepsSince ??= row.seq;
  if (row.type === 'evaluation' && payload.replay) state.replaySince ??= row.seq;
  if (row.type === 'evaluation' && COMMAND_ENGINES.includes(payload.replay?.engine)) state.commandsSince ??= row.seq;
  if (row.type === 'evaluation' && IMPORT_ENGINES.includes(payload.replay?.engine)) state.importsSince ??= row.seq;
  if (row.type === 'evaluation' && payload.replay?.engine === EVALUATION_ENGINE_V9) state.contentSince ??= row.seq;
  if (REGISTRY_INPUT_TYPES.includes(row.type) || row.type === STOP_ORDER_TYPE) {
    state.registryRows.push({seq: row.seq, type: row.type, recordedAt: row.recordedAt, hash: row.hash, payload});
  }
}

// steps: whether the evaluation names engine v5 or later, whose input (relatedSteps) earlier engines never had; commands: whether it
// names v7 or later (agentCommands); imports: whether it names v8 or later (historyImports); contents: whether it names v9
// (contentSignals).
function snapshot(state, actionId, {steps = false, commands = false, imports = false, contents = false} = {}) {
  const events = [...(state.byAction.get(actionId)?.values() || [])];
  const registry = registryAnalysisInput(state.registry), relatedDecisions = relatedDenyInput(events, state.events.values());
  const approvals = approvalAnalysisInput((state.approvalActions.get(actionId) || []).map(id => state.approvals.get(id)));
  const stopOrders = stopOrderAnalysisInput(state.registryRows, state.events.values());
  const rules = [...state.rules.values()].flatMap(rule => (rule.versions || []).filter(version => version.status === 'active'));
  const relatedSteps = steps ? relatedStepInput(events, state.events.values(), rules, ruleMatches) : undefined;
  const agentCommands = commands ? agentCommandInput(events) : undefined;
  const historyImports = imports ? historyImportInput(events) : undefined;
  const contentSignals = contents ? contentSignalInput(events, state.events.values(), rules, ruleMatches) : undefined;
  return {
    events: events.sort(eventOrder),
    assets: [...state.assets.values()],
    rules,
    exceptions: [...state.exceptions.values()],
    ...(registry ? {registry} : {}),
    ...(relatedDecisions ? {relatedDecisions} : {}),
    ...(approvals ? {approvals} : {}),
    ...(stopOrders ? {stopOrders} : {}),
    ...(relatedSteps ? {relatedSteps} : {}),
    ...(agentCommands ? {agentCommands} : {}),
    ...(historyImports ? {historyImports} : {}),
    ...(contentSignals ? {contentSignals} : {}),
  };
}
const EXTRA_INPUTS = ['registry', 'relatedDecisions', 'approvals', 'stopOrders', 'relatedSteps', 'agentCommands', 'historyImports', 'contentSignals'];
const extraBytes = data => (EXTRA_INPUTS.some(name => data[name])
  ? bytes(Object.fromEntries(EXTRA_INPUTS.filter(name => data[name]).map(name => [name, data[name]]))) + 1 : 0);

// Mirrors Store.cachedAnalysisSnapshot resource checks followed by the claim-time size check in src/analysis.mjs.
function quarantineReason(data, limits) {
  const used = 100 + extraBytes(data)
    + [...data.events, ...data.assets, ...data.rules, ...data.exceptions].reduce((total, value) => total + bytes(value) + 1, 0);
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
    exceptions: data.exceptions.length, ...(data.registry ? {registry: {entries: data.registry.entries.length, policies: data.registry.policies.length}} : {}),
    ...(data.relatedDecisions ? {relatedDecisions: data.relatedDecisions.map(d => d.seq)} : {}),
    ...(data.approvals ? {approvals: data.approvals.map(a => ({id: a.id, version: a.version}))} : {}),
    ...(data.stopOrders ? {stopOrders: {orders: data.stopOrders.orders.length, activations: data.stopOrders.activations.map(a => a.seq)}} : {}),
    ...(data.relatedSteps ? {relatedSteps: data.relatedSteps.map(s => s.seq)} : {}),
    ...(data.agentCommands ? {agentCommands: data.agentCommands} : {}),
    ...(data.historyImports ? {historyImports: data.historyImports} : {}),
    ...(data.contentSignals ? {contentSignals: {own: data.contentSignals.own, related: data.contentSignals.related.map(r => r.seq)}} : {}),
    snapshotHash: matches ? 'matches_record' : 'differs_from_record'};
}

function replayOne(state, row, engines) {
  const evaluation = row.payload || {}, recordedEngine = evaluation.replay?.engine;
  const base = {seq: row.seq, id: evaluation.id ?? null, actionId: evaluation.actionId ?? null, version: evaluation.version ?? null,
    evaluationStatus: evaluation.status ?? null, engine: recordedEngine ?? 'unrecorded'};
  const notReplayable = (reason, extra = {}) => ({...base, status: 'not_replayable', reason, ...extra});
  if (typeof evaluation.actionId !== 'string') return notReplayable('invalid_record');
  if (recordedEngine !== undefined && !engines.includes(recordedEngine)) return notReplayable('engine_unavailable');
  const data = snapshot(state, evaluation.actionId, {steps: STEP_ENGINES.includes(recordedEngine), commands: COMMAND_ENGINES.includes(recordedEngine),
    imports: IMPORT_ENGINES.includes(recordedEngine), contents: recordedEngine === EVALUATION_ENGINE_V9});
  const stepsDowngraded = !STEP_ENGINES.includes(recordedEngine) && state.stepsSince !== undefined
    && relatedStepInput(data.events, state.events.values(), data.rules, ruleMatches) !== undefined;
  const commandsDowngraded = !COMMAND_ENGINES.includes(recordedEngine) && state.commandsSince !== undefined
    && agentCommandInput(data.events) !== undefined;
  const importsDowngraded = !IMPORT_ENGINES.includes(recordedEngine) && state.importsSince !== undefined && historyImportInput(data.events) !== undefined;
  const contentDowngraded = recordedEngine !== EVALUATION_ENGINE_V9 && state.contentSince !== undefined
    && contentSignalInput(data.events, state.events.values(), data.rules, ruleMatches) !== undefined;
  const downgrade = stepsDowngraded || commandsDowngraded || importsDowngraded || contentDowngraded ? {engine: {recorded: recordedEngine ?? 'unrecorded',
    replayed: evaluationEngine({...data, ...(stepsDowngraded ? {relatedSteps: []} : {}), ...(commandsDowngraded ? {agentCommands: []} : {}),
      ...(importsDowngraded ? {historyImports: []} : {}), ...(contentDowngraded ? {contentSignals: {own: [], related: []}} : {})})}} : null;
  const hidden = [...state.unavailable.values()].filter(u => u.actionId === null || u.actionId === evaluation.actionId).map(u => u.seq);
  const recordedSeqs = Array.isArray(evaluation.replay?.inputs?.events) ? evaluation.replay.inputs.events : null;
  // Related denies of other actions erased since the evaluation cannot be re-examined either.
  // So are stop-order activation reports, risky steps of other actions and the content records and risky steps of the same session.
  const related = [...(Array.isArray(evaluation.replay?.inputs?.relatedDecisions) ? evaluation.replay.inputs.relatedDecisions : []),
    ...(Array.isArray(evaluation.replay?.inputs?.stopOrders?.activations) ? evaluation.replay.inputs.stopOrders.activations : []),
    ...(Array.isArray(evaluation.replay?.inputs?.relatedSteps) ? evaluation.replay.inputs.relatedSteps : []),
    ...(Array.isArray(evaluation.replay?.inputs?.contentSignals?.related) ? evaluation.replay.inputs.contentSignals.related : [])];
  const erased = [...(recordedSeqs ? recordedSeqs.filter(seq => hidden.includes(seq)) : hidden),
    ...related.filter(seq => Number.isSafeInteger(seq) && !state.events.has(seq) && !hidden.includes(seq))];
  if (evaluation.status === 'quarantined_resource_limit') {
    if (erased.length) return notReplayable('erased_input', {erasedEvents: erased});
    const expected = quarantineReason(data, {...LEGACY_ANALYSIS_LIMITS, ...evaluation.replay?.limits});
    if (expected === evaluation.coverage?.reason && !downgrade) {
      return notReplayable('resource_limit', {quarantineConfirmed: true, coverage: evaluation.coverage});
    }
    const quarantine = expected === evaluation.coverage?.reason ? {} : {quarantine: {recorded: evaluation.coverage?.reason ?? null, replayed: expected}};
    return {...base, status: 'mismatch', diff: {...quarantine, ...downgrade}};
  }
  if (evaluation.status !== 'evaluated') return notReplayable('unknown_status');
  if (typeof evaluation.snapshotHash !== 'string' || !Number.isFinite(Date.parse(evaluation.analysisTime))) {
    return notReplayable('legacy_record_lacks_inputs');
  }
  const matches = digest(data) === evaluation.snapshotHash;
  if (!matches && erased.length) return notReplayable('erased_input', {erasedEvents: erased});
  const limits = {...LEGACY_ANALYSIS_LIMITS, ...evaluation.replay?.limits};
  const replayed = boundedEvaluation({...data, analysisTime: Date.parse(evaluation.analysisTime)}, limits);
  let diff = compare(evaluation, replayed);
  // The engine an evaluation names must be the one its inputs call for (v1 snapshots never name v2, and the reverse).
  const expectedEngine = evaluationEngine(data);
  if (recordedEngine !== undefined && recordedEngine !== expectedEngine) diff = {...diff, engine: {recorded: recordedEngine, replayed: expectedEngine}};
  if (downgrade) diff = {...diff, ...downgrade};
  const order = ordering(data.events);
  const report = {...base, inputs: inputSummary(data, matches), ordering: order,
    approvalRecordedAfterExecution: order.some(o => o.authorityRecordedAfter.some(a => a.kind === 'human_approval'))};
  if (matches) {
    const basis = evaluation.replay ? 'recorded_inputs' : 'snapshot_hash_engine_assumed';
    // A record from before the ledger's first evaluation with replay metadata does not name the code that wrote it, so a difference
    // there can be that older code rather than a rewrite: reported with its diff, not as a mismatch. A record that lacks the metadata
    // after one that has it is not legacy and still fails.
    if (diff && !evaluation.replay && state.replaySince === undefined) return notReplayable('legacy_engine_unrecorded', {inputs: report.inputs, diff});
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
// engine (one identifier) or engines (a list) restricts what is replayed; by default every engine this module implements.
export function replayEvaluations(bundle, {engine, engines = engine ? [engine] : EVALUATION_ENGINES} = {}) {
  if (!bundle || !Array.isArray(bundle.records)) throw TypeError('An export bundle with records is required');
  const disclosures = new Map((bundle.disclosures || []).map(d => [d.seq, d.event]));
  const state = emptyState(), evaluations = [];
  for (const row of bundle.records) {
    if (row.type === 'evaluation') evaluations.push(replayOne(state, row, engines));
    apply(state, row, disclosures);
  }
  const count = status => evaluations.filter(e => e.status === status).length;
  const reasons = {};
  for (const e of evaluations) if (e.status === 'not_replayable') reasons[e.reason] = (reasons[e.reason] || 0) + 1;
  const summary = {evaluations: evaluations.length, replayed: count('replayed'), mismatch: count('mismatch'), notReplayable: count('not_replayable'),
    notReplayableReasons: reasons, approvalRecordedAfterExecution: evaluations.filter(e => e.approvalRecordedAfterExecution).length};
  return {
    format: POLICY_REPLAY_FORMAT, engine: engine ?? EVALUATION_ENGINE, engines: [...engines], tenant: bundle.checkpoint?.tenant ?? null,
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
