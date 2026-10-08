// EvidScope verdicts on the traces teams already read (docs/observability-integration.md). An export is checked offline with the
// operator's trust anchor first; only then does an action get `verified`. Everything else is `unverified` or `tampered` with a
// reason code. The mapping carries verdicts, finding codes, ledger positions, a deep link and a receipt locator; never an event
// body, a finding message or any other field a source submitted. Pure functions; scripts/push-verdicts.mjs does the HTTP.
import {createHash} from 'node:crypto';
import {isEncryptedEvent, verifyBundle, verifyCheckpoint} from './crypto.mjs';
import {REGISTRY_TYPES, verifyRegistryHistory} from './agent-registry.mjs';
import {APPROVAL_TYPE, verifyApprovalHistory} from './approvals.mjs';
import {STOP_ORDER_TYPE, verifyExportStopOrders} from './stop-orders.mjs';
import {replayEvaluations} from './policy-replay.mjs';
import {signingKeyId} from './ocsf.mjs';

export const VERDICTS = Object.freeze(['verified', 'unverified', 'tampered']);
export const WITNESS_LEVELS = Object.freeze(['vault_host', 'signing_key_holder', 'database_tamper', 'pinned_checkpoint', 'none']);
export const NAMES = Object.freeze({verified: 'evidscope.verified', findings: 'evidscope.findings', witness: 'evidscope.witness',
  recorded: 'evidscope.recorded'});
export const LIMITS = Object.freeze({spansPerTrace: 100, codes: 5, comment: 1000});
// Reason codes are the only explanation that leaves EvidScope; the local report keeps the verifier's message.
export const REASONS = Object.freeze({
  checkpoint_missing: 'The export has no signed checkpoint',
  checkpoint_signature_invalid: 'The checkpoint signature does not verify with the trusted key (wrong key or forged)',
  ledger_altered: 'Records do not match the signed checkpoint (altered, reordered, truncated or a disclosure changed)',
  rollback_detected: 'The export differs from the pinned checkpoint (possible rollback)',
  transparency_not_verified: 'Required transparency or witness evidence did not verify',
  registry_history_invalid: 'The signed agent registry history is inconsistent',
  approval_history_invalid: 'The signed approval history is inconsistent',
  stop_order_history_invalid: 'The signed stop-order history is inconsistent',
  replay_mismatch: 'Recomputing the signed evaluation from earlier records gives a different result',
  not_evaluated: 'No signed evaluation of this action yet',
  analysis_incomplete: 'The evaluation stopped at a resource limit; no findings is not a clean result',
});
const TAMPERED = new Set(['ledger_altered', 'rollback_detected', 'replay_mismatch']);
const HEX32 = /^[a-f0-9]{32}$/, HEX16 = /^[a-f0-9]{16}$/, ZERO = /^0+$/, CODE = /^[A-Za-z0-9_.:-]{1,100}$/;
// The vault's identifier rule (src/model.mjs): an export that did not verify cannot slip other text out as an action id or tenant.
const isId = v => typeof v === 'string' && /^[a-zA-Z0-9._:@/-]{1,120}$/.test(v);
const otelTrace = v => typeof v === 'string' && HEX32.test(v) && !ZERO.test(v);
const otelSpan = v => typeof v === 'string' && HEX16.test(v) && !ZERO.test(v);
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sha256 = value => createHash('sha256').update(value).digest('hex');
const SEVERITY_ORDER = {high: 0, medium: 1, low: 2};

function chainReason(message) {
  if (message === 'Missing checkpoint') return 'checkpoint_missing';
  if (message === 'Checkpoint signature invalid') return 'checkpoint_signature_invalid';
  if (/^External checkpoint mismatch/.test(message)) return 'rollback_detected';
  return 'ledger_altered';
}
function historyChecks(bundle) {
  const failed = [], has = types => bundle.records.some(row => types.includes(row.type));
  if (has(REGISTRY_TYPES) && !verifyRegistryHistory(bundle.records).valid) failed.push('registry_history_invalid');
  if (has([APPROVAL_TYPE]) && !verifyApprovalHistory(bundle.records).valid) failed.push('approval_history_invalid');
  if (has([STOP_ORDER_TYPE]) && !verifyExportStopOrders(bundle).valid) failed.push('stop_order_history_invalid');
  return failed;
}
function witnessLevel(result) {
  const against = result.transparency?.rollbackCheckedAgainst;
  if (WITNESS_LEVELS.includes(against)) return against;
  return result.rollbackChecked ? 'pinned_checkpoint' : 'none';
}

// Checks one export the way scripts/verify.mjs does (signature, chain, disclosures, opt-in transparency, signed histories,
// replay) and keeps the outcome as reason codes. `bytes` is the export file as read or fetched; its digest is the locator.
// `transparency` is verifier options or a function of the parsed bundle returning them (undefined: legacy behaviour).
export function assessExport(bytes, {publicKey, expectedCheckpoint, transparency, replay = true} = {}) {
  if (!publicKey) throw TypeError('A trusted public key is required');
  const exportSha256 = sha256(bytes);
  let bundle;
  try { bundle = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch { bundle = null; }
  if (!plain(bundle) || !Array.isArray(bundle.records)) return {readable: false, exportSha256, verdict: 'unverified', reasons: ['export_unreadable']};
  const cp = plain(bundle.checkpoint) ? bundle.checkpoint : null, keyId = signingKeyId(publicKey);
  const base = {readable: true, bundle, exportSha256, keyId, tenant: isId(cp?.tenant) ? cp.tenant : null,
    checkpoint: cp && Number.isSafeInteger(cp.count) && /^[a-f0-9]{64}$/.test(cp.head) ? {count: cp.count, head: cp.head} : null, witness: 'none'};
  const fail = (code, message) => ({...base, verdict: TAMPERED.has(code) ? 'tampered' : 'unverified', reasons: [code], messages: [message]});
  try { verifyCheckpoint(cp, publicKey); } catch (error) {
    return fail(error.message === 'Missing checkpoint' ? 'checkpoint_missing' : 'checkpoint_signature_invalid', error.message);
  }
  // Without transparency first: an altered record under a valid signature is tampering whatever the witness policy says.
  try { verifyBundle(bundle, publicKey, expectedCheckpoint); } catch (error) { return fail(chainReason(error.message), error.message); }
  let result;
  try {
    const options = typeof transparency === 'function' ? transparency(bundle) : transparency;
    result = verifyBundle(bundle, publicKey, expectedCheckpoint, options ? {transparency: options} : {});
  } catch (error) {
    return fail('transparency_not_verified', error.message);
  }
  const history = historyChecks(bundle);
  if (history.length) return {...base, verdict: 'unverified', reasons: history, messages: history.map(code => REASONS[code])};
  const replayed = replay ? new Map(replayEvaluations(bundle).evaluations.map(e => [e.seq, e])) : null;
  return {...base, verdict: 'verified', reasons: [], messages: [], witness: witnessLevel(result), replay: replayed, trusted: true};
}

// Disclosed or plaintext events of an export with their ledger rows; erased events have no body and are skipped.
function exportEvents(bundle) {
  const disclosed = new Map((Array.isArray(bundle.disclosures) ? bundle.disclosures : []).filter(plain).map(d => [d.seq, d.event]));
  const events = [];
  for (const row of bundle.records) {
    if (!plain(row) || row.type !== 'event') continue;
    const event = isEncryptedEvent(row.payload) ? disclosed.get(row.seq) : row.payload;
    if (plain(event) && isId(event.actionId)) events.push({event, seq: row.seq, hash: row.hash, recordedAt: row.recordedAt});
  }
  return events;
}
// The OTel identity of an event: OTLP-mapped ids carry trace and span; SDK events may carry a W3C trace id only.
function spanContext(event) {
  const match = typeof event.id === 'string' && /^otel(?:-decision)?:([a-f0-9]{32}):([a-f0-9]{16})$/.exec(event.id);
  if (match) return {traceId: match[1], spanId: match[2]};
  const span = plain(event.aiObservation) && plain(event.aiObservation.span) ? event.aiObservation.span : null;
  const traceId = otelTrace(span?.traceId) ? span.traceId : otelTrace(event.traceId) ? event.traceId : null;
  return traceId ? {traceId, spanId: span && span.traceId === traceId && otelSpan(span.spanId) ? span.spanId : null} : null;
}
const isoMillis = value => { const t = Date.parse(value); return Number.isFinite(t) ? new Date(t).toISOString() : null; };

function findingSummary(evaluation) {
  const findings = Array.isArray(evaluation.findings) ? evaluation.findings.filter(plain) : [];
  const open = findings.filter(f => typeof f.suppressedBy !== 'string');
  const code = f => (typeof f.code === 'string' && CODE.test(f.code) ? f.code : 'INVALID_CODE');
  const ranked = [...open].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3));
  const severities = {high: 0, medium: 0, low: 0};
  for (const f of open) if (Object.hasOwn(severities, f.severity)) severities[f.severity]++;
  const codes = [...new Set(ranked.map(code))];
  return {open: open.length, suppressed: findings.length - open.length, severities, codes: codes.slice(0, LIMITS.codes),
    stopCodes: codes.filter(c => c.startsWith('STOP_')), approvalCodes: codes.filter(c => c.startsWith('APPROVAL_'))};
}
function approvalCounts(bundle) {
  const latest = new Map();
  for (const row of bundle.records)
    if (plain(row) && row.type === APPROVAL_TYPE && plain(row.payload) && typeof row.payload.id === 'string') latest.set(row.payload.id, row.payload);
  const byAction = new Map();
  for (const request of latest.values()) {
    if (typeof request.actionId !== 'string') continue;
    const counts = byAction.get(request.actionId) || {pending: 0, approved: 0, refused: 0};
    if (Object.hasOwn(counts, request.status)) counts[request.status]++;
    byAction.set(request.actionId, counts);
  }
  return byAction;
}
export function deepLink(linkBase, actionId) {
  return linkBase ? `${linkBase}#action=${encodeURIComponent(actionId)}` : null;
}

// One verdict per (action, OTel trace). An export that did not verify still yields negative verdicts for the trace ids it names,
// so a reviewer sees `tampered` where a stale `verified` stood; nothing from it is ever reported as verified.
export function actionVerdicts(assessment, {linkBase = null} = {}) {
  if (!assessment.readable) return [];
  const {bundle} = assessment, trusted = assessment.trusted === true, evaluations = new Map(), groups = new Map();
  for (const row of bundle.records) if (plain(row) && row.type === 'evaluation' && plain(row.payload) && typeof row.payload.actionId === 'string')
    evaluations.set(row.payload.actionId, {payload: row.payload, seq: row.seq, hash: row.hash});
  for (const {event, seq, hash, recordedAt} of exportEvents(bundle)) {
    const context = spanContext(event);
    if (!context) continue;
    const key = `${event.actionId}\0${context.traceId}`;
    if (!groups.has(key))
      groups.set(key, {actionId: event.actionId, traceId: context.traceId, firstRecordedAt: isoMillis(recordedAt), spans: new Map()});
    const group = groups.get(key);
    if (context.spanId && !group.spans.has(context.spanId) && group.spans.size < LIMITS.spansPerTrace) group.spans.set(context.spanId, {seq, hash});
  }
  const approvals = trusted ? approvalCounts(bundle) : new Map(), actionSeqs = new Map();
  for (const {event, seq} of exportEvents(bundle)) {
    if (!actionSeqs.has(event.actionId)) actionSeqs.set(event.actionId, []);
    actionSeqs.get(event.actionId).push(seq);
  }
  return [...groups.values()].map(group => {
    const ledgerRow = evaluations.get(group.actionId), evaluation = ledgerRow?.payload;
    let verdict = assessment.verdict, reasons = [...assessment.reasons], analysis = trusted ? 'not_evaluated' : 'unknown', replay = 'not_run', findings = null;
    if (trusted) {
      const replayed = assessment.replay?.get(ledgerRow?.seq);
      if (replayed) replay = replayed.status === 'not_replayable' ? `not_replayable:${replayed.reason}` : replayed.status;
      if (!evaluation) { verdict = 'unverified'; reasons = ['not_evaluated']; }
      else if (replay === 'mismatch') { verdict = 'tampered'; reasons = ['replay_mismatch']; analysis = 'mismatch'; }
      else if (evaluation.status !== 'evaluated') { verdict = 'unverified'; reasons = ['analysis_incomplete']; analysis = 'incomplete'; }
      else {
        const covered = Array.isArray(evaluation.replay?.inputs?.events) ? new Set(evaluation.replay.inputs.events) : null;
        const later = (actionSeqs.get(group.actionId) || []).some(seq => (covered ? !covered.has(seq) : seq > ledgerRow.seq));
        analysis = later ? 'pending' : 'current';
        findings = findingSummary(evaluation);
      }
    }
    const verified = verdict === 'verified';
    return {
      tenant: assessment.tenant, actionId: group.actionId, traceId: group.traceId, timestamp: group.firstRecordedAt, verdict, reasons,
      witness: verified ? assessment.witness : 'none', analysis, replay,
      ledger: verified && ledgerRow ? {seq: ledgerRow.seq, hash: ledgerRow.hash,
        evaluationVersion: Number.isSafeInteger(evaluation.version) ? evaluation.version : null} : null,
      checkpoint: assessment.checkpoint, findings: verified ? findings : null,
      approvals: verified ? approvals.get(group.actionId) || {pending: 0, approved: 0, refused: 0} : null,
      spans: [...group.spans].map(([spanId, row]) => ({spanId, ...(verified ? {seq: row.seq, hash: row.hash} : {})})),
      link: deepLink(linkBase, group.actionId),
      receipt: {exportSha256: assessment.exportSha256, trustAnchorSha256: assessment.keyId ?? null,
        ...(verified && ledgerRow ? {record: `/api/receipts/record?seq=${ledgerRow.seq}`} : {})},
    };
  });
}

// Stable ids: the same tenant, action, trace, name (and span) always map to the same score or annotation identifier.
export function stableId(...parts) {
  const h = sha256(parts.map(String).join('\0'));
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-8${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
// Only these fields leave EvidScope (allowlist); the canary tests check that nothing a source submitted is among them.
export function verdictMetadata(v) {
  return {evidscope: {format: 'evidscope-verdict-v1', verdict: v.verdict, reasons: v.reasons, tenant: v.tenant, actionId: v.actionId, witness: v.witness,
    analysis: v.analysis, replay: v.replay, ledger: v.ledger, checkpoint: v.checkpoint, findings: v.findings, approvals: v.approvals,
    link: v.link, receipt: v.receipt}};
}
export function verdictText(v) {
  const parts = [`EvidScope ${v.verdict}`];
  if (v.verdict === 'verified') {
    parts.push(`signed evaluation at ledger #${v.ledger?.seq ?? '?'} of ${v.checkpoint?.count ?? '?'} (head ${String(v.checkpoint?.head ?? '').slice(0, 16)})`,
      `witness: ${v.witness}`);
    if (v.findings) parts.push(`open findings ${v.findings.open}${v.findings.codes.length ? ` [${v.findings.codes.join(', ')}]` : ''}`);
    if (v.approvals && v.approvals.pending + v.approvals.approved + v.approvals.refused)
      parts.push(`approvals ${v.approvals.approved} approved, ${v.approvals.refused} refused, ${v.approvals.pending} pending`);
    if (v.analysis === 'pending') parts.push('later evidence not yet evaluated');
  } else parts.push(`not a verified result: ${v.reasons.map(code => REASONS[code] || code).join('; ')}`);
  parts.push(v.link ? `evidence: ${v.link}` : `re-verify: export sha256 ${v.receipt.exportSha256.slice(0, 16)} with scripts/verify.mjs`);
  return parts.join(' · ').slice(0, LIMITS.comment);
}
const findingsText = v => (v.findings ? `open ${v.findings.open} (high ${v.findings.severities.high}, medium ${v.findings.severities.medium}, `
  + `low ${v.findings.severities.low}), suppressed ${v.findings.suppressed}${v.findings.codes.length ? `: ${v.findings.codes.join(', ')}` : ''}`
  : 'unavailable');
const findingsComment = (v, text) => `EvidScope findings ${findingsText(v)} · ${text}`.slice(0, LIMITS.comment);

// Langfuse: score-create events for POST /api/public/ingestion. A score is replaced only when id, name and the date of its
// timestamp all match, so the timestamp is the vault's receipt time of the trace's first event in this action (fixed forever).
// `deletes` lists findings scores to remove when the action is no longer verified (DELETE /api/public/scores/{id}). The envelope
// id, which Langfuse uses to drop repeated deliveries, is added per request when sending.
export function langfuseScores(verdicts, {environment} = {}) {
  const events = [], deletes = [];
  for (const v of verdicts) {
    if (!v.timestamp) continue;
    const metadata = verdictMetadata(v), comment = verdictText(v), env = environment ? {environment} : {};
    const score = (name, value, dataType, extra = {}) => {
      const body = {id: stableId('langfuse', v.tenant, v.actionId, v.traceId, name, extra.observationId ?? ''), traceId: v.traceId, name, value, dataType,
        comment, metadata, ...env, ...extra};
      events.push({timestamp: v.timestamp, type: 'score-create', body});
    };
    score(NAMES.verified, v.verdict, 'CATEGORICAL');
    score(NAMES.witness, v.witness, 'CATEGORICAL');
    if (v.findings) score(NAMES.findings, v.findings.open, 'NUMERIC', {comment: findingsComment(v, comment)});
    else deletes.push(stableId('langfuse', v.tenant, v.actionId, v.traceId, NAMES.findings, ''));
    for (const span of v.spans) score(NAMES.recorded, v.verdict, 'CATEGORICAL', {observationId: span.spanId,
      comment: `${comment.split(' · ')[0]}${span.seq ? ` · span recorded at ledger #${span.seq} (${span.hash.slice(0, 16)})` : ''}`,
      metadata: {evidscope: {...metadata.evidscope, span: span.seq ? {spanId: span.spanId, seq: span.seq, hash: span.hash} : {spanId: span.spanId}}}});
  }
  return {events, deletes};
}

// Phoenix: trace annotations (POST /v1/trace_annotations) and span annotations (POST /v1/span_annotations). Phoenix upserts on
// (name, trace or span, identifier), so the identifier is stable per tenant and action.
export function phoenixAnnotations(verdicts) {
  const traces = [], spans = [];
  for (const v of verdicts) {
    const identifier = `evidscope-${stableId('phoenix', v.tenant, v.actionId)}`, metadata = verdictMetadata(v), explanation = verdictText(v);
    const common = {annotator_kind: 'CODE', identifier, metadata};
    traces.push({...common, trace_id: v.traceId, name: NAMES.verified, result: {label: v.verdict, score: v.verdict === 'verified' ? 1 : 0, explanation}});
    traces.push({...common, trace_id: v.traceId, name: NAMES.witness, result: {label: v.witness, score: null, explanation}});
    traces.push({...common, trace_id: v.traceId, name: NAMES.findings, result: v.findings
      ? {label: v.findings.open ? 'open' : 'none', score: v.findings.open, explanation: findingsComment(v, explanation)}
      : {label: 'unavailable', score: null, explanation}});
    for (const span of v.spans) spans.push({...common, span_id: span.spanId, name: NAMES.recorded, metadata: {evidscope: {...metadata.evidscope,
      span: span.seq ? {spanId: span.spanId, seq: span.seq, hash: span.hash} : {spanId: span.spanId}}},
    result: {label: v.verdict, score: null, explanation: `${explanation.split(' · ')[0]}${span.seq ? ` · span recorded at ledger #${span.seq}` : ''}`
      + `${v.link ? ` · evidence: ${v.link}` : ''}`}});
  }
  return {traces, spans};
}
