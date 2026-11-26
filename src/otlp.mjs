// OTLP GenAI span -> EvidScope event mapping (mapping version otel-genai-map-1).
// Pure and deterministic: identical span metadata always yields the identical raw event (same
// fingerprint), whatever the encoding, so OTLP's at-least-once retries become duplicates. It runs at
// the ingress before authentication and therefore depends on no principal configuration.
// Only allowlisted attribute keys are ever read; content attributes, span names, events, links
// and status messages never enter an event.
import {validateAIObservation} from './ai-observations.mjs';
import {screeningUnavailable} from './content-screening.mjs';
import {canonical, digest} from './crypto.mjs';
import {decodeTraceRequestProtobuf, OtlpDecodeError, structureBudget, structureLimits, NO_ATTRIBUTES} from './otlp-protobuf.mjs';

export {OtlpDecodeError};
export const OTLP_MAPPING_VERSION = 'otel-genai-map-1';
export const OTLP_BATCH_FORMAT = 'evidscope-otlp-batch-v1';
export const OTLP_COLLECTOR_ID = 'evidscope-otlp-receiver';
export const OTLP_DECISION_MAPPING = 'otel-decision-map-1';

// The only span attributes EvidScope decodes (protobuf) or reads (JSON).
export const SPAN_ATTRIBUTE_ALLOWLIST = Object.freeze([
  'gen_ai.operation.name', 'gen_ai.provider.name', 'gen_ai.system',
  'gen_ai.request.model', 'gen_ai.response.model',
  'gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens', 'gen_ai.usage.prompt_tokens', 'gen_ai.usage.completion_tokens',
  'gen_ai.agent.id', 'gen_ai.agent.name', 'gen_ai.tool.name',
  'error.type', 'server.address', 'server.port',
  // OpenInference dialect (Arize Phoenix / OpenInference instrumentations)
  'openinference.span.kind', 'llm.provider', 'llm.system', 'llm.model_name',
  'llm.token_count.prompt', 'llm.token_count.completion', 'embedding.model_name', 'tool.name', 'agent.name',
]);
// Policy-decision spans (docs/agent-registry.md): kube-agentic-networking proposal 0033 `event.action` / `event.outcome` on the
// check span, OTel `security_rule.*` (registry, development) for the policy, `agent.id` as 0033 propagates it, MCP method name.
export const DECISION_ATTRIBUTE_ALLOWLIST = Object.freeze([
  'event.action', 'event.outcome', 'security_rule.name', 'security_rule.ruleset.name', 'security_rule.version', 'mcp.method.name', 'agent.id',
]);
export const RESOURCE_ATTRIBUTE_ALLOWLIST = Object.freeze(['service.name']);
const SPAN_KEYS = new Set([...SPAN_ATTRIBUTE_ALLOWLIST, ...DECISION_ATTRIBUTE_ALLOWLIST]), RESOURCE_KEYS = new Set(RESOURCE_ATTRIBUTE_ALLOWLIST);

// Known content-bearing keys (GenAI semconv opt-in content, deprecated and vendor dialects). Not used
// for filtering (the allowlist is authoritative); kept for tests and the Collector configuration.
export const CONTENT_ATTRIBUTE_KEYS = Object.freeze([
  'gen_ai.input.messages', 'gen_ai.output.messages', 'gen_ai.system_instructions', 'gen_ai.tool.definitions',
  'gen_ai.tool.call.arguments', 'gen_ai.tool.call.result', 'gen_ai.retrieval.query.text', 'gen_ai.retrieval.documents',
  'gen_ai.memory.query.text', 'gen_ai.memory.records', 'gen_ai.evaluation.explanation', 'gen_ai.prompt', 'gen_ai.completion',
  'gen_ai.tool.description', 'gen_ai.agent.description', 'mcp.resource.uri',
]);

export const DEFAULT_LIMITS = Object.freeze({maxSpans: 8192});

const MODEL_OPERATIONS = new Set(['chat', 'text_completion', 'generate_content', 'embeddings']);
const AGENT_OPERATIONS = new Set(['invoke_agent', 'create_agent']);
const KNOWN_OPERATIONS = new Set([...MODEL_OPERATIONS, ...AGENT_OPERATIONS, 'execute_tool', 'retrieval', 'fetch_response', 'invoke_workflow', 'plan',
  'search_memory', 'create_memory', 'update_memory', 'upsert_memory', 'delete_memory', 'create_memory_store', 'delete_memory_store']);
const OPENINFERENCE_KINDS = new Map([['LLM', 'chat'], ['EMBEDDING', 'embeddings'], ['TOOL', 'execute_tool'], ['AGENT', 'invoke_agent']]);
// gen_ai.provider.name (current), deprecated gen_ai.system values, and OpenInference llm.provider/llm.system values.
const PROVIDERS = new Map(Object.entries({
  openai: 'openai', anthropic: 'anthropic',
  'aws.bedrock': 'aws', aws: 'aws', amazon: 'aws',
  'azure.ai.openai': 'azure', 'azure.ai.inference': 'azure', 'az.ai.openai': 'azure', 'az.ai.inference': 'azure', azure: 'azure',
  'gcp.gemini': 'google', 'gcp.vertex_ai': 'google', 'gcp.gen_ai': 'google', gemini: 'google', vertex_ai: 'google', vertexai: 'google', google: 'google',
  ollama: 'ollama', vllm: 'vllm', 'llama.cpp': 'llama.cpp', huggingface: 'huggingface',
}));
const STATUS_CODES = new Map([['STATUS_CODE_UNSET', 0], ['STATUS_CODE_OK', 1], ['STATUS_CODE_ERROR', 2]]);

const HEX32 = /^[0-9a-f]{32}$/, HEX16 = /^[0-9a-f]{16}$/, ZERO = /^0+$/;
const ID = /^[A-Za-z0-9._:@/-]{1,120}$/, OBSERVATION_ID = /^[A-Za-z0-9._:@/-]{1,128}$/;
const UNSAFE_TEXT = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f‪-‮⁦-⁩]/u;
const text = (v, max = 256) => typeof v === 'string' && v.length > 0 && v.length <= max && !UNSAFE_TEXT.test(v) ? v : undefined;
const id = v => typeof v === 'string' && ID.test(v) ? v : undefined;
const natural = v => {
  if (typeof v === 'string' && /^\d{1,15}$/.test(v)) v = Number(v);
  return Number.isSafeInteger(v) && v >= 0 ? v : undefined;
};
function host(v) {
  if (typeof v !== 'string' || v.length > 253) return undefined;
  if (/^[0-9a-fA-F:]+$/.test(v) && v.includes(':')) v = `[${v}]`;
  return /^([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$/.test(v) ? v.toLowerCase() : undefined;
}

// ---- OTLP/JSON -> internal shape -------------------------------------------------------------

// OTLP/JSON encodes int64 as decimal strings (the Collector and the JS SDK do). A JSON number is accepted too; beyond 2^53
// it is the nearest double, so only such non-conforming producers can see a timestamp off by a few hundred nanoseconds.
const int64 = (v, signed) => {
  const n = typeof v === 'string' ? (/^-?\d{1,20}$/.test(v) ? BigInt(v) : undefined) : Number.isInteger(v) ? BigInt(v) : undefined;
  if (n === undefined || (!signed && (n < 0n || n >= 2n ** 64n))) return undefined;
  return (signed ? BigInt.asIntN(64, n) : n).toString();
};

function jsonScalar(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return undefined;
  if (typeof v.stringValue === 'string') return v.stringValue;
  if (typeof v.boolValue === 'boolean') return v.boolValue;
  if (v.intValue !== undefined) return int64(v.intValue, true);
  if (typeof v.doubleValue === 'number') return v.doubleValue;
  return undefined;
}
function jsonValue(v, charge) {
  const values = v?.arrayValue?.values;
  if (!Array.isArray(values)) return jsonScalar(v);
  const items = values.slice(0, 16);
  for (let i = 0; i < items.length; i++) charge('values');
  return items.map(jsonScalar).filter(x => x !== undefined);
}
function jsonAttributes(list, allow, charge) {
  let out = NO_ATTRIBUTES;
  if (!Array.isArray(list)) return out;
  for (const kv of list) {
    charge('values');
    if (!kv || typeof kv.key !== 'string' || !allow.has(kv.key) || out.has(kv.key)) continue;
    if (out === NO_ATTRIBUTES) out = new Map();
    out.set(kv.key, jsonValue(kv.value, charge));
  }
  return out;
}
const arrayOf = (v, name) => {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new OtlpDecodeError(`${name} must be an array`);
  return v;
};
const objectOf = (v, name) => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new OtlpDecodeError(`${name} must be an object`);
  return v;
};
const nanos = v => typeof v === 'string' && /^\d{1,20}$/.test(v) ? v : int64(v, false) ?? '';
const hexId = v => typeof v === 'string' ? v.toLowerCase() : '';

// Counts objects, arrays and value separators outside strings before JSON.parse materializes anything: 8 MiB of `{},`
// would otherwise parse into ~180 MB of objects. UTF-8 continuation bytes never equal these ASCII bytes.
function assertJsonShape(bytes, maxSpans) {
  const limit = structureLimits(maxSpans).values;
  let nodes = 0, tokens = 0, inString = false;
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (inString) { if (c === 0x5c) i++; else if (c === 0x22) inString = false; }
    else if (c === 0x22) inString = true;
    else if (c === 0x7b || c === 0x5b) { nodes++; tokens++; }
    else if (c === 0x2c) tokens++;
  }
  if (nodes > limit || tokens > 2 * limit) throw new OtlpDecodeError(`more than ${limit} JSON objects or ${2 * limit} JSON values in one request`, 413);
}

export function decodeTraceRequestJson(body, {maxSpans = DEFAULT_LIMITS.maxSpans} = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  assertJsonShape(bytes, maxSpans);
  let parsed;
  try { parsed = JSON.parse(bytes.toString('utf8')); } catch { throw new OtlpDecodeError('invalid JSON'); }
  objectOf(parsed, 'ExportTraceServiceRequest');
  const out = {resourceSpans: []}, charge = structureBudget(maxSpans);
  for (const rs of arrayOf(parsed.resourceSpans, 'resourceSpans')) {
    objectOf(rs, 'ResourceSpans');
    charge('containers');
    const resource = rs.resource === undefined ? {} : objectOf(rs.resource, 'Resource');
    let scopeSpans = null;
    for (const ss of arrayOf(rs.scopeSpans, 'scopeSpans')) {
      objectOf(ss, 'ScopeSpans');
      charge('containers');
      let spans = null;
      for (const s of arrayOf(ss.spans, 'spans')) {
        objectOf(s, 'Span');
        charge('spans');
        const status = s.status && typeof s.status === 'object' ? s.status : {};
        (spans ||= []).push({
          traceId: hexId(s.traceId), spanId: hexId(s.spanId), parentSpanId: hexId(s.parentSpanId),
          kind: Number.isSafeInteger(s.kind) ? s.kind : 0,
          startTimeUnixNano: nanos(s.startTimeUnixNano), endTimeUnixNano: nanos(s.endTimeUnixNano),
          statusCode: status.code === undefined ? 0 : Number.isSafeInteger(status.code) ? status.code : STATUS_CODES.get(status.code) ?? -1,
          attributes: jsonAttributes(s.attributes, SPAN_KEYS, charge),
        });
      }
      if (spans) (scopeSpans ||= []).push({spans});
    }
    if (scopeSpans) out.resourceSpans.push({resource: jsonAttributes(resource.attributes, RESOURCE_KEYS, charge), scopeSpans});
  }
  return out;
}

export function decodeTraceRequest(body, format, limits = {}) {
  const maxSpans = limits.maxSpans ?? DEFAULT_LIMITS.maxSpans;
  if (format === 'json') return decodeTraceRequestJson(body, {maxSpans});
  if (format === 'protobuf') return decodeTraceRequestProtobuf(body, {spanKeys: SPAN_KEYS, resourceKeys: RESOURCE_KEYS, maxSpans});
  throw new OtlpDecodeError('unsupported encoding', 415);
}

// ---- span -> event ---------------------------------------------------------------------------

function occurredAt(value) {
  if (typeof value !== 'string' || !/^\d{1,20}$/.test(value)) return undefined;
  const ms = BigInt(value) / 1000000n;
  if (ms <= 0n || ms > 8640000000000000n) return undefined;
  return new Date(Number(ms)).toISOString();
}
function provider(raw) {
  if (raw === undefined) return 'unknown';
  if (typeof raw !== 'string' || !raw) return 'other';
  return PROVIDERS.get(raw.toLowerCase()) ?? 'other';
}
// service.name is self-declared. The otel-service: namespace keeps it from matching ordinary asset ids; a
// reviewer who registers asset id otel-service:<name> accepts that name as reported by this tenant's OTLP sources.
function assetRef(serviceName) {
  const candidate = serviceName === undefined ? undefined : `otel-service:${serviceName}`;
  return candidate && OBSERVATION_ID.test(candidate) ? candidate : 'unregistered';
}

// Returns {event} or {rejected: reason}. Never throws for span-level problems.
export function mapSpan(span, resource, now = Date.now()) {
  const traceId = span.traceId, spanId = span.spanId, parent = span.parentSpanId;
  if (!HEX32.test(traceId) || ZERO.test(traceId) || !HEX16.test(spanId) || ZERO.test(spanId)) return {rejected: 'invalid_span_context'};
  const a = span.attributes;
  let operation = a.get('gen_ai.operation.name');
  if (typeof operation !== 'string' || !operation) {
    const kind = a.get('openinference.span.kind');
    if (typeof kind !== 'string') return {rejected: 'not_genai'};
    operation = OPENINFERENCE_KINDS.get(kind.toUpperCase());
    if (!operation) return {rejected: 'unsupported_operation'};
  }
  const at = occurredAt(span.startTimeUnixNano);
  if (!at) return {rejected: 'invalid_time'};
  if (Date.parse(at) > now + 300000) return {rejected: 'future_time'};

  const serviceName = text(resource.get('service.name'), 200);
  const errorType = a.get('error.type');
  const failed = span.statusCode === 2 || (errorType !== undefined && errorType !== '');
  const status = failed ? 'failure' : span.statusCode === 0 || span.statusCode === 1 ? 'success' : 'unknown';
  const agentName = text(a.get('gen_ai.agent.name')) ?? text(a.get('agent.name'));
  const actor = agentName ?? id(a.get('gen_ai.agent.id')) ?? (serviceName ? `service:${serviceName}` : 'unknown');
  const modelName = a.get('gen_ai.response.model') ?? a.get('gen_ai.request.model') ?? a.get('llm.model_name') ?? a.get('embedding.model_name');
  const base = {id: `otel:${traceId}:${spanId}`, occurredAt: at, traceId, status, actor, clockUncertaintyMs: 'unknown'};

  if (operation === 'execute_tool') {
    const tool = text(a.get('gen_ai.tool.name')) ?? text(a.get('tool.name'));
    return {event: {...base, kind: 'self_report', actionId: base.id, action: 'execute_tool', ...(tool ? {tool, resource: tool} : {})}};
  }
  if (AGENT_OPERATIONS.has(operation)) {
    // invoke_agent usage is an aggregate of its child model calls: no aiObservation, no token counts.
    const target = id(a.get('gen_ai.agent.id')) ?? agentName, model = text(modelName);
    return {event: {...base, kind: 'self_report', actionId: base.id, action: operation, ...(target ? {resource: target} : {}), ...(model ? {model} : {})}};
  }
  const providerRaw = a.get('gen_ai.provider.name') ?? a.get('gen_ai.system') ?? a.get('llm.provider') ?? a.get('llm.system');
  const modelCall = MODEL_OPERATIONS.has(operation);
  if (!modelCall && providerRaw === undefined && modelName === undefined) return {rejected: 'unsupported_operation'};

  const observation = {
    version: 2, assetRef: assetRef(serviceName),
    collector: {kind: 'otlp', id: OTLP_COLLECTOR_ID, version: OTLP_MAPPING_VERSION},
    provider: provider(providerRaw),
    model: typeof modelName === 'string' && OBSERVATION_ID.test(modelName) ? modelName : 'unknown',
    correlation: {method: 'trace', confidence: 'exact'},
    coverage: {mode: 'metadata', status: 'observed', reason: 'metadata_only'},
    span: {traceId, spanId, ...(HEX16.test(parent) && !ZERO.test(parent) ? {parentSpanId: parent} : {})},
    screening: screeningUnavailable(), signals: [], timeBasis: 'source_observed',
  };
  if (modelCall) {
    // Aggregating operations (workflows, retrieval, memory) may roll up child usage; count tokens on model calls only.
    const usage = {};
    const input = natural(a.get('gen_ai.usage.input_tokens')) ?? natural(a.get('gen_ai.usage.prompt_tokens')) ?? natural(a.get('llm.token_count.prompt'));
    const output = natural(a.get('gen_ai.usage.output_tokens')) ?? natural(a.get('gen_ai.usage.completion_tokens'))
      ?? natural(a.get('llm.token_count.completion'));
    if (input !== undefined) usage.inputTokens = input;
    if (output !== undefined) usage.outputTokens = output;
    if (Object.keys(usage).length) observation.usage = usage;
  }
  const destinationHost = host(a.get('server.address')), port = natural(a.get('server.port'));
  if (destinationHost || (port !== undefined && port <= 65535)) {
    observation.network = {...(destinationHost ? {destinationHost} : {}), ...(port !== undefined && port <= 65535 ? {destinationPort: port} : {})};
  }
  let aiObservation;
  try { aiObservation = validateAIObservation(observation); } catch { return {rejected: 'invalid_metadata'}; }
  const model = text(modelName);
  return {event: {
    ...base, kind: 'notice', actionId: `otel-trace:${traceId}`, tool: 'otel-genai', action: KNOWN_OPERATIONS.has(operation) ? operation : 'other',
    ...(model ? {model} : {}), ...(destinationHost ? {destination: destinationHost} : {}), aiObservation,
  }};
}

// ---- decision span -> policy_decision candidate -----------------------------------------------

const SPAN_DECISIONS = new Set(['allow', 'deny']), OUTCOMES = new Set(['success', 'failure', 'unknown']);
const MAX_LATENCY_MS = 3600000;
// A span carrying `event.action` is a decision span. Returns undefined for any other span, else {decision} or {rejected}.
// The candidate is not a record yet: the vault accepts it only from an enforcement source that opted in, and adds the
// enforcement point, engine and clock bound from that credential's configuration (src/otlp-ingest.mjs).
export function mapDecisionSpan(span, now = Date.now()) {
  const a = span.attributes, value = a.get('event.action');
  if (value === undefined) return undefined;
  const traceId = span.traceId, spanId = span.spanId;
  if (!HEX32.test(traceId) || ZERO.test(traceId) || !HEX16.test(spanId) || ZERO.test(spanId)) return {rejected: 'invalid_span_context'};
  if (typeof value !== 'string' || !SPAN_DECISIONS.has(value)) return {rejected: 'unsupported_decision'};
  // 0033 per-rule spans (security_rule.name) attribute the outcome of their parent check span, which carries the same
  // event.action; storing both would count one decision twice.
  if (a.get('security_rule.name') !== undefined) return {rejected: 'decision_rule_span'};
  // The decision exists when the check span ends; its start is used only when the end is missing or earlier.
  const start = occurredAt(span.startTimeUnixNano);
  if (!start) return {rejected: 'invalid_time'};
  const ended = occurredAt(span.endTimeUnixNano) && BigInt(span.endTimeUnixNano) >= BigInt(span.startTimeUnixNano);
  const at = ended ? occurredAt(span.endTimeUnixNano) : start, nanos = ended ? BigInt(span.endTimeUnixNano) - BigInt(span.startTimeUnixNano) : undefined;
  if (Date.parse(at) > now + 300000) return {rejected: 'future_time'};
  const actor = text(a.get('gen_ai.agent.name')) ?? text(a.get('agent.name')) ?? id(a.get('gen_ai.agent.id')) ?? id(a.get('agent.id'));
  const tool = text(a.get('gen_ai.tool.name')) ?? text(a.get('tool.name'));
  // With a tool named, the MCP method (tools/call) is not the action of the tool record and would never match it.
  const action = tool ? undefined : text(a.get('mcp.method.name'));
  if (!actor || (!tool && !action)) return {rejected: 'decision_target_missing'};
  const outcome = a.get('event.outcome'), ruleset = text(a.get('security_rule.ruleset.name')), version = text(a.get('security_rule.version'));
  return {decision: {
    id: `otel-decision:${traceId}:${spanId}`, kind: 'policy_decision', occurredAt: at, traceId, actionId: `otel-trace:${traceId}`, actor,
    ...(tool ? {tool} : {action}), decision: value, decisionId: `otel:${traceId}:${spanId}`,
    ...(OUTCOMES.has(outcome) ? {status: outcome} : {}),
    ...(ruleset ? {policyId: ID.test(ruleset) ? ruleset : `otel-ruleset:${digest(ruleset).slice(0, 32)}`} : {}),
    ...(version ? {policyVersion: version} : {}),
    ...(nanos !== undefined ? {latencyMs: Math.min(MAX_LATENCY_MS, Number(nanos / 1000000n))} : {}),
  }};
}

// Maps a decoded request. rejected counts every span that is not stored, including non-GenAI spans. A decision span is
// forwarded as a candidate; `companion` marks one whose span also became a GenAI event, so the vault counts that span once
// whichever of the two the credential may store.
export function mapTraceRequest(decoded, {now = Date.now()} = {}) {
  const events = [], decisions = [], rejected = {};
  let spans = 0;
  for (const rs of decoded.resourceSpans) for (const ss of rs.scopeSpans) for (const span of ss.spans) {
    spans++;
    const mapped = mapSpan(span, rs.resource, now), decision = mapDecisionSpan(span, now);
    if (mapped.event) { events.push(mapped.event); if (decision?.decision) decisions.push({...decision.decision, companion: true}); }
    else if (decision?.decision) decisions.push(decision.decision);
    else { const reason = decision?.rejected ?? mapped.rejected; rejected[reason] = (rejected[reason] || 0) + 1; }
  }
  return {spans, events, decisions, rejected};
}

// Vault-side re-validation. An OTLP principal can POST /api/ingest/otlp itself (MODE=vault serves it on the public
// listener), so every event must have exactly the shape mapSpan emits: no free-text fields such as note, purpose or
// dataRefs, and an aiObservation that claims nothing the receiver does not do (metadata only, no content screening).
const OTEL_ID = /^otel:([0-9a-f]{32}):([0-9a-f]{16})$/;
const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const EVENT_KEYS = ['id', 'occurredAt', 'traceId', 'status', 'actor', 'clockUncertaintyMs', 'kind', 'actionId', 'action', 'tool', 'resource', 'model',
  'destination', 'aiObservation'];
const OBSERVATION_KEYS = ['version', 'assetRef', 'collector', 'provider', 'model', 'correlation', 'coverage', 'span', 'screening', 'signals', 'timeBasis',
  'usage', 'network'];
const NOTICE_ACTIONS = new Set([...KNOWN_OPERATIONS, 'other'].filter(a => a !== 'execute_tool' && !AGENT_OPERATIONS.has(a)));
const PROVIDER_VALUES = new Set([...PROVIDERS.values(), 'other', 'unknown']);
const plain = (v, keys) => !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).every(k => keys.includes(k));
const same = (v, expected) => plain(v, Object.keys(expected)) && canonical(v) === canonical(expected);
const optional = (v, check) => v === undefined || check(v);
const counter = v => Number.isSafeInteger(v) && v >= 0;

function observationInvariant(o, event, traceId, spanId) {
  if (!plain(o, OBSERVATION_KEYS) || o.version !== 2 || o.timeBasis !== 'source_observed' || !PROVIDER_VALUES.has(o.provider)) return false;
  if (!same(o.collector, {kind: 'otlp', id: OTLP_COLLECTOR_ID, version: OTLP_MAPPING_VERSION}) || !same(o.correlation, {method: 'trace', confidence: 'exact'})
    || !same(o.coverage, {mode: 'metadata', status: 'observed', reason: 'metadata_only'}) || !same(o.screening, screeningUnavailable())) return false;
  if (!Array.isArray(o.signals) || o.signals.length !== 0) return false;
  if (o.model !== 'unknown' && !(typeof o.model === 'string' && OBSERVATION_ID.test(o.model))) return false;
  if (o.assetRef !== 'unregistered' && !(typeof o.assetRef === 'string' && /^otel-service:/.test(o.assetRef) && OBSERVATION_ID.test(o.assetRef))) return false;
  const parent = o.span?.parentSpanId;
  if (!plain(o.span, ['traceId', 'spanId', 'parentSpanId']) || o.span.traceId !== traceId || o.span.spanId !== spanId
    || !optional(parent, v => typeof v === 'string' && HEX16.test(v) && !ZERO.test(v))) return false;
  const usage = o.usage, network = o.network;
  if (!optional(usage, u => MODEL_OPERATIONS.has(event.action) && plain(u, ['inputTokens', 'outputTokens']) && Object.keys(u).length > 0
    && optional(u.inputTokens, counter) && optional(u.outputTokens, counter))) return false;
  if (!optional(network, n => plain(n, ['destinationHost', 'destinationPort']) && Object.keys(n).length > 0
    && optional(n.destinationHost, h => host(h) === h) && optional(n.destinationPort, p => counter(p) && p <= 65535))) return false;
  return event.destination === network?.destinationHost;
}

export function otlpEventInvariant(raw) {
  const match = typeof raw?.id === 'string' && OTEL_ID.exec(raw.id);
  if (!match || !plain(raw, EVENT_KEYS) || raw.traceId !== match[1] || raw.clockUncertaintyMs !== 'unknown') return false;
  if (!['success', 'failure', 'unknown'].includes(raw.status) || text(raw.actor) !== raw.actor) return false;
  if (typeof raw.occurredAt !== 'string' || !ISO_MS.test(raw.occurredAt) || new Date(raw.occurredAt).toISOString() !== raw.occurredAt) return false;
  if (!optional(raw.model, v => text(v) === v)) return false;
  if (raw.kind === 'self_report') {
    if (raw.actionId !== raw.id || raw.aiObservation !== undefined || raw.destination !== undefined) return false;
    if (raw.action === 'execute_tool') return raw.model === undefined && raw.tool === raw.resource && optional(raw.tool, v => text(v) === v);
    return AGENT_OPERATIONS.has(raw.action) && raw.tool === undefined && optional(raw.resource, v => text(v) === v);
  }
  if (raw.kind !== 'notice' || raw.actionId !== `otel-trace:${match[1]}` || raw.tool !== 'otel-genai' || raw.resource !== undefined) return false;
  return NOTICE_ACTIONS.has(raw.action) && observationInvariant(raw.aiObservation, raw, match[1], match[2]);
}

// Vault-side shape of a decision candidate: exactly what mapDecisionSpan emits (plus the companion flag), nothing else.
const DECISION_ID = /^otel-decision:([0-9a-f]{32}):([0-9a-f]{16})$/;
const DECISION_KEYS = ['id', 'kind', 'occurredAt', 'traceId', 'actionId', 'actor', 'tool', 'action', 'decision', 'decisionId', 'status', 'policyId',
  'policyVersion', 'latencyMs', 'companion'];
export function otlpDecisionInvariant(raw) {
  const match = typeof raw?.id === 'string' && DECISION_ID.exec(raw.id);
  if (!match || !plain(raw, DECISION_KEYS) || raw.kind !== 'policy_decision' || raw.traceId !== match[1]) return false;
  if (raw.actionId !== `otel-trace:${match[1]}` || raw.decisionId !== `otel:${match[1]}:${match[2]}` || !SPAN_DECISIONS.has(raw.decision)) return false;
  if (typeof raw.occurredAt !== 'string' || !ISO_MS.test(raw.occurredAt) || new Date(raw.occurredAt).toISOString() !== raw.occurredAt) return false;
  if (text(raw.actor) !== raw.actor || (raw.tool === undefined) === (raw.action === undefined)) return false;
  if (!optional(raw.tool, v => text(v) === v) || !optional(raw.action, v => text(v) === v)) return false;
  if (!optional(raw.status, v => OUTCOMES.has(v)) || !optional(raw.policyId, v => ID.test(v)) || !optional(raw.policyVersion, v => text(v) === v)) return false;
  return optional(raw.latencyMs, v => counter(v) && v <= MAX_LATENCY_MS) && optional(raw.companion, v => v === true);
}

export function rejectionSummary(rejected) {
  const total = Object.values(rejected).reduce((n, v) => n + v, 0);
  if (!total) return {total, message: ''};
  const parts = Object.entries(rejected).sort(([x], [y]) => x.localeCompare(y)).map(([k, v]) => `${k}=${v}`).join(', ');
  const hint = rejected.not_genai ? '; non-GenAI spans are not stored (filter them in the Collector)' : '';
  return {total, message: `${total} span${total === 1 ? '' : 's'} not stored: ${parts}${hint}`};
}
