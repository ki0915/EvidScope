// OTLP GenAI span -> EvidScope event mapping (mapping version otel-genai-map-1).
// Pure and deterministic: identical span metadata always yields the identical raw event (same
// fingerprint), whatever the encoding, so OTLP's at-least-once retries become duplicates. It runs at
// the ingress before authentication and therefore depends on no principal configuration.
// Only allowlisted attribute keys are ever read; content attributes, span names, events, links
// and status messages never enter an event.
import {validateAIObservation} from './ai-observations.mjs';
import {screeningUnavailable} from './content-screening.mjs';
import {decodeTraceRequestProtobuf, OtlpDecodeError} from './otlp-protobuf.mjs';

export {OtlpDecodeError};
export const OTLP_MAPPING_VERSION = 'otel-genai-map-1';
export const OTLP_BATCH_FORMAT = 'evidscope-otlp-batch-v1';
export const OTLP_COLLECTOR_ID = 'evidscope-otlp-receiver';

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
export const RESOURCE_ATTRIBUTE_ALLOWLIST = Object.freeze(['service.name']);
const SPAN_KEYS = new Set(SPAN_ATTRIBUTE_ALLOWLIST), RESOURCE_KEYS = new Set(RESOURCE_ATTRIBUTE_ALLOWLIST);

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

// Keeps int64 precision: integers beyond 2^53 come back as their decimal source text.
const reviver = (key, value, context) => typeof value === 'number' && !Number.isSafeInteger(value) && context && /^-?\d+$/.test(context.source) ? context.source : value;

function jsonScalar(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return undefined;
  if (typeof v.stringValue === 'string') return v.stringValue;
  if (typeof v.boolValue === 'boolean') return v.boolValue;
  if (v.intValue !== undefined) {
    if (typeof v.intValue === 'number' && Number.isSafeInteger(v.intValue)) return String(v.intValue);
    if (typeof v.intValue === 'string' && /^-?\d{1,20}$/.test(v.intValue)) return BigInt.asIntN(64, BigInt(v.intValue)).toString();
    return undefined;
  }
  if (typeof v.doubleValue === 'number') return v.doubleValue;
  return undefined;
}
function jsonValue(v) {
  const values = v?.arrayValue?.values;
  if (Array.isArray(values)) return values.slice(0, 16).map(jsonScalar).filter(x => x !== undefined);
  return jsonScalar(v);
}
function jsonAttributes(list, allow) {
  const out = new Map();
  if (!Array.isArray(list)) return out;
  for (const kv of list) {
    if (!kv || typeof kv.key !== 'string' || !allow.has(kv.key) || out.has(kv.key)) continue;
    out.set(kv.key, jsonValue(kv.value));
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
const nanos = v => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? String(v) : typeof v === 'string' && /^\d{1,20}$/.test(v) ? v : '';
const hexId = v => typeof v === 'string' ? v.toLowerCase() : '';

export function decodeTraceRequestJson(textBody, {maxSpans = DEFAULT_LIMITS.maxSpans} = {}) {
  let parsed;
  try { parsed = JSON.parse(textBody, reviver); } catch { throw new OtlpDecodeError('invalid JSON'); }
  objectOf(parsed, 'ExportTraceServiceRequest');
  const out = {resourceSpans: []};
  let spans = 0;
  for (const rs of arrayOf(parsed.resourceSpans, 'resourceSpans')) {
    objectOf(rs, 'ResourceSpans');
    const resource = rs.resource === undefined ? {} : objectOf(rs.resource, 'Resource');
    const entry = {resource: jsonAttributes(resource.attributes, RESOURCE_KEYS), scopeSpans: []};
    for (const ss of arrayOf(rs.scopeSpans, 'scopeSpans')) {
      objectOf(ss, 'ScopeSpans');
      const scoped = {spans: []};
      for (const s of arrayOf(ss.spans, 'spans')) {
        objectOf(s, 'Span');
        if (++spans > maxSpans) throw new OtlpDecodeError(`more than ${maxSpans} spans in one request`, 413);
        const status = s.status && typeof s.status === 'object' ? s.status : {};
        scoped.spans.push({
          traceId: hexId(s.traceId), spanId: hexId(s.spanId), parentSpanId: hexId(s.parentSpanId),
          kind: Number.isSafeInteger(s.kind) ? s.kind : 0,
          startTimeUnixNano: nanos(s.startTimeUnixNano), endTimeUnixNano: nanos(s.endTimeUnixNano),
          statusCode: status.code === undefined ? 0 : Number.isSafeInteger(status.code) ? status.code : STATUS_CODES.get(status.code) ?? -1,
          attributes: jsonAttributes(s.attributes, SPAN_KEYS),
        });
      }
      entry.scopeSpans.push(scoped);
    }
    out.resourceSpans.push(entry);
  }
  return out;
}

export function decodeTraceRequest(body, format, limits = {}) {
  const maxSpans = limits.maxSpans ?? DEFAULT_LIMITS.maxSpans;
  if (format === 'json') return decodeTraceRequestJson(Buffer.isBuffer(body) ? body.toString('utf8') : String(body), {maxSpans});
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
  const status = span.statusCode === 2 || (errorType !== undefined && errorType !== '') ? 'failure' : span.statusCode === 0 || span.statusCode === 1 ? 'success' : 'unknown';
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
    const output = natural(a.get('gen_ai.usage.output_tokens')) ?? natural(a.get('gen_ai.usage.completion_tokens')) ?? natural(a.get('llm.token_count.completion'));
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

// Maps a decoded request. rejected counts every span that is not stored, including non-GenAI spans.
export function mapTraceRequest(decoded, {now = Date.now()} = {}) {
  const events = [], rejected = {};
  let spans = 0;
  for (const rs of decoded.resourceSpans) for (const ss of rs.scopeSpans) for (const span of ss.spans) {
    spans++;
    const mapped = mapSpan(span, rs.resource, now);
    if (mapped.event) events.push(mapped.event);
    else rejected[mapped.rejected] = (rejected[mapped.rejected] || 0) + 1;
  }
  return {spans, events, rejected};
}

// Vault-side re-validation of OTLP invariants on an already schema-validated event.
const OTEL_ID = /^otel:([0-9a-f]{32}):([0-9a-f]{16})$/;
export function otlpEventInvariant(raw) {
  const match = typeof raw?.id === 'string' && OTEL_ID.exec(raw.id);
  if (!match || raw.traceId !== match[1]) return false;
  if (raw.kind === 'self_report') return raw.actionId === raw.id && raw.aiObservation === undefined;
  if (raw.kind !== 'notice') return false;
  const o = raw.aiObservation;
  return raw.actionId === `otel-trace:${match[1]}` && !!o && o.collector?.kind === 'otlp' && o.span?.traceId === match[1] && o.span?.spanId === match[2];
}

export function rejectionSummary(rejected) {
  const total = Object.values(rejected).reduce((n, v) => n + v, 0);
  if (!total) return {total, message: ''};
  const parts = Object.entries(rejected).sort(([x], [y]) => x.localeCompare(y)).map(([k, v]) => `${k}=${v}`).join(', ');
  const hint = rejected.not_genai ? '; non-GenAI spans are not stored (filter them in the Collector)' : '';
  return {total, message: `${total} span${total === 1 ? '' : 's'} not stored: ${parts}${hint}`};
}
