import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import zlib from 'node:zlib';
import {decodeTraceRequest, mapTraceRequest, mapSpan, otlpEventInvariant, rejectionSummary, SPAN_ATTRIBUTE_ALLOWLIST, CONTENT_ATTRIBUTE_KEYS,
  OtlpDecodeError} from '../src/otlp.mjs';
import {encodeExportTraceServiceResponse, encodeStatus, structureLimits} from '../src/otlp-protobuf.mjs';
import {validateEvent} from '../src/model.mjs';

const fixture = name => readFileSync(new URL(`./fixtures/otlp/${name}`, import.meta.url));
const NOW = Date.parse('2026-10-06T16:00:00Z');
const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
const map = (body, format) => mapTraceRequest(decodeTraceRequest(body, format), {now: NOW});
const otlpPrincipal = {id: 'alpha-otlp', tenant: 'alpha', role: 'source', kind: 'otlp', token: 'x'.repeat(43)};

// Minimal protobuf writer for crafting hostile or edge-case inputs.
const varint = n => { const out = []; let v = BigInt(n); do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; out.push(b); } while (v);
  return Buffer.from(out); };
const tag = (field, wire) => varint((field << 3) | wire);
const ld = (field, payload) => { const b = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  return Buffer.concat([tag(field, 2), varint(b.length), b]); };
const vi = (field, n) => Buffer.concat([tag(field, 0), varint(n)]);
const f64 = (field, n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return Buffer.concat([tag(field, 1), b]); };
const cat = (...parts) => Buffer.concat(parts);
const kv = (key, value) => ld(9, cat(ld(1, key), ld(2, value)));
const sv = s => ld(1, s);
const spanPb = ({trace = TRACE, span = '00f067aa0ba902b9', start = 1791297000000000000n, attrs = [], extra = []} = {}) =>
  ld(2, cat(ld(1, Buffer.from(trace, 'hex')), ld(2, Buffer.from(span, 'hex')), f64(7, start), ...attrs, ...extra));
const requestPb = (...spans) => ld(1, cat(ld(1, ld(1, cat(ld(1, 'service.name'), ld(2, sv('svc'))))), ld(2, cat(...spans))));
const jsonSpan = (attributes, extra = {}) => ({traceId: TRACE, spanId: '00f067aa0ba902c1', startTimeUnixNano: '1791297000000000000',
  attributes: Object.entries(attributes).map(([key, value]) => ({key, value: typeof value === 'number' ? {intValue: value} : {stringValue: value}})),
    ...extra});
const jsonRequest = (...spans) => JSON.stringify({resourceSpans: [{resource: {attributes: [{key: 'service.name', value: {stringValue: 'svc'}}]},
  scopeSpans: [{spans}]}]});

test('every captured producer and encoding maps to byte-identical events', () => {
  const encodings = [
    ['sdk-genai.json', 'json', x => x], ['collector-genai.json', 'json', x => x],
    ['sdk-genai.pb', 'protobuf', x => x], ['collector-genai.pb', 'protobuf', x => x],
    ['sdk-genai.pb.gz', 'protobuf', zlib.gunzipSync], ['collector-genai.pb.zst', 'protobuf', zlib.zstdDecompressSync],
      ['collector-genai.pb.deflate', 'protobuf', zlib.inflateSync],
  ];
  const reference = map(fixture('sdk-genai.json'), 'json');
  assert.equal(reference.spans, 4); assert.equal(reference.events.length, 4); assert.deepEqual(reference.rejected, {});
  for (const [name, format, decode] of encodings) assert.deepEqual(map(decode(fixture(name)), format).events, reference.events, name);
  // Same canonical raw event => same fingerprint regardless of JSON/protobuf or producer.
  const fingerprints = encodings.map(([name, format, decode]) => map(decode(fixture(name)), format).events.map(
    e => validateEvent(e, otlpPrincipal).fingerprint).join());
  assert.equal(new Set(fingerprints).size, 1);
});

test('GenAI semantics: UNSET is success, ERROR fails, invoke_agent carries no tokens, ids are span-derived', () => {
  const byId = new Map(map(fixture('collector-genai.pb'), 'protobuf').events.map(e => [e.id.slice(-2), e]));
  const [agent, chat1, tool, chat2] = ['b1', 'b2', 'b3', 'b4'].map(k => byId.get(k));
  assert.equal(chat1.id, `otel:${TRACE}:00f067aa0ba902b2`); assert.equal(chat1.traceId, TRACE); assert.equal(chat1.actionId, `otel-trace:${TRACE}`);
  assert.equal(chat1.kind, 'notice'); assert.equal(chat1.status, 'success'); assert.equal(chat1.model, 'gpt-4o-2024-08-06');
  assert.equal(chat1.destination, 'api.openai.com');
  assert.deepEqual(chat1.aiObservation.usage, {inputTokens: 97, outputTokens: 52}); assert.equal(chat1.aiObservation.provider, 'openai');
  assert.equal(chat1.aiObservation.assetRef, 'otel-service:travel-agent'); assert.equal(chat1.aiObservation.span.parentSpanId, '00f067aa0ba902b1');
  assert.equal(chat1.actor, 'service:travel-agent');
  assert.equal(tool.kind, 'self_report'); assert.equal(tool.status, 'failure'); assert.equal(tool.tool, 'get_weather');
  assert.equal(tool.resource, 'get_weather'); assert.equal(tool.actor, 'travel-planner');
  assert.equal(tool.actionId, tool.id); assert.equal(tool.aiObservation, undefined);
  assert.equal(agent.kind, 'self_report'); assert.equal(agent.action, 'invoke_agent'); assert.equal(agent.status, 'success');
  assert.equal(agent.aiObservation, undefined);
  assert.equal(agent.resource, 'asst_5j66UpCpwteGg4YSxUnt7lPY'); assert.equal(agent.actor, 'travel-planner'); assert.equal(agent.model, 'gpt-4o');
  const tokens = [...byId.values()].reduce((n, e) => n + (e.aiObservation?.usage?.inputTokens || 0) + (e.aiObservation?.usage?.outputTokens || 0), 0);
  assert.equal(tokens, 97 + 52 + 160 + 31); // the root's aggregate 257+83 is not added again
  assert.equal(chat2.aiObservation.usage.inputTokens, 160);
  for (const e of byId.values()) { const v = validateEvent(e, otlpPrincipal); assert.equal(v.assurance, 'authenticated_telemetry_report');
    assert.equal(v.sourceKind, 'otlp'); assert.ok(otlpEventInvariant(e)); }
});

test('content attributes, span names, events, links and status messages never reach an event', () => {
  const canaries = ['Weather in Paris', 'weather API timed out', 'Plans trips', 'Get current weather', '"location"', 'tool_calls', 'chatcmpl-AbC123',
    'conv_5j66'];
  for (const [name, format] of [['sdk-genai.json', 'json'], ['sdk-genai.pb', 'protobuf']]) {
    const text = JSON.stringify(map(fixture(name), format).events);
    for (const canary of canaries) assert.ok(!text.includes(canary), `${name} leaked ${canary}`);
  }
  const legacy = map(fixture('legacy-content.json'), 'json');
  const text = JSON.stringify(legacy.events);
  for (const canary of ['123-45-6789', 'secret', 'Paris', 'sk-live', 'rate limited', 'noted', 'You are']) assert.ok(!text.includes(canary), canary);
  assert.equal(legacy.events.length, 1); assert.equal(legacy.events[0].status, 'failure');
  assert.equal(legacy.events[0].aiObservation.provider, 'openai'); // deprecated gen_ai.system
  assert.equal(legacy.events[0].aiObservation.usage.inputTokens, 12); // deprecated gen_ai.usage.prompt_tokens
  assert.equal(legacy.events[0].occurredAt, '2026-10-06T14:30:00.000Z'); // JSON number beyond 2^53 kept exact
  assert.equal(legacy.events[0].traceId, '5b8efff798038103d269b633813fc60c'); // upper-case hex normalised
  // Decoded protobuf keeps only allowlisted keys; content keys are skipped undecoded.
  const decoded = decodeTraceRequest(fixture('sdk-genai.pb'), 'protobuf');
  for (const span of decoded.resourceSpans[0].scopeSpans[0].spans) for (const key of span.attributes.keys()) assert.ok(
    SPAN_ATTRIBUTE_ALLOWLIST.includes(key), key);
  for (const key of CONTENT_ATTRIBUTE_KEYS) assert.ok(!SPAN_ATTRIBUTE_ALLOWLIST.includes(key), key);
});

test('span validation rejects bad context and time, counts non-GenAI spans as not stored', () => {
  const result = map(requestPb(
    spanPb({attrs: [kv('gen_ai.operation.name', sv('chat'))]}),
    spanPb({trace: '0'.repeat(32), attrs: [kv('gen_ai.operation.name', sv('chat'))]}),
    spanPb({span: '00', attrs: [kv('gen_ai.operation.name', sv('chat'))]}),
    spanPb({span: '00f067aa0ba902ba', start: 0n, attrs: [kv('gen_ai.operation.name', sv('chat'))]}),
    spanPb({span: '00f067aa0ba902bb', start: BigInt(NOW + 600000) * 1000000n, attrs: [kv('gen_ai.operation.name', sv('chat'))]}),
    spanPb({span: '00f067aa0ba902bc', attrs: [kv('http.request.method', sv('GET'))]}),
    spanPb({span: '00f067aa0ba902bd', attrs: [kv('gen_ai.operation.name', sv('invoke_workflow'))]}),
    spanPb({span: '00f067aa0ba902be', attrs: [kv('gen_ai.operation.name', sv('retrieval')), kv('gen_ai.provider.name', sv('openai')),
      kv('gen_ai.usage.input_tokens', vi(3, 9))]}),
  ), 'protobuf');
  assert.equal(result.spans, 8);
  assert.deepEqual(result.rejected, {invalid_span_context: 2, invalid_time: 1, future_time: 1, not_genai: 1, unsupported_operation: 1});
  assert.equal(result.events.length, 2);
  const retrieval = result.events.find(e => e.action === 'retrieval');
  assert.equal(retrieval.kind, 'notice'); assert.equal(retrieval.aiObservation.usage, undefined); // aggregate operations never add tokens
  const summary = rejectionSummary(result.rejected);
  assert.equal(summary.total, 6);
  assert.match(summary.message, /^6 spans not stored: future_time=1, invalid_span_context=2, invalid_time=1, not_genai=1, unsupported_operation=1; non-GenAI/);
});

test('status, provider and dialect mapping', () => {
  const resource = new Map([['service.name', 'svc']]);
  const span = (attributes, statusCode = 0) => ({traceId: TRACE, spanId: '00f067aa0ba902c1', parentSpanId: '', startTimeUnixNano: '1791297000000000000',
    statusCode, attributes: new Map(Object.entries(attributes))});
  const chat = extra => ({'gen_ai.operation.name': 'chat', ...extra});
  assert.equal(mapSpan(span(chat()), resource, NOW).event.status, 'success');
  assert.equal(mapSpan(span(chat(), 1), resource, NOW).event.status, 'success');
  assert.equal(mapSpan(span(chat(), 2), resource, NOW).event.status, 'failure');
  assert.equal(mapSpan(span(chat({'error.type': 'timeout'})), resource, NOW).event.status, 'failure');
  for (const [raw, expected] of [['aws.bedrock', 'aws'], ['az.ai.openai', 'azure'], ['azure.ai.inference', 'azure'], ['gcp.vertex_ai', 'google'],
    ['gemini', 'google'], ['anthropic', 'anthropic'], ['mistral_ai', 'other'], ['constructor', 'other']])
    assert.equal(mapSpan(span(chat({'gen_ai.provider.name': raw})), resource, NOW).event.aiObservation.provider, expected, raw);
  assert.equal(mapSpan(span(chat()), resource, NOW).event.aiObservation.provider, 'unknown');
  assert.equal(mapSpan(span(chat({'gen_ai.system': 'vertex_ai', 'gen_ai.provider.name': 'openai'})), resource, NOW).event.aiObservation.provider, 'openai');
  // OpenInference dialect
  const llm = mapSpan(span({'openinference.span.kind': 'LLM', 'llm.model_name': 'gpt-4o-mini', 'llm.provider': 'azure', 'llm.token_count.prompt': '11',
    'llm.token_count.completion': '3'}), resource, NOW).event;
  assert.equal(llm.kind, 'notice'); assert.equal(llm.action, 'chat'); assert.equal(llm.aiObservation.provider, 'azure');
  assert.deepEqual(llm.aiObservation.usage, {inputTokens: 11, outputTokens: 3});
  const tool = mapSpan(span({'openinference.span.kind': 'TOOL', 'tool.name': 'search'}), resource, NOW).event;
  assert.equal(tool.kind, 'self_report'); assert.equal(tool.tool, 'search');
  assert.equal(mapSpan(span({'openinference.span.kind': 'CHAIN'}), resource, NOW).rejected, 'unsupported_operation');
  // Unsafe free text is omitted rather than rejecting the span.
  const odd = mapSpan(span({'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'bad‮tool', 'gen_ai.agent.name': 'x'.repeat(300)}), resource,
    NOW).event;
  assert.equal(odd.tool, undefined); assert.equal(odd.actor, 'service:svc');
  assert.equal(mapSpan(span(chat({'server.address': '2001:db8::1'})), resource, NOW).event.aiObservation.network.destinationHost, '[2001:db8::1]');
});

test('OTLP/JSON decoding accepts producer variants and ignores unknown fields', () => {
  const variants = [
    jsonSpan({'gen_ai.operation.name': 'chat', 'gen_ai.usage.input_tokens': 5}, {unknownField: {x: 1}, status: {code: 'STATUS_CODE_ERROR'}}),
    jsonSpan({'gen_ai.operation.name': 'chat'}, {spanId: '00F067AA0BA902C2', startTimeUnixNano: 1791297000000000000, kind: 3}),
  ];
  const result = map(jsonRequest(...variants), 'json');
  assert.equal(result.events.length, 2); assert.equal(result.events[0].status, 'failure'); assert.equal(result.events[0].aiObservation.usage.inputTokens, 5);
  assert.equal(result.events[1].id, `otel:${TRACE}:00f067aa0ba902c2`); assert.equal(result.events[1].occurredAt, '2026-10-06T14:30:00.000Z');
  assert.deepEqual(map('{}', 'json'), {spans: 0, events: [], rejected: {}});
  for (const bad of ['not json', '[]', '{"resourceSpans":{}}', '{"resourceSpans":[{"scopeSpans":[{"spans":[1]}]}]}'])
    assert.throws(() => decodeTraceRequest(bad, 'json'), e => e instanceof OtlpDecodeError && e.status === 400, bad);
  assert.throws(() => decodeTraceRequest(jsonRequest(jsonSpan({}), jsonSpan({})), 'json', {maxSpans: 1}), e => e.status === 413);
});

test('protobuf decoder is order independent, bounded and rejects malformed wire data', () => {
  // Collector style: fields in descending order, KeyValue value before key, explicit defaults.
  const reversed = ld(2, cat(ld(15, vi(3, 0)), ld(9, cat(ld(2, sv('chat')), ld(1, 'gen_ai.operation.name'))), f64(7, 1791297000000000000n),
    ld(2, Buffer.from('00f067aa0ba902c3', 'hex')), ld(1, Buffer.from(TRACE, 'hex'))));
  const events = map(requestPb(reversed), 'protobuf').events;
  assert.equal(events.length, 1); assert.equal(events[0].id, `otel:${TRACE}:00f067aa0ba902c3`);
  assert.equal(events[0].aiObservation.assetRef, 'otel-service:svc');
  // Unknown fields of every wire type are skipped.
  const unknown = cat(vi(99, 7), f64(98, 1), ld(97, 'x'), tag(96, 5), Buffer.alloc(4));
  assert.equal(map(cat(unknown, requestPb(spanPb({attrs: [kv('gen_ai.operation.name', sv('chat'))], extra: [unknown]}))), 'protobuf').events.length, 1);
  // Invalid UTF-8 in an allowlisted value is replaced, never thrown or echoed raw.
  const badUtf8 = map(requestPb(spanPb({attrs: [kv('gen_ai.operation.name', sv('chat')), kv(
    'gen_ai.request.model', ld(1, Buffer.from([0x67, 0xff, 0x70])))]})), 'protobuf').events[0];
  assert.equal(badUtf8.model, 'g�p'); assert.equal(badUtf8.aiObservation.model, 'unknown');
  const full = requestPb(spanPb({attrs: [kv('gen_ai.operation.name', sv('chat'))]}));
  const malformed = [full.subarray(0, full.length - 3), Buffer.from([0x0b]), Buffer.from([0x03, 0x00]), Buffer.from([0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f]),
    Buffer.from([0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]), requestPb(ld(2, cat(vi(1, 5)))), requestPb(ld(2, cat(vi(7, 5))))];
  for (const buf of malformed) assert.throws(() => decodeTraceRequest(buf, 'protobuf'), e => e instanceof OtlpDecodeError && e.status === 400,
    buf.toString('hex'));
  assert.throws(() => decodeTraceRequest(requestPb(spanPb(), spanPb()), 'protobuf', {maxSpans: 1}), e => e.status === 413);
});

test('OTLP response and Status encodings are byte-exact', () => {
  assert.equal(encodeExportTraceServiceResponse(0, '').length, 0);
  assert.equal(encodeExportTraceServiceResponse(1, 'x').toString('hex'), '0a050801120178');
  assert.equal(encodeExportTraceServiceResponse(3, '3 spans rejected').toString('hex'), '0a140803121033207370616e732072656a6563746564');
  assert.equal(encodeStatus(14, 'retry').toString('hex'), '080e1205' + Buffer.from('retry').toString('hex'));
});

test('vault invariants refuse events that were not produced by the span mapper', () => {
  const [event] = map(requestPb(spanPb({attrs: [kv('gen_ai.operation.name', sv('chat'))]})), 'protobuf').events;
  assert.ok(otlpEventInvariant(event));
  for (const mutate of [e => { e.id = 'otel:custom'; }, e => { e.traceId = 'f'.repeat(32); }, e => { e.actionId = 'other'; }, e => { e.kind = 'execution'; },
    e => { e.aiObservation.span.spanId = 'a'.repeat(16); }, e => { e.aiObservation.collector.kind = 'sdk'; }, e => { delete e.aiObservation; }])
  { const copy = structuredClone(event); mutate(copy); assert.equal(otlpEventInvariant(copy), false); }
  assert.throws(() => validateEvent({...event, kind: 'execution', aiObservation: undefined}, otlpPrincipal), e => e.status === 403);
});

test('structural budget: empty containers, attributes and array values are bounded in both encodings (413, nothing materialized)', () => {
  const tooMany = (what, limit) => e => e instanceof OtlpDecodeError && e.status === 413 && e.message === `more than ${limit} ${what} in one request`;
  const small = (body, format) => mapTraceRequest(decodeTraceRequest(body, format, {maxSpans: 4}), {now: NOW});
  assert.deepEqual(structureLimits(8192), {spans: 8192, containers: 32768, values: 524288});
  assert.deepEqual(structureLimits(4), {spans: 4, containers: 64, values: 4096});
  // 8 KiB of gzip that used to decode into ~1 GB of objects: empty ResourceSpans, empty ScopeSpans.
  assert.throws(() => decodeTraceRequest(Buffer.alloc(8 * 1024 * 1024, Buffer.from([0x0a, 0x00])), 'protobuf'), tooMany('ResourceSpans/ScopeSpans', 32768));
  assert.throws(() => decodeTraceRequest(ld(1, Buffer.alloc(2 * 65, Buffer.from([0x12, 0x00]))), 'protobuf', {maxSpans: 4}),
    tooMany('ResourceSpans/ScopeSpans', 64));
  // Within the budget, empty containers are counted but not returned.
  const chat = spanPb({attrs: [kv('gen_ai.operation.name', sv('chat'))]});
  const empties = decodeTraceRequest(cat(Buffer.alloc(2 * 30, Buffer.from([0x0a, 0x00])), requestPb(chat)), 'protobuf', {maxSpans: 4});
  assert.equal(empties.resourceSpans.length, 1); assert.equal(small(cat(Buffer.alloc(60, Buffer.from([0x0a, 0x00])), requestPb()), 'protobuf').spans, 0);
  // Every KeyValue counts, allowlisted or not, on resources and spans; so do elements of decoded arrays.
  const junk = n => Array.from({length: n}, () => kv('x', sv('y')));
  assert.equal(small(requestPb(spanPb({attrs: [kv('gen_ai.operation.name', sv('chat')), ...junk(4094)]})), 'protobuf').events.length, 1);
  assert.throws(() => decodeTraceRequest(requestPb(spanPb({attrs: [kv('gen_ai.operation.name', sv('chat')), ...junk(4095)]})), 'protobuf', {maxSpans: 4}),
    tooMany('attributes and array values', 4096));
  assert.throws(() => decodeTraceRequest(ld(1, ld(1, Buffer.alloc(5 * 4097, Buffer.from([0x0a, 0x03, 0x0a, 0x01, 0x78])))), 'protobuf', {maxSpans: 4}),
    tooMany('attributes and array values', 4096));
  const array = n => ld(5, Buffer.concat(Array.from({length: n}, () => ld(1, sv('m')))));
  assert.deepEqual([...decodeTraceRequest(requestPb(spanPb({attrs: [kv('gen_ai.request.model', array(40))]})), 'protobuf', {maxSpans: 4})
    .resourceSpans[0].scopeSpans[0].spans[0].attributes.get('gen_ai.request.model')], Array(16).fill('m'));
  assert.throws(() => decodeTraceRequest(requestPb(spanPb({attrs: [kv('gen_ai.request.model', array(4096))]})), 'protobuf', {maxSpans: 4}),
    tooMany('attributes and array values', 4096));
  // JSON: objects, arrays and separators are counted before JSON.parse, then containers and attributes while walking.
  const objects = n => `{"resourceSpans":[${Array(n).fill('{}').join(',')}]}`;
  assert.throws(() => decodeTraceRequest(objects(4096), 'json', {maxSpans: 4}), tooMany('JSON objects or 8192 JSON values', 4096));
  assert.throws(() => decodeTraceRequest(`{"x":[${Array(8192).fill(1).join(',')}]}`, 'json', {maxSpans: 4}), tooMany('JSON objects or 8192 JSON values', 4096));
  assert.throws(() => decodeTraceRequest(objects(65), 'json', {maxSpans: 4}), tooMany('ResourceSpans/ScopeSpans', 64));
  assert.deepEqual(decodeTraceRequest(objects(64), 'json', {maxSpans: 4}), {resourceSpans: []});
  const wide = n => JSON.stringify({resourceSpans: [{scopeSpans: [{spans: [jsonSpan({'gen_ai.operation.name': 'chat'})]}]}]})
    .replace('"attributes":[', `"attributes":[${'1,'.repeat(n)}`);
  assert.equal(small(wide(4095), 'json').events.length, 1);
  assert.throws(() => decodeTraceRequest(wide(4100), 'json', {maxSpans: 4}), tooMany('attributes and array values', 4096));
  // Strings containing structural characters do not count; escaped quotes do not end a string.
  assert.equal(small(jsonRequest(jsonSpan({'gen_ai.operation.name': 'chat', 'gen_ai.agent.name': `a\\"${'{['.repeat(5000)}`})), 'json').events.length, 1);
});

test('OTLP/JSON int64 fields are parsed explicitly from strings and numbers (no reviver)', () => {
  const [event] = map(jsonRequest(jsonSpan({'gen_ai.operation.name': 'chat', 'gen_ai.usage.input_tokens': 7},
    {startTimeUnixNano: 1791297000000000000})), 'json').events;
  assert.equal(event.occurredAt, '2026-10-06T14:30:00.000Z'); assert.equal(event.aiObservation.usage.inputTokens, 7);
  const decoded = decodeTraceRequest(JSON.stringify({resourceSpans: [{scopeSpans: [{spans: [{...jsonSpan({}), startTimeUnixNano: '18446744073709551615',
    endTimeUnixNano: -1, attributes: [{key: 'gen_ai.usage.input_tokens', value: {intValue: '-9223372036854775809'}},
      {key: 'gen_ai.usage.output_tokens', value: {intValue: 2 ** 60}}]}]}]}]}), 'json').resourceSpans[0].scopeSpans[0].spans[0];
  assert.equal(decoded.startTimeUnixNano, '18446744073709551615'); assert.equal(decoded.endTimeUnixNano, '');
  assert.equal(decoded.attributes.get('gen_ai.usage.input_tokens'), '9223372036854775807'); // int64 wrap, as protobuf varints
  assert.equal(decoded.attributes.get('gen_ai.usage.output_tokens'), String(2n ** 60n));
});

test('vault invariant accepts exactly the mapper output: no free text, no forged collector, coverage or screening', () => {
  const produced = [...['sdk-genai.json', 'collector-genai.json', 'legacy-content.json'].flatMap(name => map(fixture(name), 'json').events),
    ...map(fixture('collector-genai.pb'), 'protobuf').events];
  const resource = new Map([['service.name', 'svc']]), span = (attributes, extra = {}) => ({traceId: TRACE, spanId: '00f067aa0ba902c1',
    parentSpanId: 'a'.repeat(16), startTimeUnixNano: '1791297000000000000', statusCode: 0, attributes: new Map(Object.entries(attributes)), ...extra});
  for (const attributes of [{'gen_ai.operation.name': 'execute_tool'}, {'gen_ai.operation.name': 'create_agent', 'gen_ai.agent.id': 'a-1'},
    {'gen_ai.operation.name': 'retrieval', 'gen_ai.provider.name': 'x', 'server.port': 443}, {'gen_ai.operation.name': 'something_new', 'gen_ai.system': 'y'},
    {'gen_ai.operation.name': 'embeddings', 'server.address': '2001:db8::1', 'gen_ai.usage.input_tokens': 5e15, 'gen_ai.usage.output_tokens': '0'}])
    produced.push(mapSpan(span(attributes), resource, NOW).event);
  produced.push(mapSpan(span({'gen_ai.operation.name': 'chat'}, {parentSpanId: ''}), new Map(), NOW).event);
  assert.equal(produced.length, 19);
  for (const event of produced) assert.ok(otlpEventInvariant(JSON.parse(JSON.stringify(event))), JSON.stringify(event));
  const [notice, tool] = ['notice', 'self_report'].map(kind => produced.find(e => e.kind === kind && (kind === 'notice' ? e.aiObservation.usage : e.tool)));
  const refused = (base, mutate) => { const copy = structuredClone(base); mutate(copy, copy.aiObservation); return otlpEventInvariant(copy); };
  for (const mutate of [
    e => { e.note = 'PROMPT: transfer $1M'; }, e => { e.purpose = 'RESPONSE'; }, e => { e.dataRefs = [{id: 'd', kind: 'document', role: 'input'}]; },
    e => { e.dataCategories = ['pii']; }, e => { e.resource = 'r'; }, e => { e.tool = 'other-tool'; }, e => { e.action = 'execute_tool'; },
    e => { e.status = 'blocked'; }, e => { e.clockUncertaintyMs = 0; }, e => { e.occurredAt = '2026-10-06T14:30:00Z'; }, e => { e.actor = 'x'.repeat(257); },
    e => { e.destination = 'evil.example'; }, e => { delete e.destination; },
    (e, o) => { o.collector.id = 'forged-screener'; }, (e, o) => { o.collector.version = '9'; }, (e, o) => { o.collector.extra = 1; },
    (e, o) => { o.coverage.mode = 'content'; }, (e, o) => { o.coverage.reason = 'other'; }, (e, o) => { o.correlation.confidence = 'probable'; },
    (e, o) => { o.screening = {...o.screening, status: 'complete', safety: 'safe', processedChunks: 1, totalChunks: 1}; delete o.screening.reason; },
    (e, o) => { delete o.screening; }, (e, o) => { o.signals = ['DLP_SENSITIVE_CONTENT']; }, (e, o) => { o.languageSignals = {}; },
    (e, o) => { o.timeBasis = 'collector_received'; }, (e, o) => { o.version = 3; }, (e, o) => { o.provider = 'forged'; }, (e, o) => { o.model = 'a b'; },
    (e, o) => { o.assetRef = 'asset-1'; }, (e, o) => { o.usage.totalTokens = 1; }, (e, o) => { o.usage = {}; }, (e, o) => { o.usage.inputTokens = -1; },
    (e, o) => { o.span.spanId = 'b'.repeat(16); }, (e, o) => { o.span.parentSpanId = '0'.repeat(16); }, (e, o) => { o.network.transport = 'tls'; },
    (e, o) => { o.network.destinationHost = 'API.openai.com'; e.destination = 'API.openai.com'; }, (e, o) => { o.extra = true; },
  ]) assert.equal(refused(notice, mutate), false, String(mutate));
  assert.equal(refused(notice, e => { e.action = 'other'; }), false, 'token counts only on model calls');
  for (const mutate of [e => { e.aiObservation = notice.aiObservation; }, e => { e.model = 'm'; }, e => { e.resource = 'other'; }, e => { e.note = 'x'; },
    e => { e.action = 'invoke_agent'; }, e => { e.destination = 'h'; }, e => { e.actionId = `otel-trace:${e.traceId}`; }])
    assert.equal(refused(tool, mutate), false, String(mutate));
});
