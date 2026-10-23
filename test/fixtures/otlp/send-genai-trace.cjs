// Interop helper (test only): emits one deterministic GenAI agent trace with the official OpenTelemetry JS SDK.
// usage: node send-genai-trace.cjs <json|proto> <url> <gzip|none> <traceId32hex> <startMs> [--with-http-span]
// Modules come from EVIDSCOPE_OTEL_JS_DIR/node_modules; the bearer token from EVIDSCOPE_OTLP_TOKEN.
const path = require('node:path');
const modules = path.join(process.env.EVIDSCOPE_OTEL_JS_DIR || '', 'node_modules');
const load = name => require(path.join(modules, name));
const api = load('@opentelemetry/api');
const {BasicTracerProvider, BatchSpanProcessor} = load('@opentelemetry/sdk-trace-base');
const {resourceFromAttributes} = load('@opentelemetry/resources');
const [encoding, url, compression, traceId, start, flag] = process.argv.slice(2);
const {OTLPTraceExporter} = load(encoding === 'json' ? '@opentelemetry/exporter-trace-otlp-http' : '@opentelemetry/exporter-trace-otlp-proto');
api.diag.setLogger(new api.DiagConsoleLogger(), api.DiagLogLevel.WARN);
let next = 0;
const idGenerator = {generateTraceId: () => traceId, generateSpanId: () => '00f067aa0ba902b' + (++next).toString(16)};
const exporter = new OTLPTraceExporter({url, compression, headers: {Authorization: `Bearer ${process.env.EVIDSCOPE_OTLP_TOKEN}`}});
const provider = new BasicTracerProvider({idGenerator, resource: resourceFromAttributes({'service.name': 'travel-agent', 'service.version': '1.4.2'}),
  spanProcessors: [new BatchSpanProcessor(exporter, {scheduledDelayMillis: 60000, maxExportBatchSize: 512})]});
const tracer = provider.getTracer('evidscope-interop', '0.1.0');
const t0 = Number(start), at = d => t0 + d, K = api.SpanKind;
const root = tracer.startSpan('invoke_agent travel-planner', {kind: K.INTERNAL, startTime: at(0), attributes: {
  'gen_ai.operation.name': 'invoke_agent', 'gen_ai.provider.name': 'openai', 'gen_ai.agent.name': 'travel-planner', 'gen_ai.agent.id': 'asst_interop',
  'gen_ai.agent.description': 'Plans trips (CANARY-DESCRIPTION)', 'gen_ai.request.model': 'gpt-4o'}});
const ctx = api.trace.setSpan(api.context.active(), root);
const chat = tracer.startSpan('chat gpt-4o', {kind: K.CLIENT, startTime: at(10), attributes: {
  'gen_ai.operation.name': 'chat', 'gen_ai.provider.name': 'openai', 'gen_ai.request.model': 'gpt-4o', 'gen_ai.response.model': 'gpt-4o-2024-08-06',
  'gen_ai.usage.input_tokens': 97, 'gen_ai.usage.output_tokens': 52, 'server.address': 'api.openai.com', 'server.port': 443,
  'gen_ai.input.messages': JSON.stringify([{role: 'user', parts: [{type: 'text', content: 'CANARY-PROMPT Weather in Paris?'}]}])}}, ctx);
chat.end(at(900));
const tool = tracer.startSpan('execute_tool get_weather', {kind: K.INTERNAL, startTime: at(905), attributes: {
  'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'get_weather', 'gen_ai.agent.name': 'travel-planner',
  'gen_ai.tool.call.arguments': '{"location":"CANARY-ARGUMENT"}'}}, ctx);
tool.setAttribute('error.type', 'TimeoutError');
tool.setStatus({code: api.SpanStatusCode.ERROR, message: 'CANARY-STATUS weather API timed out'});
tool.end(at(1905));
if (flag === '--with-http-span') {
  tracer.startSpan('GET /weather', {kind: K.CLIENT, startTime: at(1000), attributes: {'http.request.method': 'GET'}}, ctx).end(at(1100));
}
root.setAttribute('gen_ai.usage.input_tokens', 97); root.setAttribute('gen_ai.usage.output_tokens', 52);
root.end(at(2000));
provider.forceFlush().then(() => provider.shutdown()).then(() => console.log('sent'),
  error => { console.error('ERR', error?.message || error); process.exit(1); });
