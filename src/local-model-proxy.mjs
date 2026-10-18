// Recording proxy for locally hosted model servers (docs/local-model-proxy.md): Ollama, vLLM, LM Studio, llama.cpp server and any other
// OpenAI-compatible server. A tool that calls the model (Open WebUI, Continue, Aider, a script) is pointed at the proxy instead of the
// server; every request goes to the server unchanged and every answer comes back unchanged, byte for byte, streamed as it arrives.
// On the side the proxy writes signed `agent` source records of each model call, like the coding agent hooks (src/agent-hook-runner.mjs):
//  - an intent when the request arrives (endpoint, model, message and tool counts, the tool names offered, request size and SHA-256);
//  - with content screening on (default), content records of the text that is new to the model in this call: the user's new messages
//    (prompt) and tool answers handed back to it (tool_result), as labels, counts and a hash (src/agent-content-signals.mjs), so the
//    engine v9 findings (planted instructions, secrets or personal data sent to the model) cover local models too;
//  - a self_report when the answer ends (HTTP status, finish reason, the tool names the model asked to call, token counts, answer size
//    and SHA-256, latency), with an aiObservation so the call shows in the AI usage view.
// Records are numbered and linked in one chain (hookChain, docs/agent-monitoring.md "수집 연속성") and wait in a spool while EvidScope
// cannot be reached. The proxy also sends a numbered heartbeat record at start and every heartbeatMs, so records removed from the end
// of the chain before they were sent show as a hole once the next heartbeat arrives.
// Text is never put on a record. With recordText on (default off) the proxy keeps the exact request and answer bodies in a local
// archive (one JSON line per call) whose SHA-256s are the ones on the signed records, so an archived body can be checked against the
// ledger later. A failure to record never blocks or changes a model call: the proxy forwards first and records on the side.
import {createHash, randomUUID} from 'node:crypto';
import {appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync} from 'node:fs';
import {createServer, request as httpRequest} from 'node:http';
import {request as httpsRequest} from 'node:https';
import {homedir, hostname} from 'node:os';
import {dirname, join} from 'node:path';
import {StringDecoder} from 'node:string_decoder';
import {contentFields, contentSignals} from './agent-content-signals.mjs';
import {MODEL_PROXY_TOOL, normalizeTarget, safeId} from './agent-hook-events.mjs';
import {hookChain, hookExecutor, postEvent} from './agent-hook-runner.mjs';
import {normalizeAIObservation} from './ai-observations.mjs';

export const PROXY_TOOL = MODEL_PROXY_TOOL;
export const PROXY_POLICY = 'local-model-monitoring-v1';
export const PROXY_FORMAT = 'local-model-proxy-v1';
export const PROXY_DEFAULTS = Object.freeze({listen: '127.0.0.1:11435', upstream: 'http://127.0.0.1:11434', provider: 'ollama',
  screenContent: true, recordText: false, heartbeatMs: 10 * 60 * 1000});
const PROVIDERS = ['ollama', 'vllm', 'llama.cpp', 'local', 'other'];
const LIMITS = {requestBytes: 64 * 1024 * 1024, parseBytes: 16 * 1024 * 1024, textChars: 1024 * 1024, names: 8, spoolBytes: 5 * 1024 * 1024,
  flush: 50, archiveBytes: 16 * 1024 * 1024};
// Hop-by-hop headers (RFC 9110 7.6.1) are not forwarded; content-length is recomputed by node for the buffered request.
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'proxy-authorization',
  'proxy-authenticate', 'host', 'content-length']);

// The model endpoints the proxy records, by path: [format, action]. Every other path (model lists, versions, the web UI of LM Studio) is
// forwarded without a record: it reads no prompt and runs no model.
const ENDPOINTS = Object.freeze({
  '/v1/chat/completions': ['openai-chat', 'model_call'], '/v1/completions': ['openai-completion', 'model_call'],
  '/v1/responses': ['openai-responses', 'model_call'], '/v1/embeddings': ['openai-embedding', 'model_embed'],
  '/api/chat': ['ollama-chat', 'model_call'], '/api/generate': ['ollama-generate', 'model_call'], '/api/embed': ['ollama-embed', 'model_embed'],
  '/api/embeddings': ['ollama-embed', 'model_embed'], '/api/pull': ['ollama-pull', 'model_admin'], '/api/push': ['ollama-push', 'model_admin'],
  '/api/create': ['ollama-create', 'model_admin'], '/api/delete': ['ollama-delete', 'model_admin'], '/api/copy': ['ollama-copy', 'model_admin']});
export function modelEndpoint(method, url) {
  let path;
  try { path = new URL(url, 'http://x').pathname.replace(/\/+$/, ''); } catch { return null; }
  const hit = ENDPOINTS[path];
  return hit && ['POST', 'DELETE'].includes(method) ? {path, format: hit[0], action: hit[1]} : null;
}

const sha256 = data => createHash('sha256').update(data).digest('hex');
const slug = (v, n = 64) => String(v ?? '').toLowerCase().replace(/[^a-z0-9._:/-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, n);
const json = buffer => { try { return JSON.parse(buffer.toString('utf8')); } catch { return null; } };
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
// The text of a message content: a string, or OpenAI content parts ({type: 'text', text}); images and audio are counted, not read.
const textOf = content => typeof content === 'string' ? content
  : Array.isArray(content) ? content.map(p => typeof p === 'string' ? p : typeof p?.text === 'string' ? p.text : '').filter(Boolean).join('\n') : '';
const toolNames = tools => (Array.isArray(tools) ? tools : []).map(t => t?.function?.name ?? t?.name).filter(n => typeof n === 'string' && n);
const append = (s, add) => s.length >= LIMITS.textChars ? s : (s + add).slice(0, LIMITS.textChars);

// What a request asks for, read from its JSON body: the model, whether the answer streams, how many messages and which tools it offers,
// and the text new to the model in this call. A chat request carries the whole conversation again each time; only the messages after
// the model's last answer are new, so only those are screened: user (and system) messages as prompt, tool answers as tool_result.
export function requestSummary(format, body) {
  const raw = json(body), out = {bytes: body.length, sha256: sha256(body), parsed: plain(raw), model: 'unknown', stream: false, messages: 0,
    tools: [], prompt: '', toolResult: '', inputs: 0};
  if (!out.parsed) return out;
  if (typeof raw.model === 'string' && raw.model) out.model = raw.model;
  else if (typeof raw.name === 'string' && raw.name) out.model = raw.name;
  out.stream = format.startsWith('ollama-') ? raw.stream !== false && ['ollama-chat', 'ollama-generate', 'ollama-pull', 'ollama-push',
    'ollama-create'].includes(format) : raw.stream === true;
  out.tools = toolNames(raw.tools);
  let items = [];
  if (Array.isArray(raw.messages)) items = raw.messages;
  else if (format === 'openai-responses')
    items = typeof raw.input === 'string' ? [{role: 'user', content: raw.input}] : Array.isArray(raw.input) ? raw.input : [];
  out.messages = items.length;
  let from = 0;
  items.forEach((m, i) => { if (m?.role === 'assistant' || m?.type === 'function_call') from = i + 1; });
  for (const m of items.slice(from)) {
    if (!plain(m)) continue;
    if (m.role === 'tool' || m.type === 'function_call_output') out.toolResult = append(out.toolResult, textOf(m.content ?? m.output) + '\n');
    else if (['user', 'system', 'developer'].includes(m.role) || m.type === 'message') out.prompt = append(out.prompt, textOf(m.content) + '\n');
  }
  if (typeof raw.prompt === 'string') out.prompt = append(out.prompt, raw.prompt);
  if (typeof raw.system === 'string' && !items.length) out.prompt = append(out.prompt, raw.system);
  const input = raw.input ?? raw.prompt;
  if (format.endsWith('embedding') || format === 'ollama-embed') out.inputs = Array.isArray(input) ? input.length : input === undefined ? 0 : 1;
  return out;
}

// Reads an answer as it passes, without holding it back: a JSON body, an SSE stream (OpenAI-compatible servers) or NDJSON (Ollama).
// Keeps the model name, finish reason, the tool names the model asks to call, token counts, an error flag and, bounded, the answer text.
export function answerTap() {
  const hash = createHash('sha256'), names = new Map(), state = {bytes: 0, model: null, finish: null, usage: {}, error: false, text: '',
    embeddings: 0, lines: 0, bad: 0};
  let mode = null, pending = '', whole = [], wholeBytes = 0;
  const decoder = new StringDecoder('utf8');
  const tokens = u => {
    if (!plain(u)) return;
    const n = (...keys) => keys.map(k => u[k]).find(v => Number.isSafeInteger(v) && v >= 0);
    const i = n('prompt_tokens', 'input_tokens'), o = n('completion_tokens', 'output_tokens'), t = n('total_tokens');
    if (i !== undefined) state.usage.inputTokens = i;if (o !== undefined) state.usage.outputTokens = o;if (t !== undefined) state.usage.totalTokens = t;
  };
  const called = (calls, base = 0) => (Array.isArray(calls) ? calls : []).forEach((c, k) => {
    const name = c?.function?.name ?? c?.name;
    if (typeof name === 'string' && name) names.set(`${base}.${Number.isSafeInteger(c?.index) ? c.index : k}`, name);
  });
  function absorb(o) {
    if (!plain(o)) return;
    if (plain(o.response) && typeof o.type === 'string') return absorb(o.response);
    if (typeof o.model === 'string' && o.model) state.model = o.model;
    if (o.error) state.error = true;
    tokens(o.usage);
    if (Number.isSafeInteger(o.prompt_eval_count)) state.usage.inputTokens = o.prompt_eval_count;
    if (Number.isSafeInteger(o.eval_count)) state.usage.outputTokens = o.eval_count;
    for (const [n, c] of (Array.isArray(o.choices) ? o.choices : []).entries()) {
      const part = c?.delta ?? c?.message ?? {};
      if (typeof part.content === 'string') state.text = append(state.text, part.content);
      if (typeof c?.text === 'string') state.text = append(state.text, c.text);
      called(part.tool_calls, n);
      if (typeof c?.finish_reason === 'string') state.finish = c.finish_reason;
    }
    if (plain(o.message)) { if (typeof o.message.content === 'string') state.text = append(state.text, o.message.content); called(o.message.tool_calls, 'm'); }
    if (typeof o.response === 'string') state.text = append(state.text, o.response);
    if (typeof o.done_reason === 'string') state.finish = o.done_reason;
    if (o.done === true && !state.finish) state.finish = 'stop';
    if (o.object === 'response' && typeof o.status === 'string') state.finish = o.status;
    for (const [n, item] of (Array.isArray(o.output) ? o.output : []).entries()) {
      if (item?.type === 'function_call' && typeof item.name === 'string') names.set(`o.${n}`, item.name);
      for (const c of Array.isArray(item?.content) ? item.content : []) if (typeof c?.text === 'string') state.text = append(state.text, c.text);
    }
    if (Array.isArray(o.data) && o.object === 'list') state.embeddings = o.data.length;
    if (Array.isArray(o.embeddings)) state.embeddings = o.embeddings.length;
    if (Array.isArray(o.embedding)) state.embeddings = 1;
  }
  const line = text => {
    let s = text.trim();
    if (!s || s.startsWith(':') || /^(event|id|retry):/.test(s)) return;
    if (s.startsWith('data:')) s = s.slice(5).trim();
    if (s === '[DONE]') return;
    state.lines++;
    try { absorb(JSON.parse(s)); } catch { state.bad++; }
  };
  return {
    start(contentType) { mode = /text\/event-stream|ndjson|jsonl/i.test(String(contentType || '')) ? 'lines' : 'whole'; },
    push(chunk) {
      hash.update(chunk);state.bytes += chunk.length;
      if (mode === 'lines') {
        if (pending.length > LIMITS.parseBytes) return;
        pending += decoder.write(chunk);
        let at;
        while ((at = pending.indexOf('\n')) >= 0) { line(pending.slice(0, at)); pending = pending.slice(at + 1); }
      } else if (wholeBytes <= LIMITS.parseBytes) { whole.push(chunk); wholeBytes += chunk.length; }
    },
    end() {
      if (mode === 'lines') { pending += decoder.end(); if (pending) line(pending); }
      if (mode === 'whole' && wholeBytes && wholeBytes <= LIMITS.parseBytes) {
        const body = Buffer.concat(whole), parsed = json(body);
        if (parsed) absorb(parsed); else if (/\n/.test(body.toString('utf8'))) body.toString('utf8').split('\n').forEach(line);
      }
      whole = [];pending = '';
      return {...state, sha256: hash.digest('hex'), toolCalls: [...names.values()]};
    }};
}

// Which program called: the X-EvidScope-Client header, else the first product of the User-Agent (python-httpx, node, OpenAI/Python …).
export function clientName(headers = {}) {
  const named = slug(headers['x-evidscope-client'], 40);
  if (named) return named;
  const ua = String(headers['user-agent'] || '').trim();
  return slug(ua.split(/[\s(]/)[0].split('/')[0], 40) || 'unknown';
}
const loopbackAddress = a => /^(127\.|::1$|::ffff:127\.)/.test(String(a || ''));
const day = now => now.toISOString().slice(0, 10).replace(/-/g, '');
const shortHash = s => sha256(String(s)).slice(0, 16);
const listed = (prefix, names) => [...new Set(names)].slice(0, LIMITS.names).map(n => `${prefix}:${slug(n, 48) || 'unnamed'}`);

// The records of one model call. call: {actionId, traceId, endpoint, client, remote, startedAt, endedAt?, summary, answer?, status?,
// failure?, archived}. context: {actor, policyVersion, executor, upstream, provider, assetRef, screen}.
export function intentRecord(call, context) {
  const {endpoint, summary: s} = call;
  const categories = [`endpoint:${endpoint.format}`, `client:${call.client}`, `client-addr:${loopbackAddress(call.remote) ? 'loopback' : 'network'}`,
    `stream:${s.stream ? 'yes' : 'no'}`, ...(s.tools.length ? [`tools-offered:${s.tools.length}`, ...listed('tool-offered', s.tools)] : [])];
  const what = endpoint.action === 'model_embed' ? `inputs=${s.inputs}` : endpoint.action === 'model_admin' ? 'model management' : `messages=${s.messages}`;
  return withContext({id: safeId(`lm.${call.actionId}.pre`), kind: 'intent', occurredAt: call.startedAt.toISOString(), traceId: call.traceId,
    actionId: call.actionId, model: s.model, action: endpoint.action, resource: normalizeTarget(`model:${s.model} ${endpoint.path}`),
    destination: upstreamHost(context.upstream), status: 'requested', dataCategories: categories.slice(0, 16),
    dataRefs: [{id: `request.${s.sha256.slice(0, 16)}`, kind: 'record', role: 'input', version: PROXY_FORMAT, hash: s.sha256,
      description: `request body, ${s.bytes} bytes${s.parsed ? '' : ', not JSON'}, text ${call.archived ? 'kept in the local text archive' : 'not stored'}`}],
    note: `[llm] ${endpoint.path} model=${s.model} ${what} tools=${s.tools.length} bytes=${s.bytes} client=${call.client}`}, context);
}
export function answerRecord(call, context) {
  const {endpoint, summary: s, answer: a} = call, model = a?.model || s.model;
  const failed = !!call.failure || !(call.status >= 200 && call.status < 300) || a?.error;
  const ms = Math.max(0, call.endedAt - call.startedAt);
  const categories = [`http:${call.status || 'none'}`, ...(a?.finish ? [`finish:${slug(a.finish, 32)}`] : []),
    ...(call.failure ? [`proxy:${call.failure}`] : []),
    ...(a?.toolCalls?.length ? [`tool-calls:${a.toolCalls.length}`, ...listed('tool-call', a.toolCalls)] : [])];
  const usage = a?.usage && Object.keys(a.usage).length ? a.usage : undefined;
  const parts = [`HTTP ${call.status || 'none'}`, `${ms} ms`, ...(usage?.outputTokens !== undefined ? [`${usage.outputTokens} tokens out`] : []),
    ...(a?.finish ? [`finish ${a.finish}`] : []),
    ...(a?.toolCalls?.length ? [`tool calls: ${[...new Set(a.toolCalls)].slice(0, LIMITS.names).join(', ')}`] : []),
    ...(a?.embeddings ? [`${a.embeddings} embeddings`] : []), ...(call.failure ? [`proxy: ${call.failure}`] : [])];
  const record = {id: safeId(`lm.${call.actionId}.post`), kind: 'self_report', occurredAt: call.endedAt.toISOString(), traceId: call.traceId,
    actionId: call.actionId, model, action: endpoint.action, status: failed ? 'failure' : 'success', dataCategories: categories.slice(0, 16),
    note: `[llm] answer ${parts.join(', ')}`.slice(0, 1024),
    aiObservation: normalizeAIObservation('http', {provider: context.provider, model, usage, url: context.upstream},
      {assetRef: context.assetRef, collectorId: PROXY_TOOL, collectorVersion: '1.0.0'})};
  if (a?.bytes) record.dataRefs = [{id: `answer.${a.sha256.slice(0, 16)}`, kind: 'record', role: 'output', version: PROXY_FORMAT, hash: a.sha256,
    description: `answer body, ${a.bytes} bytes, text ${call.archived ? 'kept in the local text archive' : 'not stored'}`}];
  return withContext(record, context);
}
// The content records of the text new to the model in this call (requestSummary prompt and toolResult), in the hook's format.
export function contentRecords(call, context) {
  if (!context.screen) return [];
  const out = [];
  for (const [source, text, tag] of [['prompt', call.summary.prompt, 'prompt'], ['tool_result', call.summary.toolResult, 'context']]) {
    if (!text.trim()) continue;
    const found = contentSignals(text), labels = Object.entries(found.signals).map(([k, n]) => `${k}=${n}`).join(' ') || 'no signal';
    const what = source === 'prompt' ? 'new user messages' : 'tool answers handed to the model';
    out.push(withContext({id: safeId(`lm.${call.actionId}.${tag}`), kind: 'self_report', occurredAt: call.startedAt.toISOString(), traceId: call.traceId,
      actionId: source === 'prompt' ? `${call.actionId}-prompt` : call.actionId, model: call.summary.model, action: 'content_screen', status: 'success',
      note: `[content] ${what} screened, ${found.chars} characters${found.truncated ? ' (cut)' : ''}, text not stored: ${labels}`,
      ...contentFields(source, found)}, context));
  }
  return out;
}
export function heartbeatRecord(kind, stats, context, now = new Date()) {
  const id = `${kind}-${randomUUID()}`;
  return withContext({id: safeId(`lm.${id}`), kind: 'self_report', occurredAt: now.toISOString(), traceId: `llm.proxy.${day(now)}`, actionId: id,
    action: `collector_${kind}`, status: 'success', resource: normalizeTarget(`proxy ${context.listen || ''} -> ${context.upstream}`),
    note: `[llm] proxy ${kind}: calls=${stats.calls} failures=${stats.failures} spooled=${stats.spooled} since=${stats.since}`}, context);
}
const upstreamHost = url => { try { return new URL(url).hostname.toLowerCase(); } catch { return 'unknown'; } };
function withContext(record, {actor, policyVersion, executor}) {
  const out = {...record, actor, tool: PROXY_TOOL};
  if (policyVersion) out.policyVersion = policyVersion;
  if (executor && Object.keys(executor).length) out.executor = {...executor};
  return out;
}

// Signed delivery with a spool, in order: records are numbered when they are made and sent one at a time; a record EvidScope cannot
// take now waits in the spool with everything after it and goes out on the next flush.
export function recordSender(config, {spool, chainPath, note = () => {}}) {
  let tail = Promise.resolve(), spooled = 0;
  async function sendOne(event) {
    try {
      let {status, text} = await postEvent(config, event, {timeoutMs: 3000});
      if (status === 400 && (event.executor || event.chain) && /executor|chain/.test(text)) {
        const bare = {...event};delete bare.executor;delete bare.chain;({status} = await postEvent(config, bare, {timeoutMs: 3000}));
      }
      if (status === 202 || status === 409) return true;
      if (status >= 400 && status < 500 && ![408, 429].includes(status)) { note(`dropped ${event.id}: HTTP ${status}`); return true; }
      return false;
    } catch { return false; }
  }
  function keep(events) {
    if (!events.length) return;
    try { if (existsSync(spool) && statSync(spool).size > LIMITS.spoolBytes) { note(`spool full, dropped ${events.length}`); return; } } catch {}
    try { appendFileSync(spool, events.map(e => JSON.stringify(e) + '\n').join('')); spooled += events.length; } catch (e) { note(`spool ${e.message}`); }
  }
  function claim() {
    if (!existsSync(spool)) return [];
    const claimed = `${spool}.${process.pid}.claim`;
    try { renameSync(spool, claimed); } catch { return []; }
    try { return readFileSync(claimed, 'utf8').split('\n').filter(Boolean).flatMap(l => { try { return [JSON.parse(l)]; } catch { return []; } }); }
    finally { try { unlinkSync(claimed); } catch {} }
  }
  async function deliver(events) {
    const backlog = claim(), queue = [...backlog, ...events], rest = [];
    for (const event of queue) if (rest.length || !await sendOne(event)) rest.push(event);
    spooled = Math.max(0, spooled - backlog.length);
    keep(rest);
  }
  const run = job => (tail = tail.then(job, job));
  return {
    // Numbers the records now (chain order is the order calls end), then queues them for delivery.
    send(events) {
      if (config.chain !== false && events.length && !hookChain(chainPath, events)) note('chain: state busy or unwritable, sent unnumbered');
      return run(() => deliver(events));
    },
    flush: () => run(() => deliver([])),
    idle: () => tail,
    get spooled() { return spooled; }};
}

// The local text archive (recordText on): one JSON line per call with the exact bodies; their SHA-256s are on the signed records.
function archiveCall(dir, call, requestBody, answerChunks) {
  const answer = Buffer.concat(answerChunks), at = call.startedAt;
  const line = {format: PROXY_FORMAT, actionId: call.actionId, at: at.toISOString(), endpoint: call.endpoint.path, model: call.summary.model,
    requestSha256: call.summary.sha256, answerSha256: call.answer?.sha256 || null,
    request: requestBody.length <= LIMITS.archiveBytes ? requestBody.toString('utf8') : null,
    answer: answer.length <= LIMITS.archiveBytes && answer.length === (call.answer?.bytes || 0) ? answer.toString('utf8') : null};
  mkdirSync(dir, {recursive: true});
  appendFileSync(join(dir, `${at.toISOString().slice(0, 10)}.jsonl`), JSON.stringify(line) + '\n');
}

export const proxyActor = () => `${PROXY_TOOL}@${hostname().toLowerCase().replace(/[^a-z0-9.-]/g, '-')}`;
// The asset id the records' aiObservation names, the same form scripts/install-agent-monitoring.mjs gives a coding agent's asset.
export const proxyAsset = actor => `asset.${actor.replace('@', '.')}`.slice(0, 120);
export const proxyConfigPath = (env = process.env) => env.EVIDSCOPE_PROXY_CONFIG || join(homedir(), '.evidscope', 'local-model-proxy.json');
const hostPort = listen => { const m = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(String(listen)); if (!m) throw Error(`listen is host:port, got ${listen}`);
  return {host: m[1].replace(/^\[|\]$/g, ''), port: Number(m[2])}; };

// Starts the proxy. options: the config ({url, token, hmacSecret, actor?, upstream, listen, provider, assetRef?, screenContent, recordText,
// textDir?, heartbeatMs}), configPath (spool, chain and log go next to it) and now (tests). Resolves {url, close(), sender, stats}.
export async function startModelProxy(options = {}) {
  const config = {...PROXY_DEFAULTS, ...options.config};
  if (!config.url || !config.token || !config.hmacSecret) throw Error('proxy config needs url, token and hmacSecret of an agent source');
  const upstream = new URL(config.upstream);
  if (!['http:', 'https:'].includes(upstream.protocol)) throw Error('upstream is an http(s) URL');
  const provider = PROVIDERS.includes(config.provider) ? config.provider : 'other';
  const configPath = options.configPath || proxyConfigPath(), dir = dirname(configPath);
  mkdirSync(dir, {recursive: true});
  const log = join(dir, 'local-model-proxy.log'), note = m => { try { appendFileSync(log, `${new Date().toISOString()} ${m}\n`); } catch {} };
  const actor = config.actor || proxyActor();
  const context = {actor, policyVersion: config.policyVersion || PROXY_POLICY,
    executor: config.executor === false ? undefined : hookExecutor({}, {}), upstream: upstream.href, listen: config.listen, provider,
    assetRef: safeId(config.assetRef || proxyAsset(actor)) || 'unregistered', screen: config.screenContent !== false};
  const sender = recordSender(config, {spool: join(dir, 'local-model-proxy-spool.jsonl'), chainPath: join(dir, 'local-model-proxy-chain.json'), note});
  const textDir = config.textDir || join(dir, 'local-model-text');
  const stats = {calls: 0, failures: 0, since: new Date().toISOString(), get spooled() { return sender.spooled; }};
  const forward = upstream.protocol === 'https:' ? httpsRequest : httpRequest;
  const basePath = upstream.pathname.replace(/\/+$/, '');

  const server = createServer((req, res) => {
    const endpoint = modelEndpoint(req.method, req.url), chunks = [];
    let size = 0, tooBig = false;
    req.on('data', c => { size += c.length; if (size > LIMITS.requestBytes) tooBig = true; else chunks.push(c); });
    req.on('error', () => {});
    req.on('end', () => {
      if (tooBig) { res.writeHead(413, {'content-type': 'application/json'}); res.end('{"error":"request too large for the recording proxy"}');
        note(`refused ${req.url}: request over ${LIMITS.requestBytes} bytes`); return; }
      const body = Buffer.concat(chunks), startedAt = new Date();
      let call = null;
      if (endpoint) {
        const summary = requestSummary(endpoint.format, body), client = clientName(req.headers);
        const session = safeId(req.headers['x-evidscope-session']);
        call = {actionId: `llm-${randomUUID()}`, traceId: session || `llm.${shortHash(`${client}|${req.socket.remoteAddress}`)}.${day(startedAt)}`,
          endpoint, client, remote: req.socket.remoteAddress, startedAt, summary, archived: config.recordText === true};
        stats.calls++;
      }
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && !k.startsWith('x-evidscope-')) headers[k] = v;
      headers.host = upstream.host;
      if (body.length || !['GET', 'HEAD'].includes(req.method)) headers['content-length'] = String(body.length);
      const tap = call ? answerTap() : null, kept = [];
      let keptBytes = 0, finished = false, upStatus = 0;
      const finish = (status, failure) => {
        if (!call || finished) return;
        finished = true;
        Object.assign(call, {status, failure, endedAt: new Date(), answer: tap.end()});
        if (failure || call.answer.error || !(status >= 200 && status < 300)) stats.failures++;
        if (call.archived) try { archiveCall(textDir, call, body, kept); } catch (e) { note(`text archive: ${e.message}`); }
        let records;
        try { records = [intentRecord(call, context), ...contentRecords(call, context), answerRecord(call, context)]; }
        catch (e) { note(`record ${call.actionId}: ${e.message}`); return; }
        sender.send(records).catch(e => note(`send ${e.message}`));
      };
      const out = forward({protocol: upstream.protocol, hostname: upstream.hostname, port: upstream.port, method: req.method,
        path: basePath + req.url, headers}, up => {
        upStatus = up.statusCode;
        const back = {...up.headers};
        for (const k of ['connection', 'keep-alive', 'transfer-encoding']) delete back[k];
        res.writeHead(up.statusCode, up.statusMessage, back);
        tap?.start(up.headers['content-type']);
        up.on('data', c => {
          tap?.push(c);
          if (call?.archived && keptBytes <= LIMITS.archiveBytes) { kept.push(c); keptBytes += c.length; }
          res.write(c);
        });
        up.on('end', () => { res.end(); finish(up.statusCode); });
        up.on('error', () => { res.destroy(); finish(up.statusCode, 'upstream_aborted'); });
      });
      out.on('error', error => {
        if (!res.headersSent) { res.writeHead(502, {'content-type': 'application/json'});
          res.end(JSON.stringify({error: `model server unreachable through the recording proxy: ${error.code || error.message}`})); }
        else res.destroy();
        if (call) { tap.start('application/json'); finish(0, 'upstream_unreachable'); }
      });
      res.on('close', () => { if (!res.writableEnded) { out.destroy(); finish(upStatus, 'client_closed'); } });
      out.end(body);
    });
  });
  const {host: bindHost, port} = hostPort(config.listen);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, bindHost, resolve); });
  const address = server.address(), shown = address.family === 'IPv6' ? `[${address.address}]` : address.address;
  const beat = kind => sender.send([heartbeatRecord(kind, stats, context, options.now?.() ?? new Date())]).catch(() => {});
  beat('start');
  const timer = config.heartbeatMs > 0 ? setInterval(() => { beat('heartbeat'); }, config.heartbeatMs) : null;
  timer?.unref();
  return {url: `http://${shown}:${address.port}`, sender, stats, context, beat,
    async close() {
      if (timer) clearInterval(timer);
      await new Promise(r => { server.close(r); server.closeAllConnections?.(); });
      await sender.idle();
    }};
}
