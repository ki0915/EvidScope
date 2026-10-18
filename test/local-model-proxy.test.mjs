// Recording proxy for local model servers (docs/local-model-proxy.md): answers pass through unchanged and streamed, each model call
// leaves numbered, signed intent / content / answer records without its text, text is archived only when asked and matches the signed
// hashes, records wait in the spool while EvidScope is down, and end to end the vault stores them, keeps the chain whole and raises the
// engine v9 content finding for a secret sent to a local model.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createHmac} from 'node:crypto';
import {createServer} from 'node:http';
import {existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import * as F from './content-signal-fixtures.mjs';
import {answerTap, clientName, modelEndpoint, proxyAsset, requestSummary, startModelProxy, PROXY_POLICY, PROXY_TOOL} from '../src/local-model-proxy.mjs';
import {validateEvent} from '../src/model.mjs';
import {recordDigest} from '../src/agent-hook-runner.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const listen = server => new Promise(r => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${server.address().port}`)));
const closeServer = server => new Promise(r => { server.close(r); server.closeAllConnections(); });

// A fake model server speaking the OpenAI-compatible API (JSON and SSE) and Ollama's native API (NDJSON).
const SSE = [
  {id: 'c1', model: 'qwen3:4b', choices: [{index: 0, delta: {role: 'assistant', content: 'Hel'}}]},
  {id: 'c1', model: 'qwen3:4b', choices: [{index: 0, delta: {content: 'lo'}}]},
  {id: 'c1', model: 'qwen3:4b', choices: [{index: 0, delta: {tool_calls: [{index: 0, id: 't1', type: 'function',
    function: {name: 'run_shell', arguments: ''}}]}}]},
  {id: 'c1', model: 'qwen3:4b', choices: [{index: 0, delta: {tool_calls: [{index: 0, function: {arguments: '{"cmd":"ls"}'}}]}}]},
  {id: 'c1', model: 'qwen3:4b', choices: [{index: 0, delta: {}, finish_reason: 'tool_calls'}],
    usage: {prompt_tokens: 31, completion_tokens: 7, total_tokens: 38}}];
const sseBody = SSE.map(c => `data: ${JSON.stringify(c)}\n\n`).join('') + 'data: [DONE]\n\n';
const NDJSON = [{model: 'llama3.2', message: {role: 'assistant', content: '안녕'}, done: false},
  {model: 'llama3.2', message: {role: 'assistant', content: '하세요'}, done: false},
  {model: 'llama3.2', message: {role: 'assistant', content: ''}, done: true, done_reason: 'stop', prompt_eval_count: 12, eval_count: 4}];
const ndjsonBody = NDJSON.map(c => JSON.stringify(c) + '\n').join('');
function fakeModelServer() {
  const seen = [];
  const server = createServer((req, res) => {
    const parts = [];
    req.on('data', c => parts.push(c));
    req.on('end', () => {
      const body = Buffer.concat(parts);seen.push({method: req.method, url: req.url, headers: req.headers, body});
      const json = (() => { try { return JSON.parse(body); } catch { return {}; } })();
      if (req.url === '/v1/models') { res.writeHead(200, {'content-type': 'application/json'}); res.end('{"data":[{"id":"qwen3:4b"}]}'); return; }
      if (req.url === '/v1/chat/completions' && json.stream) {
        res.writeHead(200, {'content-type': 'text/event-stream', 'x-upstream': 'yes'});
        let i = 0; const parts = sseBody.match(/[\s\S]{1,37}/g);
        const next = () => { if (i < parts.length) { res.write(parts[i++]); setTimeout(next, 2); } else res.end(); };
        next(); return;
      }
      if (req.url === '/v1/chat/completions') {
        if (json.model === 'broken') { res.writeHead(500, {'content-type': 'application/json'}); res.end('{"error":{"message":"model failed"}}'); return; }
        res.writeHead(200, {'content-type': 'application/json'});
        res.end(JSON.stringify({id: 'c2', model: json.model, choices: [{index: 0, message: {role: 'assistant', content: 'ok'}, finish_reason: 'stop'}],
          usage: {prompt_tokens: 5, completion_tokens: 1, total_tokens: 6}}));
        return;
      }
      if (req.url === '/api/chat') { res.writeHead(200, {'content-type': 'application/x-ndjson'}); res.end(ndjsonBody); return; }
      res.writeHead(404); res.end('not found');
    });
  });
  return {server, seen};
}
// A fake EvidScope ingest gateway that checks the signature and keeps the records.
function fakeIngest(secret, {down = () => false} = {}) {
  const records = [];
  const server = createServer((req, res) => {
    const parts = [];
    req.on('data', c => parts.push(c));
    req.on('end', () => {
      if (down()) { res.writeHead(503); res.end(); return; }
      const body = Buffer.concat(parts).toString('utf8'), h = req.headers;
      const signature = createHmac('sha256', secret).update(`${h['x-evid-timestamp']}.${h['x-evid-nonce']}.${body}`).digest('hex');
      assert.equal(h['x-evid-signature'], signature);
      records.push(JSON.parse(body)); res.writeHead(202); res.end('{}');
    });
  });
  return {server, records};
}
async function setup({recordText = false, down} = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'evid-proxy-')), model = fakeModelServer(), ingest = fakeIngest('s3cret', {down});
  const upstream = await listen(model.server), url = await listen(ingest.server);
  const proxy = await startModelProxy({configPath: join(dir, 'local-model-proxy.json'), config: {url, token: 't', hmacSecret: 's3cret',
    upstream, listen: '127.0.0.1:0', provider: 'ollama', recordText, heartbeatMs: 0, actor: 'local-model-proxy@test-pc'}});
  return {dir, model, ingest, proxy, async close() { await proxy.close(); await closeServer(model.server); await closeServer(ingest.server);
    rmSync(dir, {recursive: true, force: true}); }};
}
const post = (base, path, body, headers = {}) => fetch(base + path, {method: 'POST', body: JSON.stringify(body),
  headers: {'content-type': 'application/json', 'user-agent': 'python-httpx/0.27', ...headers}});
const agentSource = {id: 'agent-src', tenant: 'alpha', kind: 'agent'};

test('endpoints, request summaries and client names', () => {
  assert.deepEqual(modelEndpoint('POST', '/v1/chat/completions?x=1'), {path: '/v1/chat/completions', format: 'openai-chat', action: 'model_call'});
  assert.equal(modelEndpoint('GET', '/v1/models'), null);
  assert.equal(modelEndpoint('POST', '/api/tags'), null);
  assert.equal(modelEndpoint('DELETE', '/api/delete').action, 'model_admin');
  const body = Buffer.from(JSON.stringify({model: 'm', messages: [{role: 'system', content: 'be brief'}, {role: 'user', content: 'old question'},
    {role: 'assistant', content: 'old answer', tool_calls: [{function: {name: 'search'}}]}, {role: 'tool', content: 'search result text'},
    {role: 'user', content: [{type: 'text', text: 'new question'}, {type: 'image_url', image_url: {url: 'data:x'}}]}],
  tools: [{type: 'function', function: {name: 'search'}}, {type: 'function', function: {name: 'run_shell'}}]}));
  const s = requestSummary('openai-chat', body);
  assert.equal(s.model, 'm'); assert.equal(s.messages, 5); assert.equal(s.stream, false); assert.deepEqual(s.tools, ['search', 'run_shell']);
  assert.equal(s.prompt.trim(), 'new question', 'only the messages after the last answer are new');
  assert.equal(s.toolResult.trim(), 'search result text');
  assert.equal(s.sha256, sha(body));
  assert.equal(requestSummary('ollama-chat', Buffer.from('{"model":"x","messages":[]}')).stream, true, 'Ollama streams unless told not to');
  assert.equal(requestSummary('ollama-embed', Buffer.from('{"model":"e","input":["a","b"]}')).inputs, 2);
  assert.equal(requestSummary('openai-chat', Buffer.from('not json')).parsed, false);
  assert.equal(clientName({'user-agent': 'OpenAI/Python 1.40.0'}), 'openai');
  assert.equal(clientName({'x-evidscope-client': 'Open WebUI', 'user-agent': 'aiohttp'}), 'open-webui');
  assert.equal(clientName({}), 'unknown');
});

test('the answer tap reads SSE, NDJSON and JSON answers split anywhere', () => {
  const tap = answerTap();tap.start('text/event-stream');
  for (const piece of sseBody.match(/[\s\S]{1,5}/g)) tap.push(Buffer.from(piece));
  const a = tap.end();
  assert.deepEqual([a.model, a.finish, a.toolCalls, a.usage, a.text], ['qwen3:4b', 'tool_calls', ['run_shell'],
    {inputTokens: 31, outputTokens: 7, totalTokens: 38}, 'Hello']);
  assert.equal(a.sha256, sha(sseBody)); assert.equal(a.bytes, Buffer.byteLength(sseBody));
  const nd = answerTap();nd.start('application/x-ndjson');
  const raw = Buffer.from(ndjsonBody);for (let i = 0; i < raw.length; i += 3) nd.push(raw.subarray(i, i + 3));
  const b = nd.end();
  assert.deepEqual([b.model, b.finish, b.usage, b.text], ['llama3.2', 'stop', {inputTokens: 12, outputTokens: 4}, '안녕하세요'],
    'a multi-byte character split between chunks is read whole');
  const r = answerTap();r.start('application/json');
  r.push(Buffer.from(JSON.stringify({object: 'response', status: 'completed', model: 'gpt-oss', output: [{type: 'function_call', name: 'lookup'},
    {type: 'message', content: [{type: 'output_text', text: 'done'}]}], usage: {input_tokens: 9, output_tokens: 2}})));
  const c = r.end();
  assert.deepEqual([c.finish, c.toolCalls, c.text, c.usage], ['completed', ['lookup'], 'done', {inputTokens: 9, outputTokens: 2}]);
});

test('answers pass through unchanged and each call leaves signed, numbered records without its text', async () => {
  const t = await setup();
  try {
    const secret = 'please check ' + F.SECRET_TEXTS.aws;
    const streamed = await post(t.proxy.url, '/v1/chat/completions', {model: 'qwen3:4b', stream: true, messages: [{role: 'user', content: secret}],
      tools: [{type: 'function', function: {name: 'run_shell'}}]}, {authorization: 'Bearer local-key', 'x-evidscope-session': 'sess-1'});
    assert.equal(streamed.headers.get('content-type'), 'text/event-stream'); assert.equal(streamed.headers.get('x-upstream'), 'yes');
    assert.equal(await streamed.text(), sseBody, 'the stream arrives byte for byte');
    const nd = await post(t.proxy.url, '/api/chat', {model: 'llama3.2', messages: [{role: 'user', content: '인사해 줘'}]});
    assert.equal(await nd.text(), ndjsonBody);
    const failed = await post(t.proxy.url, '/v1/chat/completions', {model: 'broken', messages: [{role: 'user', content: 'x'}]});
    assert.equal(failed.status, 500);
    assert.equal((await fetch(t.proxy.url + '/v1/models')).status, 200);
    await t.proxy.sender.idle();

    const up = t.model.seen.find(s => s.url === '/v1/chat/completions');
    assert.equal(up.headers.authorization, 'Bearer local-key', 'the server gets the caller\'s own key');
    assert.equal(up.headers['x-evidscope-session'], undefined, 'proxy headers stay with the proxy');
    const records = t.ingest.records, mine = records.filter(r => r.action !== 'collector_start');
    assert.ok(records.every(r => r.tool === PROXY_TOOL && r.actor === 'local-model-proxy@test-pc'));
    assert.deepEqual(records.map(r => r.chain.seq), records.map((_, i) => i + 1), 'one chain in delivery order');
    for (let i = 1; i < records.length; i++) assert.equal(records[i].chain.prev, recordDigest(records[i - 1]));
    for (const r of records) validateEvent(r, agentSource);
    assert.ok(!JSON.stringify(records).includes('AKIA') && !JSON.stringify(records).includes('인사해') && !JSON.stringify(records).includes('local-key'),
      'no prompt, answer or key text on any record');
    assert.equal(records.filter(r => r.action === 'model_call' && r.kind === 'intent').length, 3);
    assert.equal(t.model.seen.filter(s => s.url === '/v1/models').length, 1);
    assert.ok(!mine.some(r => /\/v1\/models/.test(r.note)), 'a model list is forwarded without a record');

    const call = mine.filter(r => r.traceId === 'sess-1');
    const intent = call.find(r => r.kind === 'intent'), answer = call.find(r => r.id.endsWith('.post'));
    const content = call.find(r => r.action === 'content_screen');
    assert.equal(intent.model, 'qwen3:4b'); assert.equal(intent.destination, '127.0.0.1');
    assert.ok(['endpoint:openai-chat', 'client:python-httpx', 'client-addr:loopback', 'stream:yes', 'tools-offered:1', 'tool-offered:run_shell']
      .every(c => intent.dataCategories.includes(c)), intent.dataCategories.join(' '));
    assert.equal(intent.dataRefs[0].hash, sha(up.body));
    assert.deepEqual(content.dataCategories, ['content:prompt', 'signal:secret_value:1']);
    assert.equal(answer.status, 'success'); assert.equal(answer.dataRefs[0].hash, sha(sseBody));
    assert.ok(['http:200', 'finish:tool_calls', 'tool-calls:1', 'tool-call:run_shell'].every(c => answer.dataCategories.includes(c)));
    assert.deepEqual(answer.aiObservation.usage, {inputTokens: 31, outputTokens: 7, totalTokens: 38});
    const o = answer.aiObservation;
    assert.deepEqual([o.provider, o.coverage.mode, o.collector.id], ['ollama', 'metadata', PROXY_TOOL]);
    const ollama = mine.find(r => r.kind === 'self_report' && r.model === 'llama3.2' && r.action === 'model_call');
    assert.deepEqual(ollama.aiObservation.usage, {inputTokens: 12, outputTokens: 4});
    assert.equal(mine.find(r => r.kind === 'self_report' && r.model === 'broken' && r.action === 'model_call').status, 'failure');
    assert.ok(!existsSync(join(t.dir, 'local-model-text')), 'no text archive unless asked');
  } finally { await t.close(); }
});

test('with recordText on, the archived bodies are the ones whose hashes are signed', async () => {
  const t = await setup({recordText: true});
  try {
    const sent = {model: 'qwen3:4b', stream: true, messages: [{role: 'user', content: '요약해 줘'}]};
    assert.equal(await (await post(t.proxy.url, '/v1/chat/completions', sent)).text(), sseBody);
    await t.proxy.sender.idle();
    const [file] = readdirSync(join(t.dir, 'local-model-text'));
    const line = JSON.parse(readFileSync(join(t.dir, 'local-model-text', file), 'utf8').trim());
    const intent = t.ingest.records.find(r => r.kind === 'intent'), answer = t.ingest.records.find(r => r.id.endsWith('.post'));
    assert.equal(line.actionId, intent.actionId);
    assert.deepEqual(JSON.parse(line.request), sent); assert.equal(line.answer, sseBody);
    assert.equal(sha(Buffer.from(line.request)), intent.dataRefs[0].hash); assert.equal(sha(Buffer.from(line.answer)), answer.dataRefs[0].hash);
    assert.match(intent.dataRefs[0].description, /local text archive/);
  } finally { await t.close(); }
});

test('records wait in the spool while EvidScope is down and go out in order with the next delivery; a dead server gets a 502', async () => {
  let down = true;
  const t = await setup({down: () => down});
  try {
    assert.equal((await (await post(t.proxy.url, '/v1/chat/completions', {model: 'm', messages: [{role: 'user', content: 'a'}]})).json()).choices[0]
      .message.content, 'ok', 'the model call works while EvidScope is down');
    await t.proxy.sender.idle();
    assert.equal(t.ingest.records.length, 0); assert.ok(t.proxy.sender.spooled >= 3);
    down = false;
    await t.proxy.sender.flush();
    assert.deepEqual(t.ingest.records.map(r => r.chain.seq), t.ingest.records.map((_, i) => i + 1));
    assert.equal(t.proxy.sender.spooled, 0);
    await closeServer(t.model.server);
    const dead = await post(t.proxy.url, '/v1/chat/completions', {model: 'm', messages: [{role: 'user', content: 'b'}]});
    assert.equal(dead.status, 502);
    await t.proxy.sender.idle();
    const last = t.ingest.records.at(-1);
    assert.deepEqual([last.status, last.dataCategories.includes('proxy:upstream_unreachable')], ['failure', true]);
  } finally { await t.close(); }
});

test('records removed from the spool before delivery show as a hole once the next heartbeat arrives', async () => {
  let down = true;
  const t = await setup({down: () => down});
  try {
    await (await post(t.proxy.url, '/v1/chat/completions', {model: 'm', messages: [{role: 'user', content: 'a'}]})).text();
    await t.proxy.sender.idle();
    const spooled = t.proxy.sender.spooled;
    rmSync(join(t.dir, 'local-model-proxy-spool.jsonl'));
    down = false;
    await t.proxy.beat('heartbeat');
    await t.proxy.sender.idle();
    assert.equal(t.ingest.records.length, 1);
    assert.deepEqual([t.ingest.records[0].action, t.ingest.records[0].chain.seq], ['collector_heartbeat', spooled + 1],
      'the heartbeat carries the next number, so the removed numbers are missing');
  } finally { await t.close(); }
});

let h;
test.before(async () => { h = await harness(); });
test.after(async () => { await h?.close(); });

test('end to end: the vault stores the proxy records, the chain is whole and a secret sent to a local model is an alert', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'evid-proxy-e2e-')), model = fakeModelServer(), agent = h.principal('agent');
  const upstream = await listen(model.server), actor = 'local-model-proxy@e2e-pc';
  const registered = await h.api('/api/assets', {role: 'reviewer', body: {id: proxyAsset(actor), actor, tool: PROXY_TOOL, owner: 'local user',
    purpose: 'recording proxy test', approvalRequired: false, policyVersion: PROXY_POLICY, validFrom: new Date(Date.now() - 60000).toISOString()}});
  if (registered.status >= 300) { await closeServer(model.server); assert.fail(JSON.stringify(registered)); }
  const proxy = await startModelProxy({configPath: join(dir, 'local-model-proxy.json'), config: {url: h.ingress.url, token: agent.token,
    hmacSecret: agent.hmacSecret, upstream, listen: '127.0.0.1:0', heartbeatMs: 0, actor: 'local-model-proxy@e2e-pc'}});
  try {
    await (await post(proxy.url, '/v1/chat/completions', {model: 'qwen3:4b', messages: [{role: 'user', content: 'key ' + F.SECRET_TEXTS.aws}]})).text();
    await proxy.beat('heartbeat');
    await proxy.sender.idle();
    assert.equal(proxy.sender.spooled, 0);
    const report = (await h.api('/api/collection/chains', {role: 'auditor'})).body;
    const stream = report.streams.find(s => s.actor === 'local-model-proxy@e2e-pc');
    assert.deepEqual([stream.tool, stream.firstSeq, stream.lastSeq, stream.missingRanges, stream.brokenLinks], [PROXY_TOOL, 1, 5, 0, 0]);
    for (let i = 0; i < 20; i++) { const r = (await h.analyze()).body; if (!r.backlog && !r.processed) break; }
    const alerts = (await h.api('/api/alerts', {role: 'auditor'})).body.items;
    assert.ok(alerts.some(a => a.code === 'LLM_SECRET_IN_PROMPT'), JSON.stringify(alerts.map(a => a.code)));
    assert.ok(!alerts.some(a => /UNREGISTERED/.test(a.code)), 'the registered proxy is not an unregistered AI');
    const visibility = (await h.api('/api/ai-visibility', {role: 'auditor'})).body;
    assert.ok(visibility.summary.totalObservations >= 1);
  } finally { await proxy.close(); await closeServer(model.server); rmSync(dir, {recursive: true, force: true}); }
});

test('init writes the proxy config from a hook config and registers nothing without --local-dir', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'evid-proxy-init-')), from = join(dir, 'claude-code-hook.json'), path = join(dir, 'proxy.json');
  try {
    writeFileSync(from, JSON.stringify({url: 'http://127.0.0.1:8091', token: 'tok', hmacSecret: 'sec', actor: 'claude-code@pc'}));
    const {stdout} = await promisify(execFile)(process.execPath, ['scripts/local-model-proxy.mjs', 'init', '--from', from, '--provider', 'vllm',
      '--upstream', 'http://127.0.0.1:8000'], {env: {...process.env, EVIDSCOPE_PROXY_CONFIG: path}});
    const config = JSON.parse(readFileSync(path, 'utf8'));
    assert.deepEqual([config.url, config.token, config.provider, config.upstream, config.listen, config.recordText, config.screenContent],
      ['http://127.0.0.1:8091', 'tok', 'vllm', 'http://127.0.0.1:8000', '127.0.0.1:11435', false, true]);
    assert.match(config.actor, /^local-model-proxy@/); assert.equal(config.assetRef, proxyAsset(config.actor));
    assert.match(JSON.parse(stdout).asset, /not registered/);
  } finally { rmSync(dir, {recursive: true, force: true}); }
});
