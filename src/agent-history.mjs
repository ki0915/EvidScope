// Past tool calls of an AI coding agent, read from the transcripts the agent keeps on disk and turned into the records its live hook
// would have sent (docs/agent-monitoring.md, "지난 행동 가져오기"). scripts/import-agent-history.mjs submits them, so the risk and
// sequence rules also audit what an agent did before its hook was installed.
//  - Claude Code: <projects>/<project>/<session>.jsonl, one JSON object per line. A call is an assistant content item
//    {type:'tool_use', id, name, input}; its outcome a later user content item {type:'tool_result', tool_use_id, is_error}.
//  - Codex CLI: <sessions>/YYYY/MM/DD/rollout-*.jsonl: session_meta {id, cwd}, then response_item lines: function_call
//    {name, arguments, call_id}, custom_tool_call {name, input, call_id}, local_shell_call {action: {command}, call_id} and the
//    *_output {call_id, output} of each.
// Each call becomes hookEvent()'s PreToolUse intent, and its PostToolUse self_report when the outcome is in the transcript, built from
// the tool name and input only, with the transcript's session id and call id: a call the live hook already sent has the same event id.
// Prompt, answer and tool output text never leave this module: an outcome contributes only its failure flags (is_error, interrupted,
// exit code). Every record carries collection 'history_import' and the transcript's time, so the vault marks it late.
import {createReadStream, readdirSync} from 'node:fs';
import {createInterface} from 'node:readline';
import {basename, dirname, join} from 'node:path';
import {homedir} from 'node:os';
import {HISTORY_IMPORT, HOOK_AGENTS, hookEvent} from './agent-hook-events.mjs';
import {INGEST_ID_CONFLICT} from './event-ingest.mjs';

export function defaultHistoryDir(agent, env = process.env) {
  if (agent === 'codex') return join(env.CODEX_HOME || join(homedir(), '.codex'), 'sessions');
  return join(env.CLAUDE_CONFIG_DIR || join(homedir(), '.claude'), 'projects');
}

// Transcript files under root in name order: Claude Code sessions (*.jsonl, with subagent files under <session>/subagents/) or Codex
// rollouts (rollout-*.jsonl). Symbolic links are not followed.
export function transcriptFiles(agent, root, maxDepth = 6) {
  const files = [], name = agent === 'codex' ? /^rollout-.*\.jsonl$/ : /\.jsonl$/;
  const walk = (dir, depth) => {
    let entries;
    try { entries = readdirSync(dir, {withFileTypes: true}); } catch { return; }
    for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      if (entry.isDirectory() && depth < maxDepth) walk(join(dir, entry.name), depth + 1);
      else if (entry.isFile() && name.test(entry.name)) files.push(join(dir, entry.name));
    }
  };
  walk(root, 0);
  return files;
}

// The JSON objects of a JSONL file; a line that is not one counts as malformed and is skipped.
async function* jsonLines(path, stats) {
  const lines = createInterface({input: createReadStream(path, {encoding: 'utf8'}), crlfDelay: Infinity});
  let first = true;
  for await (const raw of lines) {
    const line = first ? raw.replace(/^\uFEFF/, '') : raw;
    first = false;
    if (!line.trim()) continue;
    let value;
    try { value = JSON.parse(line); } catch { stats.malformedLines++; continue; }
    if (!value || typeof value !== 'object' || Array.isArray(value)) { stats.malformedLines++; continue; }
    yield value;
  }
}
const time = value => (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value) : null);
const text = value => (typeof value === 'string' && value ? value : null);

// Claude Code. Subagent (sidechain) lines are skipped unless asked for and counted; meta lines (injected context) carry no call.
async function claudeCalls(path, {sidechains}, stats) {
  const calls = [], outcomes = new Map(), fileSession = basename(path, '.jsonl'), fileProject = basename(dirname(path));
  for await (const line of jsonLines(path, stats)) {
    const content = Array.isArray(line.message?.content) ? line.message.content : [];
    if (line.isSidechain === true && !sidechains) {
      stats.skipped.sidechain += content.filter(item => item?.type === 'tool_use').length;
      continue;
    }
    if (line.isMeta === true) continue;
    if (line.type === 'assistant') {
      for (const item of content.filter(i => i?.type === 'tool_use')) {
        if (!text(item.id) || !text(item.name)) { stats.malformedCalls++; continue; }
        calls.push({session: text(line.sessionId) || fileSession, project: text(line.cwd) || fileProject, id: item.id, name: item.name,
          input: item.input, at: time(line.timestamp)});
      }
    } else if (line.type === 'user') {
      const results = content.filter(item => item?.type === 'tool_result' && text(item.tool_use_id));
      // toolUseResult describes the line's one result (Bash: {stdout, stderr, interrupted}); only its interrupted flag is read.
      const interrupted = results.length === 1 && line.toolUseResult?.interrupted === true;
      for (const item of results) {
        outcomes.set(item.tool_use_id, {at: time(line.timestamp),
          response: {...(item.is_error === true ? {is_error: true} : {}), ...(interrupted ? {interrupted: true} : {})}});
      }
    }
  }
  return calls.map(call => ({...call, outcome: outcomes.get(call.id)}));
}

// Codex names its shell tool differently across versions; the live hook reports it as Bash (src/agent-hook-events.mjs).
const CODEX_SHELL = new Set(['shell', 'shell_command', 'exec_command', 'local_shell', 'container.exec']);
function codexCall(item) {
  const id = text(item.call_id) || text(item.id);
  if (item.type === 'function_call') {
    if (!id || !text(item.name)) return null;
    let args = item.arguments;
    if (typeof args === 'string') { try { args = JSON.parse(args); } catch { args = {}; } }
    if (!args || typeof args !== 'object' || Array.isArray(args)) args = {};
    return CODEX_SHELL.has(item.name) ? {id, name: 'Bash', input: {command: args.command ?? args.cmd}} : {id, name: item.name, input: args};
  }
  if (item.type === 'local_shell_call') return id ? {id, name: 'Bash', input: {command: item.action?.command}} : null;
  // A custom tool's input is free text: only apply_patch's is read, for the file paths it names.
  if (item.type === 'custom_tool_call') {
    return id && text(item.name) ? {id, name: item.name, input: item.name === 'apply_patch' ? {command: item.input} : {}} : null;
  }
  return undefined;
}
// The failure flags of a Codex call output: {"output":…, "metadata":{"exit_code":…}} as JSON text, or "Exit code: N\n…" in newer builds.
export function codexOutcome(output) {
  let value = output;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { const exit = /^Exit code: (-?\d+)/.exec(output); return exit ? {exit_code: Number(exit[1])} : {}; }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const meta = value.metadata && typeof value.metadata === 'object' ? value.metadata : value;
  return {...(Number.isInteger(meta.exit_code) ? {exit_code: meta.exit_code} : {}), ...(value.success === false ? {success: false} : {})};
}
const ROLLOUT_ID = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$/i;
async function codexCalls(path, options, stats) {
  const calls = [], outcomes = new Map();
  let session = ROLLOUT_ID.exec(basename(path))?.[1] || basename(path, '.jsonl'), project = basename(dirname(path));
  for await (const line of jsonLines(path, stats)) {
    if (line.type === 'session_meta') { session = text(line.payload?.id) || session; project = text(line.payload?.cwd) || project; continue; }
    // Older rollouts keep the items unwrapped and without a time; their calls count as calls without a time.
    const item = line.type === 'response_item' ? line.payload : /_call(_output)?$/.test(String(line.type)) ? line : null;
    if (!item || typeof item !== 'object' || typeof item.type !== 'string') continue;
    if (item.type === 'function_call_output' || item.type === 'custom_tool_call_output') {
      if (text(item.call_id)) outcomes.set(item.call_id, {at: time(line.timestamp), response: codexOutcome(item.output)});
      continue;
    }
    const call = codexCall(item);
    if (call === undefined) { if (item.type.endsWith('_call')) stats.skipped.unknown[item.type] = (stats.skipped.unknown[item.type] || 0) + 1; continue; }
    if (call === null) { stats.malformedCalls++; continue; }
    calls.push({session, project, ...call, at: time(line.timestamp)});
  }
  return calls.map(call => ({...call, outcome: outcomes.get(call.id)}));
}

// One call -> its intent and, when its outcome is in the transcript, its after-record, each marked as imported.
export function callRecords(call, {agent, actor, policyVersion}) {
  const raw = {session_id: call.session, tool_use_id: call.id, tool_name: call.name, tool_input: call.input}, context = {actor, policyVersion, tool: agent};
  const pre = hookEvent({...raw, hook_event_name: 'PreToolUse'}, {...context, now: call.at});
  const post = call.outcome?.at ? hookEvent({...raw, hook_event_name: 'PostToolUse', tool_response: call.outcome.response}, {...context, now: call.outcome.at})
    : null;
  return [pre, post].filter(Boolean).map(event => ({...event, collection: HISTORY_IMPORT}));
}

// Reads every transcript under dir and returns the calls in time order with their records, plus counts. since/until (Date) bound the
// time of the call itself (its after-record goes with it); limit keeps the first n calls. A call found in more than one transcript (a
// resumed session repeating its history) is kept once, as first read.
export async function readAgentHistory({agent, dir, since, until, limit, sidechains = false, actor, policyVersion}) {
  if (!HOOK_AGENTS.includes(agent)) throw TypeError(`agent is one of ${HOOK_AGENTS.join(', ')}`);
  const stats = {files: 0, unreadableFiles: 0, malformedLines: 0, malformedCalls: 0, calls: 0, withOutcome: 0,
    skipped: {sidechain: 0, noTime: 0, outOfRange: 0, overLimit: 0, repeated: 0, unknown: {}}};
  const byId = new Map();
  for (const path of transcriptFiles(agent, dir)) {
    let found;
    try { found = await (agent === 'codex' ? codexCalls : claudeCalls)(path, {sidechains}, stats); } catch { stats.unreadableFiles++; continue; }
    stats.files++;
    for (const call of found) {
      stats.calls++;
      if (byId.has(call.id)) { stats.skipped.repeated++; continue; }
      if (!call.at) { stats.skipped.noTime++; byId.set(call.id, null); continue; }
      if (since && call.at < since || until && call.at > until) { stats.skipped.outOfRange++; byId.set(call.id, null); continue; }
      // Only the records and what the summary shows are kept: never the tool input.
      byId.set(call.id, {at: call.at, session: call.session, project: call.project, hasOutcome: !!call.outcome?.at,
        records: callRecords(call, {agent, actor, policyVersion})});
    }
  }
  const calls = [...byId.values()].filter(Boolean).sort((a, b) => a.at - b.at || a.records[0].id.localeCompare(b.records[0].id));
  if (Number.isSafeInteger(limit) && calls.length > limit) stats.skipped.overLimit = calls.splice(limit).length;
  stats.withOutcome = calls.filter(call => call.hasOutcome).length;
  return {calls, stats};
}

// Thrown when sending cannot go on: EvidScope unreachable or busy past the retries, or the source credentials refused.
export class HistoryImportError extends Error {}
const parse = body => { try { return JSON.parse(body); } catch { return null; } };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Sends the records of each call (intent, then after-record) through send(event) => {status, text}, a signed POST /api/ingest
// (src/agent-hook-runner.mjs postEvent), a few calls at a time. Whether a record is already stored is the vault's answer for this
// source and event id (src/event-ingest.mjs): the same content again is a duplicate (an earlier import), other content a 409 conflict
// (the live hook's record, which keeps its place: the vault never replaces a stored record). Both count as already present, as does
// a record whose id is in skip (queued in the live hook's spool; it goes out with the hook's next call). A 503 (busy, or an analysis
// backlog past its limit while the worker catches up) is retried with backoff up to `retries` times, a timeout or lost connection up to
// `networkRetries` times; a 401 or 403 stops the run; any other refusal is counted with its reason.
export async function sendHistory(calls, {send, skip = new Set(), concurrency = 8, retries = 40, networkRetries = 4, wait = delay, onProgress} = {}) {
  const result = {sent: 0, accepted: 0, alreadyPresent: 0, present: {duplicate: 0, conflict: 0, erased: 0, queued: 0}, rejected: 0, reasons: {}};
  let next = 0, done = 0, stop = null;
  async function deliver(event) {
    for (let attempt = 0; ; attempt++) {
      let status = 0, body = null, failure = '';
      try { ({status, text: body} = await send(event)); }
      catch (error) { failure = error?.name === 'TimeoutError' ? 'timeout' : error?.cause?.code || error?.message || 'network error'; }
      const answer = parse(body), message = typeof answer?.error === 'string' ? answer.error : '';
      if (status === 202) return answer?.duplicate === true ? 'duplicate' : 'accepted';
      if (status === 409 && message === INGEST_ID_CONFLICT.content) return 'conflict';
      if (status === 409 && message === INGEST_ID_CONFLICT.erased) return 'erased';
      if (status === 401 || status === 403) {
        throw new HistoryImportError(`EvidScope refused the agent source (HTTP ${status} ${message}): check the hook config and the PC clock`);
      }
      if (status && status < 500 && ![408, 429].includes(status)) return {reason: `HTTP ${status} ${message}`.trim()};
      if (attempt >= (status ? retries : networkRetries)) {
        throw new HistoryImportError(`EvidScope did not take records after ${attempt + 1} attempts (${status ? `HTTP ${status} ${message}` : failure}); `
          + 'run again later: records already stored then count as already present');
      }
      await wait(Math.min(30000, 500 * 2 ** attempt));
    }
  }
  async function worker() {
    while (!stop && next < calls.length) {
      const call = calls[next++];
      for (const event of call.records) {
        if (stop) return;
        if (skip.has(event.id)) { result.alreadyPresent++; result.present.queued++; continue; }
        let outcome;
        try { outcome = await deliver(event); } catch (error) { stop ??= error; return; }
        result.sent++;
        if (outcome === 'accepted') result.accepted++;
        else if (typeof outcome === 'string') { result.alreadyPresent++; result.present[outcome]++; }
        else { result.rejected++; result.reasons[outcome.reason] = (result.reasons[outcome.reason] || 0) + 1; }
      }
      if (++done % 500 === 0) onProgress?.(done, calls.length);
    }
  }
  await Promise.all(Array.from({length: Math.max(1, Math.min(concurrency, calls.length))}, worker));
  if (stop) { stop.result = result; throw stop; }
  return result;
}
