// Claude Code and Codex CLI hook input (PreToolUse / PostToolUse: https://code.claude.com/docs/en/hooks; Codex reads the same
// format from ~/.codex/hooks.json) -> EvidScope ingest events for an `agent` source (docs/agent-monitoring.md). Unlike
// src/development-collectors.mjs (allowlist metadata only: tool kind, no target), these events carry the target of each tool call
// (file path, command, URL) so the risk rules (data/risk-rules) can see what the AI touched: reading /etc/shadow, deleting a tree,
// posting data out. Commands keep their text with common secret forms redacted.
// The intent also names the agent's permission or sandbox mode and whether a file it touches lies outside the working folder
// (hookScope), so engine v9 can flag a risky call made with approval prompts off and an edit outside the workspace.
// The events are agent-source records (intent before the call, self_report after it): the hook runs inside the AI tool itself,
// so they are the tool's own account of what it did, not an independent execution record.
// With content screening on (hookEvents, screen), the text the model reads next (the user's prompt, a tool's answer) is also checked
// in memory for LLM security signals (src/agent-content-signals.mjs) and sent as a content record of labels, counts and a hash.
import {createHash} from 'node:crypto';
import {contentFields, contentSignals} from './agent-content-signals.mjs';

export const HOOK_TOOL = 'claude-code';
// The agents whose hooks this module reads; each one's events carry it as `tool`.
export const HOOK_AGENTS = Object.freeze(['claude-code', 'codex']);
export const HOOK_LIMITS = Object.freeze({resourceChars: 256, noteChars: 1024, idChars: 120});
// The `collection` of a record built from the agent's transcript after the fact (src/agent-history.mjs) instead of by the live hook.
export const HISTORY_IMPORT = 'history_import';
// Tool name -> action category. MCP tools are mcp__<server>__<tool>. Codex names its shell tool Bash in hooks (older builds
// exec_command, shell or local_shell) and its file edits apply_patch.
const ACTIONS = Object.freeze({Bash: 'shell_exec', PowerShell: 'shell_exec', Read: 'file_read', Write: 'file_write', Edit: 'file_write',
  MultiEdit: 'file_write', NotebookEdit: 'file_write', NotebookRead: 'file_read', Glob: 'file_search', Grep: 'file_search', LS: 'file_search',
  WebFetch: 'web_fetch', WebSearch: 'web_search', Task: 'subagent', Agent: 'subagent',
  exec_command: 'shell_exec', shell: 'shell_exec', local_shell: 'shell_exec', apply_patch: 'file_write', view_image: 'file_read',
  web_search: 'web_search'});
export const hookAction = name => typeof name === 'string' && name.startsWith('mcp__') ? 'mcp_call' : ACTIONS[name] || 'tool_call';

// Control characters other than tab/newline/carriage return, and bidi overrides, are rejected by the ingest validator.
const printable = s => s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/gu, ' ');
const clip = (s, n) => s.length > n ? s.slice(0, n - 1) + '…' : s;
// Secret forms that appear in commands: key=value / key: value for secret-like keys, Authorization headers, URL userinfo,
// and well-known token prefixes. Redaction is best effort; the events stay on the local EvidScope.
const SECRET_PATTERNS = [
  [new RegExp(/((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)["']?\s*[=:]\s*)/.source
    + /("[^"]*"|'[^']*'|[^\s"'&;|]+)/.source, 'gi'), '$1<redacted>'],
  [/(authorization:\s*(?:bearer|basic|token)\s+)[^\s"']+/gi, '$1<redacted>'],
  [/(-H\s*["']?(?:x-api-key|api-key):\s*)[^\s"']+/gi, '$1<redacted>'],
  [/(\/\/[^/\s:@]+:)[^@\s/]+@/g, '$1<redacted>@'],
  [/\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|hf_[A-Za-z0-9]{20,})\b/g,
    '<redacted>'],
  [/(-p)([^\s-][^\s]*)(?=\s|$)/g, (m, flag, value, offset, all) => /\bmysql|\bmariadb/i.test(all) ? `${flag}<redacted>` : m]];
export function redact(text) {
  let s = String(text);
  for (const [pattern, replacement] of SECRET_PATTERNS) s = s.replace(pattern, replacement);
  return s;
}
// Lower-case, forward slashes, single spaces: the risk rules match with a case-sensitive `contains` (src/model.mjs matches()), and
// Windows paths arrive with backslashes and any casing.
export const normalizeTarget = s => clip(printable(redact(s)).replace(/\\/g, '/').replace(/\s+/g, ' ').trim().toLowerCase(), HOOK_LIMITS.resourceChars);
export const safeId = s => String(s || '').replace(/[^a-zA-Z0-9._:@/-]/g, '-').slice(0, HOOK_LIMITS.idChars);
const shortHash = s => createHash('sha256').update(s).digest('hex').slice(0, 16);

function urlParts(raw) {
  try { const u = new URL(raw); return {resource: normalizeTarget(`${u.protocol}//${u.host}${u.pathname}`), destination: u.hostname.toLowerCase()}; }
  catch { return {resource: normalizeTarget(String(raw))}; }
}
// The first http(s) host a shell command names: curl/wget/Invoke-WebRequest targets, used as the event destination.
const commandHost = command => { const m = /https?:\/\/([a-z0-9.-]+)/i.exec(command); return m ? m[1].toLowerCase() : undefined; };
// A command as text: Codex may pass argv (["bash", "-lc", "rm -rf build"]).
const commandText = command => Array.isArray(command) ? command.map(String).join(' ') : String(command ?? '');
// The files an apply_patch edit names (*** Add File: / Update File: / Delete File: / Move to:). Only the paths are recorded, never
// the patch body, which can hold anything the agent wrote.
export const patchFiles = patch => [...String(patch ?? '').matchAll(/^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/gm)]
  .map(m => m[1].trim()).filter(Boolean);

// What the call acts on, plus the original text for the note.
export function hookTarget(name, input = {}) {
  const i = input && typeof input === 'object' ? input : {};
  const action = hookAction(name);
  if (action === 'shell_exec') { const command = commandText(i.command ?? i.cmd); const host = commandHost(command);
    return {resource: normalizeTarget(command), ...(host ? {destination: host} : {}), text: command}; }
  if (name === 'apply_patch') { const files = patchFiles(i.command ?? i.patch ?? i.input).join(' ');
    return {resource: normalizeTarget(files), text: `patch ${files}`}; }
  if (['file_read', 'file_write'].includes(action)) { const path = String(i.file_path ?? i.notebook_path ?? i.path ?? '');
    return {resource: normalizeTarget(path), text: path}; }
  if (action === 'file_search') { const where = [i.path, i.pattern, i.glob].filter(v => typeof v === 'string' && v).join(' ');
    return {resource: normalizeTarget(where), text: where}; }
  if (action === 'web_fetch') return {...urlParts(String(i.url ?? '')), text: String(i.url ?? '')};
  if (action === 'web_search') return {resource: normalizeTarget(String(i.query ?? '')), text: String(i.query ?? '')};
  if (action === 'subagent') { const what = String(i.description ?? i.subagent_type ?? ''); return {resource: normalizeTarget(what), text: what}; }
  return {resource: normalizeTarget(String(name || 'unknown')), text: ''};
}

// The scope of a call, as dataCategories of its intent (docs/agent-monitoring.md, "작업 범위"): the agent's permission or sandbox mode
// as the hook reports it (Claude Code permission_mode; sandbox_mode or approval_policy where an agent sends them), and
// boundary:outside_workspace when a file tool or a patch names an absolute path outside the working folder (cwd) other than a
// temporary folder. Commands are not parsed for paths. Evaluation engine v9 (src/content-rules.mjs) reads these categories.
export const SCOPE_OUTSIDE = 'boundary:outside_workspace';
const modeSlug = v => typeof v === 'string' && v ? v.toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 32) : '';
const modeOf = v => modeSlug(v && typeof v === 'object' ? v.mode ?? v.type : v);
const plainPath = p => printable(String(p)).replace(/\\/g, '/').replace(/\/+/g, '/').trim().toLowerCase();
const absolute = p => /^(?:[a-z]:\/|\/|~\/)/.test(p);
const TEMP = /^(?:\/tmp\/|\/var\/tmp\/|\/private\/tmp\/|[a-z]:\/windows\/temp\/|[a-z]:\/users\/[^/]+\/appdata\/local\/temp\/)/;
function outsideWorkspace(cwd, paths) {
  if (typeof cwd !== 'string' || !cwd) return false;
  const root = plainPath(cwd).replace(/\/$/, '');
  if (!absolute(root + '/')) return false;
  return paths.map(plainPath).some(p => absolute(p) && p !== root && !p.startsWith(root + '/') && !TEMP.test(p));
}
export function hookScope(raw, name, input = {}) {
  const i = input && typeof input === 'object' ? input : {}, action = hookAction(name);
  const categories = [['agent-mode', modeOf(raw?.permission_mode)], ['agent-sandbox', modeOf(raw?.sandbox_mode ?? raw?.sandbox_policy)],
    ['agent-approval', modeOf(raw?.approval_policy)]].filter(([, v]) => v).map(([k, v]) => `${k}:${v}`);
  const paths = name === 'apply_patch' ? patchFiles(i.command ?? i.patch ?? i.input)
    : ['file_read', 'file_write', 'file_search'].includes(action) ? [i.file_path ?? i.notebook_path ?? i.path].filter(v => typeof v === 'string' && v) : [];
  if (outsideWorkspace(raw?.cwd, paths)) categories.push(SCOPE_OUTSIDE);
  return categories;
}

function failed(response) {
  if (!response || typeof response !== 'object') return false;
  const exit = response.exit_code ?? response.exitCode;
  return response.is_error === true || response.success === false || response.interrupted === true
    || typeof response.error === 'string' && response.error !== '' || Number.isInteger(exit) && exit !== 0;
}

// raw: the hook's stdin JSON. context: {actor, policyVersion?, tool?, now?}; tool is the agent (HOOK_AGENTS, default Claude Code).
// Returns null for hook events this collector does not record.
// Only the PreToolUse intent carries the target (resource, destination): the PostToolUse self_report records the outcome under the
// same actionId, so a risk rule fires once per tool call, not twice. policyVersion names the asset registration the installer made
// (scripts/install-agent-monitoring.mjs); without it a call with a destination reads as "policy context unverified".
// executor: who runs the agent (src/agent-hook-runner.mjs hookExecutor: OS account, PC, repository, git user), put on every record.
export function hookEvent(raw, {actor, policyVersion, executor, tool = HOOK_TOOL, now = new Date()} = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !HOOK_AGENTS.includes(tool)) return null;
  const phase = raw.hook_event_name === 'PreToolUse' ? 'pre' : raw.hook_event_name === 'PostToolUse' ? 'post' : null;
  if (!phase || typeof raw.tool_name !== 'string' || !raw.tool_name) return null;
  const session = safeId(raw.session_id) || 'unknown-session';
  const call = safeId(raw.tool_use_id) || `call-${shortHash(JSON.stringify([raw.session_id, raw.tool_name, raw.tool_input]))}`;
  const target = hookTarget(raw.tool_name, raw.tool_input);
  const note = clip(printable(redact(`[${raw.tool_name}] ${target.text}`)).trim(), HOOK_LIMITS.noteChars);
  const prefix = tool === 'codex' ? 'cx' : 'cc';
  const event = {id: safeId(`${prefix}.${shortHash(session)}.${call}.${phase}`), kind: phase === 'pre' ? 'intent' : 'self_report',
    occurredAt: now.toISOString(), traceId: session, actionId: call, actor, tool, action: hookAction(raw.tool_name),
    status: phase === 'pre' ? 'requested' : failed(raw.tool_response) ? 'failure' : 'success', note};
  if (phase === 'pre') {
    event.resource = target.resource || 'unknown'; if (target.destination) event.destination = target.destination;
    const scope = hookScope(raw, raw.tool_name, raw.tool_input);
    if (scope.length) event.dataCategories = scope;
  }
  if (typeof policyVersion === 'string' && policyVersion) event.policyVersion = policyVersion;
  return withExecutor(event, executor);
}
const withExecutor = (event, executor) => executor && Object.keys(executor).length ? {...event, executor: {...executor}} : event;

// A tool whose answer is new context for the model. A file edit's answer echoes what the agent itself wrote, so it is not screened.
const screenedTool = name => hookAction(name) !== 'file_write';
// The content record of one hook call (same context as hookEvent): the signals of a UserPromptSubmit's prompt, or of the answer of a
// PostToolUse whose tool returns new content, as labels with counts (dataCategories) and the SHA-256 of the text (dataRefs); the
// text itself is never put on the record. A tool answer's record shares the call's actionId, so the call is judged with what it
// returned; a prompt gets its own action. Null when the call has no text to screen.
export function contentEvent(raw, {actor, policyVersion, executor, tool = HOOK_TOOL, now = new Date()} = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !HOOK_AGENTS.includes(tool)) return null;
  const prompt = raw.hook_event_name === 'UserPromptSubmit';
  if (prompt ? typeof raw.prompt !== 'string'
    : raw.hook_event_name !== 'PostToolUse' || typeof raw.tool_name !== 'string' || !raw.tool_name || !screenedTool(raw.tool_name)) return null;
  const found = contentSignals(prompt ? raw.prompt : raw.tool_response);
  if (!found.chars) return null;
  const session = safeId(raw.session_id) || 'unknown-session';
  const call = prompt ? `prompt-${shortHash(JSON.stringify([raw.session_id, now.toISOString(), found.sha256]))}`
    : safeId(raw.tool_use_id) || `call-${shortHash(JSON.stringify([raw.session_id, raw.tool_name, raw.tool_input]))}`;
  return withExecutor(contentEventFrom({session, call, source: prompt ? 'prompt' : 'tool_result', toolName: raw.tool_name, found, actor, policyVersion,
    tool, now}), executor);
}

// The content record for a screened text, from an already-computed `found` (src/agent-content-signals.mjs contentSignals or
// syntheticContent) and an explicit session, call (the action it shares, or a prompt-… of its own) and source. contentEvent builds
// `found` from the live hook input; the synthetic answer-key scenarios (src/threat-scenarios.mjs) build it from labels, so both get
// the same id, note and category format. session and call are already safe ids.
export function contentEventFrom({session, call, source, toolName, found, actor, policyVersion, tool = HOOK_TOOL, now = new Date()}) {
  const labels = Object.entries(found.signals).map(([k, n]) => `${k}=${n}`).join(' ') || 'no signal';
  const what = source === 'prompt' ? 'user prompt' : `${clip(printable(String(toolName || 'tool')), 80)} result`;
  const event = {id: safeId(`${tool === 'codex' ? 'cx' : 'cc'}.${shortHash(session)}.${call}.content`), kind: 'self_report',
    occurredAt: now.toISOString(), traceId: session, actionId: call, actor, tool, action: 'content_screen', status: 'success',
    note: `[content] ${what} screened, ${found.chars} characters${found.truncated ? ' (cut)' : ''}, text not stored: ${labels}`,
    ...contentFields(source, found)};
  if (typeof policyVersion === 'string' && policyVersion) event.policyVersion = policyVersion;
  return event;
}

// Every record of one hook call: hookEvent()'s and, with screen on, contentEvent()'s.
export function hookEvents(raw, {screen = false, ...context} = {}) {
  return [hookEvent(raw, context), screen ? contentEvent(raw, context) : null].filter(Boolean);
}
