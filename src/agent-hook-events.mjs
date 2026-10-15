// Claude Code hook input (PreToolUse / PostToolUse, https://code.claude.com/docs/en/hooks) -> EvidScope ingest events for an
// `agent` source (docs/agent-monitoring.md). Unlike src/development-collectors.mjs (allowlist metadata only: tool kind, no target),
// these events carry the target of each tool call (file path, command, URL) so the risk rules (data/risk-rules) can see what the
// AI touched: reading /etc/shadow, deleting a tree, posting data out. Commands keep their text with common secret forms redacted.
// The events are agent-source records (intent before the call, self_report after it): the hook runs inside the AI tool itself,
// so they are the tool's own account of what it did, not an independent execution record.
import {createHash} from 'node:crypto';

export const HOOK_TOOL = 'claude-code';
export const HOOK_LIMITS = Object.freeze({resourceChars: 256, noteChars: 1024, idChars: 120});
// Tool name -> action category. MCP tools are mcp__<server>__<tool>.
const ACTIONS = Object.freeze({Bash: 'shell_exec', PowerShell: 'shell_exec', Read: 'file_read', Write: 'file_write', Edit: 'file_write',
  MultiEdit: 'file_write', NotebookEdit: 'file_write', NotebookRead: 'file_read', Glob: 'file_search', Grep: 'file_search', LS: 'file_search',
  WebFetch: 'web_fetch', WebSearch: 'web_search', Task: 'subagent', Agent: 'subagent'});
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
const safeId = s => String(s || '').replace(/[^a-zA-Z0-9._:@/-]/g, '-').slice(0, HOOK_LIMITS.idChars);
const shortHash = s => createHash('sha256').update(s).digest('hex').slice(0, 16);

function urlParts(raw) {
  try { const u = new URL(raw); return {resource: normalizeTarget(`${u.protocol}//${u.host}${u.pathname}`), destination: u.hostname.toLowerCase()}; }
  catch { return {resource: normalizeTarget(String(raw))}; }
}
// The first http(s) host a shell command names: curl/wget/Invoke-WebRequest targets, used as the event destination.
const commandHost = command => { const m = /https?:\/\/([a-z0-9.-]+)/i.exec(command); return m ? m[1].toLowerCase() : undefined; };

// What the call acts on, plus the original text for the note.
export function hookTarget(name, input = {}) {
  const i = input && typeof input === 'object' ? input : {};
  const action = hookAction(name);
  if (action === 'shell_exec') { const command = String(i.command ?? ''); const host = commandHost(command);
    return {resource: normalizeTarget(command), ...(host ? {destination: host} : {}), text: command}; }
  if (['file_read', 'file_write'].includes(action)) { const path = String(i.file_path ?? i.notebook_path ?? i.path ?? '');
    return {resource: normalizeTarget(path), text: path}; }
  if (action === 'file_search') { const where = [i.path, i.pattern, i.glob].filter(v => typeof v === 'string' && v).join(' ');
    return {resource: normalizeTarget(where), text: where}; }
  if (action === 'web_fetch') return {...urlParts(String(i.url ?? '')), text: String(i.url ?? '')};
  if (action === 'web_search') return {resource: normalizeTarget(String(i.query ?? '')), text: String(i.query ?? '')};
  if (action === 'subagent') { const what = String(i.description ?? i.subagent_type ?? ''); return {resource: normalizeTarget(what), text: what}; }
  return {resource: normalizeTarget(String(name || 'unknown')), text: ''};
}

function failed(response) {
  if (!response || typeof response !== 'object') return false;
  return response.is_error === true || response.success === false || response.interrupted === true
    || typeof response.error === 'string' && response.error !== '';
}

// raw: the hook's stdin JSON. context: {actor, policyVersion?, now?}. Returns null for hook events this collector does not record.
// Only the PreToolUse intent carries the target (resource, destination): the PostToolUse self_report records the outcome under the
// same actionId, so a risk rule fires once per tool call, not twice. policyVersion names the asset registration the installer made
// (scripts/install-agent-monitoring.mjs); without it a call with a destination reads as "policy context unverified".
export function hookEvent(raw, {actor, policyVersion, now = new Date()} = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const phase = raw.hook_event_name === 'PreToolUse' ? 'pre' : raw.hook_event_name === 'PostToolUse' ? 'post' : null;
  if (!phase || typeof raw.tool_name !== 'string' || !raw.tool_name) return null;
  const session = safeId(raw.session_id) || 'unknown-session';
  const call = safeId(raw.tool_use_id) || `call-${shortHash(JSON.stringify([raw.session_id, raw.tool_name, raw.tool_input]))}`;
  const target = hookTarget(raw.tool_name, raw.tool_input);
  const note = clip(printable(redact(`[${raw.tool_name}] ${target.text}`)).trim(), HOOK_LIMITS.noteChars);
  const event = {id: safeId(`cc.${shortHash(session)}.${call}.${phase}`), kind: phase === 'pre' ? 'intent' : 'self_report',
    occurredAt: now.toISOString(), traceId: session, actionId: call, actor, tool: HOOK_TOOL, action: hookAction(raw.tool_name),
    status: phase === 'pre' ? 'requested' : failed(raw.tool_response) ? 'failure' : 'success', note};
  if (phase === 'pre') { event.resource = target.resource || 'unknown'; if (target.destination) event.destination = target.destination; }
  if (typeof policyVersion === 'string' && policyVersion) event.policyVersion = policyVersion;
  return event;
}
