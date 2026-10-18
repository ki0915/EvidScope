// The hook process of an AI coding agent (docs/agent-monitoring.md), run by scripts/claude-code-hook.mjs (Claude Code) and
// scripts/codex-hook.mjs (Codex CLI) for every PreToolUse/PostToolUse (and, when registered, UserPromptSubmit) hook: reads the hook
// input on stdin, sends it to EvidScope's ingest gateway as signed `agent` source records (src/agent-hook-events.mjs) and queues
// them locally when EvidScope cannot be reached.
// It changes no tool call and prints nothing, except with the guard on (config "guard": true, Claude Code only): then a PreToolUse whose
// intent the guard denies (src/agent-hook-guard.mjs: audit and collection tampering, a defence switched off, a credential read and
// sent out in one command) gets Claude Code's deny answer on stdout, and its intent goes out with the guard:denied category. It always
// exits 0; a guard that cannot read the rule pack lets every call run. Events wait in a local spool and go out with the next call that
// can reach EvidScope.
// Config (EVIDSCOPE_HOOK_CONFIG or ~/.evidscope/<agent>-hook.json): {"url":"http://127.0.0.1:8091","token":"…","hmacSecret":"…",
// "actor":"<agent>@pc","policyVersion":"<agent>-monitoring-v1","screenContent":true,"guard":false,"executor":true}: the url is the ingest gateway (local launcher
// port base + 1), the credentials an `agent` source's; screenContent (default on) sends the content record of prompts and tool answers
// (labels, counts and a hash, never the text; src/agent-content-signals.mjs), false turns it off; guard (default off) reads the rule pack
// at ../data/risk-rules/ai-agent-baseline.json beside this module; executor (default on) puts who runs the agent on every record
// (hookExecutor: OS account, PC, the git repository of the working folder and the git user), false leaves it out. Only node built-ins, ./agent-hook-events.mjs,
// ./agent-content-signals.mjs, ./agent-hook-guard.mjs and ./rule-words.mjs are imported, so the installer can copy the hook to a plain
// ASCII path: a Korean or spaced user folder in a hook command line is fragile across the shells agents run hooks with.
// scripts/import-agent-history.mjs reuses the config, actor and signed request below to send past tool calls the same way.
import {readFileSync, appendFileSync, renameSync, statSync, mkdirSync, existsSync, unlinkSync} from 'node:fs';
import {createHmac, randomUUID} from 'node:crypto';
import {homedir, hostname, userInfo} from 'node:os';
import {join, dirname, resolve, isAbsolute} from 'node:path';
import {HOOK_AGENTS, hookEvents} from './agent-hook-events.mjs';
import {GUARD_DENIED, denyOutput, guardDecision} from './agent-hook-guard.mjs';

const SPOOL_MAX_BYTES = 5 * 1024 * 1024, FLUSH_MAX = 20, TIMEOUT_MS = 1000;

export const hookConfigPath = (agent, env = process.env) => env.EVIDSCOPE_HOOK_CONFIG || join(homedir(), '.evidscope', `${agent}-hook.json`);
// The spool of records the hook could not send yet (next to its config).
export const hookSpoolPath = (agent, configPath) => join(dirname(configPath), `${agent}-spool.jsonl`);
export const hookActor = (agent, config = {}) => config.actor || `${agent}@${hostname().toLowerCase().replace(/[^a-z0-9.-]/g, '-')}`;
// Who runs the agent, for the owner map (src/agent-ownership.mjs): the OS account and PC the hook runs as, and, read from the files
// (no git process per tool call), the origin remote of the git repository holding the working folder (cwd of the hook input) without
// credentials or .git, and the git user email (else name) of that repository or of ~/.gitconfig. includeIf and system git config
// are not read. Every value is the hook's own report, like the actor name. Fields that cannot be read are left out.
const iniValue = (text, section, key) => {
  let inside = false;
  for (const line of String(text).split(/\r?\n/)) {
    const head = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (head) { inside = head[1].trim().toLowerCase().replace(/\s+/g, ' ') === section; continue; }
    const m = inside && /^\s*([A-Za-z0-9-]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && m[1].toLowerCase() === key) return m[2].replace(/^"(.*)"$/, '$1');
  }
  return null;
};
const readText = path => { try { return readFileSync(path, 'utf8'); } catch { return null; } };
// The config file of the repository holding dir: .git as a folder, or as a worktree/submodule file naming its gitdir (and commondir).
function gitConfigOf(dir) {
  for (let d = resolve(dir), n = 0; n < 40; n++) {
    const dotgit = join(d, '.git');
    if (existsSync(dotgit)) {
      let gitdir = dotgit;
      try { if (statSync(dotgit).isFile()) { const m = /^gitdir:\s*(.+)$/m.exec(readText(dotgit) || ''); if (!m) return null; gitdir = resolve(d, m[1].trim()); } }
      catch { return null; }
      const common = (readText(join(gitdir, 'commondir')) || '').trim();
      return readText(join(common ? resolve(gitdir, common) : gitdir, 'config'));
    }
    const up = dirname(d); if (up === d) return null; d = up;
  }
  return null;
}
// https://user:token@host/org/repo.git, git@host:org/repo.git, ssh://git@host/org/repo -> host/org/repo (lower case).
export function repositoryName(url) {
  const s = String(url || '').trim();
  const scp = /^[^@/\s]+@([^:/\s]+):(.+)$/.exec(s);
  let host, path;
  if (scp) [host, path] = [scp[1], scp[2]];
  else { try { const u = new URL(s); if (u.protocol === 'file:') return null; host = u.hostname; path = u.pathname; } catch { return null; } }
  path = path.replace(/^\/+/, '').replace(/\/+$/, '').replace(/\.git$/i, '');
  return host && path ? `${host}/${path}`.toLowerCase().slice(0, 256) : null;
}
export function hookExecutor(raw, {home = homedir(), account, host} = {}) {
  const out = {};
  try { const name = account ?? userInfo().username; if (name) out.account = String(name).toLowerCase().slice(0, 256); } catch {}
  const pc = host ?? hostname(); if (pc) out.host = String(pc).toLowerCase().replace(/[^a-z0-9.-]/g, '-').slice(0, 256);
  const cwd = typeof raw?.cwd === 'string' && isAbsolute(raw.cwd) ? raw.cwd : null;
  const repo = cwd ? gitConfigOf(cwd) : null, global = readText(join(home, '.gitconfig'));
  const origin = repo && repositoryName(iniValue(repo, 'remote "origin"', 'url'));
  if (origin) out.repository = origin;
  const user = [repo, global].map(t => t && (iniValue(t, 'user', 'email') || iniValue(t, 'user', 'name'))).find(Boolean);
  if (user) out.gitUser = String(user).toLowerCase().replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/gu, '').slice(0, 256);
  return out;
}

// The rule pack the guard reads: beside the hook's src/ folder, in the repository and in a --hook-dir copy alike.
export const GUARD_PACK = new URL('../data/risk-rules/ai-agent-baseline.json', import.meta.url);
// What a --hook-dir copy needs besides the agent's hook script (scripts/install-agent-monitoring.mjs): this module, the modules it
// imports and the guard's rule pack, at the same relative paths.
export const HOOK_COPY = Object.freeze(['src/agent-hook-runner.mjs', 'src/agent-hook-events.mjs', 'src/agent-content-signals.mjs',
  'src/agent-hook-guard.mjs', 'src/rule-words.mjs', 'data/risk-rules/ai-agent-baseline.json']);
const guardRules = () => { try { return JSON.parse(readFileSync(GUARD_PACK, 'utf8')).rules; } catch { return null; } };

// The signed ingest request of docs/contract.md (same as src/client.mjs submit()): HMAC-SHA256 over `${timestamp}.${nonce}.${body}`.
// Resolves the HTTP status and the response text (the 202 receipt or the error); a network failure or timeout rejects.
export async function postEvent(config, event, {timeoutMs = TIMEOUT_MS} = {}) {
  const body = JSON.stringify(event), timestamp = String(Date.now()), nonce = randomUUID();
  const signature = createHmac('sha256', Buffer.from(config.hmacSecret, 'utf8')).update(`${timestamp}.${nonce}.${body}`).digest('hex');
  const response = await fetch(new URL('/api/ingest', config.url), {method: 'POST', body, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
    headers: {'content-type': 'application/json', authorization: `Bearer ${config.token}`, 'x-evid-timestamp': timestamp, 'x-evid-nonce': nonce,
      'x-evid-signature': signature}});
  return {status: response.status, text: await response.text()};
}

// agent: one of HOOK_AGENTS; it names the config, spool and log files and the event's tool. input: the hook's stdin (tests pass it);
// write: where the guard's answer goes (stdout).
export async function runHook(agent, {input = null, env = process.env, write = text => process.stdout.write(text)} = {}) {
  if (!HOOK_AGENTS.includes(agent)) return;
  const configPath = hookConfigPath(agent, env);
  const dir = dirname(configPath), spool = hookSpoolPath(agent, configPath), log = join(dir, `${agent}-hook.log`);
  const note = message => { try { appendFileSync(log, `${new Date().toISOString()} ${message}\n`); } catch {} };
  async function send(config, event) {
    try {
      let {status, text} = await postEvent(config, event);
      // An EvidScope from before the executor field refuses it: send the record again without it.
      if (status === 400 && event.executor && /executor/.test(text)) { delete event.executor; ({status} = await postEvent(config, event)); }
      if (status === 202 || status === 409) return 'done';
      if (status >= 400 && status < 500 && status !== 408 && status !== 429) { note(`dropped ${event.id}: HTTP ${status}`); return 'done'; }
      return 'retry';
    } catch { return 'retry'; }
  }
  function keep(events) {
    if (!events.length) return;
    try { if (existsSync(spool) && statSync(spool).size > SPOOL_MAX_BYTES) { note(`spool full, dropped ${events.length}`); return; } } catch {}
    appendFileSync(spool, events.map(e => JSON.stringify(e) + '\n').join(''));
  }
  // Claim the spool by renaming it (atomic), so concurrent hook processes never send the same backlog twice.
  function claimSpool() {
    if (!existsSync(spool)) return [];
    const claimed = `${spool}.${process.pid}.claim`;
    try { renameSync(spool, claimed); } catch { return []; }
    try { return readFileSync(claimed, 'utf8').split('\n').filter(Boolean).flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } }); }
    finally { try { unlinkSync(claimed); } catch {} }
  }
  try {
    let config;
    try { config = JSON.parse(readFileSync(configPath, 'utf8')); } catch { return; }
    if (!config.url || !config.token || !config.hmacSecret) return;
    mkdirSync(dir, {recursive: true});
    let raw;
    try { raw = JSON.parse(input ?? readFileSync(0, 'utf8')); } catch { return; }
    const events = hookEvents(raw, {actor: hookActor(agent, config), policyVersion: config.policyVersion, tool: agent,
      screen: config.screenContent !== false, executor: config.executor === false ? undefined : hookExecutor(raw, {home: env.EVIDSCOPE_HOOK_HOME})});
    if (config.guard === true && agent === 'claude-code' && events[0]?.kind === 'intent') {
      const rules = guardRules(), decision = rules ? guardDecision(events[0], rules) : null;
      if (!rules) note('guard: rule pack unreadable, nothing denied');
      if (decision) {
        events[0].dataCategories = [...(events[0].dataCategories || []).slice(0, 15), GUARD_DENIED];
        write(denyOutput(decision.reason) + '\n');
        note(`guard denied ${events[0].id}: ${decision.rules.join(',')}`);
      }
    }
    const unsent = [];
    for (const event of events) if (unsent.length || await send(config, event) === 'retry') unsent.push(event);
    if (!events.length || unsent.length) { keep(unsent); return; }
    const backlog = claimSpool(), rest = [];
    for (const [n, queued] of backlog.entries()) {
      if (n >= FLUSH_MAX || rest.length) { rest.push(queued); continue; }
      if (await send(config, queued) === 'retry') rest.push(queued);
    }
    keep(rest);
  } catch (error) { note(`error ${error?.message || error}`); }
  finally { process.exitCode = 0; }
}
