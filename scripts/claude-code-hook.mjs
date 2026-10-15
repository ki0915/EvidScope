#!/usr/bin/env node
// Claude Code PreToolUse/PostToolUse hook -> EvidScope ingest (docs/agent-monitoring.md). Installed by
// scripts/install-agent-monitoring.mjs as `node <repo>/scripts/claude-code-hook.mjs` in ~/.claude/settings.json.
// It never blocks or changes the tool call: it prints nothing and always exits 0. Events that cannot be delivered (EvidScope not
// running) wait in a local spool and go out with the next call that can reach it.
// Config (EVIDSCOPE_HOOK_CONFIG or ~/.evidscope/claude-code-hook.json): {"url":"http://127.0.0.1:8091","token":"…","hmacSecret":"…",
// "actor":"claude-code@pc","policyVersion":"claude-code-monitoring-v1"}: the url is the ingest gateway (local launcher port base + 1),
// the credentials an `agent` source's.
// It imports only src/agent-hook-events.mjs (node built-ins only), so the installer can copy the pair to a plain ASCII path: a
// Korean or spaced user folder in a hook command line is fragile across the shells Claude Code may run hooks with.
import {readFileSync, appendFileSync, renameSync, statSync, mkdirSync, existsSync, unlinkSync} from 'node:fs';
import {createHmac, randomUUID} from 'node:crypto';
import {homedir, hostname} from 'node:os';
import {join, dirname} from 'node:path';
import {hookEvent} from '../src/agent-hook-events.mjs';

const configPath = process.env.EVIDSCOPE_HOOK_CONFIG || join(homedir(), '.evidscope', 'claude-code-hook.json');
const SPOOL_MAX_BYTES = 5 * 1024 * 1024, FLUSH_MAX = 20, TIMEOUT_MS = 1000;
const dir = dirname(configPath), spool = join(dir, 'claude-code-spool.jsonl'), log = join(dir, 'claude-code-hook.log');
const note = message => { try { appendFileSync(log, `${new Date().toISOString()} ${message}\n`); } catch {} };

// The signed ingest request of docs/contract.md (same as src/client.mjs submit()): HMAC-SHA256 over `${timestamp}.${nonce}.${body}`.
async function post(config, event) {
  const body = JSON.stringify(event), timestamp = String(Date.now()), nonce = randomUUID();
  const signature = createHmac('sha256', Buffer.from(config.hmacSecret, 'utf8')).update(`${timestamp}.${nonce}.${body}`).digest('hex');
  const response = await fetch(new URL('/api/ingest', config.url), {method: 'POST', body, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: {'content-type': 'application/json', authorization: `Bearer ${config.token}`, 'x-evid-timestamp': timestamp, 'x-evid-nonce': nonce,
      'x-evid-signature': signature}});
  await response.arrayBuffer();
  return response.status;
}
async function send(config, event) {
  try {
    const status = await post(config, event);
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

async function main() {
  let config;
  try { config = JSON.parse(readFileSync(configPath, 'utf8')); } catch { return; }
  if (!config.url || !config.token || !config.hmacSecret) return;
  mkdirSync(dir, {recursive: true});
  let raw;
  try { raw = JSON.parse(readFileSync(0, 'utf8')); } catch { return; }
  const actor = config.actor || `claude-code@${hostname().toLowerCase().replace(/[^a-z0-9.-]/g, '-')}`;
  const event = hookEvent(raw, {actor, policyVersion: config.policyVersion});
  if (!event) return;
  if (await send(config, event) === 'retry') { keep([event]); return; }
  const backlog = claimSpool(), rest = [];
  for (const [n, queued] of backlog.entries()) {
    if (n >= FLUSH_MAX || rest.length) { rest.push(queued); continue; }
    if (await send(config, queued) === 'retry') rest.push(queued);
  }
  keep(rest);
}
main().catch(error => note(`error ${error?.message || error}`)).finally(() => { process.exitCode = 0; });
