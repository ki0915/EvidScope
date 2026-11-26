#!/usr/bin/env node
// Imports the past tool calls of an AI coding agent from the transcripts it keeps on this PC into the local EvidScope, so the risk and
// sequence rules also audit what it did before its hook was installed (docs/agent-monitoring.md, "지난 행동 가져오기"; the reading is
// src/agent-history.mjs). It uses the hook config the installer wrote (~/.evidscope/<agent>-hook.json: ingest URL, agent source
// credentials, actor) and signs each record like the live hook. Tokens and secrets are never printed.
// usage: node scripts/import-agent-history.mjs [--agent claude-code|codex] [--dir <transcripts>] [--since <ISO>] [--until <ISO>]
//        [--limit <n>] [--dry-run] [--config <hook config>] [--include-sidechains]
// Exits 1 only when it cannot run or EvidScope stops taking records (running it again is safe: what is stored counts as already
// present), 2 on a usage error.
import {existsSync, readFileSync, statSync} from 'node:fs';
import {HOOK_AGENTS} from '../src/agent-hook-events.mjs';
import {hookActor, hookConfigPath, hookSpoolPath, postEvent} from '../src/agent-hook-runner.mjs';
import {HistoryImportError, defaultHistoryDir, readAgentHistory, sendHistory} from '../src/agent-history.mjs';

const USAGE = 'usage: node scripts/import-agent-history.mjs [--agent claude-code|codex] [--dir <transcripts>] [--since <ISO>] [--until <ISO>]\n'
  + '       [--limit <n>] [--dry-run] [--config <hook config>] [--include-sidechains]';
const VALUES = ['--agent', '--dir', '--since', '--until', '--limit', '--config'], FLAGS = ['--dry-run', '--include-sidechains'];
class UsageError extends Error {}

function parseArgs(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (FLAGS.includes(args[i])) options[args[i]] = true;
    else if (VALUES.includes(args[i]) && i + 1 < args.length) options[args[i]] = args[++i];
    else throw new UsageError(`Unknown or incomplete argument: ${args[i]}`);
  }
  const agent = options['--agent'] || 'claude-code';
  if (!HOOK_AGENTS.includes(agent)) throw new UsageError(`--agent is one of ${HOOK_AGENTS.join(', ')}`);
  const when = name => {
    const value = options[name];
    if (value === undefined) return undefined;
    if (!/^\d{4}-\d\d-\d\d/.test(value) || !Number.isFinite(Date.parse(value))) {
      throw new UsageError(`${name} needs an ISO date or time, e.g. 2026-09-01T00:00:00Z`);
    }
    return new Date(value);
  };
  const raw = options['--limit'];
  if (raw !== undefined && !/^[1-9]\d{0,8}$/.test(raw)) throw new UsageError('--limit needs a positive whole number');
  return {agent, dryRun: !!options['--dry-run'], sidechains: !!options['--include-sidechains'], since: when('--since'), until: when('--until'),
    limit: raw === undefined ? undefined : Number(raw), dir: options['--dir'] || defaultHistoryDir(agent),
    configPath: options['--config'] || hookConfigPath(agent)};
}

// Projects and sessions with their call counts and time span, then the first intents as they would be sent.
function preview(calls) {
  const projects = new Map();
  for (const call of calls) {
    const sessions = projects.get(call.project) || projects.set(call.project, new Map()).get(call.project);
    const s = sessions.get(call.session) || sessions.set(call.session, {calls: 0, outcomes: 0, first: call.at, last: call.at}).get(call.session);
    s.calls++; if (call.hasOutcome) s.outcomes++; s.last = call.at;
  }
  const lines = [`Dry run: nothing is sent. ${calls.length} tool call(s) in ${[...projects.values()].reduce((n, s) => n + s.size, 0)} session(s).`];
  for (const [project, sessions] of projects) {
    lines.push(`${project}: ${sessions.size} session(s), ${[...sessions.values()].reduce((n, s) => n + s.calls, 0)} call(s)`);
    for (const [session, s] of sessions) {
      lines.push(`  ${session}  ${s.first.toISOString()} .. ${s.last.toISOString()}  ${s.calls} call(s), ${s.outcomes} with an outcome`);
    }
  }
  lines.push('First records, as they would be sent:');
  for (const call of calls.slice(0, 5)) { const [intent] = call.records; lines.push(`  ${intent.occurredAt} ${intent.kind} ${intent.action} ${intent.note}`); }
  return lines.join('\n');
}

// Records the live hook could not send yet wait in its spool and go out with its next call: they are not sent again here.
function queuedIds(spool) {
  const ids = new Set();
  try {
    for (const line of readFileSync(spool, 'utf8').split('\n')) {
      try { const id = JSON.parse(line)?.id; if (typeof id === 'string') ids.add(id); } catch {}
    }
  } catch {}
  return ids;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (!existsSync(o.dir) || !statSync(o.dir).isDirectory()) { console.error(`No transcript folder at ${o.dir}; pass --dir <folder>.`); return 1; }
  let config = null;
  try { config = JSON.parse(readFileSync(o.configPath, 'utf8').trimStart()); } catch {}
  const usable = !!config && typeof config.url === 'string' && !!config.url && !!config.token && !!config.hmacSecret;
  if (!usable && !o.dryRun) {
    console.error(`No usable hook config at ${o.configPath}: set up monitoring first (scripts/install-agent-monitoring.mjs) or pass --config.`);
    return 1;
  }
  const actor = hookActor(o.agent, config || {});
  const {calls, stats} = await readAgentHistory({...o, actor, policyVersion: config?.policyVersion});
  const summary = {agent: o.agent, dir: o.dir, dryRun: o.dryRun, ingest: usable ? config.url : null, actor,
    files: {read: stats.files, unreadable: stats.unreadableFiles}, malformedLines: stats.malformedLines,
    toolCalls: {found: stats.calls, selected: calls.length, withOutcome: stats.withOutcome, malformed: stats.malformedCalls, skipped: stats.skipped},
    records: {built: calls.reduce((n, call) => n + call.records.length, 0)}};
  if (o.dryRun) {
    console.log(preview(calls));
    if (!usable) console.log(`No usable hook config at ${o.configPath} yet: the actor shown is the default one.`);
    console.log(JSON.stringify(summary, null, 1));
    return 0;
  }
  try {
    Object.assign(summary.records, await sendHistory(calls, {send: event => postEvent(config, event, {timeoutMs: 30000}),
      skip: queuedIds(hookSpoolPath(o.agent, o.configPath)), onProgress: (done, total) => console.error(`${done}/${total} tool calls sent`)}));
  } catch (error) {
    if (!(error instanceof HistoryImportError)) throw error;
    Object.assign(summary.records, error.result, {stopped: error.message});
    console.log(JSON.stringify(summary, null, 1));
    console.error(error.message);
    return 1;
  }
  console.log(JSON.stringify(summary, null, 1));
  return 0;
}

try { process.exitCode = await main(); }
catch (error) {
  if (!(error instanceof UsageError)) throw error;
  console.error(`${error.message}\n${USAGE}`);
  process.exitCode = 2;
}
