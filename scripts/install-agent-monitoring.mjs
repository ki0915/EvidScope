#!/usr/bin/env node
// Sets up AI coding agent monitoring on a local EvidScope (docs/agent-monitoring.md), for Claude Code (--agent claude-code, the
// default) or Codex CLI (--agent codex):
//  1. registers the agent as an asset (actor <agent>@<host>, tool <agent>) so its records are not "unregistered";
//  2. loads data/risk-rules/ai-agent-baseline.json as tenant rules: a reviewer drafts and tests each one, an admin approves it
//     (the rule API's four-eyes rule); rules already active with the same field, operator, value, severity and title are left alone;
//  3. writes the hook config (~/.evidscope/<agent>-hook.json) with the tenant's agent source credentials;
//  4. with --claude-settings (Claude Code) adds the PreToolUse/PostToolUse hook to ~/.claude/settings.json, with --codex-hooks (Codex)
//     to ~/.codex/hooks.json ($CODEX_HOME when set); a copy of the old file is kept next to it. Codex runs a new hook only after the
//     user trusts it with /hooks in the Codex CLI. Without the flag the hook entry is printed for review. --hook-dir copies the hook
//     and its two modules to that folder first and points the command there (for repositories under a non-ASCII or spaced path,
//     e.g. a Korean Windows user folder).
// usage: node scripts/install-agent-monitoring.mjs --local-dir <EVIDSCOPE_LOCAL_DIR> [--agent claude-code|codex] [--port-base 8080]
//        [--tenant alpha] [--host 127.0.0.1] [--hook-dir C:/evidscope-work/hook] [--claude-settings | --codex-hooks] [--dry-run]
import {readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync} from 'node:fs';
import {homedir, hostname} from 'node:os';
import {join, resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {HOOK_AGENTS} from '../src/agent-hook-events.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2), flag = name => args.includes(name);
const option = (name, fallback) => { const i = args.indexOf(name); return i >= 0 && args[i + 1] ? args[i + 1] : fallback; };
const agent = option('--agent', 'claude-code');
if (!HOOK_AGENTS.includes(agent)) throw Error(`--agent is one of ${HOOK_AGENTS.join(', ')}`);
const localDir = resolve(option('--local-dir', join(root, '.local'))), tenant = option('--tenant', 'alpha');
const host = option('--host', '127.0.0.1'), portBase = Number(option('--port-base', '8080')), dryRun = flag('--dry-run');
const hostPart = host === '::1' ? '[::1]' : host, auditUrl = `http://${hostPart}:${portBase + 2}`, ingestUrl = `http://${hostPart}:${portBase + 1}`;
const actor = `${agent}@${hostname().toLowerCase().replace(/[^a-z0-9.-]/g, '-')}`;
const policyVersion = `${agent}-monitoring-v1`, label = agent === 'codex' ? 'Codex CLI' : 'Claude Code';

const config = JSON.parse(readFileSync(join(localDir, 'config.json'), 'utf8'));
const principal = (role, kind) => config.principals.find(p => p.tenant === tenant && p.role === role && (kind === undefined || p.kind === kind));
const reviewer = principal('reviewer'), admin = principal('admin'), source = principal('source', 'agent');
if (!reviewer || !admin || !source) throw Error(`tenant ${tenant} needs reviewer, admin and agent source principals in ${localDir}/config.json`);

async function api(who, method, path, body) {
  if (dryRun && method !== 'GET') { console.log(`[dry-run] ${method} ${path} as ${who.id}`); return {}; }
  const response = await fetch(new URL(path, auditUrl), {method, headers: {authorization: `Bearer ${who.token}`, 'content-type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual', signal: AbortSignal.timeout(15000)});
  const text = await response.text();
  if (!response.ok) throw Error(`${method} ${path}: HTTP ${response.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : {};
}

const pack = JSON.parse(readFileSync(join(root, 'data/risk-rules/ai-agent-baseline.json'), 'utf8'));
const summary = {agent, asset: null, rules: {added: 0, unchanged: 0}, hookConfig: null, agentSettings: 'not changed'};

const assets = (await api(reviewer, 'GET', '/api/assets')).items || [];
if (!assets.some(a => a.actor === actor && a.tool === agent && a.policyVersion === policyVersion)) {
  await api(reviewer, 'POST', '/api/assets', {id: `asset.${actor.replace('@', '.')}`.slice(0, 120), actor, tool: agent,
    owner: 'local user', purpose: `AI coding agent on this PC (${label}), monitored through its tool-call hook`, approvalRequired: false,
    policyVersion, validFrom: new Date(Date.now() - 60000).toISOString()});
  summary.asset = 'registered';
} else summary.asset = 'already registered';

const active = new Map(((await api(reviewer, 'GET', '/api/rules')).items || []).filter(v => v.status === 'active').map(v => [v.id, v]));
for (const rule of pack.rules) {
  const current = active.get(rule.id);
  // Pack version 1 rules name no field or operator: a substring of the resource.
  const field = rule.field || 'resource', op = rule.op || 'contains';
  if (current && current.value === rule.value && current.severity === rule.severity && current.field === field && current.op === op
    && current.title === rule.title) { summary.rules.unchanged++; continue; }
  const draft = await api(reviewer, 'POST', '/api/rules', {id: rule.id, title: rule.title, field, op, value: rule.value, severity: rule.severity});
  await api(reviewer, 'POST', `/api/rules/${rule.id}/test`, {version: draft.version});
  await api(admin, 'POST', `/api/rules/${rule.id}/approve`, {version: draft.version});
  summary.rules.added++;
}

const configDir = join(homedir(), '.evidscope'), hookConfig = join(configDir, `${agent}-hook.json`);
if (!dryRun) {
  mkdirSync(configDir, {recursive: true});
  const hook = {url: ingestUrl, token: source.token, hmacSecret: source.hmacSecret, actor, policyVersion};
  writeFileSync(hookConfig, JSON.stringify(hook, null, 1) + '\n', {mode: 0o600});
}
summary.hookConfig = hookConfig;

const hookFile = `scripts/${agent}-hook.mjs`, hookDir = option('--hook-dir');
let hookRoot = root;
if (hookDir) {
  hookRoot = resolve(hookDir);
  if (!dryRun) for (const file of [hookFile, 'src/agent-hook-runner.mjs', 'src/agent-hook-events.mjs']) {
    mkdirSync(dirname(join(hookRoot, file)), {recursive: true}); copyFileSync(join(root, file), join(hookRoot, file));
  }
}
const hookScript = join(hookRoot, hookFile).replace(/\\/g, '/');
const command = /^[A-Za-z0-9:/._-]+$/.test(hookScript) ? `node ${hookScript}` : `node "${hookScript}"`;
const entry = {matcher: '*', hooks: [{type: 'command', command, timeout: 10}]};
const settingsFlag = agent === 'codex' ? '--codex-hooks' : '--claude-settings';
const settingsFile = agent === 'codex' ? join(process.env.CODEX_HOME || join(homedir(), '.codex'), 'hooks.json')
  : join(homedir(), '.claude', 'settings.json');
if (flag(settingsFlag)) {
  // trimStart() also drops a UTF-8 byte order mark, which Windows editors may leave at the start of the file.
  const settings = existsSync(settingsFile) ? JSON.parse(readFileSync(settingsFile, 'utf8').trimStart()) : {};
  settings.hooks ??= {};
  let added = 0;
  for (const name of ['PreToolUse', 'PostToolUse']) {
    const list = settings.hooks[name] ??= [];
    const ours = list.flatMap(group => (group.hooks || []).filter(h => typeof h.command === 'string' && h.command.includes(hookFile.slice('scripts/'.length))));
    if (!ours.length) { list.push(structuredClone(entry)); added++; }
    for (const h of ours) if (h.command !== command) { h.command = command; added++; }
  }
  if (added && !dryRun) {
    if (existsSync(settingsFile)) copyFileSync(settingsFile, `${settingsFile}.before-evidscope-${new Date().toISOString().replace(/[:.]/g, '-')}`);
    mkdirSync(dirname(settingsFile), {recursive: true});
    writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + '\n');
  }
  summary.agentSettings = added ? `hook added or updated in ${settingsFile}` + (agent === 'codex' ? '; trust it with /hooks in Codex' : '')
    : 'hook already present';
} else console.log(`Add to ${settingsFile} under "hooks" (PreToolUse and PostToolUse):\n${JSON.stringify(entry, null, 2)}`);
console.log(JSON.stringify({auditUrl, ingestUrl, actor, ...summary}, null, 1));
