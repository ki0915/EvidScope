#!/usr/bin/env node
// Recording proxy for local model servers (docs/local-model-proxy.md, src/local-model-proxy.mjs).
//   init: writes ~/.evidscope/local-model-proxy.json (EVIDSCOPE_PROXY_CONFIG) with the agent source credentials of an existing hook
//         config (~/.evidscope/claude-code-hook.json, else codex-hook.json, or --from <file>) and the given options. With --local-dir
//         it also registers the proxy as an asset on that local EvidScope (actor local-model-proxy@<pc>, tool local-model-proxy), so
//         its records are not "unregistered". It registers nothing on the PC: no service, no autostart, no system proxy setting.
//   run:  starts the proxy in the foreground until Ctrl+C. Options given here override the config for this run.
// usage: node scripts/local-model-proxy.mjs init [--from <hook config>] [--upstream http://127.0.0.1:11434] [--listen 127.0.0.1:11435]
//          [--provider ollama|vllm|llama.cpp|local|other] [--record-text | --no-record-text] [--no-screen]
//          [--local-dir <EVIDSCOPE_LOCAL_DIR> [--tenant alpha] [--port-base 8080]]
//        node scripts/local-model-proxy.mjs run [same options]
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {dirname, join} from 'node:path';
import {PROXY_DEFAULTS, PROXY_POLICY, PROXY_TOOL, proxyActor, proxyAsset, proxyConfigPath, startModelProxy} from '../src/local-model-proxy.mjs';

const [command, ...args] = process.argv.slice(2), flag = name => args.includes(name);
const option = name => { const i = args.indexOf(name); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
const overrides = Object.fromEntries(Object.entries({upstream: option('--upstream'), listen: option('--listen'), provider: option('--provider'),
  recordText: flag('--record-text') ? true : flag('--no-record-text') ? false : undefined, screenContent: flag('--no-screen') ? false : undefined})
  .filter(([, v]) => v !== undefined));
const path = proxyConfigPath();
const read = file => { try { return JSON.parse(readFileSync(file, 'utf8')); } catch { return null; } };

// The asset registration of scripts/install-agent-monitoring.mjs, for the proxy: the tenant reviewer of the local EvidScope registers it.
async function register(config) {
  const local = read(join(option('--local-dir'), 'config.json')), tenant = option('--tenant') || 'alpha';
  const reviewer = local?.principals?.find(p => p.tenant === tenant && p.role === 'reviewer');
  if (!reviewer) throw Error(`no reviewer of tenant ${tenant} in ${option('--local-dir')}/config.json`);
  const audit = `http://127.0.0.1:${Number(option('--port-base') || 8080) + 2}`;
  const api = async (method, path, body) => {
    const r = await fetch(new URL(path, audit), {method, headers: {authorization: `Bearer ${reviewer.token}`, 'content-type': 'application/json'},
      body: body && JSON.stringify(body), redirect: 'manual', signal: AbortSignal.timeout(15000)});
    const text = await r.text();
    if (!r.ok) throw Error(`${method} ${path}: HTTP ${r.status} ${text.slice(0, 300)}`);
    return text ? JSON.parse(text) : {};
  };
  const items = (await api('GET', '/api/assets')).items || [];
  if (items.some(a => a.actor === config.actor && a.tool === PROXY_TOOL)) return 'already registered';
  await api('POST', '/api/assets', {id: config.assetRef, actor: config.actor, tool: PROXY_TOOL, owner: 'local user', approvalRequired: false,
    purpose: `recording proxy in front of the local model server ${config.upstream}`, policyVersion: config.policyVersion || PROXY_POLICY,
    validFrom: new Date(Date.now() - 60000).toISOString()});
  return 'registered';
}

if (command === 'init') {
  const from = option('--from') || ['claude-code', 'codex'].map(a => join(homedir(), '.evidscope', `${a}-hook.json`)).find(existsSync);
  const hook = from && read(from), old = read(path) || {};
  if (!hook?.url || !hook.token || !hook.hmacSecret) {
    console.error('no hook config with url, token and hmacSecret found: install agent monitoring first or pass --from <file>');
    process.exit(2);
  }
  const config = {...PROXY_DEFAULTS, actor: proxyActor(), ...old, url: hook.url, token: hook.token, hmacSecret: hook.hmacSecret, ...overrides};
  config.assetRef ||= proxyAsset(config.actor);
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, JSON.stringify(config, null, 2) + '\n', {mode: 0o600});
  const asset = option('--local-dir') ? await register(config) : 'not registered (no --local-dir)';
  console.log(JSON.stringify({config: path, upstream: config.upstream, listen: config.listen, provider: config.provider,
    screenContent: config.screenContent, recordText: config.recordText, asset}, null, 2));
} else if (command === 'run') {
  const config = read(path);
  if (!config) { console.error(`no proxy config at ${path}: run init first`); process.exit(2); }
  const proxy = await startModelProxy({config: {...config, ...overrides}, configPath: path});
  console.log(`recording proxy ${proxy.url} -> ${proxy.context.upstream} (text ${{...config, ...overrides}.recordText ? 'archived' : 'not stored'})`);
  const stop = async () => { await proxy.beat('stop'); await proxy.close(); process.exit(0); };
  process.on('SIGINT', stop);process.on('SIGTERM', stop);
} else {
  console.error('usage: node scripts/local-model-proxy.mjs init|run [options] (see the header of this file)');
  process.exit(2);
}
