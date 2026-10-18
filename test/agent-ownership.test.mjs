// Executors and owners of agents (docs/agent-registry.md, "실행자와 책임자"): the executor the hook reads (OS account, PC, repository,
// git user), the owner map and its inference, auto-registration as discovered entries, the reviewer's owner confirmation, owners on
// alerts, the signed history check, and the accountability report of an export.
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {verifyBundle} from '../src/crypto.mjs';
import {hookExecutor, repositoryName} from '../src/agent-hook-runner.mjs';
import {hookEvents} from '../src/agent-hook-events.mjs';
import {verifyRegistryHistory} from '../src/agent-registry.mjs';
import {AUTO_DISCOVERY_PRINCIPAL, accountabilityReport, inferOwner, matchOwner, ownershipOf} from '../src/agent-ownership.mjs';
import {validateEvent} from '../src/model.mjs';

test('the hook reads the executor from files: account, PC, origin without credentials, git user', () => {
  assert.equal(repositoryName('https://user:secret@git.example.com/Team/Repo.git'), 'git.example.com/team/repo');
  assert.equal(repositoryName('git@git.example.com:team/repo.git'), 'git.example.com/team/repo');
  assert.equal(repositoryName('ssh://git@git.example.com/team/repo/'), 'git.example.com/team/repo');
  assert.equal(repositoryName('/srv/repos/local'), null, 'a local path is no repository name');
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-executor-')), home = join(dir, 'home'), repo = join(dir, 'work', 'repo');
  try {
    mkdirSync(join(repo, '.git'), {recursive: true});mkdirSync(join(repo, 'src'), {recursive: true});mkdirSync(home);
    writeFileSync(join(repo, '.git', 'config'), '[core]\n\tbare = false\n[remote "origin"]\n\turl = https://u:tok@git.example.com/Team/Repo.git\n');
    writeFileSync(join(home, '.gitconfig'), '[user]\n\tname = Dev One\n\temail = Dev.One@Example.com\n');
    const x = hookExecutor({cwd: join(repo, 'src')}, {home, account: 'DevOne', host: 'Dev PC'});
    assert.deepEqual(x, {account: 'devone', host: 'dev-pc', repository: 'git.example.com/team/repo', gitUser: 'dev.one@example.com'});
    assert.ok(!JSON.stringify(x).includes('tok'), 'credentials in the remote never leave the PC');
    writeFileSync(join(repo, '.git', 'config'), '[remote "origin"]\n\turl = git@git.example.com:team/repo.git\n[user]\n\temail = bot@example.com\n');
    assert.equal(hookExecutor({cwd: repo}, {home, account: 'a', host: 'b'}).gitUser, 'bot@example.com', 'the repository user wins');
    assert.deepEqual(hookExecutor({cwd: 'relative/path'}, {home: join(dir, 'none'), account: 'a', host: 'b'}), {account: 'a', host: 'b'});
    const events = hookEvents({hook_event_name: 'PreToolUse', session_id: 's', tool_use_id: 't', tool_name: 'Read', tool_input: {file_path: '/x'}},
      {actor: 'claude-code@b', executor: {account: 'a', host: 'b'}});
    assert.deepEqual(events[0].executor, {account: 'a', host: 'b'});
  } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('the executor field is accepted from agent sources only, with known fields only', () => {
  const agent = {id: 'a', tenant: 't', kind: 'agent'}, tool = {id: 'b', tenant: 't', kind: 'tool'};
  const base = {id: 'e1', kind: 'intent', occurredAt: new Date().toISOString(), traceId: 't1', actionId: 'a1', actor: 'x'};
  assert.deepEqual(validateEvent({...base, executor: {account: 'dev', repository: 'git.example.com/a/b'}}, agent).executor,
    {account: 'dev', repository: 'git.example.com/a/b'});
  assert.throws(() => validateEvent({...base, executor: {email: 'x'}}, agent), /executor/);
  assert.throws(() => validateEvent({...base, executor: {}}, agent), /executor/);
  assert.throws(() => validateEvent({...base, kind: 'execution', executor: {account: 'dev'}}, tool), /executor/);
});

test('the owner map infers in rule order; two owners are a conflict; only a reviewer confirms', () => {
  const map = {version: 2, rules: [
    {id: 'repo-pay', field: 'repository', op: 'prefix', value: 'git.example.com/payments/', team: 'payments', owner: 'pay-lead'},
    {id: 'acct-dev', field: 'account', op: 'eq', value: 'dev', team: 'platform', owner: 'platform-lead'},
    {id: 'host-lab', field: 'host', op: 'suffix', value: '.lab', team: 'research', owner: 'lab-lead'}]};
  assert.equal(matchOwner(map, {executor: {account: 'dev', repository: 'git.example.com/payments/api'}}).ruleId, 'repo-pay', 'first rule wins');
  const one = inferOwner(map, [{executor: {account: 'DEV'}, events: 3}]);
  assert.deepEqual([one.status, one.owner, one.team, one.rule.id, one.rule.mapVersion], ['inferred', 'platform-lead', 'platform', 'acct-dev', 2]);
  const two = inferOwner(map, [{executor: {account: 'dev'}, events: 1}, {executor: {host: 'pc1.lab'}, events: 2}]);
  assert.equal(two.status, 'conflict');assert.deepEqual(two.candidates.map(c => c.owner), ['lab-lead', 'platform-lead']);
  assert.equal(inferOwner(map, [{executor: {account: 'other'}, events: 1}]).status, 'unknown');
  assert.equal(inferOwner(null, [{executor: {account: 'dev'}, events: 1}]).status, 'unknown');
  const auto = {id: 'x', owner: '', registeredBy: AUTO_DISCOVERY_PRINCIPAL};
  assert.equal(ownershipOf(auto, one).status, 'inferred');
  assert.equal(ownershipOf({...auto, owner: 'someone'}, one).status, 'inferred', 'an owner on an auto entry without a confirmation is not confirmed');
  assert.equal(ownershipOf({...auto, owner: 'pay', ownership: {status: 'confirmed', owner: 'pay', by: 'r', at: 't'}}).status, 'confirmed');
  assert.equal(ownershipOf({...auto, owner: 'new', ownership: {status: 'confirmed', owner: 'old', by: 'r'}}, null).status, 'unknown',
    'a confirmation is for the owner it named');
  assert.deepEqual([ownershipOf({id: 'y', owner: 'ops', registeredBy: 'alice'}).status, ownershipOf({id: 'y', owner: 'ops', catalog: {}}).basis],
    ['confirmed', 'catalog_document'], 'a typed owner is confirmed; a catalog owner is only reported');
});

let h;
test.before(async () => { h = await harness(); });
test.after(async () => { await h?.close(); });
const call = (path, body, role = 'reviewer') => h.api(path, {body, role});
const send = async event => {
  const r = await submit(h.ingress.url, h.principal('agent'), {occurredAt: new Date().toISOString(), kind: 'intent', status: 'requested', ...event});
  assert.equal(r.status, 202, JSON.stringify(r.body));
};
async function analyzeAll() {for (let i = 0; i < 20; i++) {const r = (await h.analyze()).body;if (!r.backlog && !r.processed) return;}}

test('auto-registration, owner inference and confirmation end to end', async () => {
  const dev = {account: 'dev', host: 'pc-1', repository: 'git.example.com/payments/api', gitUser: 'dev@example.com'};
  await send({id: 'w1', actionId: 'w1', traceId: 's1', actor: 'claude-code@pc-1', tool: 'claude-code', action: 'shell_exec', resource: 'npm test', executor: dev});
  await send({id: 'w2', actionId: 'w2', traceId: 's1', actor: 'claude-code@pc-1', tool: 'claude-code', action: 'file_read', resource: '/etc/shadow', executor: dev});
  await send({id: 'w3', actionId: 'w3', traceId: 's2', actor: 'codex@pc-2', tool: 'codex', action: 'file_read', resource: 'readme.md',
    executor: {account: 'guest', host: 'pc-2'}});
  let candidates = (await call('/api/registry/candidates', undefined, 'auditor')).body;
  const cc = candidates.items.find(c => c.actor === 'claude-code@pc-1');
  assert.deepEqual([cc.executors[0].executor, cc.executors[0].events, cc.owner.status, candidates.autoRegister], [dev, 2, 'unknown', 'off']);

  assert.equal((await call('/api/registry/owners', {rules: []})).status, 403, 'the owner map is admin-only');
  assert.equal((await call('/api/registry/owners', {rules: [{id: 'r', field: 'email', value: 'x', owner: 'y'}]}, 'admin')).status, 400);
  const map = await call('/api/registry/owners', {rules: [
    {id: 'payments-repo', field: 'repository', op: 'prefix', value: 'git.example.com/payments/', team: 'payments', owner: 'pay-lead'}]}, 'admin');
  assert.deepEqual([map.status, map.body.version], [200, 1]);
  candidates = (await call('/api/registry/candidates', undefined, 'auditor')).body;
  assert.equal(candidates.items.find(c => c.actor === 'claude-code@pc-1').owner.owner, 'pay-lead');
  assert.equal((await call('/api/registry', undefined, 'auditor')).body.items.length, 0, 'nothing registered while autoRegister is off');

  assert.equal((await call('/api/registry/policy', {autoRegister: 'always'}, 'admin')).status, 400);
  assert.equal((await call('/api/registry/policy', {autoRegister: 'discovered'}, 'admin')).body.autoRegister, 'discovered');
  const preview = await call('/api/registry/discover', {dryRun: true});
  assert.deepEqual([preview.status, preview.body.registered.length], [200, 2]);
  assert.equal((await call('/api/registry', undefined, 'auditor')).body.items.length, 0, 'a dry run writes nothing');
  assert.equal((await call('/api/registry/discover', {}, 'auditor')).status, 403);
  const run = (await call('/api/registry/discover', {})).body;
  assert.deepEqual(run.registered.map(r => [r.id, r.owner.status]).sort(), [['claude-code@pc-1', 'inferred'], ['codex@pc-2', 'unknown']]);
  assert.deepEqual((await call('/api/registry/discover', {})).body.registered, [], 'a registered candidate is not registered twice');
  assert.ok(!(await call('/api/registry/candidates', undefined, 'auditor')).body.items.some(c => c.actor === 'claude-code@pc-1'));

  const list = (await call('/api/registry', undefined, 'auditor')).body;
  const entry = list.items.find(i => i.id === 'claude-code@pc-1');
  assert.deepEqual([entry.state, entry.owner, entry.registeredBy, entry.sources, entry.actors, entry.ownerStatus.status, entry.ownerStatus.owner],
    ['discovered', '', AUTO_DISCOVERY_PRINCIPAL, [], [], 'inferred', 'pay-lead']);
  assert.equal(list.policy.autoRegister, 'discovered');
  const id = encodeURIComponent('claude-code@pc-1');
  const toDraft = await call(`/api/registry/${id}/transitions`, {to: 'draft', reason: 'review it'});
  assert.equal(toDraft.status, 200, JSON.stringify(toDraft.body));
  assert.equal((await call(`/api/registry/${id}/transitions`, {to: 'testing', reason: 'pilot'})).status, 200);
  const gate = (await call(`/api/registry/${id}`, undefined, 'auditor')).body.next.find(n => n.to === 'approved').gate;
  assert.ok(gate.unmet.includes('owner-purpose'), 'an inferred owner does not pass the owner gate');

  assert.equal((await call(`/api/registry/${encodeURIComponent('codex@pc-2')}/owner`, {reason: 'take the map'})).status, 409, 'nothing inferred');
  assert.equal((await call(`/api/registry/${id}/owner`, {})).status, 400, 'a reason is required');
  const confirmed = await call(`/api/registry/${id}/owner`, {reason: 'payments lead runs this agent'});
  assert.equal(confirmed.status, 200, JSON.stringify(confirmed.body));
  assert.deepEqual([confirmed.body.change, confirmed.body.owner, confirmed.body.ownership.team, confirmed.body.ownership.by, confirmed.body.ownership.basis.kind],
    ['owner_confirmed', 'pay-lead', 'payments', 'alpha-reviewer', 'owner_map']);
  const detail = (await call(`/api/registry/${id}`, undefined, 'auditor')).body;
  assert.deepEqual([detail.ownership.status, detail.lifecycle.valid, detail.executors[0].events], ['confirmed', true, 2]);
  const typed = await call(`/api/registry/${encodeURIComponent('codex@pc-2')}`, {owner: 'guest-team'});
  assert.equal(typed.body.ownership.by, 'alpha-reviewer', 'an owner typed by a reviewer is confirmed by that reviewer');

  await analyzeAll();
  const alerts = (await call('/api/alerts', undefined, 'auditor')).body.items;
  const shadow = alerts.find(a => a.actionId === 'w2');
  assert.ok(shadow, JSON.stringify(alerts.map(a => [a.actionId, a.code])));
  assert.deepEqual([shadow.accountability.agent.id, shadow.accountability.executor.account, shadow.accountability.owner.status,
    shadow.accountability.owner.owner], ['claude-code@pc-1', 'dev', 'confirmed', 'pay-lead']);

  const bundle = (await call('/api/export', undefined, 'auditor')).body;
  assert.equal(verifyBundle(bundle, readFileSync(join(h.dir, 'trust-anchor.pem'), 'utf8')).valid, true);
  assert.equal(verifyRegistryHistory(bundle.records).valid, true, JSON.stringify(verifyRegistryHistory(bundle.records).problems));
  const report = accountabilityReport(bundle.records, bundle.disclosures);
  assert.deepEqual([report.counts.agents, report.counts.confirmed, report.ownerMap.version], [2, 2, 1]);
  assert.equal(report.agents.find(a => a.id === 'claude-code@pc-1').autoRegistered, true);
  assert.equal(JSON.stringify(accountabilityReport(bundle.records, bundle.disclosures)), JSON.stringify(report), 'same records, same report');

  // A forged history: an owner confirmation signed by the auto-discovery principal, and an auto entry born with an owner.
  const rows = bundle.records.filter(r => r.type === 'agent_registry');
  const forged = rows.map(r => r.payload.change === 'owner_confirmed' ? {...r, principal: AUTO_DISCOVERY_PRINCIPAL} : r);
  assert.ok(verifyRegistryHistory(forged).problems.some(p => p.message.startsWith('owner confirmation')));
  const born = rows.map(r => r.payload.version === 1 && r.payload.registeredBy === AUTO_DISCOVERY_PRINCIPAL ? {...r, payload: {...r.payload, owner: 'x'}} : r);
  assert.ok(verifyRegistryHistory(born).problems.some(p => p.message.startsWith('auto-registered entry')));
});
