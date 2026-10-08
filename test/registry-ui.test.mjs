// Agent registry screen (public/registry.js, docs/agent-registry.md): list, candidates, detail with gates and history,
// transition requests, approvals and draft creation, rendered as text only, without a browser dependency.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.value = ''; this.ownText = ''; this.className = ''; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Unsafe HTML rendering'); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; this.ownText = ''; }
  setAttribute(key, value) { this[key] = value; }
  addEventListener(key, listener) { this.events[key] = listener; }
}
const all = node => [node, ...node.children.flatMap(all)];
const el = (tag, className = '', text) => {
  const node = new Element(tag); node.className = className; if (text !== undefined) node.textContent = text; return node;
};
function fixture(responses) {
  const routes = new Map(), calls = [], details = [], navigations = [];
  const card = (title, description = '') => { const node = el('section', 'card'); node.append(el('h2', '', title), el('p', '', description)); return node; };
  const core = {
    el, card, empty: card, date: value => value || '미확인', limits: items => el('p', '', (items || []).join('\n')),
    jsonDetails: (title, data) => { const node = el('details'); node.append(el('summary', '', title), el('pre', '', JSON.stringify(data))); return node; },
    button: (text, action, className = '') => { const node = el('button', className, text); node.events.click = action; return node; },
    field: (title, name, options = {}) => { const node = el('label', 'field', title), input = el('input'); input.name = name; input.value = options.value ?? '';
      if (options.choices) input.choices = options.choices.map(c => c.value ?? c); node.append(input); return node; },
    form: (fields, submitText, onSubmit) => { const node = el('form'), result = el('div'); node.append(...fields, result, el('button', 'primary', submitText));
      node.events.submit = async values => {
        try { await onSubmit(values, result); } catch (error) { result.append(el('div', 'message error', error.message)); }
      };
      return node; },
    table: (headers, rows) => { const node = el('table'); node.append(...headers.map(text => el('th', '', text)));
      for (const row of rows) { const tr = el('tr'); tr.append(...row.map(value => value instanceof Element ? value : el('td', '', value))); node.append(tr); }
      return node; },
    factList: entries => {
      const node = el('dl'); for (const [title, value] of entries) node.append(el('dt', '', title), el('dd', '', value || '미수집')); return node;
    },
    registerView: (id, title, description, render) => routes.set(id, {title, description, render}),
    showDetail: (title, node) => details.push({title, node}), captureDetailContext: () => ({}), isCurrentDetail: () => true,
    navigate: view => navigations.push(view),
    api: async (path, method = 'GET', body) => { calls.push({path, method, body: body === undefined ? undefined : JSON.parse(JSON.stringify(body))});
      const value = responses(path, method, body); if (value instanceof Error) throw value; return value; },
  };
  const sandbox = {window: {EvidScopeCore: core}};
  vm.runInNewContext(readFileSync('public/registry.js', 'utf8'), sandbox);
  return {ui: sandbox.window.EvidScopeRegistry, routes, calls, details, navigations, last: () => details.at(-1).node};
}
const button = (root, text) => all(root).find(node => node.tagName === 'button' && node.textContent === text);
const forms = root => all(root).filter(node => node.tagName === 'form');
const hostile = '<img src=x onerror=alert(1)>';
const gate = met => ({tier: 'high', target: 'approved', policyVersion: 0, policySource: 'built_in_default', met,
  conditions: [{id: 'owner-purpose', check: 'fields_present', met: true, detail: {missing: []}}, {id: 'otlp-in-testing', check: 'events_in_state',
    met, detail: {count: met ? 1 : 0}}]});
const entry = {id: 'pay-agent', name: hostile, state: 'testing', version: 3, owner: 'ops', purpose: 'payments', sources: ['alpha-agent'], actors: ['pay-agent'],
  assetIds: [], systemId: null, models: [], tools: [{name: 'payment_transfer', enforcement: 'required'}], dataCategories: ['financial'], destinations: []};
const detail = {entry, risk: {tier: 'high', computed: 'high', reasons: [{rule: 'tool-payment', value: 'payment_transfer'}], override: null},
  versions: [{seq: 4, version: 1, state: 'draft', change: 'created', principal: 'alice', effectiveFrom: 't1'}],
  transitions: [{id: 't-1', agentId: 'pay-agent', from: 'testing', to: 'approved', status: 'pending', requestedBy: 'bob', reason: 'ready', gate: gate(true)}],
  transitionRecords: [{seq: 9, id: 't-1', from: 'testing', to: 'approved', status: 'pending', requestedBy: 'bob', reason: 'ready'}],
  next: [{to: 'approved', approvalRequired: true, gate: gate(false)}, {to: 'retired', approvalRequired: false, gate: gate(true)}],
  lifecycle: {valid: true, problems: []}, policy: {version: 0, source: 'built_in_default', enforcement: 'off'}};

test('the registry view lists entries and unregistered candidates as text and is reachable from the agent section', async () => {
  const f = fixture(path => path === '/api/registry' ? {items: [{...entry, effectiveRisk: 'high', pendingTransition: detail.transitions[0]}],
    policy: {version: 2, source: 'signed', enforcement: 'unregistered_activity'}, limitations: ['EvidScope는 실행을 차단하지 않습니다']}
    : {items: [{source: 'alpha-agent', actor: hostile, reasons: ['observed_activity'], actions: 2, events: 3, tools: ['mailer'], lastSeen: 't',
      suggestedId: 'img'}],
      limitations: ['후보 목록이며 자동 등록하지 않습니다']});
  const view = f.routes.get('registry');
  assert.match(view.description, /차단하지 않습니다/);
  const node = await view.render();
  assert.deepEqual(f.calls.map(c => [c.path, c.method]), [['/api/registry', 'GET'], ['/api/registry/candidates', 'GET']]);
  const text = node.textContent;
  for (const expected of ['정책 v2', '미등록 활동 발견 켜짐', '시험', '높음', 'testing → approved', '자동 등록하지 않습니다', hostile]) assert.ok(text.includes(expected), expected);
  await button(node, '초안으로').events.click();
  const [create] = forms(f.last());
  assert.equal(all(create).find(n => n.name === 'id').value, 'img');
  assert.equal(all(create).find(n => n.name === 'actors').value, hostile, 'prefilled values stay text');
  const html = readFileSync('public/index.html', 'utf8'), consoleSource = readFileSync('public/console.js', 'utf8');
  assert.match(html, /<script src="\/registry\.js" defer><\/script>/);
  assert.ok(consoleSource.includes("['registry', '에이전트 레지스트리']"));
  assert.ok(readFileSync('src/server.mjs', 'utf8').includes("'/registry.js'"));
  const failed = fixture(path => path === '/api/registry' ? {items: [], policy: {version: 0, source: 'built_in_default'}} : new Error('403'));
  assert.match((await failed.routes.get('registry').render()).textContent, /후보를 불러오지 못했습니다403/);
});

test('detail shows gates, history and four-eyes approval; requests and decisions post exactly what was entered', async () => {
  const f = fixture((path, method) => method === 'POST' ? {transition: {status: path.endsWith('/transitions') ? 'pending' : 'approved'}} : detail);
  await f.ui.openEntry('pay-agent');
  const node = f.last(), text = node.textContent;
  for (const expected of ['tool-payment: payment_transfer', 'payment_transfer(결정 필수)', '미충족 · otlp-in-testing', '4-eyes', '승인 대기 전이', '생애주기 검증이상 없음', hostile])
    assert.ok(text.includes(expected), expected);
  const [approve, refuse, request] = forms(node), post = () => f.calls.filter(c => c.method === 'POST').at(-1);
  await approve.events.submit({reason: '증거 확인'});
  assert.deepEqual(post(), {path: '/api/registry/transitions/t-1/approve', method: 'POST', body: {reason: '증거 확인'}});
  assert.equal(f.calls.at(-1).path, '/api/registry/pay-agent', 'the detail is reloaded after a decision');
  await forms(f.last())[1].events.submit({reason: '부족'});
  assert.equal(post().path, '/api/registry/transitions/t-1/refuse');
  const before = f.calls.length;
  await forms(f.last())[2].events.submit({to: 'approved', reason: '시험 완료', evidence: 'script:alert(1)'});
  assert.equal(f.calls.length, before, 'an unknown evidence type is refused before posting');
  assert.match(forms(f.last())[2].textContent, /증거 참조는/);
  await forms(f.last())[2].events.submit({to: 'approved', reason: '시험 완료', evidence: 'event:alpha-agent/e-1\nexternal: https://ticket.example/1'});
  assert.deepEqual(post().body, {to: 'approved', reason: '시험 완료',
    evidence: [{type: 'event', ref: 'alpha-agent/e-1'}, {type: 'external', ref: 'https://ticket.example/1'}]});
  assert.ok(f.navigations.includes('registry'), 'the list is refreshed after a change');
  assert.ok(refuse && request);
});

test('a draft is created with explicit lists and tools that require an enforcement decision', async () => {
  const f = fixture((path, method) => method === 'POST' ? {id: 'mail-agent', version: 1, risk: {computed: 'medium'}} : {...detail, entry: {...entry,
    id: 'mail-agent'}});
  const create = f.ui.createForm();
  await create.events.submit({id: ' mail-agent ', name: '', owner: 'ops', purpose: 'mail', sources: 'alpha-agent', actors: 'mail-agent, mail-bot',
    tools: 'mailer, search', enforcedTools: 'mailer', dataCategories: 'customer', destinations: 'smtp.vendor.example', assetIds: '', systemId: '',
      state: 'draft'});
  assert.deepEqual(f.calls[0], {path: '/api/registry', method: 'POST', body: {id: 'mail-agent', owner: 'ops', purpose: 'mail', sources: ['alpha-agent'],
    actors: ['mail-agent', 'mail-bot'], tools: [{name: 'mailer', enforcement: 'required'}, {name: 'search', enforcement: 'not_required'}],
    dataCategories: ['customer'], destinations: ['smtp.vendor.example'], assetIds: [], state: 'draft'}});
  assert.match(create.textContent, /mail-agent v1을 서명했습니다. 위험 등급 계산값: 중간/);
  assert.equal(f.calls[1].path, '/api/registry/mail-agent');
});

test('catalog import posts the pasted document, renders the report as text and shows provenance on the entry', async () => {
  const report = {importId: 'i-1', dryRun: false, summary: {created: 1, updated: 0, unchanged: 0, conflict: 1, skipped: 0, rejected: 0, rejectedDocuments: 0},
    documents: [{index: 0, format: 'a2a-agent-card'}],
    results: [{documentIndex: 0, entityIndex: 0, outcome: 'created', key: 'a2a:https://geo.example/a2a', entry: {id: 'a2a.geo.0123456789'},
      signature: {status: 'verified'}, dropped: [{field: 'skills', reason: 'offered_skills_are_not_tools_used'}]},
    {documentIndex: 0, entityIndex: 1, outcome: 'conflict', reason: 'edited_since_import', key: hostile, entry: {id: 'x'}, dropped: []}],
    limitations: ['카탈로그 문서의 값은 자기 보고입니다']};
  const catalog = {format: 'a2a-agent-card', formatVersion: '1.0', key: 'a2a:https://geo.example/a2a', endpoint: 'https://geo.example/a2a',
    locator: hostile, locatorMatchesEndpoint: false, documentDigest: 'sha256:aa', entityDigest: 'sha256:bb', importedBy: 'alice', importedAt: 't',
    signature: {status: 'unverified', signatures: [{alg: 'ES256', kid: 'k1', status: 'no_supplied_key'}]}, mapped: ['name', 'purpose'], dropped: ['skills']};
  const f = fixture((path, method) => method === 'POST' ? report : {...detail, entry: {...entry, state: 'discovered', catalog}});
  const form = f.ui.importForm(), before = f.calls.length;
  await form.events.submit({format: 'a2a', content: '{"name":"Geo"}', locator: '', agentTypes: '', keys: '{not json', mode: 'import'});
  assert.equal(f.calls.length, before, 'invalid key JSON is refused before posting');
  await form.events.submit({format: 'backstage', content: 'kind: Component', locator: ' https://git.example/catalog-info.yaml ', agentTypes: 'ai-agent, bot',
    keys: '{"keys":[]}', mode: 'preview'});
  assert.deepEqual(f.calls.at(-1), {path: '/api/registry/import', method: 'POST', body: {documents: [{format: 'backstage', content: 'kind: Component',
    locator: 'https://git.example/catalog-info.yaml'}], keys: {keys: []}, agentTypes: ['ai-agent', 'bot'], dryRun: true}});
  await form.events.submit({format: 'a2a', content: '{"name":"Geo"}', locator: '', agentTypes: '', keys: '', mode: 'import'});
  assert.deepEqual(f.calls.at(-1).body, {documents: [{format: 'a2a', content: '{"name":"Geo"}'}], dryRun: false});
  const text = form.textContent;
  for (const expected of ['가져오기 완료', '새로 1', '충돌 1', '새로 등록(발견됨)', '충돌(덮어쓰지 않음)', 'edited_since_import', '제출한 공개 키로 확인',
    'skills(offered_skills_are_not_tools_used)', '자기 보고입니다', hostile]) assert.ok(text.includes(expected), expected);
  assert.ok(f.navigations.includes('registry'), 'the list is refreshed after an import');
  await f.ui.openEntry('a2a.geo.0123456789');
  const shown = f.last().textContent;
  for (const expected of ['카탈로그 출처', 'A2A Agent Card (1.0)', '불일치', 'sha256:bb', '서명 있음·확인할 키 없음', 'ES256 k1', 'alice · t', '버린 필드skills', hostile])
    assert.ok(shown.includes(expected), expected);
});
