// Approval queue screen (public/approvals.js, docs/approval-queue.md): pending first with remaining time, detail with target,
// registry entry, tier, prior decisions and history, answers posted with the version shown, in-place polling refresh, all
// rendered as text without a browser dependency.
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
function fixture(responses, {active = 'approvals'} = {}) {
  const routes = new Map(), calls = [], details = [], navigations = [], timers = [];
  const card = (title, description = '') => { const node = el('section', 'card'); node.append(el('h2', '', title), el('p', '', description)); return node; };
  const core = {
    el, card, empty: card, date: value => value || '미확인', limits: items => el('p', '', (items || []).join('\n')),
    jsonDetails: (title, data) => { const node = el('details'); node.append(el('summary', '', title), el('pre', '', JSON.stringify(data))); return node; },
    button: (text, action, className = '') => { const node = el('button', className, text); node.events.click = action; return node; },
    field: (title, name) => { const node = el('label', 'field', title), input = el('input'); input.name = name; node.append(input); return node; },
    form: (fields, submitText, onSubmit) => { const node = el('form'), result = el('div'); node.append(...fields, result, el('button', 'primary', submitText));
      node.events.submit = async values => { try { await onSubmit(values, result); } catch (error) { result.append(el('div', 'message error',
        error.message)); } };
      return node; },
    table: (headers, rows) => { const node = el('table'); node.append(...headers.map(text => el('th', '', text)));
      for (const row of rows) { const tr = el('tr'); tr.append(...row.map(value => value instanceof Element ? value : el('td', '', value))); node.append(tr); }
      return node; },
    factList: entries => { const node = el('dl'); for (const [title, value] of entries) node.append(el('dt', '', title), el('dd', '',
      value || '미수집')); return node; },
    registerView: (id, title, description, render) => routes.set(id, {title, description, render}),
    showDetail: (title, node) => details.push({title, node}), captureDetailContext: () => ({}), isCurrentDetail: () => true,
    navigate: view => navigations.push(view), getActiveView: () => active, getRenderEpoch: () => 1,
    api: async (path, method = 'GET', body) => { calls.push({path, method, body: body === undefined ? undefined : JSON.parse(JSON.stringify(body))});
      const value = responses(path, method, body); if (value instanceof Error) throw value; return value; },
  };
  const sandbox = {window: {EvidScopeCore: core, setTimeout: (fn, ms) => timers.push({fn, ms})}};
  vm.runInNewContext(readFileSync('public/approvals.js', 'utf8'), sandbox);
  return {ui: sandbox.window.EvidScopeApprovals, routes, calls, details, navigations, timers, last: () => details.at(-1).node};
}
const forms = root => all(root).filter(node => node.tagName === 'form');
const hostile = '<img src=x onerror=alert(1)>';
const eligibility = {tier: 'high', approvers: 2, roles: ['reviewer', 'admin'], excluded: ['alpha-reviewer'], basis: {entryId: 'pay-agent'}};
const request = {id: 'apr_x', version: 2, state: 'pending', status: 'pending', remainingSeconds: 125, bindingMessage: hostile, actionId: 'pay-1',
  traceId: 't-1',
  decisionId: 'dec-1', policyId: 'payments.refund', policyVersion: 'p1', requestedBy: 'alpha-gateway', enforcementPointId: 'gw-1', requestedAt: 't0',
    expiresAt: 't9',
  target: {actor: 'pay-agent', tool: 'payment_transfer', resource: hostile}, targetDigest: 'ab'.repeat(32), eligibility,
  approvals: [{by: 'alpha-reviewer-2', role: 'reviewer', at: 't1', reason: 'ok'}], refusal: null, executionWindow: null, mayAnswer: {allowed: true}};
const queue = {pending: [request], pendingTotal: 1, total: 2, recent: [{...request, id: 'apr_y', state: 'expired', status: 'pending', approvals: []}],
  policy: {version: 1, source: 'signed', defaultLifetimeSeconds: 300, maxLifetimeSeconds: 900, executionWindowSeconds: 300, intervalSeconds: 5},
  limitations: ['만료된 요청은 거절입니다']};
const detail = {request, registry: {id: 'pay-agent', state: 'production', version: 4, owner: 'payments', tier: 'high'},
  otherRequests: [{id: 'apr_z', state: 'refused', target: request.target, decidedAt: 't3'}],
  decisions: [{source: 'alpha-gateway', id: 'd-1', kind: 'policy_decision', decision: 'require_approval', decisionId: 'dec-1', engine: 'opa',
    occurredAt: 't0'}],
  history: [{seq: 7, version: 1, change: 'requested', status: 'pending', principal: 'alpha-gateway', recordedAt: 't0'},
    {seq: 9, version: 2, change: 'approval_added', status: 'pending', principal: 'alpha-reviewer-2', recordedAt: 't1'}]};

test('the queue lists pending requests first with remaining time, as text, and refreshes in place while open', async () => {
  const f = fixture(() => queue), view = f.routes.get('approvals');
  assert.match(view.description, /만료는 거절/);
  const node = await view.render(), text = node.textContent;
  for (const expected of ['정책 v1', '2분 5초', hostile, '높음', '1/2', '만료(거절)', '만료된 요청은 거절입니다']) assert.ok(text.includes(expected), expected);
  assert.ok(text.indexOf('답변 대기') < text.indexOf('최근 결정'), 'pending first');
  assert.equal(f.timers.length, 1);assert.equal(f.timers[0].ms, 15000);
  await f.timers[0].fn();
  assert.deepEqual(f.calls.map(c => c.path), ['/api/approvals', '/api/approvals'], 'polls the API');
  assert.equal(f.timers.length, 2, 'keeps polling while the view is open');
  const away = fixture(() => queue, {active: 'registry'});await (await away.routes.get('approvals').render());await away.timers[0].fn();
  assert.equal(away.calls.length, 1, 'stops when another view is shown');
  assert.equal(f.ui.remaining(3700), '1시간 1분');
  const html = readFileSync('public/index.html', 'utf8');
  assert.match(html, /<script src="\/approvals\.js" defer><\/script>/);
  assert.ok(readFileSync('public/console.js', 'utf8').includes("['approvals', '승인 대기열']"));
  assert.ok(readFileSync('src/server.mjs', 'utf8').includes("'/approvals.js'"));
});

test('detail shows target, registry entry, tier, prior decisions and history; answers post the reason and the version shown', async () => {
  const f = fixture((path, method) => method === 'POST' ? {status: 'approved', approvals: [{by: 'a'}, {by: 'b'}], eligibility} : detail);
  await f.ui.openRequest('apr_x');
  const node = f.last(), text = node.textContent;
  for (const expected of ['pay-agent (production, v4)', '서로 다른 2명', 'alpha-reviewer', 'require_approval', 'apr_z', 'approval_added', hostile, '남은 시간 2분 5초'])
    assert.ok(text.includes(expected), expected);
  const [approve, refuse] = forms(node);
  await approve.events.submit({reason: '금액 확인'});
  assert.deepEqual(f.calls.find(c => c.method === 'POST'), {path: '/api/approvals/apr_x/approve', method: 'POST', body: {reason: '금액 확인', version: 2}});
  assert.equal(f.calls.at(-1).path, '/api/approvals/apr_x', 'the detail is reloaded after an answer');
  assert.ok(f.navigations.includes('approvals'));
  await refuse.events.submit({reason: '한도 초과'});
  assert.equal(f.calls.filter(c => c.method === 'POST').at(-1).path, '/api/approvals/apr_x/refuse');
  const blocked = fixture(() => ({...detail, request: {...request, mayAnswer: {allowed: false, reason: '정책이 제외한 사람'}}}));
  await blocked.ui.openRequest('apr_x');
  assert.equal(forms(blocked.last()).length, 0);assert.match(blocked.last().textContent, /답할 수 없습니다: 정책이 제외한 사람/);
  const done = fixture(() => ({...detail, request: {...request, state: 'expired'}}));
  await done.ui.openRequest('apr_x');
  assert.equal(forms(done.last()).length, 0);assert.match(done.last().textContent, /만료\(거절\) 상태라 더 답할 수 없습니다/);
});
