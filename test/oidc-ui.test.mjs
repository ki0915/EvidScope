import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

const source = readFileSync('public/app.js', 'utf8');
const all = node => [node, ...node.children.flatMap(all)];
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
class Element {
  constructor(tag = 'div') { this.tagName = tag.toUpperCase(); this.children = []; this.listeners = {}; this.attributes = {}; this.ownText = ''; this.value = ''; this.open = false; this.dataset = {}; this.classes = new Set(); this.classList = { add: value => this.classes.add(value), remove: value => this.classes.delete(value), toggle: (value, on) => on ? this.classes.add(value) : this.classes.delete(value) }; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  set innerHTML(_) { throw new Error('Unsafe HTML rendering'); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.ownText = ''; this.children = [...nodes]; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
  async emit(name, event = {}) { for (const fn of this.listeners[name] || []) await fn({ preventDefault() {}, target: this, ...event }); }
  showModal() { this.open = true; }
  close() { this.open = false; }
  querySelector(selector) { return all(this).slice(1).find(node => selector.startsWith('.') ? node.className === selector.slice(1) : /^\[name=/.test(selector) ? node.name === selector.match(/"([^"]+)"/)[1] : selector.includes('[type=') ? node.tagName === selector.split('[')[0].toUpperCase() && node.type === selector.match(/"([^"]+)"/)[1] : node.tagName === selector.toUpperCase()); }
}
function fixture({ mode = 'oidc', role = 'admin', session = true, config, fetchHandler } = {}) {
  const nodes = new Map(), requests = [], redirects = [], history = [], events = new Map();
  const node = selector => { if (!nodes.has(selector)) nodes.set(selector, new Element(selector === '#auth-form' ? 'form' : 'div')); return nodes.get(selector); };
  const submit = new Element('button'); submit.type = 'submit'; node('#auth-form').append(submit); nodes.set('#auth-form button[type="submit"]', submit);
  const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  const sessionData = { principal: { id: 'admin-one', tenant: 'tenant-one', role }, csrfToken: 'csrf-private-value', expiresAt: new Date(Date.now() + 900000).toISOString() };
  const sandbox = {
    document: { querySelector: node, querySelectorAll: () => [], createElement: tag => new Element(tag), createTextNode: text => Object.assign(new Element('#text'), { textContent: text }), body: new Element('body') },
    window: { location: { search: '', assign: path => redirects.push(path) }, history: { replaceState: (...args) => history.push(args) }, addEventListener: (name, fn) => events.set(name, fn) },
    Node: Element, AbortController, URLSearchParams, URL, setTimeout, clearTimeout, Blob,
    FormData: class { constructor(form) { this.form = form; } entries() { return all(this.form).filter(item => item.name && !item.disabled).map(item => [item.name, item.value]); } },
    fetch: async (path, options) => {
      const request = { path, ...options }; requests.push(request);
      const custom = await fetchHandler?.(request, response); if (custom !== undefined) return custom;
      if (path === '/auth/config') return response(config || { mode, ...(mode === 'oidc' ? { loginPath: '/auth/login' } : {}) });
      if (path === '/auth/session') return response(sessionData, session ? 200 : 401);
      if (path === '/auth/logout') return response({ loggedOut: true, idpSessionEnded: false });
      if (path === '/api/access') return response({ subjects: [{ ...sessionData.principal, disabled: false, sessionCount: 1 }, { id: '<script>other</script>', tenant: 'tenant-one', role: 'reviewer', disabled: false, sessionCount: 2 }], limitations: ['IdP account is unchanged'] });
      return response({ counts: {}, sources: [] });
    },
  };
  for (const key of ['localStorage', 'sessionStorage']) for (const target of [sandbox, sandbox.window]) Object.defineProperty(target, key, { get() { throw new Error(`${key} must not hold credentials`); } });
  Object.defineProperty(sandbox.document, 'cookie', { get() { throw new Error('Session cookies must remain inaccessible to UI code'); }, set() { throw new Error('UI must not mint session cookies'); } });
  const context = vm.createContext(sandbox);
  vm.runInContext(source, context);
  vm.runInContext("renderers.investigations = async () => el('div', '', 'Current authenticated evidence');", context);
  const run = code => vm.runInContext(code, context);
  const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
  return { node, run, flush, requests, redirects, history, events, response, sessionData, core: sandbox.window.EvidScopeCore };
}

test('OIDC session uses same-origin cookies and CSRF without exposing the session marker as bearer credentials', async () => {
  const f = fixture(); await f.flush();
  assert.equal(f.node('#auth-form').hidden, true); assert.match(f.node('#connection').textContent, /admin-one · tenant-one · admin/);
  await f.core.api('/api/protected'); await f.core.api('/api/protected', 'POST', { reason: 'review' });
  for (const request of f.requests) { assert.equal(request.credentials, 'same-origin'); assert.equal(request.headers?.Authorization, undefined); assert.equal(request.redirect, 'error'); }
  assert.equal(f.requests.at(-1).headers['X-Evid-CSRF'], f.sessionData.csrfToken);
  assert.equal(f.requests.at(-2).headers['X-Evid-CSRF'], undefined);
  assert.equal(f.node('#auth-token').value, '');
});

test('anonymous OIDC login selects only the fixed SSO path and never opens the local token form', async () => {
  const f = fixture({ session: false }); await f.flush();
  assert.equal(f.core.getToken(), ''); assert.match(f.node('#auth-toggle').textContent, /조직 계정으로 접속/);
  await f.node('#auth-toggle').emit('click'); assert.deepEqual(f.redirects, ['/auth/login']); assert.equal(f.node('#auth-dialog').open, false);
  const hostile = fixture({ config: { mode: 'oidc', loginPath: 'https://attacker.test' } }); await hostile.flush(); await hostile.node('#auth-toggle').emit('click');
  assert.equal(hostile.redirects.length, 0); assert.match(hostile.node('#notice').textContent, /접속 방식을 확인할 수 없습니다/);
});

test('local token workflow keeps credentials in memory and preserves a visible failed-login message', async () => {
  const f = fixture({ mode: 'local', fetchHandler: (request, reply) => request.path === '/api/overview' && request.headers.Authorization === 'Bearer invalid' ? reply({ error: 'invalid token' }, 401) : undefined }); await f.flush();
  await f.node('#auth-toggle').emit('click'); assert.equal(f.node('#auth-dialog').open, true);
  f.node('#auth-token').value = 'invalid'; await f.node('#auth-form').emit('submit');
  assert.equal(f.core.getToken(), ''); assert.equal(f.node('#auth-token').value, ''); assert.equal(f.node('#auth-dialog').open, true); assert.match(f.node('#auth-error').textContent, /인증이 만료/);
  f.node('#auth-token').value = 'valid-local'; await f.node('#auth-form').emit('submit');
  assert.equal(f.node('#auth-dialog').open, false); assert.equal(f.core.getToken(), 'valid-local');
  const request = f.requests.findLast(item => item.path === '/api/overview'); assert.equal(request.headers.Authorization, 'Bearer valid-local'); assert.equal(request.credentials, 'omit'); assert.equal(request.headers['X-Evid-CSRF'], undefined);
  await f.node('#auth-toggle').emit('click'); assert.equal(f.core.getToken(), ''); assert.equal(f.requests.some(item => item.path === '/auth/logout'), false);
});

test('late local login responses cannot clear a newer login or reopen its dialog', async () => {
  const old = deferred();
  const f = fixture({ mode: 'local', fetchHandler: request => request.path === '/api/overview' && request.headers.Authorization === 'Bearer old' ? old.promise : undefined }); await f.flush();
  f.node('#auth-token').value = 'old'; const pending = f.node('#auth-form').emit('submit');
  f.run('clearAuth()'); f.node('#auth-token').value = 'current'; await f.node('#auth-form').emit('submit');
  old.resolve(f.response({}, 401)); await pending;
  assert.equal(f.core.getToken(), 'current'); assert.equal(f.node('#auth-dialog').open, false); assert.equal(f.node('#auth-error').textContent, ''); assert.match(f.node('#connection').textContent, /연결됨/);
});

test('logout clears visible evidence immediately, rejects late API responses and revokes with the old CSRF only', async () => {
  const slow = deferred(), end = deferred();
  const f = fixture({ fetchHandler: request => request.path === '/api/slow' ? slow.promise : request.path === '/auth/logout' ? end.promise : undefined }); await f.flush();
  const pending = f.core.api('/api/slow'), rejection = assert.rejects(pending, /접속 상태가 변경/);
  const epoch = f.core.getAuthEpoch(), logout = f.node('#auth-toggle').emit('click');
  assert.equal(f.core.getToken(), ''); assert.ok(f.core.getAuthEpoch() > epoch); assert.doesNotMatch(f.node('#content').textContent, /Current authenticated evidence/);
  assert.equal(f.requests.at(-1).headers['X-Evid-CSRF'], f.sessionData.csrfToken); assert.equal(f.requests.at(-1).headers.Authorization, undefined);
  slow.resolve(f.response({ confidential: 'old session evidence' })); await rejection;
  end.resolve(f.response({ loggedOut: true, idpSessionEnded: false })); await logout;
  assert.match(f.node('#notice').textContent, /조직 인증 제공자의 로그인은 종료하지 않았습니다/); await assert.rejects(f.core.api('/api/protected'), /먼저 접속/);
});

test('401 revokes browser state and a late session lookup cannot restore a cleared authentication epoch', async () => {
  const f = fixture({ fetchHandler: (request, reply) => request.path === '/api/expired' ? reply({}, 401) : undefined }); await f.flush();
  await assert.rejects(f.core.api('/api/expired'), error => error.status === 401); assert.equal(f.core.getToken(), ''); assert.equal(f.run('csrfToken'), ''); assert.equal(f.run('sessionPrincipal'), null);
  const slow = deferred(), restoring = fixture({ fetchHandler: request => request.path === '/auth/session' ? slow.promise : undefined }); await restoring.flush();
  restoring.run('clearAuth()'); slow.resolve(restoring.response(restoring.sessionData)); await restoring.flush();
  assert.equal(restoring.core.getToken(), ''); assert.equal(restoring.run('csrfToken'), '');
});

test('page cache entry clears evidence and restoration requires a fresh server session', async () => {
  const f = fixture(); await f.flush(); assert.match(f.node('#content').textContent, /Current authenticated evidence/);
  f.events.get('pagehide')(); assert.equal(f.core.getToken(), ''); assert.doesNotMatch(f.node('#content').textContent, /Current authenticated evidence/);
  await f.events.get('pageshow')({ persisted: true }); await f.flush(); assert.equal(f.requests.filter(item => item.path === '/auth/session').length, 2); assert.equal(f.core.getToken(), 'oidc-session');
});

test('admin access manager keeps hostile account names literal and sends scoped changes with a reason', async () => {
  const f = fixture(); await f.flush(); await f.run('accessSubjects()');
  const root = f.node('#detail-content'); assert.match(root.textContent, /<script>other<\/script>/); assert.equal(all(root).filter(node => node.tagName === 'SCRIPT').length, 0);
  await all(root).filter(node => node.tagName === 'BUTTON' && node.textContent === '접근 변경')[1].emit('click');
  let form = all(root).find(node => node.tagName === 'FORM'), reason = all(form).find(node => node.name === 'reason'), action = all(form).find(node => node.name === 'action');
  action.value = 'disable'; reason.value = '  '; const before = f.requests.length; await form.emit('submit'); assert.equal(f.requests.length, before); assert.match(form.textContent, /변경 사유를 입력/);
  reason.value = '  approved departure  '; await form.emit('submit');
  const change = f.requests.find(item => item.path.startsWith('/api/access/subjects/')); assert.equal(change.path, '/api/access/subjects/%3Cscript%3Eother%3C%2Fscript%3E'); assert.deepEqual(JSON.parse(change.body), { action: 'disable', reason: 'approved departure' });
  await all(root).find(node => node.tagName === 'BUTTON' && node.textContent === '접근 변경').emit('click');
  form = all(root).find(node => node.tagName === 'FORM'); action = all(form).find(node => node.name === 'action'); assert.deepEqual(all(action).filter(node => node.tagName === 'OPTION').map(node => node.value), ['revoke_sessions']);
  action.value = 'revoke_sessions'; all(form).find(node => node.name === 'reason').value = 'End my sessions'; await form.emit('submit'); assert.equal(f.core.getToken(), '');
});

test('non-admins have no account management action and failed logout does not claim server revocation', async () => {
  const f = fixture({ role: 'reviewer', fetchHandler: (request, reply) => request.path === '/auth/logout' ? reply({}, 503) : undefined }); await f.flush();
  const health = await f.run('healthView()'); assert.doesNotMatch(health.textContent, /조직 계정 접근 관리/);
  await assert.rejects(f.run('accessSubjects()'), /관리 권한/); assert.equal(f.requests.some(item => item.path === '/api/access'), false);
  await f.node('#auth-toggle').emit('click'); assert.equal(f.core.getToken(), ''); assert.match(f.node('#notice').textContent, /서버 세션 종료를 확인하지 못했습니다/);
});
