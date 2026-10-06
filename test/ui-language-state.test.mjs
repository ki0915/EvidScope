import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

// Exercise rendered DOM text and interactions without a browser dependency.
class Element {
  constructor(tag) {
    this.tagName = tag; this.children = []; this.attributes = {}; this.events = {}; this.dataset = {}; this.value = ''; this.ownText = ''; this.className = '';
    this.classList = { add: name => { this.className += ` ${name}`; }, toggle: (name, on) => { const names = this.className.split(' ').filter(n => n && n !== name); if (on) names.push(name); this.className = names.join(' '); } };
  }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent).join(''); }
  get lastChild() { return this.children.at(-1); }
  set innerHTML(_) { throw new Error('Unsafe HTML rendering'); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; this.ownText = ''; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(key, listener) { const previous = this.events[key]; this.events[key] = (...args) => { previous?.(...args); return listener(...args); }; }
  querySelector(selector) { return all(this).find(node => node !== this && node.tagName === selector) || null; }
}
const all = node => [node, ...node.children.flatMap(all)];
const el = (tag, className = '', text) => { const node = new Element(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; };
const card = (title, description = '') => { const node = el('section', 'card'); node.append(el('h2', '', title), el('p', '', description)); return node; };
const jsonDetails = (title, data) => { const node = el('details'); node.append(el('summary', '', title), el('pre', '', JSON.stringify(data, null, 2))); return node; };
const button = (text, action, className = '') => { const node = el('button', className, text); node.events.click = action; return node; };
const field = (title, name, options = {}) => {
  const node = el('label', 'field', title), input = el(options.choices ? 'select' : options.multiline ? 'textarea' : 'input'); input.name = name;
  input.value = options.value ?? options.choices?.[0]?.value ?? '';
  node.append(input); return node;
};
const table = (headers, rows) => { const node = el('table'); node.append(...headers.map(text => el('th', '', text))); for (const row of rows) { const tr = el('tr'); tr.append(...row.map(value => value instanceof Element ? value : el('td', '', value))); node.append(tr); } return node; };
function fixture() {
  const routes = new Map(), calls = [], navigations = [], responses = new Map();
  const core = {
    el, card, jsonDetails, button, field, table,
    empty: card, limits: items => el('p', '', (items || []).join('\n')), date: value => value || '미확인',
    factList: items => table([], items), badge: value => el('span', 'badge', value), label: value => value,
    getWorkspaceFilters: () => ({ q: '', range: '24h' }), getActiveView: () => 'overview',
    registerView: (id, title, description, render) => routes.set(id, render),
    navigate: view => navigations.push(view), showDetail: () => {},
    api: async path => { calls.push(path); return responses.get(path) || {}; },
  };
  const sandbox = { window: { EvidScopeCore: core }, document: { body: el('body'), querySelector: () => null, querySelectorAll: () => [] }, URLSearchParams };
  vm.runInNewContext(readFileSync('public/console.js', 'utf8'), sandbox);
  const source = readFileSync('public/team-support.js', 'utf8');
  const functions = source.slice(source.indexOf('  function draftContents('), source.indexOf('  function runDetailNode('));
  const packageFunction = source.slice(source.indexOf('  function packagePreview('), source.indexOf('  function credentialPanel('));
  const requestFunctions = source.slice(source.indexOf('  function governanceRequirementPicker('), source.indexOf('  async function requestBuilder('));
  const appSource = readFileSync('public/app.js', 'utf8'), systemFunctions = appSource.slice(appSource.indexOf('const systemTriFacts ='), appSource.indexOf('function systemEditor('));
  const helpers = { ...core, stringify: value => JSON.stringify(value, null, 2), rlabel: value => ({ accept: '채택', reject: '반려' }[value] || value) };
  vm.runInNewContext(functions + packageFunction + requestFunctions + systemFunctions + '\nglobalThis.helpers = { draftDiff, reviewHistory, packagePreview, governanceRequirementPicker, assistanceRequestOptions, systemFactsPayload };', helpers);
  return { console: sandbox.window.EvidScopeConsole, helpers: helpers.helpers, core, routes, calls, navigations, responses };
}

test('visibility distinguishes complete, partial and absent content with missing values kept unknown', () => {
  const { console: ui } = fixture();
  assert.equal(ui.observationState({ contentObserved: 3, bodyNotObserved: 0, observationCount: 3 }), 'contentObserved');
  assert.equal(ui.observationState({ contentObserved: 1, bodyNotObserved: 2, observationCount: 3 }), 'partial');
  assert.equal(ui.observationState({ contentObserved: 0, bodyNotObserved: 3, observationCount: 3 }), 'not_observed');
  assert.equal(ui.observationState({}), 'unknown');
  const content = ui.visibilitySummary({ summary: { registeredAssets: 0, observedAssets: 2 } });
  const numbers = all(content).filter(node => node.className === 'data-number').map(node => node.textContent);
  assert.deepEqual(numbers, ['0', '2', '—', '—']);
});

test('default OFF is separate from unavailable runtime and UI reads never start models', async () => {
  const { console: ui, routes, calls, responses } = fixture();
  const runtime = { schemaVersion: 1, enabledByDefault: false, observationStatus: 'unavailable', models: [{ id: 'audit', declaredEnabled: false, state: 'unavailable', observedAt: null, terminationConfirmed: false, isolationVerified: false }], training: { state: 'not_evaluated', minimumReviewed: { tune: 300, validation: 50, test: 100 } } };
  const node = ui.modelStatusCard(runtime);
  assert.match(node.textContent, /기본 정책 OFF/); assert.match(node.textContent, /실행 상태 확인 불가/); assert.match(node.textContent, /관측 시각 없음/); assert.match(node.textContent, /종료 미확인/); assert.match(node.textContent, /격리 검증 미완료/);
  assert.doesNotMatch(node.textContent, /종료 확인됨/);
  assert.match(ui.modelStatusCard(null).textContent, /꺼져 있다고 판정할 수 없습니다/);
  responses.set('/api/model-runtime', runtime); const full = await routes.get('model-runtime')();
  assert.deepEqual(calls, ['/api/model-runtime']);
  assert.match(full.textContent, /평가 미실시/); assert.match(full.textContent, /최소 검토 필요량/);
  assert.deepEqual(all(full).filter(n => n.className === 'data-number').map(n => n.textContent), ['—', '—', '—']);
  const observed = ui.modelStatusCard({ ...runtime, observationStatus: 'observed', models: [{ id: 'audit', state: 'stopped', observedAt: '2026-09-12T00:00:00Z', terminationConfirmed: true, isolationVerified: false }] });
  assert.match(observed.textContent, /Kubernetes 관측 수신/); assert.match(observed.textContent, /종료 확인됨/); assert.match(observed.textContent, /격리 검증 미완료/);
});

test('script signals and screening counts do not imply English proficiency or safety', () => {
  const { console: ui } = fixture();
  const signals = ui.languageCard({ hangul: 2, latin: 4, mixed: 1, undetermined: 0 });
  assert.match(signals.textContent, /라틴 문자/); assert.match(signals.textContent, /한국어 능력을 확정하지 않습니다/); assert.doesNotMatch(signals.textContent, /영어 4/);
  const screened = ui.screeningCard({ completed: 0, incomplete: 1, not_observed: 3, not_run: 2 });
  assert.match(screened.textContent, /내용 미관측3/); assert.match(screened.textContent, /검사 미실행2/); assert.match(screened.textContent, /검사 완료는 안전 판정이 아닙니다/);
});

test('asset drilldown renders hostile names and evidence as text, never executable DOM', () => {
  const { console: ui } = fixture();
  const text = '<script>alert("x")</script>';
  const node = ui.assetDetailNode({ id: text, owner: text, observationCount: 1, contentObserved: 1, bodyNotObserved: 0, attention: [{ code: text, message: text, evidenceRefs: [text] }] }, {});
  assert.ok(node.textContent.includes(text)); assert.equal(all(node).filter(n => n.tagName === 'script').length, 0);
});

test('frozen package preview exposes full governance and role contracts, including beyond display summaries', () => {
  const { helpers } = fixture();
  const pkg = { id: 'pkg-1', status: 'prepared', contextHash: 'context', bundleHash: 'bundle', roleExecutionHash: 'rolehash', profileSnapshot: { id: 'governance-assistant' }, roleExecutionSnapshot: { toolPolicy: 'readonly-no-tools' }, governanceSnapshot: { catalogHash: 'catalog', requirements: [{ id: 'KR-33', sourceUrl: 'https://example.test/law' }] }, analysisSnapshot: { findings: [] }, evidence: Array.from({ length: 55 }, (_, i) => ({ ref: `evidence/${i}` })) };
  const node = helpers.packagePreview(pkg);
  assert.match(node.textContent, /거버넌스·요구사항 스냅샷 전체/); assert.match(node.textContent, /readonly-no-tools/); assert.match(node.textContent, /KR-33/); assert.match(node.textContent, /evidence\/54/);
  const complete = all(node).find(n => n.tagName === 'details' && n.children[0].textContent === '고정된 근거 묶음 전체 원문');
  assert.deepEqual(JSON.parse(complete.children[1].textContent), pkg);
});

test('human adopted drafts and sequential changes preserve machine original and rejected history', () => {
  const { helpers } = fixture();
  const original = { summary: 'Machine original', findings: [{ claim: 'Evidence observed', confidence: 'low', evidenceRefs: ['source/1'] }], uncertainties: ['Missing body'] };
  const edited = { ...original, summary: '<script>Human edit</script>', uncertainties: ['Human caveat'] };
  const edits = [{ action: 'accept', draft: edited, reviewedBy: 'reviewer-1' }];
  const before = JSON.stringify(original), node = helpers.reviewHistory(edits, original);
  assert.match(node.textContent, /현재 채택된 사람 검토본/); assert.ok(node.textContent.includes(edited.summary)); assert.match(node.textContent, /Machine original/); assert.match(node.textContent, /변경된 필드 2개/); assert.equal(JSON.stringify(original), before);
  assert.equal(all(node).filter(n => n.tagName === 'script').length, 0);
  const rejected = helpers.reviewHistory([...edits, { action: 'reject', reason: 'Needs more evidence' }], original);
  assert.doesNotMatch(rejected.textContent, /현재 채택된 사람 검토본/); assert.match(rejected.textContent, /이전 채택본은 이력/); assert.match(rejected.textContent, /Needs more evidence/);
  const second = { ...edited, summary: 'Second edit' };
  assert.match(helpers.reviewHistory([...edits, { action: 'accept', draft: second }], original).textContent, /직전 저장 초안과 변경점/);
});

test('six primary task groups retain all existing destinations and local-only assets', () => {
  const html = readFileSync('public/index.html', 'utf8'), source = readFileSync('public/console.js', 'utf8');
  assert.equal((html.match(/data-section=/g) || []).length, 6);
  for (const route of ['agents', 'graphs', 'investigations', 'overview', 'events', 'alerts', 'cases', 'rules', 'governance', 'retention', 'health', 'team', 'assistance']) assert.ok(source.includes(`['${route}',`), route);
  assert.doesNotMatch(html, /(?:src|href)="https?:\/\//);
  assert.match(readFileSync('public/console.css', 'utf8'), /prefers-reduced-motion/);
});

test('governance requirement selection caps at three and changes invalidate package preview', () => {
  const { helpers } = fixture(); let invalidations = 0;
  const picker = helpers.governanceRequirementPicker({ maxSelected: 3, items: Array.from({ length: 5 }, (_, i) => ({ id: `KR-${i}`, title: `Requirement ${i}` })) }, () => invalidations++);
  const inputs = all(picker.node).filter(n => n.tagName === 'input');
  for (const input of inputs.slice(0, 3)) { input.checked = true; input.events.change(); }
  assert.equal(invalidations, 3); assert.equal(picker.value().length, 3); assert.equal(inputs[3].disabled, true); assert.equal(inputs[4].disabled, true);
  inputs[0].checked = false; inputs[0].events.change(); assert.equal(inputs[3].disabled, false); assert.equal(picker.value().length, 2);
  assert.equal(helpers.governanceRequirementPicker({ error: 'offline' }, () => {}).value().length, 0);
});

test('only governance requests include explicitly selected requirements; manual question is optional and bounded', () => {
  const { helpers } = fixture();
  const result = helpers.assistanceRequestOptions('governance-assistant', ['KR-33', 'NIST-GOVERN'], '  Review missing evidence.  ');
  assert.deepEqual(JSON.parse(JSON.stringify(result)), { operatorQuestion: 'Review missing evidence.', selectedRequirementIds: ['KR-33', 'NIST-GOVERN'] });
  assert.deepEqual(JSON.parse(JSON.stringify(helpers.assistanceRequestOptions('evidence-organizer', ['KR-33'], '   '))), {});
  assert.throws(() => helpers.assistanceRequestOptions('governance-assistant', [], 'Review'), /1개에서 3개/);
  assert.throws(() => helpers.assistanceRequestOptions('governance-assistant', ['a', 'a'], ''), /1개에서 3개/);
  assert.throws(() => helpers.assistanceRequestOptions('evidence-organizer', [], 'a'.repeat(501)), /500자/);
  assert.match(helpers.packagePreview({ operatorQuestion: 'Human audit question' }).textContent, /Human audit question/);
});

test('system facts preserve unknown and explicit false, numeric compute and independently selected EU roles', () => {
  const { helpers } = fixture();
  const unknown = helpers.systemFactsPayload({ generative: 'unknown', internalOnly: '', publicInstitution: 'false', trainingCompute: '', modelVersion: '', marketEntryAt: '' });
  assert.equal(unknown.generative, 'unknown'); assert.equal(unknown.internalOnly, 'unknown'); assert.equal(unknown.publicInstitution, false); assert.equal(unknown.trainingCompute, 'unknown'); assert.equal(unknown.modelVersion, 'unknown'); assert.equal(unknown.marketEntryAt, undefined);
  const known = helpers.systemFactsPayload({ markets: 'KR, EU', generative: 'true', frontierTechnology: 'true', trainingCompute: '1e26', euRole_provider: 'on', euRole_deployer: 'on', marketEntryAt: '2026-09-12T00:00:00Z' });
  assert.equal(known.generative, true); assert.equal(known.frontierTechnology, true); assert.equal(known.trainingCompute, 1e26); assert.deepEqual([...known.euRoles], ['provider', 'deployer']); assert.equal(known.euRole_provider, undefined); assert.equal(known.marketEntryAt, '2026-09-12T00:00:00.000Z');
  assert.throws(() => helpers.systemFactsPayload({ trainingCompute: '-1' }), /0 이상/); assert.throws(() => helpers.systemFactsPayload({ trainingCompute: 'Infinity' }), /0 이상/);
});

test('request builder sends latest profile and selected scope, invalidates frozen preview and rejects late responses', async () => {
  const { core, routes } = fixture(), requests = [];
  let completePackage;
  const pkg = { id: 'pkg-ui', status: 'prepared', evidence: [{ ref: 'source/event-1' }] };
  const responses = {
    '/api/cases': { items: [{ id: 'case-1', title: 'UI case' }] },
    '/api/assistance/profiles': { items: [{ id: 'evidence-organizer', kind: 'runtime', version: 2 }, { id: 'governance-assistant', kind: 'runtime', version: 2 }] },
    '/api/assistance/requirements': { maxSelected: 3, items: [{ id: 'KR-33', title: 'Impact review' }, { id: 'NIST-GOVERN', title: 'Voluntary governance' }] },
    '/api/cases/case-1/review-context': { contextHash: 'context-v1', events: [{ source: 'source', id: 'event-1' }] },
    '/api/assistance/runs': { items: [] },
  };
  Object.assign(core, { getRenderEpoch: () => 1, getAuthEpoch: () => 1, stringify: value => JSON.stringify(value), api: async (path, method = 'GET', body) => {
    requests.push({ path, method, body });
    return path === '/api/assistance/packages' ? new Promise(resolve => { completePackage = resolve; }) : responses[path];
  } });
  vm.runInNewContext(readFileSync('public/team-support.js', 'utf8'), { window: { EvidScopeCore: core } });
  const root = await routes.get('assistance')();
  await all(root).find(n => n.tagName === 'button' && n.textContent === '새 지원 요청 만들기').events.click();
  const profile = all(root).find(n => n.name === 'profileId'); profile.value = 'governance-assistant'; profile.events.change();
  const picker = all(root).find(n => n.className === 'requirement-picker'); assert.equal(picker.hidden, false);
  const selected = all(picker).find(n => n.tagName === 'input' && n.value === 'KR-33'); selected.checked = true; selected.events.change();
  const evidence = all(root).find(n => n.tagName === 'label' && n.children.some(child => child.textContent.includes('source/event-1')));
  evidence.querySelector('input').checked = true; evidence.querySelector('input').events.change();
  const question = all(root).find(n => n.name === 'operatorQuestion'); question.value = 'Review missing evidence'; question.events.input();
  const prepare = all(root).find(n => n.tagName === 'button' && n.textContent.includes('묶음 미리보기 만들기'));
  const pending = prepare.events.click();
  const request = requests.at(-1); assert.equal(request.method, 'POST'); assert.equal(request.body.profileVersion, 2); assert.equal(request.body.operatorQuestion, question.value); assert.deepEqual([...request.body.selectedRequirementIds], ['KR-33']);
  question.value = 'Updated question'; question.events.input(); completePackage(pkg); await pending;
  assert.equal(all(root).filter(n => n.className === 'bundle-preview').length, 0);
  const current = prepare.events.click(); completePackage(pkg); await current;
  assert.equal(all(root).filter(n => n.className === 'bundle-preview').length, 1);
  selected.checked = false; selected.events.change(); assert.equal(all(root).filter(n => n.className === 'bundle-preview').length, 0);
  profile.value = 'evidence-organizer'; profile.events.change(); assert.equal(picker.hidden, true);
  const organizer = prepare.events.click(); assert.equal(requests.at(-1).body.selectedRequirementIds, undefined); completePackage(pkg); await organizer;
});
