// Console home, running-agents panel and model status screens (public/home.js) and the windowed lists of public/app.js,
// rendered as text only, without a browser dependency.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.value = ''; this.ownText = ''; this.className = ''; this.style = {};
    this.dataset = {}; this.classList = {add: name => { this.className += ' ' + name; }}; }
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
const hostile = '<img src=x onerror=alert(1)>';
function fixture(responses, {active = 'investigations', storage} = {}) {
  const routes = new Map(), calls = [], details = [], navigations = [], lists = [];
  const card = (title, description = '') => { const node = el('section', 'card'); node.append(el('h2', '', title), el('p', '', description)); return node; };
  const core = {
    el, card, empty: card, date: value => value ? String(value) : '미확인', label: value => String(value), limits: items => el('p', '', (items || []).join('\n')),
    jsonDetails: (title, data) => { const node = el('details'); node.append(el('summary', '', title), el('pre', '', JSON.stringify(data))); return node; },
    button: (text, action, className = '') => { const node = el('button', className, text); node.events.click = action; return node; },
    table: (headers, rows) => { const node = el('table'); node.append(...headers.map(text => el('th', '', text)));
      for (const row of rows) { const tr = el('tr'); tr.append(...row.map(value => value instanceof Element ? value : el('td', '', value))); node.append(tr); }
      return node; },
    factList: entries => { const node = el('dl'); for (const [title, value] of entries) node.append(el('dt', '', title), el('dd', '', value)); return node; },
    registerView: (id, title, description, render) => routes.set(id, {title, description, render}),
    showDetail: (title, node) => details.push({title, node}), navigate: view => navigations.push(view), openList: (view, preset) => lists.push([view, preset]),
    getRenderEpoch: () => 1, getToken: () => 'token', getActiveView: () => active,
    api: async path => { calls.push(path); const value = responses(path); if (value instanceof Error) throw value; return structuredClone(value); },
  };
  const window = {EvidScopeCore: core};
  if (storage) window.localStorage = storage;
  else Object.defineProperty(window, 'localStorage', {get() { throw new Error('storage blocked'); }});
  const sandbox = {window, setInterval: () => 0, clearInterval: () => {}, URLSearchParams};
  vm.runInNewContext(readFileSync('public/home.js', 'utf8'), sandbox);
  return {ui: sandbox.window.EvidScopeHome, routes, calls, details, navigations, lists};
}
const button = (root, text) => all(root).find(node => node.tagName === 'button' && node.textContent.includes(text));
const home = {generatedAt: '2026-10-08T06:00:00.000Z', tenant: 'alpha', viewer: {id: 'alpha-auditor', role: 'auditor', mayDecide: false},
  agents: {status: 'ok', definition: '활동 = 수신 기록. heartbeat 아님', summary: {active: 4, unregistered: 2, flagged: 1, quietRegistered: 1}},
  threats: {findings: {status: 'ok', open: 7, bySeverity: {high: 3, medium: 4}, newSince: {since: 't0', count: 2}},
    stopOrders: {status: 'ok', active: 1, notPropagated: [{agentId: hostile, propagation: 'no_enforcement_point', issuedAt: 't1'}], notHeld: []},
    integrity: {status: 'ok', quarantine: null, faults: ['objects:case']}},
  review: {approvals: {status: 'ok', pending: 1, mayAnswer: 0,
    soonest: [{id: 'apr_1', actor: hostile, tool: 'mailer', remainingSeconds: 290, mayAnswer: false}]},
    cases: {status: 'ok', open: 2, inReview: 1}, registryChanges: {status: 'ok', pendingTransitions: 1, mayDecide: 0, pendingStopLifts: 0, mayDecideLifts: 0},
    governance: {status: 'unavailable', reason: '정책 서명 원장을 검증할 수 없습니다'}},
  governance: {status: 'ok', period: {from: 'f', to: 't'}, recordsInPeriod: 40, computedAt: 'c', notice: '“증거 있음”은 준수 판정이 아닙니다.',
    pack: {command: 'node scripts/evidence-pack.mjs build', tenant: 'alpha', from: '2026-10-01T00:00:00.000Z', to: '2026-10-08T00:00:00.000Z'},
    frameworks: [{id: 'kr-ai-basic-act', title: '인공지능기본법', items: 10, evidencePresent: 6, noEvidence: 3, notCountedHere: 1,
      list: [{id: 'KR-1', title: hostile, citation: '제31조', status: 'no_evidence_recorded'}]}]},
  model: {status: 'ok', reviewModel: 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct', revision: '0b58da4736f799f3', quantization: 'Q4_K_M', runtimeEnabled: false,
    observationStatus: 'unavailable', fineTuning: 'none_base_model_as_published', upgradePending: 4, evalStatuses: ['UNREVIEWED'], trainingRuns: 1,
    latestRun: {id: 'run-r2', passed: 60, items: 128, alwaysAbstainReference: 64, promoted: false}, promotionAutomatic: false}};

test('the home answers threats, needs review and governance support at a glance; counts open their filtered lists', async () => {
  const {governance, ...summary} = home;
  const route = path => path === '/api/home' ? summary : path.startsWith('/api/home/governance?') ? governance : new Error('unexpected ' + path);
  const f = fixture(route, {active: 'home'});
  assert.deepEqual(f.navigations.splice(0), ['home'], 'a signed-in landing rendered before home.js loaded is drawn again as the home');
  const view = f.routes.get('home');
  assert.match(view.title, /지금 확인할 일/);
  const node = await view.render();await node.governanceReady;const text = node.textContent;
  assert.deepEqual(f.calls, ['/api/home', '/api/home/governance?period=7d'], 'storage unavailable: no last-visit time is sent');
  for (const expected of ['최근 15분 활동', '미등록', '정지·중단 중 활동', 'high 발견', '전파 안 된 정지 명령', '집행 지점 없음', '조회 사본 불일치: objects:case',
    '승인 대기', '4분 남음', '조회 전용 계정', '확인할 수 없음: 정책 서명 원장', '증거 있음 6 · 기록 없음 3 · 여기서 세지 않음 1 / 10개 항목', 'AI 기본법',
    '없음 — 공개된 기본 모델 그대로', '60/128 (항상 판단 보류 기준 64/128) · 승격 안 됨', hostile]) assert.ok(text.includes(expected), expected);
  assert.doesNotMatch(text, /준수함|compliant/);
  await button(node, 'high 발견').events.click();
  assert.deepEqual(JSON.parse(JSON.stringify(f.lists.at(-1))), ['alerts', {severity: 'high', state: 'open', range: 'all'}]);
  await button(node, '검토 중인 사건').events.click();
  assert.deepEqual(JSON.parse(JSON.stringify(f.lists.at(-1))), ['cases', {status: 'active', range: 'all'}]);
  await button(node, '승인 대기').events.click();await button(node, '최근 15분 활동').events.click();await button(node, '무결성').events.click();
  assert.deepEqual(f.navigations, ['approvals', 'agents-now', 'health']);
  await button(node, '감사 패키지 만들기').events.click();
  const pack = f.details.at(-1).node.textContent;
  assert.match(pack, /--framework kr-ai-basic-act --tenant alpha/);assert.match(pack, /--from 2026-10-01T00:00:00.000Z --to 2026-10-08T00:00:00.000Z/);
  await button(node, '최근 30일').events.click();
  assert.equal(f.navigations.at(-1), 'home');
  await (await view.render()).governanceReady;assert.equal(f.calls.at(-1), '/api/home/governance?period=30d', 'the chosen period is kept for the next render');
});

test('new-since counts are shown only to the same principal and tenant that stored the last visit', async () => {
  const store = new Map([['evidscope.home.lastVisit', JSON.stringify({key: 'alpha/alpha-auditor', at: '2026-10-07T00:00:00.000Z'})]]);
  const storage = {getItem: key => store.get(key) ?? null, setItem: (key, value) => store.set(key, value)};
  const f = fixture(path => path.startsWith('/api/home/governance') ? home.governance : home, {storage});
  const text = (await f.routes.get('home').render()).textContent;
  assert.match(f.calls[0], /since=2026-10-07T00%3A00%3A00.000Z/);
  assert.match(text, /이후 새 발견 2건/);
  assert.equal(JSON.parse(store.get('evidscope.home.lastVisit')).at, home.generatedAt);
  store.set('evidscope.home.lastVisit', JSON.stringify({key: 'beta/someone', at: '2026-10-07T00:00:00.000Z'}));
  assert.doesNotMatch((await f.routes.get('home').render()).textContent, /이후 새 발견/);
});

test('the running-agents panel lists registered and unregistered agents with flags, quiet entries and the window definition', async () => {
  const agents = {window: {id: '15m', since: 's', until: 'u'}, definition: 'd', summary: {active: 2, registered: 1, unregistered: 1, unattributedEvents: 3},
    scanned: {events: 9, truncated: false}, limitations: ['도구 기록은 행위자 이름이 있을 때만'],
    items: [{registered: true, registryId: 'paused-agent', name: hostile, state: 'suspended', flags: ['active_after_stop_order', 'active_while_suspended'],
      lastActivity: new Date().toISOString(), counts: {events: 2, actions: 1, decisions: 1, denies: 1}, openFindings: {total: 1, bySeverity: {high: 1}},
      stopOrders: {active: 1}, pendingApprovals: 0},
    {registered: false, source: 'alpha-agent-2', actor: 'rogue', name: 'rogue', state: 'not_registered', flags: ['not_registered'],
      lastActivity: new Date().toISOString(), counts: {events: 2, actions: 1, decisions: 0, denies: 0},
      openFindings: null, stopOrders: {active: 0}, pendingApprovals: 1}],
    quiet: [{registryId: 'quiet-agent', name: 'quiet-agent', state: 'production', lastSourceActivity: null, activeStopOrders: 0}]};
  const f = fixture(path => path.startsWith('/api/home/agents') ? agents : new Error(path));
  const node = await f.routes.get('agents-now').render(), text = node.textContent;
  assert.deepEqual(f.calls, ['/api/home/agents?window=15m']);
  for (const expected of ['heartbeat', '정지(중단)', '정지 명령 이후 활동', '정지 상태에서 활동', '미등록', '출처 alpha-agent-2 · 행위자 rogue', '거부 1',
    '확인 불가', '기간 안에 기록이 없는 운영', 'quiet-agent', '에이전트에 붙지 않은 기록 3건', hostile]) assert.ok(text.includes(expected), expected);
  await button(node, '미등록').events.click();
  assert.ok(!node.textContent.includes(hostile), 'the unregistered filter hides registered agents');
  await button(node, '최근 1시간').events.click();
  assert.equal(f.calls.at(-1), '/api/home/agents?window=1h');
});

test('model status names the base model, no adapter, the upgrade as such, training records and that promotion is never automatic', async () => {
  const status = {reviewModel: {model: 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct', provider: 'isolated-llama.cpp',
    artifactRepository: 'repo', revision: 'abc', quantization: 'Q4_K_M'},
    classifier: {model: 'cipher', revision: null}, runtime: {enabledByDefault: false, observationStatus: 'unavailable'},
    fineTuning: {attached: false, roles: []}, roles: [{id: 'evidence-organizer', profileVersion: 1, model: 'qwen3:4b', upgradePending: true,
      upgradeTo: 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct', adapter: 'none', evalStatus: 'UNREVIEWED'}],
    training: {howTo: 'node scripts/training-run.mjs --check-only', repository: {notice: '저장소 기록',
      runs: [{id: 'run-r2', baseModel: 'Reasoning', baseRevision: 'r',
      dataset: 'KLUE', evaluation: {items: 128, passed: 60, baselineAdapterOff: 0, alwaysAbstainReference: 64}, promoted: false, attachedToRuntime: false,
      runtimeNote: '다른 베이스'}]}}, limitations: ['승격은 자동으로 일어나지 않습니다']};
  const f = fixture(() => status);
  const text = (await f.routes.get('assistance-model').render()).textContent;
  for (const expected of ['없음 — 공개된 기본 모델을 그대로 씁니다', '자동 승격 없음', '이전 기본값 qwen3:4b → fdtn-ai/Foundation-Sec-1.1-8B-Instruct 자동 갱신 예정',
    'UNREVIEWED', '60/128', '항상 판단 보류 기준 64', '승격 안 됨 · 연결 안 됨', '다른 베이스', '기본 비활성']) assert.ok(text.includes(expected), expected);
  const empty = fixture(() => ({...status, training: {...status.training, repository: {runs: []}}}));
  assert.match((await empty.ui.modelPanel()).textContent, /학습 기록 없음.*training-run\.mjs/);
});

test('model status lists the signed factsheets; a shakedown shows resource numbers only and is never promotable', async () => {
  const base = {reviewModel: {model: 'm', provider: 'p', revision: 'r', quantization: 'q'}, classifier: {model: 'c'}, runtime: {enabledByDefault: false},
    fineTuning: {attached: false, roles: []}, roles: [], training: {howTo: 'x', repository: {runs: []}}, limitations: []};
  const shakedown = {id: 'training-1', kind: 'training', label: 'shakedown', runMode: 'shakedown', promotable: false, promoted: false, recordedAt: 't1',
    operator: {id: hostile, role: 'reviewer'}, baseModel: {repository: 'fdtn', revision: '0b58da47aaaa', ggufSha256: '5813d725aaaa',
      training: {revision: 'f'.repeat(40), artifactLockSha256: 'b'.repeat(64)}},
    dataset: {sha256: 'a'.repeat(64), rows: 215, humanReviewedRows: 0, withSignedQueueDecision: 0, verification: 'reproduced_from_repository'},
    recipe: {rank: 8, alpha: 16, epochs: 2, sequenceLength: 1536},
      metrics: {cudaPeakAllocatedMiB: 7123, trainSeconds: 1480, totalSeconds: 1590, globalStep: 54},
    adapter: {ggufSha256: null}, gate: null, approver: null};
  const evaluation = {id: 'evaluation-1', kind: 'evaluation', label: 'candidate_evaluation', promotable: true,
    recordedAt: 't2', operator: {id: 'op', role: 'admin'},
    dataset: {}, metrics: {candidate: {precision: 0.96, recall: 0.62, ece: 0.05}}, gate: {eligible: true}, approver: null};
  const f = fixture(() => ({...base, factsheets: {status: 'ok', items: [evaluation, shakedown]}}));
  const text = (await f.ui.modelPanel()).textContent;
  for (const expected of ['서명된 팩트시트', '셰이크다운 — 승격 불가, 품질 결과 아님', 'GPU 최대 7123 MiB', '(자원 측정만)', '승격 불가', '215행',
    'reproduced_from_repository', '후보 정밀도 96.0%', '게이트와 서명 승인을 거쳐야 함', hostile]) assert.ok(text.includes(expected), expected);
  assert.ok(!text.includes('학습 손실'), 'no loss for a shakedown');
  const missing = fixture(() => ({...base, factsheets: {status: 'unavailable', reason: '정책 서명 원장을 검증할 수 없습니다', items: []}}));
  assert.match((await missing.ui.modelPanel()).textContent, /팩트시트를 확인하지 못했습니다/);
});

test('lists of public/app.js open on 24 hours, newest first, and load older records through the cursor', async () => {
  const app = readFileSync('public/app.js', 'utf8'), source = app.slice(app.indexOf('const listRanges ='), app.indexOf('function evidenceFacts('));
  const calls = [], pages = {first: {items: [{id: 'b'}], windowTotal: 2, hasMore: true, nextCursor: 'CUR'},
    second: {items: [{id: 'a'}], windowTotal: 2, hasMore: false, nextCursor: null}};
  const sandbox = {el, URLSearchParams, Object, Date,
    button: (text, action) => { const node = el('button', '', text); node.events.click = action; return node; },
    empty: (title, text) => el('div', 'empty', title + text), field: (title, name, options) => ({name, ...options}),
    api: async path => { calls.push(path);return path.includes('cursor=CUR') ? pages.second : pages.first; },
    FormData: class {}};
  const form = {values: [['q', 'mail'], ['range', '24h']]};
  vm.runInNewContext(source + ';this.windowedList=windowedList;this.rangeField=rangeField;', sandbox);
  sandbox.FormData = class { entries() { return form.values; } };
  assert.equal(sandbox.rangeField().value, '24h');assert.equal(sandbox.rangeField('bogus').value, '24h');
  const count = el('p'), results = el('div'), more = el('div');
  const render = items => el('table', '', items.map(i => i.id).join(','));
  const list = sandbox.windowedList({path: '/api/events', form, count, results, more, unit: '건', render});
  await list.reload();
  const first = new URL('http://x' + calls[0]);
  assert.equal(first.searchParams.get('q'), 'mail');assert.ok(Date.now() - Date.parse(first.searchParams.get('since')) - 86400000 < 5000);
  assert.match(count.textContent, /최근 24시간 · 2건 중 1건 표시 · 최신순/);
  await more.children[0].events.click();
  assert.match(calls[1], /cursor=CUR/);assert.equal(results.textContent, 'b,a');assert.match(more.textContent, /마지막 기록/);
  form.values = [['range', 'all']];await list.reload();
  assert.equal(new URL('http://x' + calls[2]).searchParams.get('order'), 'desc', 'the whole period is still newest first');
});
