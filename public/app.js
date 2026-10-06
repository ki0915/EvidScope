'use strict';

// Evidence is untrusted data. Render through DOM text nodes, never HTML or executable templates.
const $ = (selector) => document.querySelector(selector);
let token = '';
let authMode = null;
let csrfToken = '';
let sessionPrincipal = null;
let sessionExpiresAt = null;
let authBusy = false;
let activeView = 'investigations';
let renderEpoch = 0;
let authEpoch = 0;
let detailEpoch = 0;
let disposeView = () => {};
let workspaceFilters = { q: '', range: '24h' };
const views = {
  agents: ['에이전트 목록', '에이전트별 정책 점검 결과와 평가 범위, 참고자료 및 사람의 검토 현황을 확인합니다.'],
  graphs: ['가시성 그래프', 'AI 행동의 관측 범위를 비교하고, 그래프에서 근거와 실제 검증 결과로 이어갑니다.'],
  investigations: ['행동 조사함', '검토할 행동을 고르고, 실제 근거를 대조한 뒤 사람의 판단과 후속 조치를 남깁니다.'],
  overview: ['관측 개요', 'AI 행동, 당시 권한, 확인된 결과를 증거로 조사합니다.'],
  events: ['증거 탐색 · 타임라인', '수집된 신호를 검색하고 행동 단위로 출처·권한·결과를 대조합니다.'],
  alerts: ['탐지 경보', '위험 신호는 조사 출발점입니다. 경보만으로 실행 차단이나 악의를 확정하지 않습니다.'],
  cases: ['사건 · 인간 감사', '원본 근거, 담당자, 검토 의견과 조치 이력을 함께 관리합니다.'],
  rules: ['탐지 룰 · 예외', '제한된 조건식으로 룰을 시험하고, 사람의 검토를 거쳐 버전을 적용합니다.'],
  governance: ['거버넌스 검토', '시스템의 적용성부터 통제·증거·인간 평가·재검토까지 연결합니다.'],
  retention: ['보존 · 파기 검토', '보존 목적·기간·보류 사유를 기록하고, 구체적인 파기 대상을 사람이 검토합니다.'],
  health: ['수집 · 증적 건강', '수집 공백과 분석 지연을 확인하고, 보관된 증적의 무결성을 검증합니다.'],
};
const labels = {
  high: '높음', critical: '심각', medium: '중간', low: '낮음', info: '정보',
  unknown: '미확인', pending: '검토 대기', reviewed: '인간 검토됨', sufficient: '충분', insufficient: '부족',
  context_only: '참고 맥락', partial: '일부 관측', contentObserved: '내용 관측', not_run: '미실행', unverified: '검증 전',
  open: '진행 전', in_review: '검토 중', investigating: '조사 중', closed: '종결', resolved: '해결됨',
  draft: '초안', active: '적용 중', approved: '승인됨', rejected: '반려', expired: '기한 만료',
  healthy: '정상 신호', stale: '최근 수집 없음', disconnected: '미연결', failed: '실패',
  applicable: '적용', not_applicable: '비적용', confirmed: '확인됨', candidate: '검토 후보', no: '해당 없음',
  self_report: 'AI 자기보고', authenticated_source: '인증된 출처', independent: '독립 출처',
  evidence_missing: '증거 없음', review_required: '재검토 필요', human_marked_not_applicable: '인간이 비적용 판단',
  human_evidence_assessed: '인간이 증거 평가', evidence_insufficient: '증거 부족', draft_requires_human_review: '초안 · 인간 검토 필요',
  suppressed: '예외 적용', retired: '이전 버전', voluntary: '자율 적용',
  unverified_or_mismatch: '권한 미확인 또는 불일치', matched_at_event_time: '행동 시점 범위 일치', not_observed: '실행 미관측',
  independently_reported_success: '독립 서비스 성공 기록', independently_reported_failure: '독립 서비스 실패 기록', unconfirmed: '외부 결과 미확인',
  authenticated_self_report: '인증된 AI 자기보고', authenticated_service_record: '인증된 서비스 기록',
  receiving: '최근 수신됨', not_connected: '미연결', no_observation: '수신 이력 없음', started: '시작 기록', success: '성공 기록', failure: '실패 기록', registered: '등록됨',
  released: '보류 해제됨', executed: '파기 실행됨', quarantined_resource_limit: '분석 미완료 · 자원 한도',
  intent: '행동 요청', execution: '도구 실행 기록', result: '도구 결과 기록',
  grant: '권한 부여', revoke: '권한 철회', human_approval: '외부 사람 승인', automated_review: '자동 검토', delegation: '위임 자기보고',
  governance_check: '보고된 조치 시험', human_oversight_review: '사람 감독 수행 기록',
  document: '문서', dataset: '데이터셋', record: '레코드', retrieval: '검색 참조', artifact: '산출물',
  input: '입력', retrieved: '검색된 자료', output: '출력', self_reported_reference: 'AI가 보고한 참조', service_reported_reference: '서비스가 보고한 참조',
  confirmed_issue: '문제 확인', no_issue_found: '검토 범위에서 문제 미발견', inconclusive: '판단 유보',
  supports: '판단을 뒷받침', contradicts: '판단과 상충', context: '배경 근거', evaluated: '평가 완료',
  mixed_results: '독립 서비스 성공·실패 혼재',
};
const label = (value) => labels[value] || String(value ?? '미확인');
const stringify = (value) => typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value ?? '미확인');
const date = (value) => value ? new Date(value).toLocaleString('ko-KR', { hour12: false }) : '수집 없음';

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}
function button(text, fn, className = '') {
  const node = el('button', className, text);
  node.type = 'button';
  node.addEventListener('click', async () => {
    node.disabled = true;
    try { await fn(); } catch (error) { notice(error.message, true); }
    finally { node.disabled = false; }
  });
  return node;
}
function badge(value) {
  const safeClass = /^[a-z_]+$/.test(String(value)) ? String(value) : '';
  return el('span', `badge ${safeClass}`, label(value));
}
function notice(text = '', error = false) {
  $('#notice').replaceChildren();
  if (text) $('#notice').append(el('div', `message${error ? ' error' : ''}`, text));
}
function empty(title, text) {
  const node = el('div', 'empty');
  node.append(el('strong', '', title), el('p', '', text));
  return node;
}
function card(title, description) {
  const node = el('section', 'card');
  if (title) {
    const head = el('div', 'card-header');
    const group = el('div');
    group.append(el('h2', '', title));
    if (description) group.append(el('p', '', description));
    head.append(group); node.append(head);
  }
  return node;
}
function limits(items) {
  if (!items || !items.length) return el('span');
  const node = el('div', 'message warning');
  node.append(el('strong', '', '관측·판단의 한계'));
  const list = el('ul', 'limitations');
  items.forEach((item) => list.append(el('li', '', stringify(item))));
  node.append(list); return node;
}
function jsonDetails(title, data) {
  const node = el('details');
  node.append(el('summary', '', title), el('pre', 'json', stringify(data)));
  return node;
}
function table(headers, rows) {
  if (!rows.length) return empty('표시할 기록이 없습니다', '검색 조건과 수집 상태를 확인하세요. 기록이 없다는 사실은 통과나 안전을 의미하지 않습니다.');
  const wrap = el('div', 'table-wrap'); const t = el('table');
  const head = el('thead'); const hr = el('tr');
  headers.forEach((text) => { const th = el('th', '', text); th.scope = 'col'; hr.append(th); });
  head.append(hr); t.append(head); const body = el('tbody');
  rows.forEach((cells) => {
    const tr = el('tr'); cells.forEach((value) => {
      const td = el('td'); if (value instanceof Node) td.append(value); else td.textContent = String(value ?? '—'); tr.append(td);
    }); body.append(tr);
  }); t.append(body); wrap.append(t); return wrap;
}
function field(title, name, options = {}) {
  const node = el('label', `field${options.wide ? ' wide' : ''}`, title);
  let input;
  if (options.choices) {
    input = el('select');
    options.choices.forEach((choice) => {
      const value = typeof choice === 'object' ? choice.value : choice;
      const text = typeof choice === 'object' ? choice.label : label(choice);
      const option = el('option', '', text); option.value = value; input.append(option);
    });
  } else if (options.multiline) input = el('textarea');
  else { input = el('input'); input.type = options.type || 'text'; }
  input.name = name;
  input.required = Boolean(options.required);
  if (options.placeholder) input.placeholder = options.placeholder;
  if (options.value !== undefined) input.value = options.value;
  if (input.tagName !== 'SELECT') input.maxLength = options.maxLength || 4000;
  node.append(input); return node;
}
function form(fields, submitText, onSubmit) {
  const node = el('form'); const grid = el('div', 'form-grid');
  fields.forEach((item) => grid.append(item)); node.append(grid);
  const result = el('div'); result.setAttribute('role', 'status'); node.append(result);
  const submit = el('button', 'primary', submitText); submit.type = 'submit'; node.append(submit);
  node.addEventListener('submit', async (event) => {
    event.preventDefault(); submit.disabled = true; result.replaceChildren();
    const values = Object.fromEntries(new FormData(node).entries());
    try { await onSubmit(values, result); } catch (error) { result.append(el('div', 'message error', error.message)); }
    finally { submit.disabled = false; }
  }); return node;
}
async function api(path, method = 'GET', body) {
  if (!token) throw new Error('감사 워크스페이스에 먼저 접속하세요.');
  const requestToken = token;
  const requestAuthEpoch = authEpoch;
  const oidc = authMode === 'oidc';
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(path, {
      method, headers: { ...(oidc ? (method === 'POST' ? { 'X-Evid-CSRF': csrfToken } : {}) : { Authorization: `Bearer ${requestToken}` }), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: controller.signal, credentials: oidc ? 'same-origin' : 'omit', cache: 'no-store', redirect: 'error',
    });
    const data = await response.json().catch(() => ({}));
    if (requestToken !== token || requestAuthEpoch !== authEpoch) throw new Error('접속 상태가 변경되어 이전 응답을 표시하지 않습니다.');
    if (!response.ok) {
      if (response.status === 401) { clearAuth(); throw Object.assign(new Error('인증이 만료되었거나 접근 자격이 회수되었습니다. 다시 접속하세요.'), {status:401}); }
      if (response.status === 403) throw Object.assign(new Error(`접근 거부: ${stringify(data.error || data.message || '현재 계정에 이 작업의 권한이 없습니다.')}`), {status:403});
      if (response.status === 409) { const error = new Error(`현재 기록과 충돌했습니다: ${stringify(data.error || data.message || '최신 근거를 다시 조회하세요.')}`); error.status = 409; throw error; }
      throw new Error(`요청 실패 (${response.status}): ${stringify(data.error || data.message || '서버 응답을 확인하세요.')}`);
    } return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('20초 동안 응답이 없습니다. 수집·서비스 상태를 확인하고 다시 조회하세요.');
    throw error;
  } finally { clearTimeout(timer); }
}
function showDetail(title, node) {
  detailEpoch++;
  $('#detail-title').textContent = title; $('#detail-content').replaceChildren(node);
  if (!$('#detail-dialog').open) $('#detail-dialog').showModal();
}
function inspect(title, value) { showDetail(title, el('pre', 'json', stringify(value))); }
function captureDetailContext() { return { detail: detailEpoch, auth: authEpoch }; }
function isCurrentDetail(context) { return context.detail === detailEpoch && context.auth === authEpoch && Boolean(token) && $('#detail-dialog').open; }
function savedNotice(context, message) { if (context.auth === authEpoch && token) notice(message); }
function observedOutcome(events) {
  const results = (events || []).filter((event) => event.sourceKind === 'tool' && event.kind === 'result');
  const success = results.some((event) => event.status === 'success'); const failure = results.some((event) => event.status === 'failure');
  return success && failure ? 'mixed_results' : success ? 'independently_reported_success' : failure ? 'independently_reported_failure' : 'unconfirmed';
}
function findingCoverage(evaluation) {
  const displayed = evaluation.findings?.length || 0; const total = evaluation.coverage?.totalFindings;
  const knownTotal = Number.isSafeInteger(total) && total >= displayed;
  const count = knownTotal ? `총 ${total}건 · 표시 ${displayed}건 · 생략 ${total - displayed}건` : `총수 미확인 · 표시 ${displayed}건 · 생략 수 미확인`;
  return `${count} · 표시 제한 ${evaluation.coverage?.truncated ? '있음' : '없음'}`;
}
function sourceTable(sources) {
  return table(['출처 ID', '테넌트', '종류', '마지막 수신', '상태'], (sources || []).map((s) => [s.id, s.tenant, s.kind, date(s.lastSeen), badge(s.status)]));
}
async function overview() {
  const data = await api('/api/overview'); const node = el('div'); const stats = el('div', 'grid stats');
  if (window.EvidScopeConsole) node.append(await window.EvidScopeConsole.overviewPulse());
  [['수집 이벤트', 'events', '지속성 접수된 관측 기록'], ['탐지 경보', 'alerts', '행동 대조와 룰의 위험 신호'], ['감사 사건', 'cases', '담당자가 검토하는 조사 기록'], ['분석 대기', 'backlog', '아직 평가가 완료되지 않은 기록']].forEach(([title, key, note]) => {
    const stat = el('section', 'stat'); stat.append(el('div', 'stat-label', title), el('div', 'stat-value', data.counts?.[key] == null ? '—' : data.counts[key].toLocaleString('ko-KR')), el('div', 'stat-note', note)); stats.append(stat);
  }); node.append(stats);
  const columns = el('div', 'grid two');
  const sources = card('관측 출처', '연결과 최근 수신 상태를 확인합니다.'); sources.append(sourceTable(data.sources));
  const investigation = card('근거에서 판단까지', '신호의 종류와 보장 범위를 구분합니다.');
  const timeline = el('div', 'timeline');
  [['01', '행동과 요청', 'AI 자기보고와 인증된 실행 기록을 분리합니다.'], ['02', '당시 권한과 검토', '부여·철회·유효기간·대상을 사건 시점에 대조합니다.'], ['03', '독립 결과와 인간 판단', '외부 효과의 확인 여부와 남은 불확실성을 검토합니다.']].forEach(([index, title, description]) => {
    const item = el('div', 'timeline-item'); item.append(el('small', '', index), el('p', 'timeline-title', title), el('p', 'muted', description)); timeline.append(item);
  }); investigation.append(timeline); columns.append(sources, investigation); node.append(columns, limits(data.limitations)); return node;
}
async function graphsView() {
  const viewEpoch = renderEpoch; let monitor = null;
  const root = el('div'); const modes = el('div', 'graph-mode-tabs');
  const content = el('div', 'graph-view-content'); let epoch = 0;
  const liveButton = button('AI 행동 · 현재 조회', () => choose('live'));
  const clusterButton = button('Kubernetes · 실험 결과', () => choose('cluster'));
  modes.append(liveButton, clusterButton); root.append(modes, content);
  async function choose(mode) {
    monitor?.dispose(); monitor = null;
    const current = ++epoch; const access = authEpoch;
    liveButton.setAttribute('aria-pressed', String(mode === 'live')); clusterButton.setAttribute('aria-pressed', String(mode === 'cluster'));
    content.replaceChildren(el('div', 'graph-loading', '그래프를 불러오고 있습니다…'));
    try {
      if (mode === 'cluster') { content.replaceChildren(window.EvidScopeK8s.render()); return; }
      if (!token) {
        const prompt = empty('AI 행동 그래프는 감사자 접속이 필요합니다', 'Kubernetes 탭에는 공개된 합성 실험 결과만 표시합니다. 실제 테넌트의 행동·증거는 인증 후 조회합니다.');
        prompt.append(button('감사자 접속', openLogin, 'primary')); content.replaceChildren(prompt); return;
      }
      const [overviewData, investigations] = await Promise.all([api('/api/overview'), api('/api/investigations?state=all&limit=100')]);
      if (current !== epoch || access !== authEpoch || viewEpoch !== renderEpoch || !token) return;
      monitor = window.EvidScopeMonitor.mount({dataNotice:overviewData.limitations?.find(text=>text.includes('합성')),fetchData:(range, source)=>api(`/api/monitoring?${new URLSearchParams({range,source})}`),isCurrent:()=>viewEpoch===renderEpoch&&current===epoch&&access===authEpoch&&Boolean(token)});
      disposeView = () => { epoch++; monitor?.dispose(); };
      content.replaceChildren(monitor.root, window.EvidScopeLiveGraphs.render({ overview: overviewData, investigations, onOpenAction: actionDetail }));
    } catch (error) { if (current === epoch && access === authEpoch) content.replaceChildren(empty('그래프를 표시하지 못했습니다', error.message)); }
  }
  await choose(token ? 'live' : 'cluster'); return root;
}
const reviewLabels = { unreviewed: '미검토', reviewed: '현재 근거 검토됨', stale: '새 근거·기한에 따른 재검토', inconclusive: '판단 유보 · 검토 필요' };
function reviewBadge(state) { return el('span', `badge review-${Object.hasOwn(reviewLabels, state) ? state : 'unreviewed'}`, reviewLabels[state] || '검토 상태 미확인'); }
function analysisLabel(state) { return ({ pending: '분석 대기', evaluated: '평가 완료', quarantined_resource_limit: '분석 미완료 · 자원 한도', not_observed: '분석 기록 없음' })[state] || '분석 상태 미확인'; }
function reportedValue(value) { return value === 'multiple' ? '여러 값 보고됨' : value === 'unknown' || !value ? '미수집' : value; }
async function investigationsView() {
  const node = el('div'); const stats = el('div', 'grid investigation-stats');
  const panel = card('검토할 행동', '행동별 증거와 사람의 판단을 함께 확인하세요. 경보가 없거나 검토를 마쳤다는 사실만으로 안전을 보장하지 않습니다.');
  const filters = el('form', 'toolbar');
  filters.append(field('행동·행위자·도구 검색', 'q', { value: workspaceFilters.q, placeholder: '행동 ID, 행위자, 도구, 목적지…' }), field('검토 상태', 'state', { choices: [{ value: 'needs_review', label: '검토 필요' }, { value: 'reviewed', label: '현재 근거 검토됨' }, { value: 'all', label: '전체 행동' }] }));
  const submit = el('button', 'primary', '조회'); submit.type = 'submit'; filters.append(submit);
  const scope = el('p', 'muted'); const results = el('div', 'investigation-list'); const pages = el('div', 'pagination');
  let offset = 0; let searchEpoch = 0;
  async function search() {
    const epoch = ++searchEpoch; const currentOffset = offset; submit.disabled = true; results.setAttribute('aria-busy', 'true'); results.replaceChildren(el('div', 'loading', '행동과 검토 상태를 조회하고 있습니다…')); pages.replaceChildren();
    try {
      const query = new URLSearchParams(new FormData(filters)); query.set('limit', '50'); query.set('offset', String(currentOffset));
      const data = await api(`/api/investigations?${query}`); if (epoch !== searchEpoch) return;
      stats.replaceChildren();
      [['검토 필요', data.counts?.needsReview, '미검토·새 근거·판단 유보'], ['현재 근거 검토됨', data.counts?.reviewed, '현재 증거와 유효한 재검토 기한 기준'], ['분석 대기', data.counts?.analysisPending, '아직 평가가 끝나지 않은 행동']].forEach(([title, count, note]) => { const stat = el('section', 'stat'); stat.append(el('div', 'stat-label', title), el('div', 'stat-value', count ?? '—'), el('div', 'stat-note', note)); stats.append(stat); });
      scope.textContent = `${data.total ?? 0}개 행동 · ${data.items.length ? `${currentOffset + 1}–${currentOffset + data.items.length}` : '0'} 표시 · 위 집계는 검색어 일치 전체, 목록은 검토 상태 필터 적용`;
      results.replaceChildren();
      if (!data.items.length) results.append(empty('이 조건에 해당하는 행동이 없습니다', '전체 행동으로 범위를 넓히거나 검색어를 확인하세요. 기록이 없다는 사실은 미관측 행동의 안전을 뜻하지 않습니다.'));
      for (const item of data.items) {
        const row = el('article', 'investigation-row'); const heading = el('div', 'investigation-heading');
        const state = el('div', 'actions'); state.append(reviewBadge(item.reviewState)); if (item.latestDecision) state.append(badge(item.latestDecision.conclusion));
        heading.append(el('h3', 'wrap', `${reportedValue(item.actor)} → ${reportedValue(item.tool)} · ${reportedValue(item.operation)}`), state);
        const facts = el('div', 'investigation-columns');
        const action = el('div'); action.append(el('span', 'small-label-inline', '무엇을 했는가'), el('p', 'wrap', reportedValue(item.resource)), el('p', 'muted wrap', `목적지 ${reportedValue(item.destination)}`));
        const outcome = el('div'); outcome.append(el('span', 'small-label-inline', '확인 결과'), el('p', 'wrap', label(item.outcome)), el('p', 'muted wrap', label(item.authority)), el('p', 'muted', analysisLabel(item.analysisStatus)));
        const evidence = el('div'); evidence.append(el('span', 'small-label-inline', '참고 자료와 관측 범위'), el('p', '', `이벤트 ${item.eventCount ?? '미확인'}건 · 자료 참조 ${item.referenceCount ?? '미확인'}${item.referenceCount == null ? '' : '건'}`), el('p', 'muted', item.referenceCount == null ? '참조 범위 조회 제한 · 개별 조사 필요' : item.referenceCount > 0 ? '참조의 출처·버전은 조사에서 대조' : '참고 데이터 출처 미수집'));
        const attention = el('div'); attention.append(el('span', 'small-label-inline', '검토할 이유'));
        const hints = el('ul', 'attention-list'); (item.attention?.length ? item.attention : ['현재 근거와 판단 범위를 확인하세요.']).forEach((hint) => hints.append(el('li', '', hint))); attention.append(hints);
        if (item.findingCount) { const finding = el('p', 'muted'); finding.append(badge(item.highestSeverity || 'unknown'), document.createTextNode(` 발견 ${item.findingCount}건`)); attention.append(finding); }
        facts.append(action, outcome, evidence, attention);
        const footer = el('div', 'investigation-footer'); const refs = el('div'); refs.append(el('p', 'mono wrap', item.actionId), el('p', 'muted', `관측 ${date(item.firstSeen)} ~ ${date(item.lastSeen)}`));
        const actions = el('div', 'actions'); actions.append(button('행동 조사 열기', () => actionDetail(item.actionId), 'primary small'));
        (item.caseIds || []).forEach((id) => actions.append(button('연결 사건 검토', () => caseDetail({ id }), 'small')));
        footer.append(refs, actions); row.append(heading, facts, footer); results.append(row);
      }
      const previous = button('← 이전 50건', async () => { offset = Math.max(0, currentOffset - 50); await search(); }); previous.disabled = currentOffset === 0;
      const next = button('다음 50건 →', async () => { offset = currentOffset + 50; await search(); }); next.disabled = currentOffset + data.items.length >= data.total;
      pages.append(previous, el('span', 'muted', `${Math.floor(currentOffset / 50) + 1}페이지`), next);
      if (data.scope) pages.append(jsonDetails('조회 범위', data.scope));
    } catch (error) { if (epoch === searchEpoch) results.replaceChildren(el('div', 'message error', error.message), button('다시 조회', search, 'small')); }
    finally { if (epoch === searchEpoch) { submit.disabled = false; results.removeAttribute('aria-busy'); } }
  }
  filters.addEventListener('submit', (event) => { event.preventDefault(); offset = 0; search(); });
  panel.append(filters, scope, results, pages); node.append(stats, panel); await search(); return node;
}
async function eventsView() {
  const node = card('이벤트 검색', '수신 시각과 발생 시각은 다를 수 있습니다. 상세에서 원본 참조와 해시를 확인하세요.');
  const filter = el('form', 'toolbar');
  filter.append(field('통합 검색', 'q', { value: workspaceFilters.q, placeholder: '행위자, 도구, 리소스, 목적지…' }), field('Trace ID', 'traceId', { placeholder: '연결된 작업 추적' }), field('이벤트 종류', 'kind', { choices: [{ value: '', label: '모든 종류' }, { value: 'intent', label: '행동 의도' }, { value: 'self_report', label: 'AI 자기보고' }, { value: 'execution', label: '독립 실행 기록' }, { value: 'result', label: '독립 결과 기록' }, { value: 'grant', label: '권한 부여' }, { value: 'revoke', label: '권한 철회' }, { value: 'human_approval', label: '사람 승인' }, { value: 'automated_review', label: '자동 검토' }, { value: 'delegation', label: '위임' }, { value: 'stop_requested', label: '중단 요청' }, { value: 'block_registered', label: '차단 등록' }, { value: 'stop_confirmed', label: '중단 확인' }, { value: 'safety_alert', label: '안전 경보' }, { value: 'heartbeat', label: '수집 하트비트' }, { value: 'gap', label: '수집 공백' }, { value: 'notice', label: '고지 기록' }] }));
  const submit = el('button', 'primary', '검색'); submit.type = 'submit'; filter.append(submit);
  const count = el('p', 'muted'); const results = el('div'); node.append(filter, count, results);
  async function search() {
    submit.disabled = true; results.replaceChildren(el('div', 'loading', '증거 조회 중'));
    try {
      const query = new URLSearchParams(new FormData(filter)); query.set('limit', '100');
      const data = await api(`/api/events?${query}`); count.textContent = `전체 ${data.total ?? data.items.length}건 · 최대 100건 표시`;
      results.replaceChildren(table(['발생 시각', '종류 / 출처', '행위자', '도구 · 행동', 'Action ID', '근거'], data.items.map((event) => [
        date(event.occurredAt), `${event.kind} / ${event.source}`, event.actor, `${event.tool || '—'} · ${event.action || '—'}`,
        event.actionId ? button(event.actionId, () => actionDetail(event.actionId), 'small') : '연결 없음', button('상세', () => inspect('수집 증거 · 원본 참조', event), 'small'),
      ])));
    } catch (error) { results.replaceChildren(el('div', 'message error', error.message)); } finally { submit.disabled = false; }
  }
  filter.addEventListener('submit', (event) => { event.preventDefault(); search(); }); await search(); return node;
}
function evidenceFacts(entries) {
  const node = el('dl', 'evidence-facts');
  entries.forEach(([title, value]) => node.append(el('dt', '', title), el('dd', '', value || '미수집')));
  return node;
}
function evidenceComparison(title, description, events, missing) {
  const section = card(title, description);
  if (!events.length) { section.append(el('div', 'message warning', missing)); return section; }
  const list = el('div', 'list');
  for (const event of events) {
    const item = el('article', 'comparison-event'); const top = el('div', 'actions');
    top.append(badge(event.kind), badge(event.status || 'unknown'));
    item.append(top, el('p', 'evidence-origin', `수집 출처 ${event.source} · ${label(event.assurance)}`), evidenceFacts([
      ['발생 / 접수', `${date(event.occurredAt)} / ${date(event.receivedAt)}`],
      ['보고된 행위자 / 모델', `${event.actor || '미수집'} / ${event.model || '미수집'}`],
      ['도구 · 행동', `${event.tool || '미수집'} · ${event.action || '미수집'}`],
      ['대상 리소스', event.resource], ['목적지', event.destination], ['사용 목적', event.purpose],
      ['데이터 범주', (event.dataCategories || []).join(', ')], ['당시 정책 버전', event.policyVersion],
    ]));
    if (['grant', 'revoke', 'human_approval', 'automated_review', 'delegation'].includes(event.kind)) item.append(evidenceFacts([
      ['권한·승인 유효기간', event.validFrom || event.validUntil ? `${date(event.validFrom)} ~ ${date(event.validUntil)}` : '미수집'],
      ['범위', event.scope ? stringify(event.scope) : '미수집'], ['검토자 참조', event.reviewer], ['관련 권한 ID', event.authorityId], ['부모 행동 ID', event.parentActionId],
    ]));
    item.append(jsonDetails(`근거 ${event.source}/${event.id} · 전체 메타데이터`, event)); list.append(item);
  }
  section.append(list); return section;
}
function actionEvidenceSummary(data) {
  const node = el('div'); const events = [...(data.events || [])].sort((a, b) => String(a.occurredAt).localeCompare(String(b.occurredAt)));
  node.append(el('h3', '', '행동과 근거를 나란히 대조'), el('p', 'muted', '출처는 수신 인증으로 확인한 제출 주체입니다. 행위자·모델 이름과 내용은 해당 출처가 보고한 값이며, 인증만으로 사실이나 실제 데이터 사용을 보증하지 않습니다.'));
  const comparison = el('div', 'evidence-comparison');
  comparison.append(
    evidenceComparison('요청 · AI 자기보고', 'AI가 하려던 일과 스스로 보고한 결과입니다.', events.filter((event) => ['intent', 'self_report'].includes(event.kind)), '요청·자기보고 미수집: AI가 무엇을 하려 했는지 확인할 수 없습니다.'),
    evidenceComparison('실행 · 도구 관측', '인증된 도구 출처가 제출한 실행 기록입니다.', events.filter((event) => event.kind === 'execution' && event.sourceKind === 'tool'), '독립 실행 기록 미수집: 요청이 실제 실행되었는지 확인할 수 없습니다.'),
    evidenceComparison('독립 결과', 'AI 자기보고와 별개인 도구 출처의 결과를 비교하세요.', events.filter((event) => event.kind === 'result' && event.sourceKind === 'tool'), '독립 결과 미수집: 자기보고만으로 실제 외부 효과를 확정할 수 없습니다.'),
    evidenceComparison('당시 권한 · 승인 · 위임', '정책 버전·범위·유효기간을 실제 실행 시점과 대조하세요. 자동 검토와 사람 승인은 별개입니다.', events.filter((event) => ['grant', 'revoke', 'human_approval', 'automated_review', 'delegation'].includes(event.kind)), '당시 권한 증거 미수집: 유효한 권한·승인 아래 행동했는지 확인할 수 없습니다.'),
  ); node.append(comparison);
  const references = Array.isArray(data.references) ? data.references : events.flatMap((event) => (event.dataRefs || []).map((ref) => ({ ...ref, source: event.source, eventId: event.id, assurance: event.assurance, observedAt: event.occurredAt, verification: event.sourceKind === 'agent' ? 'self_reported_reference' : 'service_reported_reference' })));
  const referenceCard = card('참고 데이터 · 출처와 버전', '자료 원문을 저장하지 않고 식별자·버전·해시 메타데이터를 연결합니다. 담당자는 접근 권한이 있는 외부 실물과 직접 대조하세요.');
  if (!references.length) referenceCard.append(el('div', 'message warning', '참고 데이터 출처 미수집 / 모델이 무엇을 참고했는지 확인할 수 없음'));
  else {
    referenceCard.append(el('p', 'muted', '참조 기록은 실제 열람·사용이나 원문 일치를 자동 증명하지 않습니다. 위치는 텍스트로만 표시하며 자동 접속하거나 자료를 가져오지 않습니다.'));
    const refs = el('div', 'evidence-comparison');
    for (const ref of references) {
      const item = el('article', 'reference-item'); const top = el('div', 'actions'); top.append(badge(ref.kind), badge(ref.role), badge(ref.verification));
      item.append(top, el('h3', 'wrap', ref.id), evidenceFacts([
        ['자료 버전', ref.version], ['보고된 해시', ref.hash], ['수집 출처 / 이벤트', `${ref.source || '미수집'} / ${ref.eventId || '미수집'}`],
        ['출처 보장', label(ref.assurance)], ['관측 시각', ref.observedAt ? date(ref.observedAt) : '미수집'], ['자료 위치 (자동 접근 없음)', ref.locator], ['설명', ref.description],
      ]), jsonDetails('참조 메타데이터', ref)); refs.append(item);
    }
    referenceCard.append(refs);
  }
  node.append(referenceCard); return node;
}
async function actionDetail(actionId) {
  showDetail('행동 조사', el('div', 'loading', '행동의 원본 근거와 연결 사건을 조회합니다…')); const epoch = detailEpoch;
  let data; let caseData;
  try { [data, caseData] = await Promise.all([api(`/api/actions/${encodeURIComponent(actionId)}`), api('/api/cases')]); }
  catch (error) { if (epoch === detailEpoch) showDetail('행동 조회 실패', el('div', 'message error', error.message)); return; }
  if (epoch !== detailEpoch) return;
  const node = el('div');
  node.append(el('p', 'selection-note', `행동 ID · ${actionId}`));
  const linkedCases = (caseData.items || []).filter((item) => item.actionId === actionId); const caseLinks = el('div', 'case-links');
  caseLinks.append(el('strong', '', '사람의 판단으로 연결'));
  if (linkedCases.length) linkedCases.forEach((item) => caseLinks.append(button(`${item.title} · 사건 검토`, () => caseDetail(item), 'primary small')));
  else caseLinks.append(el('span', 'muted', '아직 연결된 감사 사건이 없습니다.'), button('사건을 만들어 판단 기록', () => newCase(actionId), 'primary small'));
  node.append(caseLinks);
  const latest = [...(data.evaluations || [])].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))[0];
  const assurance = el('div', 'assurance');
  [['출처 인증', '각 이벤트의 수신자 확인 메타데이터를 참조'], ['마지막 자동 평가의 권한 판단', label(latest?.authority ?? '평가 없음')], ['실제 외부 효과 · 현재 관측', label(observedOutcome(data.events))]].forEach(([title, value]) => { const box = el('div'); box.append(el('strong', '', title), el('span', 'wrap', value)); assurance.append(box); });
  node.append(assurance, limits(data.limitations));
  node.append(el('p', 'muted', '현재 관측 결과는 지금 조회된 도구 결과 전체를 대조합니다. 성공·실패 기록이 함께 있으면 혼재로 표시하며, 서비스 보고 자체가 외부 사실의 진실성을 보증하지 않습니다.'));
  if (latest) node.append(el('p', 'muted', `마지막 자동 평가 ${date(latest.createdAt)}의 결과: ${label(latest.effect)}. 이 평가는 이후 도착한 증거를 반영하지 않았을 수 있습니다.`));
  node.append(el('p', 'muted', data.analysis?.pending === true ? '현재 분석 대기: 새 증거의 자동 평가가 아직 끝나지 않았습니다.' : data.analysis?.pending === false ? '현재 조회 시점의 분석 대기는 없습니다.' : '이 응답에는 현재 분석 대기 상태가 없어 평가의 최신성을 확인할 수 없습니다.'));
  if (latest?.status === 'quarantined_resource_limit') node.append(el('div', 'message warning', '분석 미완료: 자원 한도를 초과하여 이 행동을 평가하지 못했습니다. 발견 사항이 없더라도 정상 또는 무사고 판정이 아닙니다.'), jsonDetails('분석 범위·제한 근거', latest.coverage));
  else if (latest?.coverage?.truncated) node.append(el('div', 'message warning', '평가 발견 사항이 제한되어 일부만 표시됩니다. 전체 범위에 대한 무사고 판정으로 사용할 수 없습니다.'), jsonDetails('평가 범위·생략 내역', latest.coverage));
  node.append(window.EvidScopeLiveGraphs.action(data, inspect), actionEvidenceSummary(data));
  if (latest?.findings?.length) {
    const findings = card('최신 평가의 발견 사항', '권한 범위 일치와 사람 승인 일치는 별개입니다. 해당 원본 근거를 확인하세요.');
    findings.append(table(['중요도', '발견 사항', '원본 근거'], latest.findings.map((finding) => {
      const refs = el('div', 'actions');
      for (const ref of finding.evidence || []) refs.append(button(ref, () => inspect('발견 사항의 원본 증거', (data.events || []).find((event) => `${event.source}/${event.id}` === ref) || { reference: ref, status: '이 행동에서 참조 이벤트를 찾을 수 없습니다.' }), 'small'));
      const message = el('div', 'wrap', finding.message); return [badge(finding.severity), message, refs];
    }))); node.append(findings);
  }
  const timeline = el('div', 'timeline');
  [...(data.events || [])].sort((a, b) => String(a.occurredAt).localeCompare(String(b.occurredAt))).forEach((event) => {
    const item = el('div', 'timeline-item'); const title = el('div', 'timeline-title'); title.append(el('span', '', event.kind), badge(event.status || 'unknown'), badge(event.assurance || 'unknown'));
    item.append(title, el('p', 'muted', `${date(event.occurredAt)} · 출처 ${event.source} · 수신 ${date(event.receivedAt)}`), el('p', '', `${event.actor || '행위자 미확인'} → ${event.tool || event.resource || '대상 미확인'} · ${event.action || ''}`), jsonDetails(`이벤트 ${event.id} · 출처 보장·본문·해시`, event)); timeline.append(item);
  }); node.append(el('h3', '', '발생 시각 기준 타임라인'), timeline);
  if (!(data.events || []).length) node.append(empty('연결된 이벤트 없음', 'Action ID와 테넌트 범위를 확인하세요.'));
  node.append(el('h3', '', '평가 이력'));
  (data.evaluations || []).forEach((evaluation) => node.append(jsonDetails(`${date(evaluation.createdAt)} · ${evaluation.status === 'quarantined_resource_limit' ? '분석 미완료 · 자원 한도' : findingCoverage(evaluation)}`, evaluation)));
  if (linkedCases.length) node.append(button('추가 사건 만들기', () => newCase(actionId), 'small'));
  showDetail('행동 · 권한 · 결과 대조', node);
}
async function alertsView() {
  const data = await api('/api/alerts'); const node = card('탐지된 위험 신호', '늦게 도착한 증거로 평가가 바뀔 수 있습니다. 행동 상세에서 평가 이력을 확인하세요.');
  node.append(table(['중요도', '탐지', '내용', '생성 시각', '상태', '조사'], data.items.map((item) => {
    const actions = el('div', 'actions');
    if (item.actionId) actions.append(button('행동 대조', () => actionDetail(item.actionId), 'small'), button('사건 생성', () => newCase(item.actionId, item.message), 'small'));
    actions.append(button('근거', () => inspect('경보 · 원본 증거 참조', item), 'small'));
    return [badge(item.severity), item.code, item.message, date(item.createdAt), badge(item.state || 'open'), actions];
  }))); return node;
}
function newCase(actionId = '', title = '') {
  const node = form([field('사건 제목', 'title', { required: true, value: title }), field('행동 ID', 'actionId', { required: true, value: actionId }), field('담당자', 'owner', { required: true })], '사건 생성', async (values) => {
    const submission = captureDetailContext(); const created = await api('/api/cases', 'POST', values);
    if (isCurrentDetail(submission)) { await navigate('cases'); if (isCurrentDetail(submission)) await caseDetail(created); }
    savedNotice(submission, `사건 '${values.title}'을 생성했습니다. 근거를 선택하고 사람의 판단을 기록하세요.`);
  }); showDetail('새 감사 사건', node);
}
async function casesView() {
  const data = await api('/api/cases'); const node = card('사건 목록', '사건의 종결은 원본 삭제나 법적 면제를 의미하지 않습니다.');
  node.querySelector('.card-header').append(button('+ 사건 생성', () => newCase(), 'primary small'));
  node.append(table(['사건', '행동 ID', '담당자', '상태', '검토'], data.items.map((item) => [item.title, item.actionId, item.owner, badge(item.status), button('검토 열기', () => caseDetail(item), 'small')]))); return node;
}
function decisionHistory(context) {
  const section = card('인간 판단 이력', '이전 판단은 보존됩니다. 새 근거·재검토 기한과 현재 판단 상태를 함께 확인하세요.');
  const decisions = [...(context.decisions || [])].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  if (!decisions.length) section.append(el('p', 'muted', '아직 기록된 인간 판단이 없습니다.'));
  for (const decision of decisions) {
    const item = el('article', 'decision-record'); const heading = el('div', 'actions'); heading.append(badge(decision.conclusion), el('span', 'muted', `${decision.reviewedBy} · ${date(decision.createdAt)}`));
    item.append(heading, evidenceFacts([['판단 근거', decision.reason], ['확인 범위', decision.scope], ['남은 한계', decision.limitations], ['다음 검토', date(decision.nextReviewAt)]]));
    if (decision.evidence?.length) item.append(table(['선택한 원본 근거', '판단과의 관계', '검토 메모'], decision.evidence.map((evidence) => [evidence.ref, label(evidence.supports), el('div', 'wrap', evidence.note)])));
    item.append(jsonDetails('판단 기록 식별자·대상 근거', decision)); section.append(item);
  }
  return section;
}
function caseDecisionForm(context) {
  const section = card('근거를 선택하고 판단 기록', '자료를 확인한 사람이 근거와 한계를 직접 작성합니다. 기술 탐지 결과와 인간 판단을 구분합니다.');
  if (context.analysis?.pending) section.append(el('div', 'message warning', '새 증거의 분석이 아직 끝나지 않았습니다. 지금 기록하는 판단은 현재까지 확인한 범위에 한정됩니다. 분석이 완료되면 재검토가 필요할 수 있습니다.'));
  const evaluation = context.evaluations?.[0];
  if (evaluation?.status === 'quarantined_resource_limit') section.append(el('div', 'message warning', '자원 한도로 분석하지 못한 행동입니다. 발견 사항이 없는 것을 정상 판정으로 해석하지 마세요.'));
  if (evaluation?.coverage?.truncated) section.append(el('div', 'message warning', '자동 분석의 발견 사항이 일부 생략되어 있습니다. 표시된 결과만으로 전체 범위를 판단하지 마세요.'));
  if (evaluation?.findings?.length) { const findings = el('details'); findings.append(el('summary', '', `자동 분석 참고 · ${findingCoverage(evaluation)}`), table(['중요도', '발견 사항', '원본 근거'], evaluation.findings.map((finding) => [badge(finding.severity), el('div', 'wrap', finding.message), el('div', 'wrap', (finding.evidence || []).join(', '))]))); section.append(findings); }
  const evidenceList = el('div', 'decision-evidence-list'); const selections = [];
  for (const [index, event] of (context.events || []).entries()) {
    const item = el('article', 'decision-evidence'); const selectLabel = el('label', 'evidence-choice'); const checkbox = el('input'); checkbox.type = 'checkbox'; checkbox.name = `evidence-${index}`;
    const caption = el('span'); caption.append(el('strong', 'wrap', `${event.source}/${event.id}`), el('span', 'muted', `${label(event.kind)} · ${date(event.occurredAt)} · ${label(event.assurance)}`)); selectLabel.append(checkbox, caption);
    const supportField = field('이 근거와 판단의 관계', `supports-${index}`, { choices: ['supports', 'contradicts', 'context'], value: 'context' }); const support = supportField.querySelector('select');
    const noteField = field('이 근거를 선택한 이유 (선택)', `note-${index}`, { multiline: true, maxLength: 1000, placeholder: '확인한 내용, 상충하는 점 또는 배경 설명' }); const note = noteField.querySelector('textarea');
    support.disabled = true; note.disabled = true;
    checkbox.addEventListener('change', () => { support.disabled = !checkbox.checked; note.disabled = !checkbox.checked; item.classList.toggle('selected', checkbox.checked); });
    const reviewFields = el('div', 'form-grid'); reviewFields.append(supportField, noteField);
    item.append(selectLabel, el('p', 'muted wrap', `${event.actor || '행위자 미수집'} → ${event.tool || '도구 미수집'} · ${event.action || '행동 미수집'} · ${event.resource || '대상 미수집'}`), jsonDetails('원본 이벤트와 참고 자료 메타데이터', event), reviewFields); evidenceList.append(item);
    selections.push({ checkbox, support, note, ref: `${event.source}/${event.id}` });
  }
  if (!selections.length) evidenceList.append(el('div', 'message warning', '선택할 원본 이벤트가 없습니다. 수집 공백·보존 종료 여부를 확인하고 판단 가능한 범위를 제한하세요.'));
  const decisionForm = form([
    field('인간 판단', 'conclusion', { choices: ['inconclusive', 'confirmed_issue', 'no_issue_found'], value: 'inconclusive' }),
    field('다음 검토 일시', 'nextReviewAt', { required: true, type: 'datetime-local' }),
    field('판단 근거', 'reason', { required: true, multiline: true, wide: true, maxLength: 3000, placeholder: '선택한 근거가 이 판단을 뒷받침하거나 제한하는 이유' }),
    field('직접 확인한 범위', 'scope', { required: true, multiline: true, wide: true, maxLength: 2000, placeholder: '대상 행동, 시점, 출처, 검토한 문서와 절차' }),
    field('남은 한계·확인하지 못한 사항', 'limitations', { required: true, multiline: true, wide: true, maxLength: 2000, placeholder: '부족한 증거, 독립 확인이 없는 주장, 추가 검토가 필요한 부분' }),
  ], '인간 판단 기록 저장', async (values, result) => {
    const submission = captureDetailContext();
    for (const name of ['reason', 'scope', 'limitations']) if (!values[name].trim()) throw new Error('판단 근거·확인 범위·남은 한계를 빈칸 없이 작성하세요.');
    const nextReviewAt = new Date(values.nextReviewAt); if (!Number.isFinite(nextReviewAt.getTime()) || nextReviewAt.getTime() <= Date.now()) throw new Error('다음 검토 일시는 현재보다 미래로 정하세요.');
    const evidence = selections.filter((selection) => selection.checkbox.checked).map((selection) => ({ ref: selection.ref, supports: selection.support.value, note: selection.note.value.trim() }));
    if (evidence.length > 30) throw new Error('판단 근거는 최대 30개까지 선택할 수 있습니다.');
    if (values.conclusion !== 'inconclusive' && !evidence.length) throw new Error('문제 확인·문제 미발견 판단에는 원본 근거를 하나 이상 선택하세요.');
    try {
      await api(`/api/cases/${encodeURIComponent(context.case.id)}/decisions`, 'POST', { contextHash: context.contextHash, conclusion: values.conclusion, reason: values.reason.trim(), scope: values.scope.trim(), limitations: values.limitations.trim(), nextReviewAt: nextReviewAt.toISOString(), evidence });
    } catch (error) {
      if (error.status === 409) { result.append(el('div', 'message warning', `${error.message} 판단은 저장되지 않았습니다. 아래 버튼으로 최신 근거를 다시 조회한 뒤 검토하세요. 현재 작성한 내용은 재조회 시 초기화됩니다.`), button('최신 근거 다시 조회 · 작성 내용 초기화', () => caseDetail(context.case), 'small')); return; }
      throw error;
    }
    if (isCurrentDetail(submission)) await caseDetail(context.case);
    savedNotice(submission, `사건 '${context.case.title}'의 근거와 인간 판단을 기록했습니다. 새 증거나 재검토 기한이 도래하면 다시 검토하세요.`);
  });
  const step = el('div', 'decision-step'); step.append(el('h3', '', '1. 판단에 사용할 원본 근거 선택'), evidenceList, el('h3', '', '2. 판단과 범위 기록'));
  decisionForm.prepend(step); section.append(decisionForm, jsonDetails('현재 판단 대상의 식별 해시', { contextHash: context.contextHash })); return section;
}
function downloadArtifact(filename, type, text) {
  const blob = new Blob([text], { type }); const url = URL.createObjectURL(blob); const link = el('a'); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000);
}
function reportMarkdown(report) {
  const snapshot = report.snapshot; const caseItem = snapshot.case; const review = snapshot.review || {}; const action = snapshot.action || {};
  const md = (value) => stringify(value ?? '미수집').replace(/[\r\n]+/g, ' / ').replace(/[\\`*_{}\[\]<>()#+.!|~]/g, '\\$&');
  const lines = [`# EvidScope 인간 감사 보고서`, '', `## 사건: ${md(caseItem.title)}`, '', `- 사건 ID: ${md(caseItem.id)}`, `- 행동 ID: ${md(action.actionId || caseItem.actionId)}`, `- 테넌트: ${md(snapshot.tenant)}`, `- 담당자: ${md(caseItem.owner)}`, `- 사건 상태: ${md(label(caseItem.status))}`, `- 보고서 생성: ${md(snapshot.exportedAt)} · ${md(snapshot.exportedBy)}`, '', '> 이 Markdown은 서명된 JSON과 동일한 스냅샷의 읽기용 사본입니다. Markdown 자체는 서명되지 않았습니다. 진본 검증에는 함께 제공되는 JSON과 별도로 확보한 신뢰 앵커가 필요합니다.', '', '## 현재 인간 검토 상태', '', md(reviewLabels[review.state] || review.state), '', '판단은 업무 AI의 실행 승인이나 법적 준수·안전을 보증하지 않습니다.', '', '## 인간 판단 이력', ''];
  if (!(review.decisions || []).length) lines.push('인간 판단 기록 없음.', '');
  for (const decision of review.decisions || []) {
    lines.push(`### ${md(label(decision.conclusion))}`, '', `- 검토자: ${md(decision.reviewedBy)} · ${md(decision.createdAt)}`, `- 판단 근거: ${md(decision.reason)}`, `- 확인 범위: ${md(decision.scope)}`, `- 남은 한계: ${md(decision.limitations)}`, `- 다음 검토: ${md(decision.nextReviewAt)}`, '');
    for (const evidence of decision.evidence || []) lines.push(`- 근거 ${md(evidence.ref)} · ${md(label(evidence.supports))}: ${md(evidence.note)}`);
    lines.push('');
  }
  lines.push('## 행동과 관측 근거', '');
  for (const event of action.events || []) lines.push(`### ${md(event.source)}/${md(event.id)}`, '', `- 종류 / 출처 보장: ${md(label(event.kind))} / ${md(label(event.assurance))}`, `- 발생 / 접수: ${md(event.occurredAt)} / ${md(event.receivedAt)}`, `- 보고된 행위자 / 모델: ${md(event.actor)} / ${md(event.model)}`, `- 도구 / 행동 / 결과: ${md(event.tool)} / ${md(event.action)} / ${md(label(event.status))}`, `- 대상 / 목적지: ${md(event.resource)} / ${md(event.destination)}`, `- 사용 목적 / 데이터 범주: ${md(event.purpose)} / ${md(event.dataCategories)}`, `- 당시 정책 버전: ${md(event.policyVersion)}`, '');
  lines.push('## 참고 자료', '', '자료 원문과 실제 사용 여부는 이 참조 기록만으로 검증되지 않습니다. 자료 위치를 자동으로 조회하지 않습니다.', '');
  if (!(action.references || []).length) lines.push('참고 데이터 출처 미수집: 모델이 무엇을 참고했는지 확인할 수 없음.', '');
  for (const reference of action.references || []) lines.push(`- ${md(reference.id)} · ${md(label(reference.kind))} · ${md(label(reference.role))}`, `  - 버전 / 해시: ${md(reference.version)} / ${md(reference.hash)}`, `  - 제출 출처 / 이벤트: ${md(reference.source)} / ${md(reference.eventId)}`, `  - 참조 보장: ${md(label(reference.verification))} · ${md(label(reference.assurance))}`, `  - 관측 시각: ${md(reference.observedAt)}`, `  - 자료 위치: ${md(reference.locator)}`, '');
  lines.push('## 기술 평가', '');
  lines.push(`- 현재 관측 결과: ${md(label(observedOutcome(action.events)))}`, `- 현재 분석 대기: ${action.analysis?.pending === true ? '있음 · 아래 기존 평가는 새 증거를 반영하지 않았을 수 있습니다.' : action.analysis?.pending === false ? '없음' : '미확인'}`, '');
  for (const evaluation of action.evaluations || []) { lines.push(`- 평가 시각 ${md(evaluation.createdAt)} · ${md(analysisLabel(evaluation.status || 'evaluated'))}`, `  - 발견 범위: ${md(findingCoverage(evaluation))}`, `  - 당시 평가의 권한: ${md(label(evaluation.authority))} · 당시 평가의 외부 결과: ${md(label(evaluation.effect))}`); for (const finding of evaluation.findings || []) lines.push(`  - ${md(label(finding.severity))}: ${md(finding.message)} · 근거 ${md(finding.evidence)}`); }
  lines.push('', '## 관측·검토 한계', ''); for (const limitation of snapshot.limitations || []) lines.push(`- ${md(limitation)}`);
  lines.push('', '## 서명 정보와 전체 스냅샷', '', `- 서명 보고서 형식: ${md(report.format)}`, `- 공개키 지문: ${md(report.publicKeyFingerprint)}`, '- 이 화면에서는 서명 진위를 독립 검증하지 않았습니다.', '- 아래 데이터에는 사건 댓글·과제, 선택 근거, 평가와 체크포인트를 포함한 같은 스냅샷 전체가 들어 있습니다.', '');
  const json = JSON.stringify(snapshot, null, 2); let fenceLength = 3; for (const match of json.matchAll(/`+/g)) fenceLength = Math.max(fenceLength, match[0].length + 1); const fence = '`'.repeat(fenceLength);
  lines.push(`${fence}json`, json, fence, ''); return lines.join('\n');
}
async function caseReport(id) {
  showDetail('사건 보고서 준비', el('div', 'loading', '같은 시점의 사건·판단·원본 근거를 묶습니다…')); const epoch = detailEpoch; const requestAuthEpoch = authEpoch;
  let report;
  try { report = await api(`/api/cases/${encodeURIComponent(id)}/report`); }
  catch (error) { if (epoch === detailEpoch) showDetail('보고서 조회 실패', el('div', 'message error', error.message)); return; }
  if (epoch !== detailEpoch) return;
  const snapshot = report.snapshot; const node = el('div');
  node.append(el('p', 'selection-note', `${snapshot.case.title} · ${date(snapshot.exportedAt)}`), reviewBadge(snapshot.review?.state), el('p', '', `관측 이벤트 ${snapshot.action?.events?.length || 0}건 · 자료 참조 ${snapshot.action?.references?.length || 0}건 · 인간 판단 ${snapshot.review?.decisions?.length || 0}건`), el('p', 'message warning', '두 파일은 동일한 스냅샷을 담습니다. JSON에는 서버 서명이 포함되며 Markdown은 서명되지 않은 읽기용 사본입니다. 이 화면에서는 진위를 독립 검증하지 않았습니다. JSON을 별도로 확보한 신뢰 앵커로 검증하세요.'));
  const actions = el('div', 'actions'); const filename = `evidscope-case-${String(id).replace(/[^a-zA-Z0-9_-]/g, '_')}-${new Date(snapshot.exportedAt).toISOString().slice(0, 10)}`;
  const checkSession = () => { if (!token || requestAuthEpoch !== authEpoch) throw new Error('접속 상태가 변경되었습니다. 보고서를 다시 조회하세요.'); };
  actions.append(button('서명된 JSON 다운로드', () => { checkSession(); downloadArtifact(`${filename}.json`, 'application/json', JSON.stringify(report, null, 2)); }, 'primary'), button('사람이 읽는 Markdown 다운로드', () => { checkSession(); downloadArtifact(`${filename}.md`, 'text/markdown;charset=utf-8', reportMarkdown(report)); }));
  node.append(actions, jsonDetails('서명 형식·공개키 지문·체크포인트', { format: report.format, publicKeyFingerprint: report.publicKeyFingerprint, signature: report.signature, checkpoint: snapshot.checkpoint }), limits(snapshot.limitations), button('사건 검토로 돌아가기', () => caseDetail({ id }), 'small')); showDetail('사건 보고서 내보내기', node);
}
async function caseDetail(item) {
  showDetail('사건 · 인간 판단', el('div', 'loading', '최신 사건과 판단할 근거를 조회합니다…')); const epoch = detailEpoch;
  let context;
  try { context = await api(`/api/cases/${encodeURIComponent(item.id)}/review-context`); }
  catch (error) { if (epoch === detailEpoch) showDetail('사건 조회 실패', el('div', 'message error', error.message)); return; }
  if (epoch !== detailEpoch) return;
  item = context.case;
  const node = el('div'); const intro = el('div', 'case-review-intro');
  intro.append(el('p', 'mono wrap', `${item.id} · ${item.actionId}`), reviewBadge(context.reviewState), el('p', '', '근거를 고르고, 확인한 범위와 남은 한계를 사람의 판단으로 남기세요. 이 기록은 업무 AI의 실행 승인이나 법적 준수 판정이 아닙니다.'));
  if (context.latestDecision) intro.append(el('p', 'wrap', `최근 판단: ${label(context.latestDecision.conclusion)} · ${context.latestDecision.reviewedBy} · 다음 검토 ${date(context.latestDecision.nextReviewAt)}`));
  const actions = el('div', 'actions'); actions.append(button('행동 원본·권한 대조', () => actionDetail(item.actionId), 'small'), button('사건 보고서 내보내기', () => caseReport(item.id), 'small'));
  if (window.EvidScopeTeamSupport) actions.append(button('AI 검토 지원 요청', () => window.EvidScopeTeamSupport.openForCase(item.id), 'small'));
  intro.append(actions); node.append(intro);
  node.append(caseDecisionForm(context), decisionHistory(context), limits(context.limitations));
  const management = el('details', 'case-management'); management.append(el('summary', '', '사건 담당자 · 댓글 · 과제 · 종결 관리'));
  management.append(form([
    field('담당자', 'owner', { value: item.owner || '', required: true }), field('사건 상태', 'status', { choices: ['open', 'in_review', 'closed'], value: item.status }),
    field('검토 의견', 'comment', { multiline: true, wide: true }), field('변경·종결 사유', 'reason', { multiline: true, wide: true, placeholder: '종결 시 판단 근거와 남은 위험을 기록하세요.' }),
    field('조치 과제 제목 (선택)', 'taskTitle'), field('과제 담당자', 'taskOwner'), field('과제 기한', 'taskDueAt', { type: 'datetime-local' }),
  ], '감사 기록 추가', async (values) => {
    const submission = captureDetailContext();
    const payload = { owner: values.owner, status: values.status, comment: values.comment, reason: values.reason };
    if (values.status === 'closed' && !values.reason.trim()) throw new Error('사건 종결 사유를 입력하세요.');
    if (values.taskTitle && !values.taskDueAt) throw new Error('조치 과제를 추가하려면 기한을 입력하세요.');
    if (values.taskTitle) payload.task = { title: values.taskTitle, owner: values.taskOwner || values.owner, dueAt: new Date(values.taskDueAt).toISOString(), status: 'open' };
    await api(`/api/cases/${encodeURIComponent(item.id)}`, 'POST', payload);
    if (isCurrentDetail(submission)) { detailEpoch++; $('#detail-dialog').close(); await navigate('cases'); }
    savedNotice(submission, `사건 '${item.title}'의 검토 의견과 변경 이력을 추가했습니다.`);
  }));
  management.append(jsonDetails('검토 의견', item.comments || []), jsonDetails('감사 변경 이력', item.history || []));
  if (item.tasks?.length) {
    management.append(el('h3', '', '조치 과제'), table(['과제', '담당자', '기한', '상태', '관리'], item.tasks.map((task) => [task.title, task.owner, date(task.dueAt), badge(task.status), button('수정', () => {
      showDetail('사건 조치 과제 수정', form([field('제목', 'title', { required: true, value: task.title }), field('담당자', 'owner', { required: true, value: task.owner }), field('기한', 'dueAt', { required: true, type: 'datetime-local', value: localDate(task.dueAt) }), field('상태', 'status', { choices: ['open', 'closed'], value: task.status }), field('변경 사유', 'reason', { required: true, wide: true })], '과제 변경 기록', async (values) => {
        const submission = captureDetailContext();
        await api(`/api/cases/${encodeURIComponent(item.id)}`, 'POST', { reason: values.reason, task: { id: task.id, title: values.title, owner: values.owner, dueAt: new Date(values.dueAt).toISOString(), status: values.status } });
        if (isCurrentDetail(submission)) { detailEpoch++; $('#detail-dialog').close(); await navigate('cases'); }
        savedNotice(submission, `사건 '${item.title}'의 과제 변경과 검토 이력을 저장했습니다.`);
      }));
    }, 'small')])));
  } node.append(management); showDetail(item.title, node);
}
async function rulesView() {
  const [data, exceptions] = await Promise.all([api('/api/rules'), api('/api/exceptions')]); const node = el('div');
  const list = card('탐지 룰 버전', '시험 결과를 확인한 뒤 다른 검토자가 승인합니다. 자유 코드나 외부 조회를 실행하지 않습니다.');
  list.querySelector('.card-header').append(button('+ 룰 작성', () => ruleEditor(), 'primary small'));
  list.append(table(['룰 / 버전', '제목', '조건', '중요도', '상태', '검토'], data.items.map((rule) => {
    const actions = el('div', 'actions'); actions.append(button('새 버전', () => ruleEditor(rule), 'small'), button('시험', async () => inspect('룰 시험 · 기존 증거의 일치 결과', await api(`/api/rules/${encodeURIComponent(rule.id)}/test`, 'POST', { version: rule.version })), 'small'), button('승인', async () => { await api(`/api/rules/${encodeURIComponent(rule.id)}/approve`, 'POST', { version: rule.version }); await navigate('rules'); notice('룰 버전을 승인했습니다. 과거 평가 이력은 보존됩니다.'); }, 'small'));
    return [`${rule.id} / v${rule.version}`, rule.title, `${rule.field} ${rule.op} ${stringify(rule.value)}`, badge(rule.severity), badge(rule.status), actions];
  }))); node.append(list);
  const exceptionCard = card('기한이 있는 예외', '사유·책임자·기한을 남기고 별도 검토자가 승인합니다. 원본 증거와 평가 이력은 보존됩니다.');
  exceptionCard.querySelector('.card-header').append(button('+ 예외 요청', exceptionEditor, 'small'));
  exceptionCard.append(table(['룰 / 행동', '사유', '책임자', '기한', '상태', '검토'], (exceptions.items || []).map((item) => [`${item.ruleId} / ${item.actionId}`, item.reason, item.owner, date(item.expiresAt), badge(item.status || item.state || 'pending'), button('승인', async () => { await api(`/api/exceptions/${encodeURIComponent(item.id)}/approve`, 'POST', {}); await navigate('rules'); notice('예외를 승인했습니다.'); }, 'small')]))); node.append(exceptionCard); return node;
}
function ruleEditor(rule = {}) {
  const node = el('div'); node.append(el('p', 'muted', '동일한 룰 ID를 입력하면 새 버전을 작성합니다. 허용된 필드와 연산자만 서버에서 검증합니다.'));
  node.append(form([
    field('룰 ID', 'id', { required: true, value: rule.id || '' }), field('제목', 'title', { required: true, value: rule.title || '' }),
    field('대상 필드', 'field', { choices: ['actor', 'tool', 'action', 'resource', 'destination', 'kind', 'status', 'note'], value: rule.field || 'destination' }),
    field('연산자', 'op', { choices: [{ value: 'eq', label: '같음 (eq)' }, { value: 'neq', label: '다름 (neq)' }, { value: 'contains', label: '포함 (contains)' }], value: rule.op || 'eq' }),
    field('비교 값', 'value', { required: true, value: rule.value || '' }), field('중요도', 'severity', { choices: ['low', 'medium', 'high'], value: rule.severity || 'medium' }),
  ], '초안 저장', async (values) => {
    await api('/api/rules', 'POST', values); $('#detail-dialog').close(); await navigate('rules'); notice('룰 초안을 저장했습니다. 시험 결과와 근거를 확인한 뒤 검토자가 승인하세요.');
  })); showDetail(rule.id ? '탐지 룰 · 새 버전' : '탐지 룰 작성', node);
}
function exceptionEditor() {
  showDetail('예외 검토 요청', form([field('룰 ID', 'ruleId', { required: true }), field('행동 ID', 'actionId', { required: true }), field('예외 사유', 'reason', { required: true, multiline: true, wide: true }), field('책임자', 'owner', { required: true }), field('만료 일시', 'expiresAt', { required: true, type: 'datetime-local' })], '검토 요청 저장', async (values) => {
    values.expiresAt = new Date(values.expiresAt).toISOString();
    await api('/api/exceptions', 'POST', values); $('#detail-dialog').close(); await navigate('rules'); notice('예외 요청을 저장했습니다. 다른 검토자의 승인이 필요합니다.');
  }));
}

async function governanceView() {
  const data = await api('/api/governance'); const node = el('div');
  const systems = card('한국 AI 기본법 · 금융 AI 증거 검토', '외부 대출·신용평가 AI의 공급사 근거와 실제 운영을 대조합니다. 금융 분야만으로 고영향 여부를 확정하지 않습니다.');
  systems.querySelector('.card-header').append(button('+ 시스템 등록', () => systemEditor(), 'primary small'));
  systems.append(table(['시스템', '담당자', '목적', '역할 / 시장', '한국 고영향 상태', '검토'], data.systems.map((system) => {
    const actions = el('div', 'actions'); actions.append(button('금융 증거 대조', () => financeEvidenceView(system.id, data.requirements), 'primary small'), button('적용성·증거 검토', () => governanceReport(system.id, data.requirements), 'small'), button('정보 수정', () => systemEditor(system), 'small'));
    const roles = (system.krRoles || []).map(role => ({ developer: '인공지능개발사업자', deployer: '인공지능이용사업자' })[role] || role);
    return [system.name, system.owner, system.purpose, `${roles.length ? roles.join(', ') : label(system.role || 'unknown')} / ${(system.markets || []).join(', ')}`, badge(system.highImpact), actions];
  }))); node.append(systems);
  node.append(governanceDocumentsCard(data));
  const requirements = card('출처에 연결된 요구사항', '법적 구속력, 조건부 적용, 기술 증거의 한계를 각각 확인하세요.');
  const list = el('div', 'list');
  for (const requirement of data.requirements) {
    const item = el('article', 'list-item requirement'); const top = el('div', 'split'); top.append(el('h3', '', requirement.title), badge(requirement.reviewStatus || 'pending'));
    item.append(top, el('p', '', requirement.requirement || requirement.description || ''), el('p', 'muted', `${requirement.id} · ${requirement.article || ''} · ${requirement.binding || '구속력 확인 필요'}`));
    if (requirement.sourceUrl) {
      try { const url = new URL(requirement.sourceUrl); if (url.protocol === 'https:') { const link = el('a', 'source-link', '공식 출처 ↗'); link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; item.append(link); } } catch { /* Untrusted links are never navigated. */ }
    }
    item.append(jsonDetails('필요 증거·버전·적용 한계', requirement)); list.append(item);
  }
  requirements.append(list); node.append(requirements);
  if (data.tasks?.length) { const tasks = card('보완·재검토 과제'); tasks.append(table(['과제', '시스템', '책임자', '상태', '근거'], data.tasks.map((task) => {
    const actions = el('div', 'actions'); actions.append(button('상세', () => inspect('거버넌스 조치 과제', task), 'small'), button('검토 기록', () => governanceTask(task), 'small'));
    return [task.title || task.reason, task.systemId, task.owner, badge(task.status || 'open'), actions];
  }))); node.append(tasks); }
  node.append(limits(['기술 관측, 증거 충분성, 법적 적용성과 인간 법률 검토는 별개입니다.', '한국 고영향 분류와 EU 고위험 분류를 같은 것으로 취급하지 않습니다.'])); return node;
}
function governanceDocumentMaximum(data) {
  const maximum = data.documentLimits?.maximumBytes;
  return Number.isSafeInteger(maximum) && maximum > 0 ? maximum : 65536;
}
function governanceDocumentsCard(data) {
  const maximum = governanceDocumentMaximum(data), node = card('조치 근거 문서', '필요한 문서 한 개씩 접수하고 현재 원본의 복구·해시를 확인합니다. 문서 접수만으로 조치 이행이나 법적 충분성이 확인되지는 않습니다.');
  node.append(el('p', 'muted', `파일 한도 ${maximum.toLocaleString('ko-KR')}바이트 · 검토자 또는 관리자 권한이 필요합니다. 개인정보가 포함된 원문과 불필요한 자료는 제외하세요.`));
  if (data.systems?.length) node.append(button('문서 파일 접수', () => governanceDocumentEditor(data), 'primary small'));
  else node.append(el('p', 'muted', '문서를 연결할 시스템을 먼저 등록하세요.'));
  const documents = data.governanceDocuments || [];
  if (!documents.length) node.append(empty('접수된 조치 근거 문서 없음', '외부 문서 참조만으로 실제 파일 복구와 해시 일치를 확인할 수 없습니다.'));
  else node.append(table(['문서 / 시스템', '접수 버전', 'SHA-256', '보관 정책 기한', '원본 확인'], documents.map(document => [
    `${document.displayName || document.name || document.id} / ${document.systemId}`, document.version, document.sha256, date(document.retentionUntil), button('복구·해시 확인', () => governanceDocumentDetail(document.id), 'small'),
  ])));
  return node;
}
async function governanceDocumentDigest(bytes) {
  if (!globalThis.crypto?.subtle) throw Error('이 브라우저에서 SHA-256 검증을 사용할 수 없습니다. 안전한 연결 또는 로컬 주소에서 다시 접속하세요.');
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), value => value.toString(16).padStart(2, '0')).join('');
}
function governanceDocumentEditor(data) {
  const maximum = governanceDocumentMaximum(data), node = el('div');
  node.append(el('p', 'muted', `한 파일씩, 최대 ${maximum.toLocaleString('ko-KR')}바이트를 접수합니다. 같은 문서 ID로 개정본을 접수하면 새 버전이 생기며 연결된 평가를 다시 검토해야 합니다.`));
  const file = field('근거 문서 파일', 'documentFile', {type: 'file', required: true}), input = file.querySelector('input');
  const name = field('문서 이름', 'name', {required: true, maxLength: 200}), media = field('파일 유형', 'mediaType', {value: 'application/octet-stream', required: true, maxLength: 100});
  input.addEventListener('change', () => { const selected = input.files?.[0]; if (!selected) return; name.querySelector('input').value = selected.name; media.querySelector('input').value = selected.type || 'application/octet-stream'; });
  node.append(form([
    field('문서 ID · 개정본은 기존 ID 사용', 'id', {required: true, maxLength: 120}),
    field('관련 시스템', 'systemId', {choices: (data.systems || []).map(system => ({value: system.id, label: system.name})), required: true}), name, media, file,
  ], '파일 검증 후 접수', async values => {
    const selected = input.files?.[0];
    if (!selected) throw Error('접수할 문서 파일을 선택하세요.');
    if (!Number.isSafeInteger(selected.size) || selected.size < 1 || selected.size > maximum) throw Error(`문서 파일은 1~${maximum.toLocaleString('ko-KR')}바이트여야 합니다.`);
    const context = captureDetailContext(), bytes = new Uint8Array(await selected.arrayBuffer());
    if (bytes.length !== selected.size || bytes.length > maximum) throw Error('선택한 문서의 크기가 변경되었거나 한도를 초과했습니다.');
    const sha256 = await governanceDocumentDigest(bytes);
    let binary = ''; for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    if (!isCurrentDetail(context)) throw Error('문서 접수 화면 또는 접속 상태가 변경되었습니다. 다시 확인하세요.');
    const saved = await api('/api/governance/documents', 'POST', {id: values.id.trim(), systemId: values.systemId, name: values.name.trim(), mediaType: values.mediaType.trim(), sha256, contentBase64: btoa(binary)});
    if (!isCurrentDetail(context)) return;
    await navigate('governance');
    if (!isCurrentDetail(context)) return;
    await governanceDocumentDetail(saved.id); notice('문서를 접수했습니다. 필요한 조치 평가에 표시된 문서 참조를 연결하세요.');
  })); showDetail('조치 근거 문서 접수', node);
}
async function governanceDocumentDetail(id) {
  const document = await api(`/api/governance/documents/${encodeURIComponent(id)}`), node = el('div');
  node.append(el('p', 'selection-note', `${document.displayName || document.name || document.id} · 시스템 ${document.systemId} · 버전 ${document.version}`));
  node.append(el('p', '', document.verification?.status === 'hash_verified_and_retrievable' ? '현재 파일 복구·SHA-256 일치 확인' : '현재 파일 복구·해시 검증 미확인'));
  node.append(el('p', 'muted wrap', `SHA-256: ${document.sha256}`), el('p', 'muted', `파일 ${document.bytes}바이트 · 확인 시각 ${date(document.verification?.checkedAt)} · 보관 정책 기한 ${date(document.retentionUntil)}`), el('p', 'muted', document.retentionBasis || '보관 근거 미확인'));
  node.append(el('p', 'wrap', `평가 연결 참조: governance-document:${document.id}`), el('p', 'muted', '증거 종류를 문서로 선택하고 이 참조를 입력하세요. 확인한 파일과 평가 당시 버전이 연결됩니다.'));
  node.append(button('검증된 문서 파일 받기', async () => {
    const context = captureDetailContext();
    const exported = await api(`/api/governance/documents/${encodeURIComponent(document.id)}/export`);
    if (exported.version !== document.version || exported.sha256 !== document.sha256) throw Error('문서가 개정되었습니다. 현재 버전의 복구·해시를 다시 확인하세요.');
    const bytes = Uint8Array.from(atob(exported.contentBase64), value => value.charCodeAt(0));
    if (bytes.length !== exported.bytes || await governanceDocumentDigest(bytes) !== exported.sha256) throw Error('내려받은 문서의 크기·해시가 접수 기록과 일치하지 않습니다.');
    if (!isCurrentDetail(context)) return;
    downloadArtifact(String(exported.displayName || exported.name || 'governance-document').replace(/[\\/]/g, '_'), exported.mediaType || 'application/octet-stream', bytes);
  }, 'small'), limits(['현재 복구·해시 확인은 문서 내용의 진실성, 조치의 충분성 또는 5년 경과 보존 실적을 입증하지 않습니다.']));
  showDetail('조치 근거 문서 · 현재 원본 확인', node);
}
function governanceCheckLabel(value) {
  if (value && typeof value === 'object') return value.message || value.reason || value.label || governanceCheckLabel(value.code || value.check || value.type || JSON.stringify(value));
  const titles = {notice_pre_delivery: '사전 고지 전달·시점', generated_output_marking: '생성형 결과 표시', realistic_media_disclosure: '사실적 합성물 고지·접근성', safety_risk_management: '수명주기 안전성 위험관리', safety_incident_monitoring: '안전사고 모니터링·대응', safety_submission_receipt: '안전성 이행자료 제출 접수', high_impact_pre_review: '고영향 해당 여부 사전 검토', high_impact_confirmation: '고영향 확인 요청 자료', high_impact_risk_management: '고영향 위험관리 운영', explanation_plan: '설명 방안 수립·시행', user_protection: '이용자 보호 절차 운영', oversight_plan: '사람 감독 계획·운영 시험', human_oversight_review: '사람 감독 수행 기록', document_publication_retention: '조치 근거 보관·게시', impact_assessment: '기본권 영향평가 내용', impact_effort: '영향평가 노력·미완료 계획', public_impact_preference: '공공 선정 시 영향평가 제품 우선 고려', certification_effort: '고영향 사전 검·인증 노력', public_certification_preference: '공공 선정 시 검·인증 제품 우선 고려', domestic_representative: '서면 국내대리인 지정·신고 접수', authority_order_response: '실제 조사·시정 명령 대응'};
  const reasons = {authenticated_typed_measurement_missing: '인증된 출처가 보고한 조치 시험 근거 없음', verified_measure_document_missing: '검증된 조치 근거 문서 없음', typed_check_definition_missing: '이 요구사항의 기술 검증 항목 미지원', document_evidence_stale: '조치 근거 문서 개정·복구 상태 재검토 필요', event_evidence_stale: '연결된 원본 기록 변경·누락', measurement_not_passed: '보고된 측정의 미통과 항목', sections_missing: '필요한 검토 항목 누락', time_order_uncertain: '시계 오차로 선후관계 미확정', not_proven_before_provision: '제품·서비스 제공 전 이행 시점 미확인', matching_verified_document_missing: '시험에 연결된 검증 문서 없음', system_facts_hash_mismatch: '시험 당시 시스템 사실 버전 불일치', requirement_version_hash_mismatch: '시험 당시 요구사항 버전 불일치', system_model_or_policy_mismatch: '시험의 시스템·모델·정책 버전 불일치', authority_receipt_source_required: '외부 접수 확인이 가능한 권한 출처 필요', reported_check_fail: '보고된 시험 실패', reported_check_inconclusive: '보고된 시험 결과 판단 보류', some_tested_outputs_unmarked: '시험한 결과 중 표시 누락', some_tested_outputs_undisclosed: '시험한 합성물 중 고지 누락', retention_below_five_years: '보고된 보관 기간이 5년 미만', publication_scope_incomplete: '게시 또는 제외 근거의 범위 부족', order_measures_missing: '실제 명령에서 요청한 조치 없음', order_response_time_out_of_range: '명령 대응 시점이 요청 범위 밖', unsupported_check_type: '지원하지 않는 시험 유형'};
  const metrics = {generationNoticeProvided: '생성형 AI 사용 안내', noticeDelivered: '고지 전달', targetUsersCovered: '대상 이용자 범위', perceptibilityTestPassed: '이용자가 알아볼 수 있는 표시', machineDetectionTestPassed: '기계 판독 표시 탐지', accessibilityTestPassed: '고지 접근성', restoreTestPassed: '문서 복구 시험', interventionExercisePassed: '사람의 개입 시험', sections: '검토 항목', publishedSections: '게시 항목', mitigationTestPassed: '위험 완화 시험', explanationDeliveryTestPassed: '설명 전달 시험', responseExercisePassed: '사고 대응 시험', submissionAccepted: '외부 제출 접수', notificationAccepted: '국내대리인 신고 접수', requestAccepted: '확인 요청 접수', responseAccepted: '명령 대응 접수'};
  Object.assign(reasons, { fixed_receipt_time_missing: '평가 당시 고정 수신 시각 없음', observation_clock_uncertain: '관측 출처의 시계 오차 미확인', observation_after_fixed_receipt: '관측 시각이 고정 수신 시각보다 미래임', observation_receipt_order_uncertain: '관측·수신 시각 구간이 겹쳐 순서 미확정', completed_measurement_clock_uncertain: '완료 보고의 시계 오차 미확인', completed_measurement_after_observation: '관측·수신 당시 아직 발생하지 않은 완료 시각', completed_measurement_order_uncertain: '완료·관측 시각 구간이 겹쳐 순서 미확정' });
  Object.assign(reasons, { registered_provision_time_unknown: '등록된 시스템의 제공 기준 시각 미확인', registered_provision_time_mismatch: '시험과 등록된 시스템의 제공 기준 시각 불일치' });
  Object.assign(metrics, { acceptedAt: '외부 접수 시각', noticeAt: '고지 시각', reviewedAt: '검토 완료 시각', requestedAt: '확인 요청 시각', evaluatedAt: '평가 시각', effortAt: '노력 수행 시각', orderReceivedAt: '명령 수령 시각', responseAt: '명령 대응 시각' });
  Object.assign(titles, {supplier_risk_reliance: '공급사 위험관리 조치 검토', supplier_explanation_reliance: '공급사 설명 방안 조치 검토', supplier_protection_reliance: '공급사 이용자 보호 조치 검토'});
  Object.assign(reasons, {supplier_bundle_binding_missing: '검토 기록과 공급사 묶음 참조·해시 불일치', supplier_scope_not_verified: '공급사 조치 범위·문서 복구 재검토 필요', supplier_manifest_hash_mismatch: '검토 기록의 공급사 묶음 해시 불일치', supplier_reviewer_binding_missing: '권한 출처 기록과 담당 검토자 불일치·미확인', supplier_role_or_change_unconfirmed: '이용사업자 역할 또는 중대한 변경 없음 미확인', original_supplier_scope_unconfirmed: '공급받은 모델·목적과 현재 사용 범위 불일치·미확인'});
  Object.assign(metrics, {supplierPerformedMeasureReviewed: '공급사 실제 조치 검토', fullMeasureScopeReviewed: '해당 조치 전체 범위 검토', noSubstantialModificationReviewed: '중대한 기능 변경 없음 검토'});
  const text = String(value ?? '미확인');
  if (text.includes('|')) return text.split('|').map(governanceCheckLabel).join(' 또는 ');
  const [type, reason, ...details] = text.split(':');
  if (titles[type]) return titles[type] + (reason ? `: ${reasons[reason] || `추가 검증 필요: ${reason}`}${details.length ? ` · ${details.map(metric => metrics[metric] || metric).join(' / ')}` : ''}` : '');
  if (reasons[type]) return reasons[type] + (reason ? ` · ${metrics[reason] || reason}` : '');
  if (text === 'authenticated_reported_measurement_supported') return '인증된 출처의 보고된 측정 근거 연결';
  if (text === 'typed_evidence_insufficient') return '보고된 측정·문서·수행 기록의 연결 근거 부족';
  if (text === 'unsupported_requirement') return '이 요구사항의 기술 검증 미지원';
  if (text === 'applicability_basis_document') return '비적용 판단 근거 문서';
  if (text === 'human_applicability_basis_document_verified') return '사람의 비적용 판단 근거 문서 복구·해시 확인';
  if (text === 'human_applicability_basis_document_missing') return '사람의 비적용 판단을 뒷받침할 검증 문서 없음';
  return ({document_evidence_missing: '조치 근거 문서 없음', document_evidence_unverified: '조치 근거 문서의 현재 버전·복구·해시 확인 필요', document_evidence_verified: '현재 조치 근거 문서 복구·해시 확인', oversight_plan_missing: '사람 감독 계획 문서 없음', oversight_review_record_missing: '현재 모델·정책에 연결된 사람 감독 수행 기록 없음', oversight_plan_and_review_record_missing: '사람 감독 계획과 수행 기록 없음', oversight_plan_and_review_record_verified: '사람 감독 계획과 수행 기록 연결 확인', external_or_missing: '외부 참조만 있거나 증거 없음', event_linked_partial_support: '관측 이벤트 연결 · 일부 근거', governance_check_missing: '보고된 조치 시험 근거 없음', assessment_snapshot_missing: '평가 당시 적용성 기록 없음', applicability_policy_version_changed: '적용성 검토 기준 버전 변경', applicability_candidate_changed: '적용 후보 사실 변경'})[value] || `추가 검증 필요: ${String(value ?? '미확인')}`;
}
function governanceTechnicalEvidence(item) {
  const technical = item.technicalEvidence || {}, node = el('div', 'message');
  node.append(el('strong', '', `기술 증거: ${governanceCheckLabel(technical.status || item.technicalStatus)}`));
  const supported = technical.supportsHumanAssessment === true && !!item.assessment && !['external_or_missing', 'event_linked_partial_support'].includes(technical.status || item.technicalStatus);
  node.append(el('p', '', supported ? '사람의 증거 평가를 뒷받침하는 기술 근거가 확인되었습니다. 법률 적용·충분성 판단은 별도입니다.' : '기술 증거 확인이 부족하거나 미확인입니다. 사람의 충분 평가만으로 검증 누락이 해소되지는 않습니다. 법률 적용·충분성 판단은 별도입니다.'));
  const missing = [...(technical.missingChecks || []), ...(technical.reasons || [])];
  if (missing.length) { node.append(el('strong', '', '추가 확인할 검증')); const list = el('ul'); for (const check of missing) list.append(el('li', '', governanceCheckLabel(check))); node.append(list); }
  if (technical.matchedChecks?.length) node.append(table(['연결된 보고 근거', '원본 기록 참조', '조치 문서 해시'], technical.matchedChecks.map(check => [governanceCheckLabel(check.checkType) + (check.effortOnly ? ' · 노력 기록' : ''), check.ref, check.documentHash])));
  if (technical.matchedChecks?.some(check => check.effortOnly)) node.append(el('p', 'muted', '노력 기록은 해당 영향평가 또는 검·인증을 완료했다는 증거가 아닙니다.'));
  const supplierChecks = (technical.matchedChecks || []).filter(check => ['supplier_risk_reliance', 'supplier_explanation_reliance', 'supplier_protection_reliance'].includes(check.checkType));
  if (supplierChecks.length) {
    node.append(el('strong', '', '공급사 조치 활용 검토 근거'), table(['관련 조치', '공급사 묶음', '묶음 해시', '담당 검토자'], supplierChecks.map(check => [governanceCheckLabel(check.checkType), check.supplierBundleRef || '미확인', check.supplierBundleHash || '미확인', check.reviewer || '미확인'])));
    node.append(el('p', 'muted', '제34조제1항제1~3호의 해당 조치 검토에만 연결합니다. 사람 감독·문서 보관을 대체하지 않으며 법적 간주·충분성 판단은 별도입니다.'));
  }
  const requestStates = { not_requested: '요청하지 않음', request_state_unknown: '요청 여부 미확인', request_receipt_missing: '요청 접수 근거 없음', request_evidence_insufficient: '요청 근거 부족·충돌', request_receipt_supported: '요청 접수 보고 근거 연결' };
  for (const workflow of Array.isArray(technical.optionalWorkflows) ? technical.optionalWorkflows : []) {
    if (!workflow || typeof workflow !== 'object') continue;
    const section = el('div', 'message'), status = workflow.status === 'request_receipt_supported' && workflow.supportsRequestReceipt !== true ? '요청 접수 근거 미확인' : requestStates[workflow.status] || governanceCheckLabel(workflow.status);
    section.append(el('strong', '', `선택적 확인 요청: ${status}`), el('p', 'muted', '필수 사전 검토와 별도로 추적합니다. 접수 보고 근거는 정부 회신·고영향 해당 여부 결정·법적 준수 완료를 의미하지 않습니다.'));
    const gaps = [...(workflow.missingChecks || []), ...(workflow.reasons || [])];
    if (gaps.length) { section.append(el('strong', '', '선택적 요청의 추가 확인')); const list = el('ul'); for (const gap of gaps) list.append(el('li', '', governanceCheckLabel(gap))); section.append(list); }
    if (workflow.matchedChecks?.length) section.append(table(['선택적 요청의 연결 근거', '원본 기록 참조', '조치 문서 해시'], workflow.matchedChecks.map(check => [governanceCheckLabel(check.checkType), check.ref, check.documentHash])));
    if (workflow.limitations?.length) section.append(limits(workflow.limitations));
    node.append(section);
  }
  if (technical.limitations?.length) node.append(limits(technical.limitations));
  node.append(el('p', 'muted', '보고된 시험 근거는 기록의 출처·버전·범위를 대조합니다. 이 화면이 시험 결과나 업무 실행 승인을 발급하지 않습니다.'));
  return node;
}
const systemTriFacts = [['substantialModification', '공급받은 AI의 목적·용도·기능을 중대하게 변경'], ['internalOnly', '내부 업무에만 사용'], ['publicInstitution', '공공기관 사용·도입'], ['realisticSyntheticMedia', '실제처럼 보이는 합성 이미지·음성·영상'], ['emotionRecognition', '감정 인식'], ['biometricCategorisation', '생체정보 범주화'], ['publicInterestText', '공익 사안 관련 공개 텍스트'], ['frontierTechnology', '첨단 AI 기술 해당 사실'], ['broadSignificantRisk', '광범위하고 중대한 위험 관련 사실'], ['domesticImpact', '국내 시장·이용자에 영향'], ['aiBusinessOperator', 'AI 제품·서비스를 개발·제공하는 사업자'], ['defenceOrNationalSecurityOnly', '국방·국가안보 목적에만 사용'], ['designatedDefenceSecurityWork', '지정된 국방·국가안보 업무 해당'], ['hasDomesticAddressOrOffice', '국내 주소·영업소 보유'], ['priorArticle43OrderFine', '법 제43조 조사·명령 관련 과태료 이력'], ['governmentOrderPresent', '실제 정부 조사·시정 명령 존재'], ['transparencyObvious', 'AI 기반 제품·서비스임이 명백한 경우'], ['artisticCreativeExpression', '예술·창작 표현에 해당'], ['seriousLifeSafetyRightsRisk', '생명·신체 안전·기본권에 중대한 위험 관련 사실']];
const systemNumberFacts = [['trainingCompute', '학습 연산량 (FLOP)'], ['previousYearTotalRevenueKrw', '직전 연도 전체 매출액 (원)'], ['previousYearAiRevenueKrw', '직전 연도 AI 관련 매출액 (원)'], ['domesticDailyAverageUsersLast3Months', '최근 3개월 국내 일평균 이용자 수']];
function systemFactsPayload(input) {
  const values = { ...input }, split = value => String(value || '').split(',').map(v => v.trim()).filter(Boolean);
  values.markets = split(values.markets); values.dataCategories = split(values.dataCategories);
  values.highImpactDomains = split(values.highImpactDomains);
  for (const key of ['generative', ...systemTriFacts.map(([key]) => key)]) values[key] = values[key] === 'true' ? true : values[key] === 'false' ? false : 'unknown';
  values.krRoles = ['developer', 'deployer'].filter(role => values[`krRole_${role}`] === 'on');
  for (const role of ['developer', 'deployer']) delete values[`krRole_${role}`];
  values.euRoles = ['provider', 'deployer', 'importer', 'distributor'].filter(role => values[`euRole_${role}`] === 'on');
  for (const role of ['provider', 'deployer', 'importer', 'distributor']) delete values[`euRole_${role}`];
  for (const key of ['modelVersion', 'policyVersion']) values[key] = String(values[key] || '').trim() || 'unknown';
  for (const [key, title] of systemNumberFacts) { const value = String(values[key] ?? '').trim(); if (value && value !== 'unknown' && (!Number.isFinite(Number(value)) || Number(value) < 0)) throw Error(`${title}은 0 이상의 숫자로 입력하세요. 알 수 없으면 비워 두세요.`); values[key] = value && value !== 'unknown' ? Number(value) : 'unknown'; }
  for (const key of ['marketEntryAt', 'providedAt']) { if (values[key]) values[key] = new Date(values[key]).toISOString(); else delete values[key]; }
  return values;
}
async function financeEvidenceView(systemId, requirements) {
  const data = await api(`/api/governance/finance?systemId=${encodeURIComponent(systemId)}`), node = el('div');
  node.append(el('p', 'selection-note', `${data.system.name} · ${data.system.modelId || '모델 미확인'} / ${data.system.modelVersion || '버전 미확인'}`));
  const controls = card('1. 관련 조치와 사실관계', '제34조 위험관리·설명·이용자보호의 공급사 근거를 검토합니다. 인간 감독·문서 보관은 별도로 판단합니다.');
  controls.append(button('조문별 적용성·사람 평가', () => governanceReport(systemId, requirements), 'small'), button('시스템 정보 수정', () => systemEditor(data.system), 'small'), button('당시 승인 정책 등록', () => financeApprovalPolicyEditor(systemId), 'small')); node.append(controls);
  const bundles = card('2. 공급사 근거', '합성 문서 바이트를 해시 검증하고 보관합니다. 변경·복구 실패는 재검토 대상입니다.');
  bundles.append(button('증빙 JSON 가져오기', () => financeBundleImport(systemId, requirements), 'primary small'));
  if (!data.bundles.length) bundles.append(empty('공급사 증빙 없음', '모델·목적·시험 범위와 연결된 근거를 등록하세요.'));
  for (const bundle of data.bundles) {
    const item = el('article', 'list-item'); item.append(el('h3', '', `${bundle.id} · 개정 ${bundle.revision}`), el('p', '', `${bundle.supplierId} / ${bundle.modelId} / ${bundle.modelVersion}`), el('p', '', bundle.testScope));
    item.append(el('p', 'muted', bundle.verification.issues.length ? `재검토 사유: ${bundle.verification.issues.map(financeIssueLabel).join(', ')}` : '문서 복구·해시·대상 정보 일치. 법적 활용 인정은 사람 검토 필요.'));
    item.append(table(['문서', '현재 복구·해시', '보관 정책 기한'], bundle.verification.documents.map(d => [d.name, d.status === 'hash_verified_and_retrievable' ? '복구·해시 확인' : '복구 불가 또는 변조', date(bundle.retentionUntil)])));
    item.append(button('증빙 JSON 내보내기', async () => { const value = await api(`/api/governance/bundles/${encodeURIComponent(bundle.id)}/export`); downloadArtifact('supplier-evidence.json', 'application/json', JSON.stringify(value, null, 2)); }, 'small'), el('p', 'muted', `평가 연결 참조: supplier-bundle:${bundle.id}`)); bundles.append(item);
  } node.append(bundles);
  const operations = card('3. 실제 운영 기록과 충돌·누락', '서로 다른 출처가 보고한 실행·승인·결과를 대조합니다.');
  if (data.operationalStatus === 'execution_evidence_missing' || !data.operations.length) operations.append(empty('실행 증거 없음', '이 시스템에 연결된 도구 실행·결과 기록이 없습니다. 무사고나 정상 실행으로 판정하지 않습니다.'));
  for (const operation of data.operations) {
    const item = el('article', 'list-item'); item.append(el('h3', '', operation.actionId));
    if (operation.analysisPending) item.append(el('p', 'muted', '새 증거 분석 대기 · 이전 결과는 현재 판단에 충분하지 않습니다.'));
    if (operation.correlationStatus !== 'explicit_system_reference') item.append(el('p', 'muted', '시스템 연결 불확실 · 다른 시스템과 기록이 혼재합니다.'));
    for (const issue of operation.modelIssues) item.append(el('p', '', `실제 모델 확인·변경 검토: ${issue.ref}`));
    item.append(table(['출처 / 증거 ID', '종류', '시도 / 모델', '발생 / 수신'], operation.events.map(e => [`${e.source}/${e.id}`, label(e.kind), `${e.attemptId || '미확인'} / ${e.modelVersion || '미확인'}`, `${date(e.occurredAt)} / ${date(e.receivedAt)}`])));
    for (const finding of operation.evaluation?.findings || []) item.append(el('p', '', `${finding.message} · 근거 ${(finding.evidence || []).join(', ')}`));
    item.append(button('행동 원본·분석 이력', () => actionDetail(operation.actionId), 'small')); operations.append(item);
  } node.append(operations);
  const review = card('4. 담당자 판단과 검토 당시 보고서', '기술적 확인과 법적 적용·충분성 판단은 별도로 기록합니다.');
  review.append(button('조치별 사람 평가 기록', () => governanceReport(systemId, requirements), 'small'), button('서명된 검토 보고서 저장·받기', async () => { const value = await api('/api/governance/finance/report', 'POST', { systemId }); downloadArtifact('finance-review.json', 'application/json', JSON.stringify(value, null, 2)); notice('검토 당시 법령·시스템·증거 버전을 고정한 보고서를 저장했습니다.'); }, 'primary small'));
  node.append(review, limits(data.limitations)); showDetail('금융 AI · 한국법 이행 증거 대조', node);
}
function financeIssueLabel(code) {
  const supplied = {SUPPLIED_MODEL_VERSION_UNKNOWN:'공급 당시 모델 버전 미확인',SUPPLIED_MODEL_VERSION_MISMATCH:'공급 당시 모델 버전과 현재 사용·증빙 불일치',SUPPLIED_PURPOSE_UNKNOWN:'공급 당시 사용 목적 미확인',SUPPLIED_PURPOSE_MISMATCH:'공급 당시 목적과 현재 사용·증빙 불일치'};
  if (Object.hasOwn(supplied, code)) return supplied[code];
  return ({MODEL_VERSION_MISMATCH:'모델 버전 불일치',MODEL_ID_MISMATCH:'모델 불일치',PURPOSE_MISMATCH:'사용 목적 불일치',SUPPLIER_MISMATCH:'공급사 불일치',DOCUMENT_EVIDENCE_MISSING:'문서 복구 불가·변조·부족',DEPLOYER_ROLE_UNCONFIRMED:'이용사업자 역할 미확인',SUBSTANTIAL_CHANGE_REVIEW:'중대한 변경 검토 필요',SUBSTANTIAL_CHANGE_UNKNOWN:'중대한 변경 여부 미확인',MODEL_ID_UNKNOWN:'모델 식별자 미확인',MODEL_VERSION_UNKNOWN:'모델 버전 미확인',PURPOSE_UNKNOWN:'목적 미확인',SUPPLIER_UNKNOWN:'공급사 미확인'})[code] || '추가 사실 확인 필요';
}
function financeBundleImport(systemId, requirements) {
  const node = el('div'); node.append(el('p', 'muted', '합성 공급사 증빙 JSON을 선택하거나 붙여넣으세요. 문서 해시·모델·목적·시험 범위를 함께 제출합니다. 실제 고객 자료는 받지 않습니다.'));
  const editor = form([field('증빙 JSON', 'bundle', { required: true, multiline: true, wide: true, maxLength: 131072 })], '검증하여 가져오기', async values => { let value; try { value = JSON.parse(values.bundle); } catch { throw Error('올바른 JSON이 아닙니다.'); } if (value.systemId !== systemId) throw Error('선택한 시스템과 증빙의 systemId가 다릅니다.'); await api('/api/governance/bundles', 'POST', value); await financeEvidenceView(systemId, requirements); });
  const file = field('JSON 파일 선택', 'bundleFile', {type:'file'}), input = file.querySelector('input'); input.accept = '.json,application/json'; input.addEventListener('change', async () => { try { const selected=input.files?.[0]; if (!selected) return; if(selected.size>131072) throw Error('JSON 파일 한도는 128KiB입니다.'); editor.querySelector('textarea').value=await selected.text(); } catch(error) { notice(error.message,true); } });
  node.append(file, editor); showDetail('공급사 합성 증빙 가져오기', node);
}
function financeApprovalPolicyEditor() {
  showDetail('행동 시점 승인 정책 등록', form([
    field('정책 등록 ID · 버전별 다른 ID', 'id', {required:true}), field('보고된 실행 주체', 'actor', {required:true}), field('도구', 'tool', {required:true}), field('책임자', 'owner', {required:true}), field('정책 버전', 'policyVersion', {required:true}), field('유효 시작', 'validFrom', {required:true,type:'datetime-local'}), field('유효 종료 · 선택', 'validUntil', {type:'datetime-local'}), field('사전 사람 승인 필요', 'approvalRequired', {choices:[{value:'unknown',label:'미확인'},{value:'true',label:'필요'},{value:'false',label:'불필요'}]}), field('허용 목적지 · 쉼표 구분', 'destinations', {}),
  ], '정책 근거 등록', async values => { const payload={...values,approvalRequired:values.approvalRequired==='true'?true:values.approvalRequired==='false'?false:'unknown',destinations:values.destinations.split(',').map(x=>x.trim()).filter(Boolean),validFrom:new Date(values.validFrom).toISOString()}; if(values.validUntil)payload.validUntil=new Date(values.validUntil).toISOString();else delete payload.validUntil; await api('/api/assets','POST',payload); $('#detail-dialog').close(); notice('정책 근거를 등록했습니다. 관련 행동의 재분석 결과를 확인하세요.'); }));
}
function systemEditor(old = {}) {
  const triChoices = [{ value: 'unknown', label: '미확인 · 추가 근거 필요' }, { value: 'true', label: '예 · 사실 확인됨' }, { value: 'false', label: '아니요 · 사실 확인됨' }];
  const additional = el('details', 'wide system-facts-more');
  additional.append(el('summary', '', '한국·EU 적용성 검토에 필요한 추가 사실'), el('p', 'muted', '알 수 없는 항목은 미확인으로 남깁니다. 사실 입력과 법적 적용성·준수 여부의 인간 판단은 별도입니다.'));
  const extraFields = el('div', 'form-grid');
  for (const [key, title] of systemTriFacts) extraFields.append(field(title, key, { choices: triChoices, value: old[key] === true ? 'true' : old[key] === false ? 'false' : 'unknown' }));
  for (const [key, title] of systemNumberFacts) extraFields.append(field(`${title} · 미확인이면 비우기`, key, {value: typeof old[key] === 'number' ? String(old[key]) : '', maxLength: 80}));
  extraFields.append(field('AI 제품·서비스 제공 일시 · 미확인이면 비우기', 'providedAt', {type: 'datetime-local', value: localDate(old.providedAt)}), field('EU 시장 출시 일시 · 미확인이면 비우기', 'marketEntryAt', { type: 'datetime-local', value: localDate(old.marketEntryAt) }), field('한국 고영향 해당 분야 · 확인한 분야만 쉼표로 구분', 'highImpactDomains', {value: (old.highImpactDomains || []).join(', '), wide: true}));
  const roles = el('fieldset', 'wide system-role-options'); roles.append(el('legend', '', 'EU 역할 · 확인된 역할만 선택 · 미선택은 미확인'));
  for (const [code, title] of [['provider', '공급자'], ['deployer', '사용·운영자'], ['importer', '수입자'], ['distributor', '유통자']]) {
    const option = el('label'), input = el('input'); input.type = 'checkbox'; input.name = `euRole_${code}`; input.checked = (old.euRoles || []).includes(code); option.append(input, document.createTextNode(`${title} (${code})`)); roles.append(option);
  }
  const krRoles = el('fieldset', 'wide system-role-options'); krRoles.append(el('legend', '', '한국 사업자 역할 · 미선택은 미확인'));
  krRoles.append(el('p', 'muted', '금융기관이라는 이유만으로 이용사업자로 분류하지 않고, 단순 AI 사용과 AI 제품·서비스 개발·제공 역할을 구분해 확인하세요.'));
  const roleGuide = el('a', 'source-link', 'NIA 역할 판단 안내 ↗'); roleGuide.href = 'https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=28987&cbIdx=99835&parentSeq=28987'; roleGuide.target = '_blank'; roleGuide.rel = 'noopener noreferrer'; krRoles.append(roleGuide);
  for (const [code, title] of [['developer', '인공지능개발사업자'], ['deployer', '인공지능이용사업자']]) { const option = el('label'), input = el('input'); input.type = 'checkbox'; input.name = `krRole_${code}`; input.checked = (old.krRoles || []).includes(code); option.append(input, document.createTextNode(title)); krRoles.append(option); }
  extraFields.append(krRoles, roles); additional.append(extraFields);
  showDetail(old.id ? 'AI 시스템 사실관계 수정' : 'AI 시스템 등록', form([
    field('시스템 ID', 'id', { required: true, value: old.id || '' }), field('시스템 이름', 'name', { required: true, value: old.name || '' }), field('책임자', 'owner', { required: true, value: old.owner || '' }), field('사업자 역할', 'role', { required: true, value: old.role || '', placeholder: '예: provider, deployer' }),
    field('제공 국가·시장', 'markets', { required: true, value: (old.markets || []).join(', '), placeholder: '예: KR, EU' }), field('사용 분야', 'domain', { required: true, value: old.domain || '', placeholder: '예: customer_support, hiring' }),
    field('사용 목적', 'purpose', { required: true, multiline: true, wide: true, value: old.purpose || '' }), field('생성형 여부', 'generative', { choices: triChoices, value: old.generative === true ? 'true' : old.generative === false ? 'false' : 'unknown' }),
    field('한국 고영향 검토 상태', 'highImpact', { choices: ['unknown', 'candidate', 'confirmed', 'no'], value: old.highImpact || 'unknown' }),
    field('EU 고위험 검토 상태 (별도 분류)', 'euHighRisk', { value: old.euHighRisk || 'unknown' }), field('데이터 범주', 'dataCategories', { value: (old.dataCategories || []).join(', '), placeholder: '쉼표로 구분' }), field('이용자·영향받는 사람', 'affectedPeople', { wide: true, value: old.affectedPeople || '' }),
    field('공급사 식별자', 'supplierId', {value: old.supplierId || '', placeholder: '미확인이면 비우기'}), field('모델 식별자', 'modelId', {value: old.modelId || ''}), field('심사에 미치는 영향', 'decisionInfluence', {choices: [{value:'unknown',label:'미확인'},{value:'advisory',label:'참고·보조'},{value:'material',label:'심사에 중대한 영향'},{value:'automated',label:'자동 결정'}],value:old.decisionInfluence||'unknown'}), field('공급받은 모델 버전', 'suppliedModelVersion', {value:old.suppliedModelVersion||''}), field('공급받은 사용 목적', 'suppliedPurpose', {value:old.suppliedPurpose||'',wide:true}),
    field('모델 버전', 'modelVersion', { value: old.modelVersion === 'unknown' ? '' : old.modelVersion || '', placeholder: '미확인이면 비우기' }), field('정책 버전', 'policyVersion', { value: old.policyVersion === 'unknown' ? '' : old.policyVersion || '', placeholder: '미확인이면 비우기' }), additional,
  ], '인벤토리 저장', async (input) => {
    const values = systemFactsPayload(input);
    await api('/api/governance/systems', 'POST', values); $('#detail-dialog').close(); await navigate('governance'); notice('시스템을 등록했습니다. 요구사항별 적용성과 증거를 검토하세요.');
  }));
}
function governanceTask(task) {
  showDetail('거버넌스 보완 과제 검토', form([field('상태', 'status', { choices: ['open', 'closed'], value: task.status || 'open' }), field('검토 사유·완료 근거', 'reason', { required: true, multiline: true, wide: true })], '검토 이력 저장', async (values) => {
    await api(`/api/governance/tasks/${encodeURIComponent(task.id)}`, 'POST', values); $('#detail-dialog').close(); await navigate('governance'); notice('보완 과제의 검토 이력을 저장했습니다.');
  }));
}
function localDate(value) {
  if (!value) return '';
  const d = new Date(value); if (Number.isNaN(d.getTime())) return '';
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
async function governanceReport(systemId, requirements) {
  const data = await api(`/api/governance/report?systemId=${encodeURIComponent(systemId)}`); const node = el('div');
  node.append(el('p', 'selection-note', `${data.system.name} · 책임자 ${data.system.owner} · 목적 ${data.system.purpose}`), limits(data.limitations));
  const list = el('div', 'list');
  for (const item of data.items || []) {
    const req = typeof item.requirement === 'object' ? item.requirement : requirements.find((r) => r.id === item.requirement) || { id: item.requirement, title: item.requirement };
    const section = el('article', 'list-item'); const header = el('div', 'split'); header.append(el('h3', '', req.title), badge(item.status || 'unknown')); section.append(header);
    if (item.applicability) {
      const candidateLabels = { candidate: '검토 후보', unknown: '사실관계 미확인', voluntary: '자율 프레임워크', readiness_only: '준비 상태 참고' };
      section.append(el('p', 'muted', `사실관계 기반 분류: ${candidateLabels[item.applicability.status] || '미확인'} · ${item.applicability.reason || '인간 적용성 검토 필요'}`));
      if (item.applicability.missingFacts?.length) section.append(el('p', 'muted wrap', `추가 확인할 사실: ${item.applicability.missingFacts.join(', ')}`));
    }
    section.append(governanceTechnicalEvidence(item));
    if (item.assessment) section.append(el('p', 'muted', `사람 평가: 적용성 ${label(item.assessment.applicability)} · 증거 충분성 ${label(item.assessment.assessment)} · 법률 검토 ${label(item.assessment.legalReview)} · 담당자 ${item.assessment.owner || '미지정'}`));
    else section.append(el('p', 'muted', '아직 인간 평가가 없습니다. 적용 대상과 필요한 근거를 확인하세요.'));
    section.append(jsonDetails('요구사항·현재 평가 근거', item), button('평가·통제·증거 기록', () => assessmentEditor(systemId, req, item.assessment, requirements), 'small')); list.append(section);
  } node.append(list, jsonDetails('시스템 사실관계', data.system)); showDetail('시스템별 거버넌스 검토 보고서', node);
}
function assessmentEditor(systemId, requirement, previous, requirements) {
  const old = previous || {}; const node = el('div');
  node.append(el('p', 'selection-note', `${requirement.title} · ${requirement.id}`), el('p', 'muted', '접수된 문서는 governance-document:문서ID로 연결하세요. 외부 참조는 파일 검증을 대신하지 않습니다. 시험·이벤트도 실제 출처의 정확한 참조를 기록하세요.'));
  node.append(form([
    field('법적 적용성', 'applicability', { choices: ['unknown', 'applicable', 'not_applicable'], value: old.applicability || 'unknown' }),
    field('증거 충분성', 'assessment', { choices: ['unknown', 'insufficient', 'sufficient'], value: old.assessment || 'unknown' }),
    field('조직 통제·이행 절차', 'control', { required: true, multiline: true, wide: true, value: old.control || '' }), field('책임자', 'owner', { required: true, value: old.owner || '' }),
    field('인간 법률 검토', 'legalReview', { choices: ['pending', 'reviewed'], value: old.legalReview || 'pending' }),
    field('평가 근거·남은 위험', 'reason', { required: true, multiline: true, wide: true, value: old.reason || '' }),
    field('증거 종류', 'evidenceType', { choices: [{ value: 'document', label: '문서' }, { value: 'event', label: '관측 이벤트' }, { value: 'test', label: '시험 결과' }, { value: 'attestation', label: '담당자 확인' }] }),
    field('증거 참조', 'evidenceRef', { placeholder: 'governance-document:문서ID 또는 source/eventId' }), field('증거 버전', 'evidenceVersion'), field('증거 설명·한계', 'evidenceNotes'), field('다음 검토 일시', 'nextReviewAt', { required: true, type: 'datetime-local', value: localDate(old.nextReviewAt) }),
  ], '인간 평가 이력 추가', async (values) => {
    const evidence = [...(old.evidence || [])];
    if (values.evidenceRef.trim()) evidence.push({ type: values.evidenceType, ref: values.evidenceRef.trim(), version: values.evidenceVersion, notes: values.evidenceNotes });
    await api('/api/governance/assessments', 'POST', { systemId, requirementId: requirement.id, applicability: values.applicability, evidence, control: values.control, owner: values.owner, assessment: values.assessment, legalReview: values.legalReview, reason: values.reason, nextReviewAt: new Date(values.nextReviewAt).toISOString() });
    await governanceReport(systemId, requirements); notice('평가 이력을 저장했습니다. 보고서에서 부족한 증거와 재검토 상태를 확인하세요.');
  })); showDetail('요구사항 평가 · 증거 연결', node);
}
function retentionItems(items, inventory = false) {
  const headers = ['원장 순번', '출처 / 이벤트', '행동 ID', '보존 종료', '정책 버전'];
  if (inventory) headers.push('현재 파기 검토 상태');
  return table(headers, (items || []).map((item) => {
    const row = [item.seq, `${item.source} / ${item.eventId}`, item.actionId || '연결 없음', date(item.retainUntil), item.policyVersion];
    if (inventory) {
      const status = el('div', 'wrap');
      status.append(el('strong', '', item.eligible ? '계획에 포함 가능' : item.expired ? '파기 보류' : '보존기간 진행 중'));
      if (item.blockingHolds?.length) status.append(el('p', 'muted', `보류: ${item.blockingHolds.join(', ')}`));
      if (item.openCases?.length) status.append(el('p', 'muted', `미종결 사건: ${item.openCases.join(', ')}`));
      row.push(status);
    }
    return row;
  }));
}
async function retentionSaved(message) {
  $('#detail-dialog').close(); await navigate('retention'); notice(message);
}
async function retentionView() {
  const data = await api('/api/retention'); const node = el('div'); const policy = data.policy || {};
  node.append(el('p', 'selection-note', '이 화면의 승인은 감사 증거의 보존·파기 검토입니다. 업무 AI의 실행 승인이나 차단을 발급하지 않습니다. 정책·보류·계획은 검토자 또는 관리자, 파기 실행은 관리자 권한이 필요합니다.'));
  const policyCard = card('보존 정책', '변경 후 새로 접수되는 이벤트에 적용됩니다. 기존 이벤트의 보존기간을 소급 단축하지 않습니다.');
  policyCard.append(el('p', '', `현재 버전 ${policy.version ?? '미확인'} · 보존기간 ${policy.retentionSeconds ?? '미확인'}초`), el('p', 'muted', `목적: ${policy.purpose || '미기록'} · 근거: ${policy.reason || '미기록'}`), jsonDetails('정책·인간 검토 기록', policy));
  policyCard.querySelector('.card-header').append(button('새 정책 버전', () => {
    const seconds = field('새 이벤트 보존기간 (초)', 'retentionSeconds', { required: true, type: 'number', value: policy.retentionSeconds });
    Object.assign(seconds.querySelector('input'), { min: '1', max: String(10 * 365 * 86400), step: '1' });
    const content = el('div');
    content.append(el('p', 'message warning', '기간은 조직의 보존 목적과 법률 검토에 따라 정하세요. 기본값은 법정 보존기간을 뜻하지 않습니다. 새 정책은 기존 이벤트의 종료일을 바꾸지 않습니다.'));
    content.append(form([seconds, field('인간 법률 검토', 'legalReview', { choices: ['pending', 'reviewed'], value: 'pending' }), field('보존 목적', 'purpose', { required: true, wide: true, maxLength: 500, value: policy.purpose || '' }), field('변경 사유·기간 산정 근거', 'reason', { required: true, multiline: true, wide: true, maxLength: 1000 })], '새 보존 정책 저장', async (values) => {
      const retentionSeconds = Number(values.retentionSeconds);
      if (!Number.isSafeInteger(retentionSeconds) || retentionSeconds < 1 || retentionSeconds > 10 * 365 * 86400) throw new Error('보존기간은 1초부터 10년까지의 정수로 입력하세요.');
      await api('/api/retention/policy', 'POST', { ...values, retentionSeconds }); await retentionSaved('새 보존 정책을 저장했습니다. 이후 접수하는 이벤트부터 적용됩니다.');
    })); showDetail('보존 정책 버전 작성', content);
  }, 'small')); node.append(policyCard);
  const holds = card('보존 보류', '테넌트 전체 또는 특정 행동의 파기를 보류합니다. 등록자와 다른 검토자가 근거를 남겨 해제해야 합니다.');
  holds.querySelector('.card-header').append(button('+ 보존 보류', () => {
    const holdForm = form([field('보류 범위', 'scopeType', { choices: [{ value: 'action', label: '특정 행동' }, { value: 'tenant', label: '현재 테넌트 전체' }] }), field('행동 ID', 'actionId', { required: true, maxLength: 200 }), field('보류 사유·관련 절차', 'reason', { required: true, multiline: true, wide: true, maxLength: 1000 })], '보존 보류 등록', async (values) => {
      await api('/api/retention/holds', 'POST', { scope: values.scopeType === 'tenant' ? 'tenant' : values.actionId.trim(), reason: values.reason }); await retentionSaved('보존 보류를 등록했습니다. 해당 이벤트는 파기 대상에서 제외됩니다.');
    });
    const actionInput = holdForm.querySelector('[name="actionId"]');
    holdForm.querySelector('[name="scopeType"]').addEventListener('change', (event) => { const tenantScope = event.target.value === 'tenant'; actionInput.disabled = tenantScope; actionInput.required = !tenantScope; });
    showDetail('보존 보류 등록', holdForm);
  }, 'small'));
  holds.append(table(['범위', '사유', '등록자', '상태', '검토'], (data.holds || []).map((hold) => {
    const actions = el('div', 'actions'); actions.append(button('이력', () => inspect('보존 보류 기록', hold), 'small'));
    if (hold.status === 'active') actions.append(button('해제 검토', () => {
      const content = el('div'); content.append(el('p', 'selection-note', `보류 ${hold.id} · 범위 ${hold.scope === 'tenant' ? '현재 테넌트 전체' : hold.scope} · 등록자 ${hold.author}`), el('p', 'muted', `등록 사유: ${hold.reason}`));
      content.append(form([field('해제 근거', 'reason', { required: true, multiline: true, wide: true, maxLength: 1000 })], '다른 검토자로 보류 해제', async (values) => {
        await api(`/api/retention/holds/${encodeURIComponent(hold.id)}/release`, 'POST', values); await retentionSaved('보존 보류 해제 이력을 저장했습니다. 기간이 끝난 이벤트는 다시 파기 검토 대상이 될 수 있습니다.');
      })); showDetail('보존 보류 해제 검토', content);
    }, 'small'));
    return [hold.scope === 'tenant' ? '현재 테넌트 전체' : hold.scope, el('div', 'wrap', hold.reason), hold.author, badge(hold.status), actions];
  }))); node.append(holds);
  const plans = card('파기 계획과 인간 승인', '기간이 끝나고 보류·미종결 사건이 없는 이벤트를 최대 1,000건 선택합니다. 계획 작성만으로 파기되지 않습니다.');
  plans.querySelector('.card-header').append(button('+ 파기 계획 작성', () => {
    const content = el('div'); content.append(el('p', 'message warning', '서버가 생성 시점의 구체적인 대상 목록과 해시를 고정합니다. 저장 후 대상·기간을 확인하고, 작성자와 다른 검토자가 승인해야 합니다.'));
    content.append(form([field('파기 목적·근거', 'reason', { required: true, multiline: true, wide: true, maxLength: 1000 })], '대상을 선택하여 계획 저장', async (values) => {
      const plan = await api('/api/retention/plans', 'POST', values); await navigate('retention'); await retentionPlanDetail(plan.id); notice('구체적인 파기 계획을 저장했습니다. 대상과 보존 종료일을 검토하세요.');
    })); showDetail('파기 계획 작성', content);
  }, 'small'));
  plans.append(table(['계획 ID', '대상 수', '작성자 / 승인자', '계획 유효기한', '상태', '검토'], (data.plans || []).map((plan) => [plan.id, plan.items?.length ?? 0, `${plan.author} / ${plan.approvedBy || '미승인'}`, date(plan.expiresAt), badge(plan.status), button('대상·승인 검토', () => retentionPlanDetail(plan.id), 'small')]))); node.append(plans);
  const inventory = card('이벤트별 보존 상태', `${data.items?.length ?? 0}건 · 계획 포함 가능 ${(data.items || []).filter((item) => item.eligible).length}건. 현재 조회 결과이며 승인·실행 시 서버가 유효성을 다시 검증합니다.`);
  inventory.append(retentionItems(data.items, true)); node.append(inventory);
  if (data.legacyPlaintextEvents) node.append(el('div', 'message warning', `기존 평문 원장 이벤트 ${data.legacyPlaintextEvents}건은 이 암호키 파기 절차의 대상이 아닙니다. 별도 승인된 이전·보존 절차가 필요합니다.`));
  node.append(limits(data.limitations)); return node;
}
async function retentionPlanDetail(id, execution = false) {
  const data = await api('/api/retention'); const plan = (data.plans || []).find((item) => item.id === id);
  if (!plan) throw new Error('파기 계획을 찾을 수 없습니다. 목록을 새로 조회하세요.');
  const node = el('div'); const expired = !plan.expiresAt || Date.parse(plan.expiresAt) <= Date.now();
  node.append(el('p', 'selection-note', `계획 ${plan.id} · ${label(plan.status)} · 대상 ${plan.items?.length ?? 0}건`), el('p', '', `작성자 ${plan.author} · 승인자 ${plan.approvedBy || '미승인'} · 유효기한 ${date(plan.expiresAt)}`), el('p', 'wrap', `계획 근거: ${plan.reason}`), el('p', 'mono wrap', `선택 대상 해시: ${plan.selectionHash}`));
  if (plan.approvalReason) node.append(el('p', 'wrap', `승인 근거: ${plan.approvalReason}`));
  if (expired && plan.status !== 'executed') node.append(el('div', 'message warning', '계획 유효기한이 지났습니다. 현재 대상을 반영한 새 계획을 작성하세요.'));
  node.append(retentionItems(plan.items), jsonDetails('고정된 대상과 계획 이력', plan));
  if (execution) {
    if (expired || plan.status !== 'approved') throw new Error('현재 승인된 유효한 계획만 실행할 수 있습니다. 계획 상태를 다시 확인하세요.');
    node.append(el('div', 'message error', '되돌릴 수 없는 파기입니다. 아래 확정 버튼은 선택한 이벤트의 현재 복호화 키와 검색 사본을 삭제합니다. 해당 원본 내용은 재조사할 수 없고 서명된 파기 이력과 원장 무결성 검증 근거가 남습니다. 기존 내보내기·백업·디스크 잔존물의 삭제는 확인되지 않습니다.'));
    const confirmation = form([field('파기를 확정하려면 위 계획 ID를 그대로 입력하세요', 'confirmation', { required: true, wide: true, maxLength: 200 })], '현재 이벤트 키·검색 사본 영구 파기 확정', async (values) => {
      if (values.confirmation.trim() !== plan.id) throw new Error('확정 입력이 계획 ID와 일치하지 않습니다.');
      try { await api(`/api/retention/plans/${encodeURIComponent(plan.id)}/execute`, 'POST', {}); }
      catch (error) { throw new Error(`${error.message} 실행 응답이 불확실하면 계획 목록을 새로 조회해 파기 이력을 먼저 확인하세요.`); }
      await retentionSaved('파기를 실행하고 이력을 저장했습니다. 외부 사본의 파기는 별도 절차에서 확인해야 합니다.');
    }); confirmation.querySelector('button[type="submit"]').className = 'danger'; node.append(confirmation, button('확정 취소 · 계획으로 돌아가기', () => retentionPlanDetail(plan.id), 'ghost'));
  } else if (plan.status === 'pending' && !expired) {
    node.append(el('p', 'muted', '작성자와 다른 검토자가 대상·기간·보류 상태를 확인하고 파기 계획을 승인합니다. 이 승인은 업무 AI 실행과 무관합니다.'), form([field('승인 검토 근거', 'reason', { required: true, multiline: true, wide: true, maxLength: 1000 })], '다른 검토자로 파기 계획 승인', async (values) => {
      await api(`/api/retention/plans/${encodeURIComponent(plan.id)}/approve`, 'POST', values); await navigate('retention'); await retentionPlanDetail(plan.id); notice('파기 계획을 승인했습니다. 관리자 실행 전까지 내용은 보존됩니다.');
    }));
  } else if (plan.status === 'approved' && !expired) node.append(button('관리자 파기 실행 · 최종 확인 열기', () => retentionPlanDetail(plan.id, true), 'danger'));
  if (plan.disposition) node.append(jsonDetails('서명 원장에 기록된 파기 내역', plan.disposition));
  node.append(limits(data.limitations)); showDetail(execution ? '영구 파기 · 최종 확정' : '파기 계획 · 구체적인 대상 검토', node);
}
async function healthView() {
  const data = await api('/api/overview'); const node = el('div');
  if (authMode === 'oidc') {
    const access = card('조직 계정 · 접속 관리', 'EvidScope 접속 종료는 이 서비스의 세션만 종료합니다. 조직 인증 제공자의 로그인은 유지될 수 있습니다.');
    access.append(el('p', 'wrap', `${sessionPrincipal?.id || '미확인'} · 테넌트 ${sessionPrincipal?.tenant || '미확인'} · 역할 ${sessionPrincipal?.role || '미확인'}`), el('p', 'muted', `세션 만료: ${date(sessionExpiresAt)}`));
    if (sessionPrincipal?.role === 'admin') access.append(button('조직 계정 접근 관리', accessSubjects, 'primary'));
    node.append(access);
  }
  const sources = card('출처별 수집 상태', '알려진 출처 범위의 상태입니다. 모든 AI 사용을 관측했다는 의미가 아닙니다.'); sources.append(sourceTable(data.sources)); node.append(sources);
  const integrity = card('증적 무결성 검증', '서명 원장, 보존된 이벤트 본문·색인, 개발 실행, 등록 객체·평가·행동 상태, 거버넌스 문서 사본과 참조된 로컬 암호화 문서를 대조합니다. 문서 검증은 파일별 읽기 시점이며 미참조 파일이나 파일시스템 전체 스냅샷을 뜻하지 않습니다. 독립 내보내기 검증에는 별도로 확보한 신뢰 앵커가 필요합니다.');
  const result = el('div'); integrity.append(el('p', 'muted', `분석 대기: ${data.counts?.backlog ?? '미확인'}건. 접수·분석·외부 봉인은 구분해서 판단하세요.`), button('보관 증적 검증 실행', async () => { result.replaceChildren(el('div', 'loading', '체인 무결성 검사 중')); try { const response = await api('/api/integrity'); result.replaceChildren(el('pre', 'json', stringify(response))); } catch (error) { result.replaceChildren(el('div', 'message error', error.message)); } }, 'primary'), result);
  node.append(integrity, limits(data.limitations), limits(['수집되지 않은 출처의 행동과 원문 미보관으로 인한 사후 검증 범위는 확인할 수 없습니다.', '체인 검증 성공은 기록 내용의 진실성이나 법적 증거능력에 대한 판정이 아닙니다.'])); return node;
}
async function accessSubjects() {
  if (authMode !== 'oidc' || sessionPrincipal?.role !== 'admin') throw new Error('조직 계정 관리 권한이 필요합니다.');
  const accessEpoch = authEpoch, modalEpoch = detailEpoch;
  const data = await api('/api/access');
  if (accessEpoch !== authEpoch || modalEpoch !== detailEpoch) return;
  const node = card('조직 계정 접근 관리', '현재 테넌트에 등록된 계정의 서비스 접근과 세션을 관리합니다. 조직 인증 제공자 계정 자체는 변경하지 않습니다.');
  node.append(table(['계정', '테넌트', '역할', '서비스 접근', '현재 세션', '관리'], (data.subjects || []).map(subject => [subject.id, subject.tenant, subject.role, subject.disabled ? '비활성화' : '허용', subject.sessionCount, button('접근 변경', () => accessSubjectEditor(subject), 'small')])), limits(data.limitations));
  showDetail('조직 계정 접근 관리', node);
}
function accessSubjectEditor(subject) {
  const node = card('계정 접근 변경', `${subject.id} · ${subject.tenant} · ${subject.role}`);
  const choices = [{ value: 'revoke_sessions', label: '현재 세션 전체 회수' }, { value: subject.disabled ? 'enable' : 'disable', label: subject.disabled ? '서비스 접근 허용' : '서비스 접근 비활성화' }];
  if (subject.id === sessionPrincipal?.id) choices.splice(1, 1);
  node.append(el('p', 'muted', '세션 회수 후에도 접근이 허용된 계정은 다시 로그인할 수 있습니다. 비활성화하면 다시 로그인할 수 없습니다. 자신의 접근 비활성화는 허용하지 않습니다.'));
  node.append(form([field('변경할 접근 상태', 'action', { choices }), field('변경 사유', 'reason', { required: true, multiline: true, maxLength: 1000 })], '사유를 기록하고 적용', async values => {
    const reason = values.reason.trim(); if (!reason) throw new Error('변경 사유를 입력하세요.');
    const context = captureDetailContext();
    await api(`/api/access/subjects/${encodeURIComponent(subject.id)}`, 'POST', { action: values.action, reason });
    if (!isCurrentDetail(context)) return;
    if (subject.id === sessionPrincipal?.id && values.action === 'revoke_sessions') { clearAuth(); notice('현재 계정의 EvidScope 세션을 회수했습니다. 조직 인증 제공자의 로그인은 종료되지 않았습니다.'); return; }
    await accessSubjects();
  }));
  showDetail('계정 접근 변경', node);
}
const agentPolicyLabels={compliant:'관측 기준 충족',violation:'위반 신호',unconfirmed:'근거 미확인',pending:'평가 대기',exception:'예외 적용'};
function agentRate(item){const n=el('div','agent-rate');n.append(el('strong','',item.compliance.percent===null?'산정 불가':`${item.compliance.percent}%`),el('p','muted',`충족 ${item.compliance.numerator} / 판정 가능 ${item.compliance.denominator}개 행동`),el('p','muted',`평가 범위 ${item.compliance.coveragePercent===null?'산정 불가':item.compliance.coveragePercent+'%'} · 전체 ${item.actions}개 중`));if(item.compliance.percent!==null){const meter=el('meter');meter.min=0;meter.max=100;meter.value=item.compliance.percent;meter.setAttribute('aria-label','관측 정책 준수율');n.append(meter);}return n;}
const agentRangeLabels={'24h':'최근 24시간','7d':'최근 7일','30d':'최근 30일',all:'전체 보존 기간'};
function agentScope(data){return `${agentRangeLabels[data.window.range]} · ${data.window.start?date(data.window.start)+' ~ ':''}${date(data.window.end)} · 현재 평가 기준`;}
function agentActionExplorer(data){
 const root=el('div'),chart=card('행동별 정책 상태 추이','첫 에이전트 수신 시각별 행동 수입니다. 현재 평가를 과거 수신 구간에 배치하며, 당시 판정의 변화 그래프는 아닙니다. 막대를 누르면 해당 행동을 조사합니다.');
 const legend=el('div','agent-legend');Object.entries(agentPolicyLabels).forEach(([key,value])=>legend.append(el('span',`agent-key ${key}`,value)));chart.append(legend);
 const plot=el('div','agent-trend'),scale=Math.max(1,...data.trend.map(p=>p.actions));plot.setAttribute('aria-label','에이전트 정책 상태 추이');
 const selection=el('p','agent-window'),filters=el('div','toolbar');
 const state=field('점검 상태','state',{choices:[{value:'all',label:'모든 상태'},...Object.entries(agentPolicyLabels).map(([value,label])=>({value,label}))]});
 const review=field('인간 검토','review',{choices:[{value:'all',label:'모든 검토 상태'},{value:'unreviewed',label:'미검토'},{value:'stale',label:'재검토 필요'},{value:'inconclusive',label:'판단 유보'},{value:'reviewed',label:'검토 완료'}]});
 const search=field('행동 ID 검색','action',{placeholder:'행동 ID 일부'});filters.append(state,review,search);const rows=el('div'),pages=el('div','pagination');let bucket=null,page=0;
 function draw(){const selectedState=state.querySelector('select').value,selectedReview=review.querySelector('select').value,q=search.querySelector('input').value.toLowerCase();
  const items=data.item.details.filter(a=>(bucket===null||a.bucket===bucket)&&(selectedState==='all'||a.state===selectedState)&&(selectedReview==='all'||a.reviewState===selectedReview)&&a.actionId.toLowerCase().includes(q));
  selection.textContent=bucket===null?`전체 구간 · 조건 일치 ${items.length}개 행동`:`${date(data.trend[bucket].at)} ~ ${date(data.trend[bucket].end)} · 조건 일치 ${items.length}개 행동`;
  [...plot.children].forEach((n,i)=>n.setAttribute('aria-pressed',String(bucket===i)));
  rows.replaceChildren(table(['행동 / 최초 수신','점검 결과','판정 근거','인간 검토','조사'],items.slice(page*20,page*20+20).map(a=>{const id=el('div');id.append(el('strong','wrap',a.actionId),el('p','muted',date(a.firstSeen)));return [id,agentPolicyLabels[a.state],a.reason,reviewBadge(a.reviewState),button('행동 근거 열기',()=>actionDetail(a.actionId),'small')];})));
  const prev=button('← 이전 행동',()=>{page--;draw();}),next=button('다음 행동 →',()=>{page++;draw();});prev.disabled=page===0;next.disabled=(page+1)*20>=items.length;pages.replaceChildren(prev,el('span','muted',items.length?`${page*20+1}–${Math.min(items.length,page*20+20)} / ${items.length}`:'0 / 0'),next);
 }
 data.trend.forEach((p,i)=>{const bar=button('',()=>{bucket=bucket===i?null:i;page=0;draw();},'agent-column');const description=`${date(p.at)} ~ ${date(p.end)} · ${p.actions}개 · `+Object.entries(p.counts).map(([key,n])=>`${agentPolicyLabels[key]} ${n}`).join(', ');bar.title=description;bar.setAttribute('aria-label',description);
  const stack=el('div','agent-stack');Object.entries(p.counts).forEach(([key,n])=>{const segment=el('span',`agent-segment ${key}`);segment.style.height=`${n/scale*150}px`;stack.append(segment);});bar.append(el('span','agent-column-count',p.actions),stack,el('small','',new Date(p.at).toLocaleString('ko-KR',data.window.range==='24h'?{hour:'2-digit',minute:'2-digit',hour12:false}:{month:'numeric',day:'numeric'})));plot.append(bar);
 });
 chart.append(el('p','muted',`최대 ${scale}개 / 구간 · ${data.trend.length}개 구간 · ${date(data.trend[0].at)} ~ ${date(data.window.end)}`),plot,button('구간 선택 해제',()=>{bucket=null;page=0;draw();},'ghost'));root.append(chart,el('h3','','행동별 산정 근거'),filters,selection,rows,pages);
 filters.addEventListener('change',()=>{page=0;draw();});search.addEventListener('input',()=>{page=0;draw();});draw();return root;
}
async function agentDetail(id,range='all',end){
 showDetail('에이전트 정책·근거 현황',el('p','','에이전트 기록을 조회하고 있습니다…'));const context=captureDetailContext();
 try{const data=await api('/api/agents?'+new URLSearchParams({id,range,...(end?{end}:{})}));if(!isCurrentDetail(context))return;const item=data.item,node=el('div');
 node.append(el('h2','wrap',item.actor),el('p','muted wrap',`${item.source} · 모델 ${item.models.join(', ')||'미수집'} · 마지막 수신 ${date(item.lastSeen)}`));
 node.append(el('p','agent-definition',agentScope(data)));
 const columns=el('div','grid two'),rate=card('관측 정책 준수율',data.definition.formula);rate.append(agentRate(item));const states=card('선택 기간 행동의 점검 상태','근거가 없거나 예외가 적용된 행동은 준수로 처리하지 않습니다.');states.append(table(['상태','행동 수'],Object.entries(item.counts).map(([k,v])=>[agentPolicyLabels[k],v])));columns.append(rate,states);node.append(columns);
 node.append(el('p','agent-definition',data.definition.checks),el('p','muted',data.definition.scope),el('p','muted',data.definition.identity),el('h3','','참고자료와 사람의 검토'),el('p','',`참조 기록 있는 행동 ${item.referenceActions}/${item.actions}개 · 현재 근거 검토 ${item.reviews.reviewed} · 재검토 ${item.reviews.stale} · 판단 유보 ${item.reviews.inconclusive} · 미검토 ${item.reviews.unreviewed}`),el('p','wrap',`보고된 당시 정책 버전: ${item.policyVersions.join(', ')||'미수집'}`));
 node.append(agentActionExplorer(data));showDetail('에이전트 정책·근거 현황',node);
 }catch(error){if(isCurrentDetail(context))showDetail('에이전트 조회 실패',empty('기록을 조회하지 못했습니다',error.message));}
}
async function agentsView(){
 const node=el('div'),panel=card('에이전트별 정책 준수 현황','인증된 출처와 보고된 에이전트 이름을 함께 식별합니다. 평가 범위가 작으면 높은 비율도 전체 준수를 뜻하지 않습니다.');
 const filters=el('form','toolbar');filters.append(field('에이전트·모델·출처 검색','q',{value:workspaceFilters.q,placeholder:'이름, qwen, 수집 출처…'}),field('조회 기간','range',{choices:Object.entries(agentRangeLabels).map(([value,label])=>({value,label})),value:'7d'}),field('우선 확인','focus',{choices:[{value:'all',label:'전체 에이전트'},{value:'violation',label:'위반 신호 있음'},{value:'unconfirmed',label:'근거 미확인 있음'},{value:'stale',label:'재검토 필요'},{value:'inactive',label:'기간 내 행동 없음'}]}),field('정렬','sort',{choices:[{value:'attention',label:'위반 → 재검토 → 근거 부족'},{value:'recent',label:'최근 수신순'},{value:'coverage',label:'평가 범위 낮은순'}]}));const submit=el('button','primary','조회');submit.type='submit';filters.append(submit);const scope=el('p','agent-definition'),stats=el('div','agent-summary'),rows=el('div'),pages=el('div','pagination');panel.append(filters,stats,scope,rows,pages);node.append(panel);let offset=0,epoch=0;const viewEpoch=renderEpoch;
 async function search(){const current=++epoch;submit.disabled=true;try{const query=new URLSearchParams(new FormData(filters));query.set('offset',String(offset));const data=await api('/api/agents?'+query);if(current!==epoch||viewEpoch!==renderEpoch)return;
 scope.textContent=`${agentScope(data)}. ${data.definition.scope} 에이전트 미귀속 행동 ${data.unattributedActions}개 · 여러 에이전트 귀속 행동 ${data.ambiguousActions}개. ${data.definition.formula}`;rows.replaceChildren();stats.replaceChildren();
 for(const [key,title,target] of [['agents','검색된 에이전트','all'],['violation','위반 신호 있음','violation'],['unconfirmed','근거 미확인 있음','unconfirmed'],['stale','재검토 필요','stale'],['inactive','기간 내 행동 없음','inactive']]){const tile=button('',()=>{filters.elements.focus.value=target;offset=0;return search();},'agent-stat');tile.append(el('span','',title),el('strong','',data.summary[key]),el('small','muted','개 에이전트'));tile.setAttribute('aria-pressed',String(query.get('focus')===target));stats.append(tile);}
 if(!data.items.length)rows.append(empty('해당 에이전트가 없습니다','에이전트 출처를 연결하거나 검색어를 확인하세요.'));
 else rows.append(table(['에이전트 / 출처','모델 / 최근 수신 (전체)','기간 내 행동','관측 정책 준수율','위반 / 미확인 / 대기 / 예외','인간 검토 / 참고자료','상세'],data.items.map(item=>{const name=el('div');name.append(el('strong','wrap',item.actor),el('p','muted wrap',item.source));const model=el('div');model.append(el('p','wrap',item.models.join(', ')||'모델 미수집'),el('small','muted',date(item.lastSeen)));return [name,model,item.actions,agentRate(item),`${item.counts.violation} / ${item.counts.unconfirmed} / ${item.counts.pending} / ${item.counts.exception}`,`검토 ${item.reviews.reviewed}/${item.actions} · 참조 ${item.referenceActions}/${item.actions}`,button('정책·근거 보기',()=>agentDetail(item.id,data.window.range,data.window.end),'small')];})));
 pages.replaceChildren();const prev=button('← 이전',async()=>{offset=Math.max(0,offset-50);await search();}),next=button('다음 →',async()=>{offset+=50;await search();});prev.disabled=offset===0;next.disabled=offset+data.items.length>=data.total;pages.append(prev,el('span','muted',data.total?`${offset+1}–${offset+data.items.length} / ${data.total}`:'0 / 0'),next);
 }catch(error){if(current===epoch&&viewEpoch===renderEpoch){stats.replaceChildren();scope.textContent='조회 실패 · 선택 조건의 집계를 확인할 수 없습니다.';pages.replaceChildren();rows.replaceChildren(empty('집계를 불러오지 못했습니다',error.message));}}finally{if(current===epoch)submit.disabled=false;}}
 filters.addEventListener('submit',event=>{event.preventDefault();offset=0;search();});filters.addEventListener('change',event=>{if(event.target.tagName==='SELECT'){offset=0;search();}});await search();return node;
}
const renderers = { agents: agentsView, graphs: graphsView, investigations: investigationsView, overview, events: eventsView, alerts: alertsView, cases: casesView, rules: rulesView, governance: governanceView, retention: retentionView, health: healthView };
async function navigate(view) {
  disposeView(); disposeView = () => {};
  if (!views[view]) view = 'investigations'; activeView = view; const epoch = ++renderEpoch;
  document.querySelectorAll('[data-view]').forEach((node) => { node.classList.toggle('active', node.dataset.view === view); if (node.dataset.view === view) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current'); });
  window.EvidScopeConsole?.updateNavigation(view);
  $('#page-title').textContent = views[view][0]; $('#page-description').textContent = views[view][1];
  document.title = `${views[view][0]} · EvidScope`; notice();
  if (!token && view !== 'graphs') {
    $('#content').removeAttribute('aria-busy');
    const blank = empty('감사 워크스페이스에 접속하세요', authMode === 'oidc' ? '조직 계정으로 인증하면 등록된 테넌트와 역할에 허용된 증거·사건·거버넌스 기록을 조회할 수 있습니다.' : authMode === 'local' ? '발급된 토큰으로 인증하면 테넌트와 역할에 허용된 증거·사건·거버넌스 기록을 조회할 수 있습니다.' : '서버의 접속 방식을 확인하고 있습니다. 확인할 수 없으면 다시 시도하세요.');
    blank.append(button(authMode === 'oidc' ? '조직 계정으로 접속' : '접속하기', openLogin, 'primary'));
    $('#content').replaceChildren(blank); return;
  }
  $('#content').replaceChildren(el('div', 'loading', '감사 기록을 조회하고 있습니다…')); $('#content').setAttribute('aria-busy', 'true');
  try {
    const rendered = await renderers[view]();
    if (epoch !== renderEpoch) return;
    $('#content').replaceChildren(rendered); $('#last-updated').textContent = `조회 ${new Date().toLocaleTimeString('ko-KR', { hour12: false })}`;
  } catch (error) { if (epoch === renderEpoch) { $('#content').replaceChildren(empty('기록을 불러오지 못했습니다', error.message)); notice(error.message, true); } }
  finally { if (epoch === renderEpoch) $('#content').removeAttribute('aria-busy'); }
}
document.querySelectorAll('[data-view]').forEach((node) => node.addEventListener('click', () => navigate(node.dataset.view)));
$('.brand').addEventListener('click', (event) => { event.preventDefault(); navigate('investigations'); });
$('#refresh').addEventListener('click', () => navigate(activeView));
$('#auth-close').addEventListener('click', () => $('#auth-dialog').close());
$('#detail-close').addEventListener('click', () => { detailEpoch++; $('#detail-dialog').close(); });
$('#detail-dialog').addEventListener('cancel', () => { detailEpoch++; });
function clearAuth(render = true) {
  token = ''; csrfToken = ''; sessionPrincipal = null; sessionExpiresAt = null;
  authEpoch++; detailEpoch++; renderEpoch++;
  $('#auth-toggle').textContent = authMode === 'oidc' ? '조직 계정으로 접속' : '접속';
  $('#connection').textContent = '인증 필요'; $('#connection-dot').classList.remove('connected');
  $('#auth-token').value = ''; $('#auth-dialog').close(); $('#detail-dialog').close(); $('#detail-content').replaceChildren(); $('#last-updated').textContent = '조회 전';
  if (render) navigate(activeView);
  else {
    disposeView(); disposeView = () => {};
    notice(); $('#content').removeAttribute('aria-busy');
    $('#content').replaceChildren(empty('감사 워크스페이스에 접속하세요', '접속 상태를 확인한 뒤 현재 권한에 허용된 기록을 다시 조회합니다.'));
  }
}
async function authRequest(path, options = {}) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 20000);
  try { return await fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal }); }
  finally { clearTimeout(timer); }
}
async function initializeAuth() {
  if (authBusy) return;
  authBusy = true; $('#auth-toggle').disabled = true;
  const epoch = authEpoch;
  try {
    const response = await authRequest('/auth/config'), config = await response.json();
    if (epoch !== authEpoch) return;
    if (!response.ok || !['local', 'oidc'].includes(config.mode) || config.mode === 'oidc' && config.loginPath !== '/auth/login') throw new Error('서버의 접속 방식을 확인할 수 없습니다.');
    authMode = config.mode; $('#auth-form').hidden = authMode !== 'local';
    $('#auth-toggle').textContent = authMode === 'oidc' ? '조직 계정으로 접속' : '접속';
    if (authMode === 'oidc') {
      const sessionResponse = await authRequest('/auth/session');
      if (epoch !== authEpoch) return;
      if (sessionResponse.ok) {
        const session = await sessionResponse.json();
        if (epoch !== authEpoch) return;
        if (!session.principal?.id || !session.principal.tenant || !['auditor', 'reviewer', 'admin'].includes(session.principal.role) || typeof session.csrfToken !== 'string' || !session.csrfToken || !(Date.parse(session.expiresAt) > Date.now())) throw new Error('유효한 조직 접속 상태를 확인할 수 없습니다.');
        // This marker preserves view guards; it is never an Authorization credential.
        token = 'oidc-session'; csrfToken = session.csrfToken; sessionPrincipal = session.principal; sessionExpiresAt = session.expiresAt; authEpoch++;
        $('#auth-toggle').textContent = 'EvidScope 접속 종료'; $('#connection').textContent = `${sessionPrincipal.id} · ${sessionPrincipal.tenant} · ${sessionPrincipal.role}`; $('#connection-dot').classList.add('connected');
      } else if (sessionResponse.status === 401) clearAuth(false);
      else throw new Error('조직 접속 상태를 조회하지 못했습니다. 다시 접속하세요.');
    } else if (!token) $('#connection').textContent = '인증 필요';
    await navigate(activeView);
    const query = new URLSearchParams(window.location.search);
    if (query.get('auth') === 'failed') { window.history.replaceState(null, '', '/'); notice('조직 계정 접속을 완료하지 못했습니다. 등록된 계정인지 확인하고 다시 시도하세요.', true); }
  } catch (error) {
    if (epoch === authEpoch) { clearAuth(); notice(error.name === 'AbortError' ? '접속 상태 확인 시간이 초과됐습니다. 다시 시도하세요.' : error.message, true); }
  } finally { authBusy = false; $('#auth-toggle').disabled = false; }
}
async function openLogin() {
  if (authBusy) return;
  if (!authMode) await initializeAuth();
  if (token) return;
  if (authMode === 'oidc') window.location.assign('/auth/login');
  else if (authMode === 'local') $('#auth-dialog').showModal();
}
async function logout() {
  if (authBusy) return;
  const oidc = authMode === 'oidc', logoutCsrf = csrfToken;
  clearAuth();
  if (!oidc) return;
  authBusy = true; $('#auth-toggle').disabled = true; const epoch = authEpoch;
  try {
    const response = await authRequest('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Evid-CSRF': logoutCsrf }, body: '{}' });
    const result = await response.json().catch(() => ({}));
    if (epoch !== authEpoch) return;
    if (!response.ok || result.loggedOut !== true) throw new Error('화면의 접속 정보는 지웠지만 서버 세션 종료를 확인하지 못했습니다. 다시 접속해 종료하거나 관리자에게 세션 회수를 요청하세요.');
    notice('EvidScope 접속을 종료했습니다. 조직 인증 제공자의 로그인은 종료하지 않았습니다.');
  } catch (error) { if (epoch === authEpoch) notice(error.name === 'AbortError' ? '서버 세션 종료를 확인하지 못했습니다. 관리자에게 세션 회수를 요청하세요.' : error.message, true); }
  finally { authBusy = false; $('#auth-toggle').disabled = false; }
}
$('#auth-toggle').addEventListener('click', () => token ? logout() : openLogin());
$('#auth-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const submit = $('#auth-form button[type="submit"]'); submit.disabled = true; $('#auth-error').textContent = '';
  if (authMode !== 'local') { submit.disabled = false; return; }
  authEpoch++; token = $('#auth-token').value.trim(); $('#auth-token').value = '';
  const attemptEpoch = authEpoch;
  try {
    await api('/api/overview'); $('#auth-dialog').close(); $('#auth-toggle').textContent = '접속 종료'; $('#connection').textContent = '감사 API 연결됨'; $('#connection-dot').classList.add('connected'); await navigate(activeView);
  } catch (error) {
    if (authEpoch === attemptEpoch || error.status === 401 && authEpoch === attemptEpoch + 1 && !token) {
      if (token) clearAuth();
      $('#auth-error').textContent = error.message; $('#auth-dialog').showModal();
    }
  } finally { submit.disabled = false; }
});
$('#export').addEventListener('click', async () => {
  const btn = $('#export'); btn.disabled = true;
  try {
    const data = await api('/api/export'); const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const link = el('a'); link.href = url; link.download = `evidscope-audit-${new Date().toISOString().slice(0, 10)}.json`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000); notice('감사 자료를 내려받았습니다. 별도로 확보한 신뢰 앵커로 독립 검증하세요.');
  } catch (error) { notice(error.message, true); } finally { btn.disabled = false; }
});
window.addEventListener('pagehide', () => clearAuth(false));
window.addEventListener('pageshow', event => { if (event.persisted) initializeAuth(); });

// Explicit public interface for optional sibling modules (e.g. team-support.js).
// Kept separate from the ambient script-global scope so integration points are
// deliberate and don't rely on load-order accidents.
window.EvidScopeCore = {
  api, el, button, badge, card, notice, empty, limits, jsonDetails, table, field, form,
  label, date, stringify, showDetail, inspect, captureDetailContext, isCurrentDetail, savedNotice,
  downloadArtifact, localDate, navigate, $,
  factList: evidenceFacts,
  openAction: actionDetail,
  openCase: caseDetail,
  getRenderEpoch: () => renderEpoch,
  getAuthEpoch: () => authEpoch,
  getToken: () => token,
  getActiveView: () => activeView,
  getWorkspaceFilters: () => ({ ...workspaceFilters }),
  setWorkspaceFilters(value) { workspaceFilters = { q: typeof value.q === 'string' ? value.q.slice(0, 200) : '', range: ['1h', '24h', '7d'].includes(value.range) ? value.range : workspaceFilters.range }; },
  registerView(key, title, description, render) { views[key] = [title, description]; renderers[key] = render; },
};

navigate('investigations');
initializeAuth();
