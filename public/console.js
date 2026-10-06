'use strict';

// This console only renders authenticated, reported values. It never starts a model.
(() => {
  const core = window.EvidScopeCore;
  if (!core) return;
  const { el, button, card, empty, table, field, jsonDetails, limits, api, date, showDetail, navigate } = core;
  const sections = [
    { id: 'status', name: '현황', routes: [['overview', '관측 개요'], ['graphs', '가시성 그래프']] },
    { id: 'assets', name: 'AI 자산·수집', routes: [['visibility', 'AI 사용 가시성'], ['agents', '에이전트 목록']] },
    { id: 'investigate', name: '탐색·조사', routes: [['investigations', '행동 조사함'], ['events', '증거 탐색'], ['alerts', '탐지 경보'], ['cases', '사건·인간 감사']] },
    { id: 'governance', name: '거버넌스', routes: [['governance', '요구사항·증거 검토']] },
    { id: 'review', name: 'AI 검토실', routes: [['assistance', '검토 요청·초안'], ['team', '역할·개발 이력'], ['model-runtime', '모델·학습 상태']] },
    { id: 'operations', name: '운영·설정', routes: [['health', '수집·증적 건강'], ['rules', '탐지 룰·예외'], ['retention', '보존·파기']] },
  ];
  const runtimeLabels = { off: '비활성', stopped: '실행 Pod 없음', terminated: '컨테이너 종료 보고', unavailable: '실행 상태 확인 불가', observed: 'Kubernetes 관측 수신', unverified: '실행 상태 검증 전', unknown: '실행 상태 미확인', running: '실행 중', unready: '준비되지 않음', starting: '시작 중', stopping: '종료 확인 중', STOP_UNCONFIRMED: '종료 미확인', stop_unconfirmed: '종료 미확인', blocked_review: '데이터 검토 필요', not_evaluated: '평가 미실시', not_run: '미실행', pending: '대기', failed: '실패' };
  const observationLabels = { contentObserved: '내용 관측', partial: '일부 내용 관측', not_observed: '내용 미관측', unknown: '관측 범위 미확인' };
  const languageLabels = { hangul: '한글 문자', latin: '라틴 문자', mixed: '한글·라틴 혼합', undetermined: '구분하지 못함' };
  const rangeLabels = { '1h': '최근 1시간', '24h': '최근 24시간', '7d': '최근 7일' };
  const count = value => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString('ko-KR') : '—';
  const list = value => Array.isArray(value) ? value : [];
  function observationState(item = {}) {
    if (Number.isSafeInteger(item.contentObserved) && item.contentObserved > 0) {
      return item.bodyNotObserved === 0 && item.contentObserved === item.observationCount ? 'contentObserved' : 'partial';
    }
    return item.contentObserved === 0 || item.bodyNotObserved > 0 ? 'not_observed' : 'unknown';
  }
  function statusPill(value, dictionary = runtimeLabels) {
    const known = Object.hasOwn(dictionary, String(value));
    const pill = el('span', `console-status ${known ? String(value).replace(/[^a-zA-Z_]/g, '').toLowerCase() : 'unknown'}`, known ? dictionary[value] : '상태 미확인');
    if (value != null) pill.title = String(value);
    return pill;
  }
  function numberFact(title, value, explanation, onClick) {
    const item = onClick ? button('', onClick, 'coverage-fact') : el('div', 'coverage-fact');
    item.append(el('span', '', title), el('strong', 'data-number', count(value)), el('small', '', explanation));
    return item;
  }
  function evidenceRibbon() {
    const strip = el('div', 'evidence-ribbon');
    for (const [title, text, view] of [['관측', '수집 범위와 공백', 'visibility'], ['근거', '출처·행동·결과 대조', 'investigations'], ['사람의 검토', '판단과 보완 이력', 'cases']]) {
      const item = button('', () => navigate(view), 'ribbon-step');
      item.append(el('strong', '', title), el('span', '', text)); strip.append(item);
    }
    return strip;
  }
  function modelStatusCard(runtime, compact = false) {
    const panel = card('감사 모델 상태', '설정된 정책과 실제 실행 확인을 구분합니다.');
    panel.classList.add('model-state-card');
    if (!runtime || typeof runtime !== 'object') {
      panel.append(empty('실행 상태를 확인하지 못했습니다', 'API 응답이 없어 모델이 꺼져 있다고 판정할 수 없습니다.')); return panel;
    }
    const top = el('div', 'model-state-line');
    top.append(el('strong', 'policy-state', runtime.enabledByDefault === false ? '기본 정책 OFF' : runtime.enabledByDefault === true ? '기본 정책: 활성화' : '기본 정책 미확인'), statusPill(runtime.observationStatus));
    panel.append(top);
    const models = list(runtime.models);
    if (!models.length) panel.append(el('p', 'muted', '등록된 모델의 실행·검증 자료가 없습니다.'));
    else if (compact) {
      for (const model of models) panel.append(el('p', 'muted wrap', `${model.model || model.id || '모델 미확인'} · ${runtimeLabels[model.state] || '상태 미확인'} · ${model.terminationConfirmed === true ? '종료 확인됨' : '종료 미확인'} · ${model.observedAt ? `관측 ${date(model.observedAt)}` : '관측 시각 없음'}`));
      panel.append(button('모델·학습 상태 보기 →', () => navigate('model-runtime'), 'small'));
    } else {
      panel.append(table(['모델 / 설정', '보고된 실행 상태', '종료·격리 확인', '관측 시각', '제한·근거'], models.map(model => {
        const policy = el('div'); policy.append(el('p', 'wrap', model.model || model.id || '미확인'), el('small', 'muted', model.declaredEnabled === false ? '설정: 비활성' : model.declaredEnabled === true ? '설정: 활성화' : '설정 미확인'));
        const verification = el('div'); verification.append(el('p', '', model.terminationConfirmed === true ? '종료 확인됨' : '종료 미확인'), el('small', 'muted', model.isolationVerified === true ? '격리 검증 보고 있음' : '격리 검증 미완료'));
        const settings = el('div'); settings.append(el('p', 'muted', `CPU ${model.limits?.cpu ?? '—'} · 메모리 ${model.limits?.memory ?? '—'} · 동시 실행 ${model.limits?.concurrency ?? '—'}`), button('설정·검증 원문', () => showDetail('모델 정책과 실제 검증 자료', jsonDetails('API가 반환한 모델 기록', model)), 'small'));
        return [policy, statusPill(model.state), verification, model.observedAt ? date(model.observedAt) : '관측 시각 없음', settings];
      })));
      panel.append(el('p', 'muted', '화면 조회는 모델을 시작하지 않습니다. 종료 요청과 Pod·GPU 자원 해제 확인은 별도의 상태입니다.'), limits(runtime.limitations));
    }
    return panel;
  }
  function languageCard(signals) {
    const panel = card('관측된 문자 신호', '허용된 텍스트 필드의 문자 분포입니다. 사용 언어 또는 모델의 한국어 능력을 확정하지 않습니다.');
    const row = el('div', 'language-signals');
    for (const [key, title] of Object.entries(languageLabels)) row.append(numberFact(title, signals?.[key], '관측 신호'));
    panel.append(row); return panel;
  }
  function screeningCard(screening) {
    const panel = card('콘텐츠 검사 범위', '내용을 관측하지 못한 기록과 검사를 실행하지 않은 기록을 구분합니다.');
    panel.append(table(['검사 상태', '관측 수'], [
      ['검사 완료', count(screening?.completed)], ['일부만 검사', count(screening?.incomplete)],
      ['내용 미관측', count(screening?.not_observed)], ['검사 미실행', count(screening?.not_run)],
      ['위험 분류 보고', count(screening?.unsafe)], ['추가 검토 분류 보고', count(screening?.controversial)],
    ]));
    panel.append(el('p', 'muted', '검사 완료는 안전 판정이 아닙니다. 분류 결과는 해당 검사기와 입력 범위에 한정됩니다.')); return panel;
  }
  function visibilitySummary(data) {
    const panel = card('수집된 범위에서 AI 사용을 확인하세요', '조직 전체 사용량을 추정하지 않고, 등록 자산과 실제 수신 기록을 함께 표시합니다.');
    panel.classList.add('visibility-summary');
    const summary = data?.summary || {};
    const facts = el('div', 'coverage-facts');
    facts.append(numberFact('등록 자산', summary.registeredAssets, '관리 목록에 등록', () => navigate('visibility')),
      numberFact('관측 자산', summary.observedAssets, '선택 기간 실제 수신', () => navigate('visibility')),
      numberFact('내용 미관측', summary.bodyNotObserved, '본문 확인 불가', () => navigate('visibility')),
      numberFact('확인할 신호', summary.attentionCount, '조사 필요 신호', () => navigate('visibility')));
    panel.append(facts);
    if (data?.window) panel.append(el('p', 'query-scope', `${rangeLabels[data.window.range] || '서버 조회 기간'} · ${date(data.window.start)} — ${date(data.window.end)} · ${data.window.timeBasis === 'receivedAt' ? '수신 시각 기준' : '시간 기준: ' + (data.window.timeBasis || '미확인')}`));
    return panel;
  }
  async function overviewPulse() {
    const node = el('div', 'console-pulse'); node.append(evidenceRibbon());
    try {
      const data = await api('/api/ai-visibility?' + new URLSearchParams({ range: core.getWorkspaceFilters().range }));
      node.append(visibilitySummary(data));
      const row = el('div', 'grid two'); row.append(languageCard(data.languageSignals), modelStatusCard(data.modelRuntime, true)); node.append(row);
    } catch (error) { node.append(empty('AI 사용 범위 조회가 준비되지 않았습니다', error.message)); }
    return node;
  }
  function assetDetailNode(item, data) {
    const node = el('div');
    node.append(el('p', 'selection-note wrap', item.id || '자산 식별자 미확인'), statusPill(observationState(item), observationLabels));
    node.append(core.factList([
      ['등록 상태', item.registered === true ? '등록됨' : item.registered === false ? '미등록 관측 자산' : '미확인'],
      ['담당자', item.owner || '미지정'], ['최근 수신', item.lastSeen ? date(item.lastSeen) : '수신 없음'],
      ['관측 기록', count(item.observationCount)], ['내용 관측 / 미관측', `${count(item.contentObserved)} / ${count(item.bodyNotObserved)}`],
      ['검사 미완료', count(item.screeningIncomplete)], ['모델', list(item.models).join(', ') || '미수집'], ['수집기', list(item.collectors).join(', ') || '미수집'],
    ]));
    const signals = card('확인할 신호와 근거', '경보는 조사 출발점이며 법적 위반이나 악의를 확정하지 않습니다.');
    if (!list(item.attention).length) signals.append(el('p', 'muted', '반환된 조사 신호가 없습니다. 미관측 영역의 안전을 의미하지 않습니다.'));
    for (const signal of list(item.attention)) {
      const row = el('article', 'attention-evidence'); row.append(core.badge(signal.severity || 'unknown'), el('h3', '', signal.code || '분류 미확인'), el('p', 'wrap', signal.message || '설명 없음'));
      const refs = list(signal.evidenceRefs); row.append(jsonDetails(`증거 참조 ${refs.length}개`, refs)); signals.append(row);
    }
    node.append(signals, languageCard(item.languageSignals), jsonDetails('자산 관측 원문', item), limits(data.limitations)); return node;
  }
  async function openAsset(id, range) {
    showDetail('AI 자산 관측 근거', el('div', 'loading', '자산의 관측 기록을 조회하고 있습니다…'));
    const context = core.captureDetailContext();
    try {
      const data = await api('/api/ai-visibility?' + new URLSearchParams({ assetRef: id, range }));
      if (!core.isCurrentDetail(context)) return;
      const item = list(data.assets).find(asset => asset.id === id);
      showDetail('AI 자산 관측 근거', item ? assetDetailNode(item, data) : empty('자산 기록이 없습니다', '권한·조회 기간 또는 변경된 자산 식별자를 확인하세요.'));
    } catch (error) { if (core.isCurrentDetail(context)) showDetail('자산 조회 실패', empty('관측 근거를 불러오지 못했습니다', error.message)); }
  }
  async function visibilityView() {
    const filters = core.getWorkspaceFilters();
    const data = await api('/api/ai-visibility?' + new URLSearchParams(filters));
    const root = el('div'); root.append(visibilitySummary(data));
    const panel = card('AI 자산의 수집 범위', '자산에서 사용 모델·수집 경로·내용 관측·의심 신호의 근거로 이동합니다.');
    const toolbar = el('div', 'toolbar');
    const observed = field('내용 관측 상태', 'contentState', { choices: [{ value: 'all', label: '모든 관측 상태' }, ...Object.entries(observationLabels).map(([value, label]) => ({ value, label }))] });
    const focus = field('확인할 자산', 'attention', { choices: [{ value: 'all', label: '모든 자산' }, { value: 'attention', label: '조사 신호 있음' }, { value: 'unregistered', label: '미등록 자산' }] });
    toolbar.append(observed, focus); panel.append(toolbar);
    const scope = el('p', 'query-scope'), rows = el('div'), pages = el('div', 'pagination'); panel.append(scope, rows, pages);
    let page = 0;
    function draw() {
      const state = observed.querySelector('select').value, attention = focus.querySelector('select').value;
      const assets = list(data.assets).filter(item => (state === 'all' || observationState(item) === state) && (attention === 'all' || attention === 'attention' && list(item.attention).length > 0 || attention === 'unregistered' && item.registered === false));
      const start = page * 20, displayed = assets.slice(start, start + 20);
      scope.textContent = `반환된 자산 ${list(data.assets).length}개 중 조건 일치 ${assets.length}개 · ${displayed.length ? start + 1 : 0}–${start + displayed.length} 표시. 위 집계는 서버 검색 조건 기준입니다.`;
      rows.replaceChildren(table(['자산 / 등록·담당자', '공급자 / 모델', '내용 관측', '관측 / 검사 미완료', '최근 수신', '근거'], displayed.map(item => {
        const name = el('div'); name.append(el('strong', 'wrap', item.id || '미확인'), el('p', 'muted', `${item.registered === true ? '등록' : item.registered === false ? '미등록' : '등록 미확인'} · ${item.owner || '담당자 미지정'}`));
        const models = el('div'); models.append(el('p', 'wrap', list(item.providers).join(', ') || '공급자 미수집'), el('small', 'muted wrap', list(item.models).join(', ') || '모델 미수집'));
        const open = button(`근거 보기${list(item.attention).length ? ` · 신호 ${item.attention.length}` : ''}`, () => openAsset(item.id, filters.range), 'small'); if (!item.id) open.disabled = true;
        return [name, models, statusPill(observationState(item), observationLabels), `${count(item.observationCount)} / ${count(item.screeningIncomplete)}`, item.lastSeen ? date(item.lastSeen) : '수신 없음', open];
      })));
      const previous = button('← 이전 자산', () => { page--; draw(); }, 'small'); previous.disabled = page === 0;
      const next = button('다음 자산 →', () => { page++; draw(); }, 'small'); next.disabled = start + displayed.length >= assets.length;
      pages.replaceChildren(previous, el('span', 'muted', `${page + 1}페이지`), next);
    }
    toolbar.addEventListener('change', () => { page = 0; draw(); }); draw(); root.append(panel);
    const lower = el('div', 'grid two'); lower.append(languageCard(data.languageSignals), screeningCard(data.screening));
    root.append(lower, modelStatusCard(data.modelRuntime, true), limits(data.limitations)); return root;
  }
  async function modelRuntimeView() {
    const data = await api('/api/model-runtime');
    const node = el('div'); node.append(modelStatusCard(data));
    const training = card('학습 데이터 준비 상태', '학습·검증·최종 평가를 분리합니다. 데이터 수는 모델 품질 검증 결과가 아닙니다.');
    training.append(statusPill(data.training?.state));
    const counts = el('div', 'training-counts');
    for (const [key, title] of [['tune', '학습'], ['validation', '검증'], ['test', '최종 평가']]) counts.append(numberFact(title, data.training?.counts?.[key], '검토 데이터'));
    training.append(counts, el('p', 'muted', '대시(—)는 실제 검토 데이터 수가 보고되지 않았다는 뜻입니다. 최소 필요량은 확보된 수와 다릅니다.'));
    if (data.training?.minimumReviewed) training.append(table(['분할', '최소 검토 필요량'], [['학습', count(data.training.minimumReviewed.tune)], ['검증', count(data.training.minimumReviewed.validation)], ['최종 평가', count(data.training.minimumReviewed.test)]]));
    training.append(jsonDetails('학습 준비·차단 사유 원문', data.training ?? { status: 'not_provided' }));
    node.append(training, jsonDetails('실행 정책과 검증 원문', data)); return node;
  }
  function updateNavigation(view) {
    if (document.body) document.body.dataset.workspaceView = view;
    const section = sections.find(item => item.routes.some(([route]) => route === view)) || sections[2];
    document.querySelectorAll('[data-section]').forEach(node => {
      const active = node.dataset.section === section.id; node.classList.toggle('active', active);
      if (active) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current');
    });
    const tabs = document.querySelector('#section-tabs');
    if (tabs) {
      tabs.replaceChildren();
      for (const [route, title] of section.routes) {
        const tab = button(title, () => navigate(route), 'section-tab');
        if (route === view) tab.setAttribute('aria-current', 'page'); tabs.append(tab);
      }
    }
    const context = document.querySelector('#section-context'); if (context) context.textContent = `${section.name} / 독립 감사 워크스페이스`;
    const host = document.querySelector('#workspace-filters'); if (!host) return;
    const searchable = ['visibility', 'agents', 'events', 'investigations'].includes(view);
    host.hidden = !searchable; host.replaceChildren(); if (!searchable) return;
    const values = core.getWorkspaceFilters(); const search = el('form', 'workspace-filter-bar');
    search.append(field('탭 간 이어지는 검색어', 'q', { value: values.q, maxLength: 200, placeholder: '자산, 모델, 행동 또는 출처 검색' }));
    if (view === 'visibility') search.append(field('수신 기준 기간', 'range', { value: values.range, choices: Object.entries(rangeLabels).map(([value, label]) => ({ value, label })) }));
    const submit = el('button', 'primary', '조건 적용'); submit.type = 'submit'; search.append(submit);
    search.append(button('초기화', () => { core.setWorkspaceFilters({ q: '', range: '24h' }); return navigate(view); }, 'ghost'));
    search.addEventListener('submit', event => { event.preventDefault(); core.setWorkspaceFilters(Object.fromEntries(new FormData(search))); navigate(view); });
    host.append(search, el('p', 'filter-scope', view === 'visibility' ? '검색어·기간은 이 화면의 자산과 관측 집계에 적용됩니다.' : '검색어를 현재 탭의 검색 조건으로 이어갑니다. 기간·종류·검토 상태는 각 탭에서 선택합니다.'));
  }
  core.registerView('visibility', 'AI 사용 가시성', '로컬·사내망의 등록 자산, 관측 경로와 확인하지 못한 내용을 함께 조사합니다.', visibilityView);
  core.registerView('model-runtime', '모델·학습 상태', '격리된 감사 모델의 기본 정책, 실제 실행 확인과 학습 준비 상태를 확인합니다.', modelRuntimeView);
  window.EvidScopeConsole = Object.freeze({ updateNavigation, overviewPulse, observationState, modelStatusCard, languageCard, screeningCard, visibilitySummary, assetDetailNode });
  document.querySelector('.brand')?.addEventListener('click', event => { event.preventDefault(); navigate('overview'); });
  updateNavigation(core.getActiveView());
})();
