'use strict';

// The console home and the running-agents panel (docs/feature-guide.md). Values are rendered as text nodes only.
// "Active" means activity recorded in the window, not a heartbeat; "evidence present" is never "compliant".
(() => {
  const core = window.EvidScopeCore;
  if (!core) return;
  const { el, button, card, empty, table, limits, api, date, showDetail, navigate, label, jsonDetails } = core;
  const openList = (view, preset) => (core.openList ? core.openList(view, preset) : navigate(view));
  const windows = [['5m', '5분'], ['15m', '15분'], ['1h', '1시간'], ['24h', '24시간']];
  const periods = [['7d', '최근 7일'], ['30d', '최근 30일'], ['90d', '최근 90일']];
  const severities = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  const stateLabels = { draft: '초안', discovered: '발견됨', testing: '시험', approved: '승인', production: '운영', suspended: '정지(중단)',
    retired: '폐기', not_registered: '미등록' };
  const flagLabels = { not_registered: '미등록 에이전트', active_after_stop_order: '정지 명령 이후 활동', active_while_suspended: '정지 상태에서 활동',
    active_after_retirement: '폐기 후 활동' };
  const propagationLabels = { overdue: '전파 기한 초과', activated_late: '늦게 적용', pending: '전파 대기', no_enforcement_point: '집행 지점 없음' };
  const frameworkLabels = { 'kr-ai-basic-act': 'AI 기본법', 'isms-p': 'ISMS-P', 'eu-ai-act-logging': 'EU AI Act' };
  const count = value => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString('ko-KR') : '—';
  const list = value => Array.isArray(value) ? value : [];
  let agentWindow = '15m', homePeriod = '7d';

  function ago(value) {
    const ms = Date.now() - Date.parse(value);
    if (!Number.isFinite(ms)) return '시각 미확인';
    if (ms < 60000) return '방금 전';
    if (ms < 3600000) return `${Math.floor(ms / 60000)}분 전`;
    if (ms < 86400000) return `${Math.floor(ms / 3600000)}시간 전`;
    return `${Math.floor(ms / 86400000)}일 전`;
  }
  function remaining(seconds) {
    if (!Number.isFinite(seconds)) return '—';
    return seconds < 60 ? `${seconds}초 남음` : seconds < 3600 ? `${Math.floor(seconds / 60)}분 남음` : `${Math.floor(seconds / 3600)}시간 남음`;
  }
  // The last time this browser showed the home to this tenant and principal; storage may be unavailable, which is fine.
  const VISIT_KEY = 'evidscope.home.lastVisit';
  function lastVisit() { try { return JSON.parse(window.localStorage.getItem(VISIT_KEY) || 'null'); } catch { return null; } }
  function rememberVisit(key, at) { try { window.localStorage.setItem(VISIT_KEY, JSON.stringify({ key, at })); } catch { /* not kept */ } }

  function countLink(title, value, note, onClick, tone = '') {
    const item = button('', onClick, `home-count ${tone}`.trim());
    item.append(el('strong', 'data-number', count(value)), el('span', '', title));
    if (note) item.append(el('small', 'muted', note));
    return item;
  }
  function unavailable(part) {
    return el('p', 'message warning', `확인할 수 없음: ${part?.reason || '응답 없음'}. 확인할 수 없는 항목을 0으로 보지 마세요.`);
  }
  function agentStrip(agents, onOpen) {
    const panel = card('지금 활동 중인 에이전트', agents?.definition || '선택한 기간 안에 기록이 수신된 에이전트입니다.');
    panel.classList.add('home-agents');
    if (agents?.status !== 'ok') { panel.append(unavailable(agents)); return panel; }
    const s = agents.summary || {}, row = el('div', 'home-count-row');
    row.append(countLink('최근 15분 활동', s.active, '등록·미등록 포함', onOpen),
      countLink('미등록', s.unregistered, '레지스트리에 없음', onOpen, s.unregistered ? 'warn' : ''),
      countLink('정지·중단 중 활동', s.flagged, '정지 명령·정지·폐기 후 기록', onOpen, s.flagged ? 'alert' : ''),
      countLink('기록 없는 운영 에이전트', s.quietRegistered, '최근 15분 수신 없음', onOpen));
    panel.append(row, button('실행 중 에이전트 패널 열기 →', onOpen, 'small'));
    return panel;
  }

  function threatsColumn(threats, since) {
    const column = card('위협', '열린 발견, 지켜지지 않은 정지 명령과 무결성 경보입니다. 경보는 조사 출발점이며 악의를 확정하지 않습니다.');
    const f = threats?.findings;
    if (f?.status === 'ok') {
      const row = el('div', 'home-count-row');
      for (const severity of severities) {
        if (!f.bySeverity?.[severity] && !['critical', 'high', 'medium'].includes(severity)) continue;
        row.append(countLink(`${label(severity)} 발견`, f.bySeverity?.[severity] || 0, '열린 신호',
          () => openList('alerts', { severity: severity === 'unknown' ? '' : severity, state: 'open', range: 'all' }),
          ['critical', 'high'].includes(severity) && f.bySeverity?.[severity] ? 'alert' : ''));
      }
      column.append(row);
      column.append(el('p', 'muted', f.newSince ? `마지막 방문(${date(since)}) 이후 새 발견 ${count(f.newSince.count)}건 · 전체 열린 발견 ${count(f.open)}건`
        : `열린 발견 ${count(f.open)}건 (첫 방문이라 새 발견 수는 다음 방문부터 표시)`));
    } else column.append(unavailable(f));
    const stops = threats?.stopOrders;
    if (stops?.status === 'ok') {
      const row = el('div', 'home-count-row');
      row.append(countLink('전파 안 된 정지 명령', list(stops.notPropagated).length, `활성 정지 명령 ${count(stops.active)}건 중`,
        () => navigate('registry'), list(stops.notPropagated).length ? 'alert' : ''),
      countLink('지켜지지 않은 정지 명령', list(stops.notHeld).length, '명령 이후 그 에이전트의 기록', () => navigate('registry'),
        list(stops.notHeld).length ? 'alert' : ''));
      column.append(row);
      for (const o of list(stops.notPropagated).slice(0, 3)) {
        column.append(el('p', 'muted wrap', `${o.agentId} · ${propagationLabels[o.propagation] || o.propagation} · 발령 ${date(o.issuedAt)}`));
      }
    } else column.append(unavailable(stops));
    const integrity = threats?.integrity;
    if (integrity?.status === 'ok') {
      const t = integrity.transparency;
      const alarms = [...(integrity.quarantine ? [`투명성 격리: ${integrity.quarantine}`] : []), ...list(integrity.faults).map(x => `조회 사본 불일치: ${x}`),
        ...list(t?.violations).map(v => `원장 ${v.kind === 'rollback' ? '되돌리기' : v.kind}: ${v.message}`)];
      const row = el('div', 'home-count-row');
      row.append(countLink('무결성·변조 경보', alarms.length, alarms.length ? alarms.slice(0, 2).join(' · ') : '서명 원장과 조회 사본 일치',
        () => navigate('health'), alarms.length ? 'alert' : 'ok'));
      column.append(row);
      // Without a transparency pin the vault cannot tell that its ledger was replaced by an older copy.
      if (t && t.mode === 'off') column.append(el('p', 'message warning', '원장 되돌리기(과거 사본으로 교체)·잘라내기는 검사하지 않습니다: 투명성 설정이 꺼져 있습니다. '
        + 'EvidScope를 멈추고 `node scripts/upgrade-local.mjs --transparency`를 한 번 실행하면 로컬 pin으로 검사합니다.'));
    } else column.append(unavailable(integrity));
    return column;
  }

  function reviewColumn(review, viewer) {
    const column = card('검토 필요', viewer?.mayDecide ? '내가 처리할 수 있는 항목을 함께 셉니다. 4-eyes 규칙으로 직접 만든 요청에는 답할 수 없습니다.'
      : '조회 전용 계정입니다. 답변·승인은 검토자·관리자가 합니다.');
    const row = el('div', 'home-count-row'), a = review?.approvals, c = review?.cases, r = review?.registryChanges, g = review?.governance;
    if (a?.status === 'ok') {
      const soonest = list(a.soonest)[0];
      row.append(countLink('승인 대기', a.pending, soonest ? `가장 빠른 만료 ${remaining(soonest.remainingSeconds)} · 내가 답할 수 있음 ${count(a.mayAnswer)}`
        : '대기 없음', () => navigate('approvals'), a.pending ? 'warn' : ''));
    }
    if (c?.status === 'ok') {
      row.append(countLink('검토 중인 사건', (c.open || 0) + (c.inReview || 0), `진행 전 ${count(c.open)} · 검토 중 ${count(c.inReview)}`,
        () => openList('cases', { status: 'active', range: 'all' })));
    }
    if (r?.status === 'ok') {
      row.append(countLink('두 번째 승인자 대기', r.pendingTransitions + r.pendingStopLifts,
        `레지스트리 전이 ${count(r.pendingTransitions)} · 정지 해제 ${count(r.pendingStopLifts)} · 내가 결정 가능 ${count(r.mayDecide + r.mayDecideLifts)}`,
        () => navigate('registry')));
    }
    if (g?.status === 'ok') {
      row.append(countLink('거버넌스 과제·법률 검토', g.openTasks + g.pendingLegalReviews, `열린 과제 ${count(g.openTasks)} · 법률 검토 대기 ${count(g.pendingLegalReviews)}`,
        () => navigate('governance')));
    }
    column.append(row);
    for (const part of [a, c, r, g]) if (part && part.status !== 'ok') column.append(unavailable(part));
    if (a?.status === 'ok' && list(a.soonest).length) {
      column.append(table(['승인 요청', '대상', '남은 시간', '내가 답할 수 있음'], list(a.soonest).map(v => [v.id, `${v.actor || '—'} → ${v.tool || v.action || '—'}`,
        remaining(v.remainingSeconds), v.mayAnswer ? '예' : '아니오'])));
    }
    return column;
  }

  function packCommand(gov, framework) {
    const pack = gov.pack || {};
    return [`${pack.command || 'node scripts/evidence-pack.mjs build'} --framework ${framework} --tenant ${pack.tenant}`,
      '  --api https://<볼트 주소> --token-file <감사자 토큰 파일> --key <볼트 공개키.pem>',
      `  --from ${pack.from} --to ${pack.to} --signing-key <작성자 서명키.pem> --out evidence-pack-${framework}.tar.gz`].join(' \\\n');
  }
  function governanceColumn(gov, onPeriod) {
    const column = card('거버넌스 지원', '프레임워크 항목별로 선택 기간에 매핑된 증거 기록이 있는지 셉니다. “증거 있음”은 준수 판정이 아닙니다.');
    const choices = el('div', 'home-period');
    for (const [id, text] of periods) {
      const choice = button(text, () => onPeriod(id), 'small'); choice.setAttribute('aria-pressed', String(homePeriod === id)); choices.append(choice);
    }
    column.append(choices);
    if (gov?.status !== 'ok') { column.append(unavailable(gov)); return column; }
    for (const f of list(gov.frameworks)) {
      const block = el('div', 'home-framework');
      block.append(el('strong', '', frameworkLabels[f.id] || f.title), el('span', 'muted wrap', f.title));
      const bar = el('div', 'home-bar'), total = Math.max(1, f.items);
      for (const [key, tone] of [['evidencePresent', 'present'], ['noEvidence', 'none'], ['notCountedHere', 'other']]) {
        const part = el('span', `home-bar-part ${tone}`); part.style.width = `${(f[key] / total) * 100}%`; bar.append(part);
      }
      const tally = `증거 있음 ${count(f.evidencePresent)} · 기록 없음 ${count(f.noEvidence)} · 여기서 세지 않음 ${count(f.notCountedHere)}`;
      block.append(bar, el('p', 'muted', `${tally} / ${count(f.items)}개 항목`));
      const actions = el('div', 'actions');
      actions.append(button('항목 보기', () => showDetail(`${frameworkLabels[f.id] || f.title} · 항목별 증거`, frameworkDetail(f, gov)), 'small'),
        button('감사 패키지 만들기', () => showDetail('감사 패키지 만들기', packDetail(gov, f.id)), 'small primary'));
      block.append(actions); column.append(block);
    }
    const span = `${gov.period?.from ? date(gov.period.from) : ''} — ${gov.period?.to ? date(gov.period.to) : ''}`;
    column.append(el('p', 'muted', `${span} · 서명 기록 ${count(gov.recordsInPeriod)}건 · 집계 ${date(gov.computedAt)}`),
      el('p', 'muted', gov.notice || ''));
    return column;
  }
  function frameworkDetail(f, gov) {
    const labels = { evidence_present: '증거 있음', no_evidence_recorded: '기록 없음', not_counted_here: '여기서 세지 않음' };
    const node = el('div');
    const rows = list(f.list).map(i => [i.title, i.citation, labels[i.status] || i.status]);
    node.append(el('p', 'muted', gov.notice || ''), table(['항목', '근거 조문', '선택 기간'], rows));
    return node;
  }
  function packDetail(gov, framework) {
    const node = el('div');
    node.append(el('p', '', '감사 패키지는 작성자 서명키로 서명하므로 콘솔이 아니라 키를 가진 운영자가 CLI로 만듭니다. 이 기간과 테넌트로 채운 명령입니다.'),
      el('pre', 'json', packCommand(gov, framework)),
      el('p', 'muted', '패키지는 서명된 내보내기와 매핑을 함께 담고 evidscope-verify pack으로 오프라인 검증됩니다(docs/evidence-pack.md). 요구사항 충족 판정은 담지 않습니다.'));
    return node;
  }
  function modelLine(m) {
    const node = card('감사용 AI 모델', '검토실이 쓰는 모델과 학습 여부입니다. 승격은 자동으로 일어나지 않습니다.');
    node.classList.add('home-model');
    if (m?.status !== 'ok') { node.append(unavailable(m)); return node; }
    const run = m.latestRun;
    node.append(core.factList([
      ['모델', `${m.reviewModel} · rev ${String(m.revision || '').slice(0, 12)} · ${m.quantization}`],
      ['미세조정', m.fineTuning === 'none_base_model_as_published' ? '없음 — 공개된 기본 모델 그대로' : '역할에 adapter 연결됨'],
      ['실행', m.runtimeEnabled ? '기본 활성' : `기본 비활성 · 관측 ${m.observationStatus === 'observed' ? '수신' : '확인 불가'}`],
      ['학습 기록', run ? `${m.trainingRuns}건 · 최근 ${run.id}: ${count(run.passed)}/${count(run.items)}`
        + ` (항상 판단 보류 기준 ${count(run.alwaysAbstainReference)}/${count(run.items)}) · ${run.promoted ? '승격됨' : '승격 안 됨'}` : '학습 기록 없음'],
      ['평가 상태', list(m.evalStatuses).join(', ') || '—'],
      ...(m.upgradePending ? [['프로필', `이전 기본 프로필 ${m.upgradePending}개가 검토실을 열 때 승인 모델로 자동 갱신됩니다`]] : []),
    ]));
    node.append(button('모델 현황 자세히 →', () => navigate('assistance-model'), 'small'));
    return node;
  }

  async function render() {
    const root = el('div', 'home');
    const visit = lastVisit(), since = visit?.at || null;
    const data = await api('/api/home' + (since ? '?' + new URLSearchParams({ since }) : ''));
    const key = `${data.tenant}/${data.viewer?.id}`, sameViewer = visit?.key === key;
    if (data.threats?.findings?.newSince && !sameViewer) data.threats.findings.newSince = null;
    rememberVisit(key, data.generatedAt);
    root.append(el('p', 'home-viewer muted', `${data.viewer?.id} · ${data.tenant} · ${data.viewer?.role} · ${date(data.generatedAt)} 기준`));
    root.append(agentStrip(data.agents, () => navigate('agents-now')));
    const columns = el('div', 'home-columns');
    // The governance column reads the period's ledger range; it is filled after the rest of the home is shown.
    const slot = card('거버넌스 지원', '선택 기간의 증거 기록을 세고 있습니다…');
    columns.append(threatsColumn(data.threats, since), reviewColumn(data.review, data.viewer), slot);
    root.append(columns, modelLine(data.model));
    const epoch = core.getRenderEpoch(), onPeriod = id => { homePeriod = id; navigate('home'); };
    const filled = api('/api/home/governance?' + new URLSearchParams({ period: homePeriod }))
      .then(gov => governanceColumn(gov, onPeriod), error => governanceColumn({ status: 'unavailable', reason: error.message }, onPeriod))
      .then(column => { if (core.getRenderEpoch() === epoch) slot.replaceWith ? slot.replaceWith(column) : columns.children.splice(2, 1, column); });
    root.governanceReady = filled;
    return root;
  }

  function agentRow(item) {
    const name = el('div');
    name.append(el('strong', 'wrap', item.name || item.actor || item.source || '이름 미수집'));
    const marks = el('div', 'actions');
    marks.append(el('span', `badge ${item.registered ? 'registered' : 'unregistered'}`, item.registered ? stateLabels[item.state] || item.state : '미등록'));
    for (const flag of item.flags.filter(f => f !== 'not_registered')) marks.append(el('span', 'badge alert-flag', flagLabels[flag] || flag));
    name.append(marks, el('small', 'muted wrap', item.registered ? `레지스트리 ${item.registryId}` : `출처 ${item.source || '도구 기록'} · 행위자 ${item.actor || '미수집'}`));
    const last = el('div'); last.append(el('strong', '', ago(item.lastActivity)), el('small', 'muted', ` · ${date(item.lastActivity)}`));
    const denies = item.counts.denies ? ` (거부 ${item.counts.denies})` : '';
    const counts = `기록 ${count(item.counts.events)} · 행동 ${count(item.counts.actions)} · 결정 ${count(item.counts.decisions)}${denies}`;
    const findings = item.openFindings == null ? '확인 불가' : item.openFindings.total
      ? Object.entries(item.openFindings.bySeverity).map(([k, v]) => `${label(k)} ${v}`).join(' · ') : '없음';
    const open = item.registered ? button('레지스트리', () => navigate('registry'), 'small') : button('등록 후보 보기', () => navigate('registry'), 'small');
    return [name, last, counts, findings, item.stopOrders.active ? `활성 ${item.stopOrders.active}` : '없음',
      item.pendingApprovals == null ? '확인 불가' : item.pendingApprovals ? `${item.pendingApprovals}건` : '없음', open];
  }
  async function renderAgents() {
    const root = el('div', 'agents-now'), epoch = core.getRenderEpoch();
    const panel = card('지금 활동 중인 에이전트', '활동 = 선택한 기간 안에 기록이 수신됨. 생존 신호(heartbeat)가 아닙니다.');
    const controls = el('div', 'home-period'), focus = el('div', 'home-period'), body = el('div'), status = el('p', 'muted');
    let filter = 'all', data = null;
    const filters = [['all', '전체'], ['unregistered', '미등록'], ['flagged', '정지·중단 중 활동'], ['findings', '열린 발견'], ['approvals', '승인 대기']];
    const tests = { unregistered: item => !item.registered, flagged: item => item.flags.some(f => f !== 'not_registered'),
      findings: item => item.openFindings?.total > 0, approvals: item => item.pendingApprovals > 0 };
    const matches = item => filter === 'all' || tests[filter](item);
    function draw() {
      if (!data) return;
      focus.replaceChildren(...filters.map(([id, text]) => {
        const b = button(text, () => { filter = id; draw(); }, 'small'); b.setAttribute('aria-pressed', String(filter === id)); return b;
      }));
      const items = data.items.filter(matches);
      const s = data.summary;
      status.textContent = `${date(data.window.since)} — ${date(data.window.until)} 수신 기준`
        + ` · 활동 ${count(s.active)} (등록 ${count(s.registered)} · 미등록 ${count(s.unregistered)})`
        + ` · 에이전트에 붙지 않은 기록 ${count(s.unattributedEvents)}건${data.scanned?.truncated ? ' · 기록이 많아 최신 기록만 셈(하한)' : ''}`;
      body.replaceChildren(items.length ? table(['에이전트', '마지막 활동', '기간 내 기록', '열린 발견', '정지 명령', '승인 대기', ''], items.map(agentRow))
        : empty('이 조건의 활동이 없습니다', '기록이 없다는 것은 멈췄다는 뜻이 아닙니다. 기간을 넓히거나 수집 상태를 확인하세요.'));
      if (data.quiet?.length) {
        body.append(el('h3', '', '기간 안에 기록이 없는 운영·승인 상태 등록 에이전트'),
          table(['에이전트', '상태', '출처 자격의 마지막 수신', '정지 명령'], data.quiet.map(q => [q.name || q.registryId, stateLabels[q.state] || q.state,
            q.lastSourceActivity ? `${ago(q.lastSourceActivity)} · ${date(q.lastSourceActivity)}` : '출처 기록 없음',
            q.activeStopOrders ? `활성 ${q.activeStopOrders}` : '없음'])));
      }
      body.append(limits(data.limitations));
    }
    async function load() {
      controls.replaceChildren(...windows.map(([id, text]) => {
        const b = button(`최근 ${text}`, () => { agentWindow = id; load(); }, 'small'); b.setAttribute('aria-pressed', String(agentWindow === id)); return b;
      }));
      try { data = await api('/api/home/agents?' + new URLSearchParams({ window: agentWindow })); draw(); }
      catch (error) { body.replaceChildren(empty('활동 중인 에이전트를 불러오지 못했습니다', error.message)); }
    }
    panel.append(el('p', 'agent-definition', '등록된 에이전트와 미등록 행위자를 함께 보여 줍니다. 30초마다 새로 조회합니다.'), controls, focus, status, body);
    root.append(panel);
    await load();
    const timer = setInterval(() => { if (core.getRenderEpoch() !== epoch || !core.getToken()) { clearInterval(timer); return; } load(); }, 30000);
    return root;
  }

  // The review model, its roles, adapters, evaluation status and the training runs EvidScope can see (src/model-status.mjs).
  async function modelPanel() {
    const data = await api('/api/model-status'), root = el('div', 'model-status');
    const head = card('모델 현황', '검토실 역할이 쓰는 모델과 학습 여부입니다. 이 화면은 모델을 시작하거나 학습·승격하지 않습니다.');
    head.append(core.factList([
      ['검토 모델', `${data.reviewModel.model} (${data.reviewModel.provider})`],
      ['고정 revision', `${data.reviewModel.artifactRepository || '—'} @ ${data.reviewModel.revision} · ${data.reviewModel.quantization}`],
      ['분류 모델', `${data.classifier.model} · revision ${data.classifier.revision || '미고정'}`],
      ['이 볼트의 실행', data.runtime.enabledByDefault ? '기본 활성' : `기본 비활성 · 실행 관측 ${data.runtime.observationStatus === 'observed' ? '수신' : '확인 불가'}`],
      ['미세조정(adapter)', data.fineTuning.attached ? `연결됨: ${data.fineTuning.roles.join(', ')}` : '없음 — 공개된 기본 모델을 그대로 씁니다'],
      ['승격', '자동 승격 없음 — 사람의 승인과 비교 평가 보고서가 있어야 바뀝니다'],
    ]));
    const roles = card('역할별 모델', '역할 패키지의 adapter·평가 상태와 테넌트에 서명된 프로필 버전입니다.');
    roles.append(table(['역할', '프로필', '모델', 'adapter', '평가 상태'], data.roles.map(r => [r.id, `v${r.profileVersion}`,
      r.upgradePending ? `${r.model} → ${r.upgradeTo}` : r.model, r.adapter === 'none' ? '없음' : r.adapter, r.evalStatus])));
    const pendingRoles = data.roles.filter(r => r.upgradePending);
    if (pendingRoles.length) {
      roles.append(el('p', 'muted wrap', `이전 기본값 ${pendingRoles[0].model} → ${pendingRoles[0].upgradeTo} 자동 갱신 예정: `
        + `v${pendingRoles[0].profileVersion} 프로필은 처음 배포된 기본값입니다. 검토실을 열 때 승인 모델로 새 버전이 서명되며, 실행은 승인 모델만 허용합니다.`));
    }
    const training = card('학습 기록', data.training.repository.notice || '저장소에 기록된 학습 실행입니다.');
    const runs = data.training.repository.runs;
    if (!runs.length) training.append(empty('학습 기록 없음', `학습은 CLI로 실행합니다: ${data.training.howTo}`));
    else {
      // One fact list per run: the values are long (model, dataset) and a wide table would cut them.
      for (const r of runs) {
        const score = r.evaluation ? `${count(r.evaluation.passed)}/${count(r.evaluation.items)} · adapter 끔 ${count(r.evaluation.baselineAdapterOff)}`
          + ` · 항상 판단 보류 기준 ${count(r.evaluation.alwaysAbstainReference)}` : '평가 없음';
        training.append(el('h3', 'wrap', `${r.id}${r.finishedOn ? ` (${r.finishedOn})` : ''}`), core.factList([
          ['베이스 모델', `${r.baseModel} @ ${String(r.baseRevision || '').slice(0, 12)}`], ['데이터', r.dataset], ['평가', score],
          ['승격 / 런타임 연결', `${r.promoted ? '승격됨' : '승격 안 됨'} · ${r.attachedToRuntime ? '연결됨' : '연결 안 됨'}`]]));
      }
      for (const r of runs) if (r.runtimeNote) training.append(el('p', 'muted wrap', r.runtimeNote));
      training.append(el('p', 'muted', `저장소 학습 기록은 서명되지 않은 요약입니다. 학습 실행: ${data.training.howTo}`));
    }
    root.append(head, roles, training, factsheetCard(data.factsheets), limits(data.limitations), jsonDetails('모델 현황 원문', data));
    return root;
  }

  // Signed factsheets of the governance-mapping model (src/governance-factsheets.mjs): one fact list per training, evaluation or
  // promotion run. A shakedown is labelled as such and shows resource numbers only.
  const factKinds = { training: '학습 실행', evaluation: '평가 실행', promotion: '승격' };
  const pct = v => typeof v === 'number' && Number.isFinite(v) ? `${(v * 100).toFixed(1)}%` : '—';
  const hash = v => typeof v === 'string' ? `${v.slice(0, 12)}…` : '—';
  function factsheetMetrics(f) {
    const m = f.metrics || {};
    if (f.kind === 'training') {
      const resource = `GPU 최대 ${m.cudaPeakAllocatedMiB ?? '—'} MiB · 학습 ${m.trainSeconds ?? m.train_runtime ?? '—'}초`
        + ` · 전체 ${m.totalSeconds ?? '—'}초 · step ${m.globalStep ?? '—'}`;
      return f.runMode === 'shakedown' ? `${resource} (자원 측정만)` : `${resource} · 학습 손실 ${m.train_loss ?? '—'} (품질 지표 아님)`;
    }
    const c = m.candidate || m.retrieval_constrained;
    return c ? `${m.candidate ? '후보' : '기본 모델(검색·제약)'} 정밀도 ${pct(c.precision)} · 재현율 ${pct(c.recall)} · ECE ${c.ece ?? '—'}`
      : f.label === 'shakedown' ? '셰이크다운 어댑터: 수치 표시 안 함' : '—';
  }
  function factsheetCard(factsheets) {
    const panel = card('서명된 팩트시트', '거버넌스 매핑 모델의 학습·평가·승격 실행마다 볼트 원장에 서명된 기록입니다. 기록자는 로그인한 사람입니다.');
    if (!factsheets || factsheets.status !== 'ok') {
      panel.append(empty('팩트시트를 확인하지 못했습니다', factsheets?.reason || '응답에 팩트시트 목록이 없습니다.')); return panel;
    }
    if (!factsheets.items.length) {
      panel.append(empty('기록된 팩트시트 없음', '학습·평가를 마친 뒤 governance-mapping.mjs factsheet로 요청을 만들고 실험 비교 화면에서 기록합니다.'));
      return panel;
    }
    for (const f of factsheets.items) {
      const d = f.dataset || {};
      panel.append(el('h3', 'wrap', `${factKinds[f.kind] || f.kind} · ${f.label === 'shakedown' ? '셰이크다운 — 승격 불가, 품질 결과 아님' : f.label}`),
        core.factList([['기록', `${date(f.recordedAt)} · ${f.operator?.id ?? '—'} (${f.operator?.role ?? '—'})`],
          ['기본 모델', `${f.baseModel?.repository ?? '—'} @ ${hash(f.baseModel?.revision)} · GGUF ${hash(f.baseModel?.ggufSha256)}`
            + (f.baseModel?.training ? ` · 학습 기반 ${hash(f.baseModel.training.revision)} (잠금 ${hash(f.baseModel.training.artifactLockSha256)})` : '')],
          ['데이터', `${hash(d.sha256)} · ${d.rows ?? '—'}행 · 사람 검토 ${d.humanReviewedRows ?? '—'}행`
            + ` (서명된 검토 결정 ${d.withSignedQueueDecision ?? '—'}) · ${d.verification ?? '—'}`],
          ['레시피', f.recipe ? `rank ${f.recipe.rank} · alpha ${f.recipe.alpha} · epoch ${f.recipe.epochs} · 길이 ${f.recipe.sequenceLength}` : '—'],
          ['수치', factsheetMetrics(f)], ['어댑터', hash(f.adapter?.ggufSha256)],
          ['게이트 / 승인', `${f.gate ? (f.gate.eligible ? '통과' : '불통과') : '—'} · `
            + (f.approver ? `승인 ${f.approver.reviewerId} (${date(f.approver.reviewedAt)})` : '승인 없음')],
          ['승격 경로', f.promoted ? '승격됨(서명 영수증 확인)' : f.promotable ? '게이트와 서명 승인을 거쳐야 함' : '승격 불가']]));
    }
    panel.append(jsonDetails('팩트시트 원문', factsheets.items));
    return panel;
  }

  core.registerView('home', '지금 확인할 일', '지금 활동 중인 에이전트, 위협, 사람의 검토가 필요한 항목과 거버넌스 증거 현황을 한 화면에서 확인합니다.', render);
  core.registerView('agents-now', '실행 중 에이전트', '최근 기간에 기록이 수신된 에이전트입니다. 활동은 수신된 기록이며 생존 신호가 아닙니다.', renderAgents);
  core.registerView('assistance-model', '모델 현황', '검토실이 쓰는 모델, 미세조정 여부, 역할별 평가 상태와 학습 기록을 확인합니다.', modelPanel);
  window.EvidScopeHome = Object.freeze({ render, renderAgents, modelPanel });
  if (core.getActiveView() === 'home' && core.getToken()) navigate('home');
})();
