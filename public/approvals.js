'use strict';

// Approval queue screen (docs/approval-queue.md): pending requests first with their remaining time, detail with the target,
// registry entry and risk tier, prior decisions for the same action and the signed history, and approve/refuse with a reason.
// Request content comes from gateways and is rendered only as text. The server decides who may answer; this screen shows it.
(() => {
  const core = window.EvidScopeCore;
  if (!core) return;
  const { el, button, card, empty, table, field, form, jsonDetails, limits, api, date, showDetail, navigate } = core;
  const stateLabels = { pending: '답변 대기', approved: '승인', refused: '거절', expired: '만료(거절)' };
  const stateClass = { pending: 'pending', approved: 'active', refused: 'denied', expired: 'denied' };
  const tierLabels = { low: '낮음', medium: '중간', high: '높음' };
  const list = value => Array.isArray(value) ? value : [];
  const REFRESH_MS = 15000;
  const pill = state => el('span', `badge ${stateClass[state] || 'unknown'}`, stateLabels[state] || '미확인');
  const targetText = target => ['actor', 'tool', 'action', 'resource', 'destination'].filter(k => target?.[k]).map(k => `${k}=${target[k]}`).join(' · ') || '—';
  const remaining = seconds => {
    const s = Math.max(0, Number(seconds) || 0);
    return s >= 3600 ? `${Math.floor(s / 3600)}시간 ${Math.floor(s % 3600 / 60)}분` : s >= 60 ? `${Math.floor(s / 60)}분 ${s % 60}초` : `${s}초`;
  };
  const progress = request => `${new Set(list(request.approvals).map(a => a.by)).size}/${request.eligibility?.approvers ?? '?'}`;

  function answerForms(request) {
    const node = el('div');
    if (request.state !== 'pending') {
      node.append(el('p', 'muted', `이 요청은 ${stateLabels[request.state] || request.state} 상태라 더 답할 수 없습니다.`));
      return node;
    }
    if (!request.mayAnswer?.allowed) {
      node.append(el('div', 'message warning', `답할 수 없습니다: ${request.mayAnswer?.reason || '권한 없음'}`));
      return node;
    }
    const box = card('답변', `요청 v${request.version} 기준으로 답합니다. 그 사이 요청이 바뀌면 서버가 거부(409)하니 다시 열어 확인하세요.`);
    for (const [operation, title] of [['approve', '승인'], ['refuse', '거절']]) {
      box.append(form([field(`${title} 사유`, 'reason', { required: true, multiline: true, maxLength: 1000 })], title, async (values, result) => {
        const answered = await api(`/api/approvals/${encodeURIComponent(request.id)}/${operation}`, 'POST', { reason: values.reason,
          version: request.version });
        result.append(el('div', 'message', answered.status === 'pending'
          ? `승인을 서명했습니다. 서로 다른 승인자 ${progress(answered)}명이 모였습니다.` : `${stateLabels[answered.status] || answered.status} 답을 서명했습니다.`));
        await openRequest(request.id); navigate('approvals');
      }));
    }
    node.append(box);
    return node;
  }
  function requestNode(data) {
    const request = data.request, eligibility = request.eligibility || {}, registry = data.registry, node = el('div');
    node.append(core.factList([
      ['상태', `${stateLabels[request.state] || request.state}${request.state === 'pending' ? ` · 남은 시간 ${remaining(request.remainingSeconds)}` : ''}`],
      ['요약(게이트웨이 제공)', request.bindingMessage], ['대상', targetText(request.target)], ['대상 digest', request.targetDigest],
      ['행동 / 추적', `${request.actionId} / ${request.traceId || '—'}`], ['정책 결정',
        `${request.decisionId} · ${request.policyId || '정책 id 없음'} ${request.policyVersion || ''}`],
      ['요청 출처 / 집행 지점', `${request.requestedBy} / ${request.enforcementPointId}`], ['요청 / 만료', `${date(request.requestedAt)} / ${date(request.expiresAt)}`],
      ['레지스트리 항목', registry ? `${registry.id} (${registry.state}, v${registry.version}) · 책임자 ${registry.owner || '—'}` : '등록되지 않은 행위자'],
      ['위험 등급', tierLabels[eligibility.tier] || eligibility.tier], ['필요한 승인', `서로 다른 ${eligibility.approvers}명 · 역할 ${list(eligibility.roles).join(', ')}`],
      ['답할 수 없는 사람', list(eligibility.excluded).join(', ') || '없음'], ['승인 진행', progress(request)],
      ['실행 창', request.executionWindow ? `${date(request.executionWindow.notBefore)} ~ ${date(request.executionWindow.notAfter)}` : '—'],
    ]));
    node.append(answerForms(request));
    node.append(el('h3', '', '같은 행동의 다른 승인 요청'), list(data.otherRequests).length
      ? table(['요청', '상태', '대상', '결정 시각'], list(data.otherRequests).map(o => [o.id, pill(o.state), targetText(o.target), date(o.decidedAt)]))
      : el('p', 'muted', '없음'));
    node.append(el('h3', '', '같은 행동의 정책 결정 기록'), list(data.decisions).length
      ? table(['결정', '결정 id', '엔진 / 정책', '시각', '출처'], list(data.decisions).map(d => [d.decision || d.kind, d.decisionId || '—',
        `${d.engine || '—'} / ${d.policyId || '—'}`, date(d.occurredAt), `${d.source}/${d.id}`]))
      : el('p', 'muted', '수집된 결정 기록이 없습니다.'));
    node.append(el('h3', '', '서명된 버전 이력'), table(['원장 seq', '버전', '변경', '상태', '기록 주체', '기록 시각'],
      list(data.history).map(v => [String(v.seq), String(v.version), v.change || '—', pill(v.status), v.principal || '—', date(v.recordedAt)])));
    node.append(jsonDetails('승인 요청 원문', request));
    return node;
  }
  async function openRequest(id) {
    showDetail('승인 요청', el('div', 'loading', '승인 요청과 이력을 조회하고 있습니다…'));
    const context = core.captureDetailContext();
    try {
      const data = await api(`/api/approvals/${encodeURIComponent(id)}`);
      if (!core.isCurrentDetail(context)) return;
      showDetail(`승인 요청 · ${data.request.bindingMessage || data.request.id}`, requestNode(data));
    } catch (error) { if (core.isCurrentDetail(context)) showDetail('승인 요청 조회 실패', empty('승인 요청을 불러오지 못했습니다', error.message)); }
  }
  function pendingTable(data) {
    const pending = list(data.pending);
    if (!pending.length) return empty('답을 기다리는 요청이 없습니다', '게이트웨이가 승인을 요구하면 여기에 남은 시간과 함께 나타납니다.');
    return table(['남은 시간', '요약', '대상', '위험 등급', '승인', '요청 출처', '상세'], pending.map(r => [remaining(r.remainingSeconds), r.bindingMessage,
      targetText(r.target), tierLabels[r.eligibility?.tier] || '미확인', progress(r), r.requestedBy, button('열기', () => openRequest(r.id), 'ghost')]));
  }
  async function approvalsView() {
    const data = await api('/api/approvals'), policy = data.policy || {}, node = el('div');
    const head = card('승인 대기열', `정책 v${policy.version}${policy.source === 'built_in_default' ? ' (기본값)' : ''} · 기본 유효 ${policy.defaultLifetimeSeconds}초`
      + ` · 최대 ${policy.maxLifetimeSeconds}초 · 실행 창 ${policy.executionWindowSeconds}초 · 폴링 간격 ${policy.intervalSeconds}초`);
    head.append(limits(data.limitations));
    node.append(head);
    const pendingCard = card('답변 대기', `${data.pendingTotal ?? 0}건 · 만료가 가까운 순서입니다. 만료되면 거절로 처리됩니다.`), slot = el('div');
    slot.append(pendingTable(data));pendingCard.append(slot);node.append(pendingCard);
    const recent = card('최근 결정', '승인·거절·만료된 요청(최근 100건)');
    recent.append(table(['결과', '요약', '대상', '결정 / 만료', '답변자', '상세'], list(data.recent).map(r => [pill(r.state), r.bindingMessage, targetText(r.target),
      date(r.decidedAt || r.expiresAt), [...list(r.approvals).map(a => a.by), ...(r.refusal ? [r.refusal.by] : [])].join(', ') || '—',
      button('열기', () => openRequest(r.id), 'ghost')])));
    node.append(recent);
    // The pending list refreshes in place while this screen stays open (polling; there is no push feed).
    const timer = window.setTimeout?.bind(window), epoch = core.getRenderEpoch?.();
    const refresh = async () => {
      if (core.getActiveView?.() !== 'approvals' || core.getRenderEpoch?.() !== epoch) return;
      try { const next = await api('/api/approvals'); slot.replaceChildren(pendingTable(next)); } catch { /* the next refresh or a manual one retries */ }
      timer(refresh, REFRESH_MS);
    };
    if (timer && epoch !== undefined) timer(refresh, REFRESH_MS);
    return node;
  }
  core.registerView('approvals', '승인 대기열', '게이트웨이가 사람 승인을 요구한 행동에 답합니다. 만료는 거절이며, 실행은 서명된 답을 검증한 게이트웨이가 결정합니다.', approvalsView);
  window.EvidScopeApprovals = Object.freeze({ approvalsView, openRequest, requestNode, remaining });
})();
