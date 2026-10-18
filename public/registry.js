'use strict';

// Agent registry screen (docs/agent-registry.md): list, detail with version and transition history, transition requests,
// approvals and refusals, catalog import with its report and per-entry provenance, auto-registration, and executors and owners
// (unknown, inferred from the owner map, or confirmed by a reviewer). Registry content is untrusted data and is
// rendered only as text. The server enforces roles, four-eyes and gates; this screen shows what it answered. EvidScope blocks nothing.
(() => {
  const core = window.EvidScopeCore;
  if (!core) return;
  const { el, button, card, empty, table, field, form, jsonDetails, limits, api, date, showDetail, navigate } = core;
  const stateLabels = { discovered: '발견됨', draft: '초안', testing: '시험', approved: '승인', production: '운영', suspended: '정지', retired: '폐기' };
  const statusLabels = { pending: '승인 대기', applied: '적용', approved: '승인·적용', refused: '거절', superseded: '무효(이후 변경)' };
  const tierLabels = { low: '낮음', medium: '중간', high: '높음' };
  const orderLabels = { active: '활성', lifted: '해제됨', superseded: '대체됨' };
  const propagationLabels = { activated_in_window: '기한 내 활성화', activated_late: '기한 후 활성화', pending: '활성화 대기', overdue: '기한 초과·미활성화',
    no_enforcement_point: '담당 집행 지점 없음', ended_before_activation: '활성화 전 종료' };
  const evidenceTypes = ['event', 'asset', 'system', 'case', 'governance_document', 'external'];
  const outcomeLabels = { created: '새로 등록(발견됨)', updated: '새 버전', unchanged: '변경 없음', conflict: '충돌(덮어쓰지 않음)', skipped: '에이전트 아님',
    rejected: '거부' };
  const signatureLabels = { absent: '서명 없음', verified: '제출한 공개 키로 확인', unverified: '서명 있음·확인할 키 없음', invalid: '서명 불일치',
    unsupported: '지원하지 않는 서명', malformed: '서명 형식 오류', not_applicable: '해당 없음' };
  const formatLabels = { 'a2a-agent-card': 'A2A Agent Card', 'backstage-entity': 'Backstage 엔터티' };
  const ownerLabels = { unknown: '책임자 미확인', inferred: '추정', conflict: '추정 충돌', confirmed: '확정' };
  const basisLabels = { owner_map: '매핑 표', catalog_document: '카탈로그 문서', entered_at_registration: '등록 시 입력', entered_by_reviewer: '검토자 입력',
    reviewer: '검토자' };
  const fieldLabels = { account: 'OS 계정', host: 'PC', repository: '저장소', gitUser: 'git 사용자', actor: '행위자 이름', source: '출처 자격' };
  const list = value => Array.isArray(value) ? value : [];
  const text = value => String(value ?? '').trim();
  const words = value => String(value || '').split(/[,\n]/).map(item => item.trim()).filter(Boolean);
  const join = value => list(value).map(item => typeof item === 'object' && item ? item.name : String(item)).join(', ') || '—';
  const pill = (value, dictionary) => {
    const known = Object.hasOwn(dictionary, String(value));
    return el('span', `badge registry-${known ? value : 'unknown'}`, known ? dictionary[value] : '미확인');
  };

  // Who ran the agent, as the hook reported it: account@PC · repository · git user.
  const executorText = x => !x ? '실행자 미수집' : [x.account && x.host ? `${x.account}@${x.host}` : x.account || x.host, x.repository, x.gitUser]
    .filter(Boolean).join(' · ');
  const ownerText = o => {
    if (!o) return '—';
    if (o.status === 'conflict') return `추정 충돌: ${list(o.candidates).map(c => c.owner).join(', ')}`;
    if (!o.owner) return ownerLabels.unknown;
    return `${o.owner}${o.team ? ` (${o.team})` : ''}`;
  };
  const ownerCell = o => { const node = el('span'); node.append(pill(o?.status || 'unknown', ownerLabels), el('span', '', ` ${ownerText(o)}`)); return node; };
  // Evidence references as `type:ref` lines; unknown types are refused here and again by the server.
  function evidenceRefs(text) {
    return words(text).map(line => {
      const at = line.indexOf(':'), type = at > 0 ? line.slice(0, at) : '';
      if (!evidenceTypes.includes(type)) throw new Error(`증거 참조는 ${evidenceTypes.join('·')} 중 하나로 시작해야 합니다: ${line}`);
      return { type, ref: line.slice(at + 1).trim() };
    });
  }
  function gateNode(gate) {
    const node = el('div', 'registry-gate');
    if (!gate) return node;
    const met = list(gate.conditions).filter(c => c.met).length;
    node.append(el('p', 'muted', `위험 등급 ${tierLabels[gate.tier] || gate.tier} · 조건 ${met}/${list(gate.conditions).length} 충족 · 정책 v${gate.policyVersion}`
      + (gate.policySource === 'built_in_default' ? ' (기본값)' : '')));
    const items = el('ul', 'limitations');
    for (const c of list(gate.conditions)) items.append(el('li', '', `${c.met ? '충족' : '미충족'} · ${c.id} (${c.check}) ${JSON.stringify(c.detail || {})}`));
    if (list(gate.conditions).length) node.append(items); else node.append(el('p', 'muted', '이 전이에 지정된 게이트 조건이 없습니다.'));
    return node;
  }
  function transitionForms(data) {
    const node = el('div');
    const pending = list(data.transitions).find(t => t.status === 'pending');
    if (pending) {
      const box = card('승인 대기 전이', `${stateLabels[pending.from] || pending.from} → ${stateLabels[pending.to] || pending.to} · 요청 ${pending.requestedBy}`);
      box.append(el('p', 'wrap', `사유: ${pending.reason}`), gateNode(pending.gate),
        el('p', 'muted', '등록자, 마지막 구성 수정자, 요청자는 승인할 수 없습니다(4-eyes). 승인할 때 게이트를 다시 확인합니다.'));
      for (const [operation, title] of [['approve', '승인'], ['refuse', '거절']]) {
        box.append(form([field(`${title} 사유`, 'reason', { required: true, multiline: true, maxLength: 1000 })], title, async (values, result) => {
          await api(`/api/registry/transitions/${encodeURIComponent(pending.id)}/${operation}`, 'POST', { reason: values.reason });
          result.append(el('div', 'message', `${title} 기록을 서명했습니다.`)); await openEntry(data.entry.id); navigate('registry');
        }));
      }
      node.append(box);
    }
    const next = list(data.next);
    if (next.length) {
      const box = card('상태 전이 요청', '요청할 때 게이트 조건을 서명된 기록과 대조합니다. 승인이 필요 없는 전이는 바로 적용됩니다.');
      for (const option of next) {
        const row = el('div', 'registry-next');
        row.append(el('strong', '', `→ ${stateLabels[option.to] || option.to}${option.approvalRequired ? ' (다른 검토자 승인 필요)' : ''}`), gateNode(option.gate));
        box.append(row);
      }
      box.append(form([
        field('목표 상태', 'to', { choices: next.map(option => ({ value: option.to, label: stateLabels[option.to] || option.to })) }),
        field('사유', 'reason', { required: true, multiline: true, maxLength: 1000 }),
        field('증거 참조 (줄마다 유형:참조, 예: event:agent-1/e-1)', 'evidence', { multiline: true, wide: true, maxLength: 4000 }),
      ], '전이 요청', async (values, result) => {
        const response = await api(`/api/registry/${encodeURIComponent(data.entry.id)}/transitions`, 'POST',
          { to: values.to, reason: values.reason, evidence: evidenceRefs(values.evidence) });
        const status = response.transition?.status;
        result.append(el('div', 'message', status === 'pending' ? '승인 대기로 기록했습니다.' : '전이를 적용했습니다.'));
        await openEntry(data.entry.id); navigate('registry');
      }));
      node.append(box);
    }
    return node;
  }
  // Stop orders and their propagation (docs/kill-switch.md): one reviewer stops at once; a lift needs a second reviewer.
  function propagationTable(order) {
    return table(['집행 지점', '담당 근거', '상태', '첫 활성화', '지연(초)', '리비전', 'OPA 인스턴스'], list(order.points).map(point => [
      point.id, point.covering ? list(point.basis).join(', ') : '담당 아님(활성화만 보고)', propagationLabels[point.status] || '미확인',
      date(point.firstActivation?.activatedAt), point.firstActivation ? String(Math.round(point.firstActivation.latencyMs / 1000)) : '—',
      point.firstActivation?.revision || '—', list(point.instances).join(', ') || '—']));
  }
  function liftForms(order, entry) {
    const node = el('div');
    if (order.status !== 'active') {
      const lift = order.lift;
      node.append(el('p', 'muted', lift ? `해제: ${lift.via === 'transition' ? 'suspended→production 전이 승인' : '해제 승인'}`
        + ` · 요청 ${lift.requestedBy} · 승인 ${lift.approvedBy}`
        : order.supersededBy ? `대체: ${order.supersededBy.orderId} (${order.supersededBy.by})` : ''));
      return node;
    }
    if (order.scope === 'agent' && entry.state === 'suspended') {
      node.append(el('p', 'muted', '정지 상태 에이전트의 전체 정지는 suspended→production 전이를 다른 검토자가 승인할 때 해제됩니다.'));
      return node;
    }
    const post = async (path, body, message, result) => {
      await api(path, 'POST', body); result.append(el('div', 'message', message)); await openEntry(entry.id); navigate('registry');
    };
    const base = `/api/registry/stops/${encodeURIComponent(order.orderId)}/lift`;
    if (order.liftRequest) {
      node.append(el('p', 'wrap', `해제 요청: ${order.liftRequest.by} · ${order.liftRequest.reason}`),
        el('p', 'muted', '해제를 요청한 사람은 승인할 수 없습니다(4-eyes).'));
      for (const [operation, title] of [['approve', '해제 승인'], ['refuse', '해제 거절']]) {
        node.append(form([field(`${title} 사유`, 'reason', { required: true, multiline: true, maxLength: 1000 })], title,
          (values, result) => post(`${base}/${operation}`, { reason: values.reason }, `${title}을 서명했습니다.`, result)));
      }
    } else {
      node.append(form([field('해제 요청 사유', 'reason', { required: true, multiline: true, maxLength: 1000 })], '해제 요청',
        (values, result) => post(base, { reason: values.reason }, '해제 요청을 기록했습니다. 다른 검토자가 승인해야 합니다.', result)));
    }
    return node;
  }
  function stopNode(data) {
    const entry = data.entry, orders = list(data.stopOrders), node = el('div');
    const box = card('정지 명령·전파', '검토자 한 명이 바로 정지합니다. 운영 중인 에이전트는 같은 기록에서 정지(suspended)로 전이합니다. 해제는 다른 검토자의 승인이 '
      + '필요합니다. EvidScope는 차단하지 않으며, 집행 지점이 묶음·거부 목록을 받아 적용하고 활성화를 보고합니다.');
    for (const order of orders) {
      const item = el('div', 'registry-stop');
      item.append(el('strong', '', `${order.orderId} · ${order.scope === 'tools' ? `도구 정지(${list(order.tools).join(', ')})` : '전체 정지'}`),
        pill(order.status, orderLabels),
        el('p', 'muted', `발령 ${order.issuedBy} · ${date(order.issuedAt)} · 전파 기한 ${order.windowSeconds}초`
          + ` · 전파 ${propagationLabels[order.propagation] || '미확인'}`),
        el('p', 'wrap', `사유: ${order.reason}`), propagationTable(order), liftForms(order, entry));
      box.append(item);
    }
    if (!orders.length) box.append(el('p', 'muted', '이 에이전트에 대한 정지 명령이 없습니다.'));
    if (entry.state !== 'retired') {
      box.append(form([
        field('정지 범위', 'scope', { choices: [{ value: 'agent', label: '에이전트 전체' }, { value: 'tools', label: '지정 도구만' }], value: 'agent' }),
        field('정지할 도구 (쉼표 구분, 범위가 지정 도구일 때)', 'tools', { maxLength: 4000 }),
        field('사유', 'reason', { required: true, multiline: true, maxLength: 1000 }),
        field('증거 참조 (줄마다 유형:참조)', 'evidence', { multiline: true, wide: true, maxLength: 4000 }),
        field('추가 집행 지점 (enforcement 출처 자격, 쉼표 구분)', 'enforcementPoints', { maxLength: 2000 }),
      ], '정지 명령 발령', async (values, result) => {
        const scope = values.scope === 'tools' ? 'tools' : 'agent';
        const response = await api(`/api/registry/${encodeURIComponent(entry.id)}/stop`, 'POST', { scope,
          ...(scope === 'tools' ? { tools: words(values.tools) } : {}), reason: values.reason, evidence: evidenceRefs(values.evidence),
          enforcementPoints: words(values.enforcementPoints) });
        result.append(el('div', 'message', `정지 명령 ${response.order?.id}을 서명했습니다.${response.transition ? ' 운영 상태를 정지로 전이했습니다.' : ''}`));
        await openEntry(entry.id); navigate('registry');
      }));
    }
    node.append(box);
    return node;
  }
  function historyNode(data) {
    const node = el('div');
    node.append(el('h3', '', '버전 이력'), table(['버전', '상태', '변경', '기록 주체', '효력 시작', '원장 seq'],
      list(data.versions).map(v => [String(v.version), pill(v.state, stateLabels), v.change || '—', v.principal || '—', date(v.effectiveFrom),
        String(v.seq)])));
    node.append(el('h3', '', '전이 기록'), table(['원장 seq', '상태', '전이', '요청', '결정', '사유'],
      list(data.transitionRecords).map(t => [String(t.seq), pill(t.status, statusLabels), `${t.from} → ${t.to}`, t.requestedBy || '—',
        t.reviewedBy || t.supersededBy || '—', t.reviewReason || t.reason || '—'])));
    return node;
  }
  async function openEntry(id) {
    showDetail('에이전트 레지스트리', el('div', 'loading', '등록 항목과 이력을 조회하고 있습니다…'));
    const context = core.captureDetailContext();
    try {
      const data = await api(`/api/registry/${encodeURIComponent(id)}`);
      if (!core.isCurrentDetail(context)) return;
      showDetail(`레지스트리 · ${data.entry.name || data.entry.id}`, entryNode(data));
    } catch (error) { if (core.isCurrentDetail(context)) showDetail('레지스트리 조회 실패', empty('등록 항목을 불러오지 못했습니다', error.message)); }
  }
  // Catalog provenance (docs/agent-registry.md): where an imported entry's self-reported fields came from.
  function provenanceNode(catalog) {
    const box = card('카탈로그 출처', '가져온 문서의 자기 보고 값입니다. 인증된 출처 자격·행위자·위험 등급·상태는 문서에서 가져오지 않습니다.');
    box.append(core.factList([
      ['형식', `${formatLabels[catalog.format] || '미확인'} (${catalog.formatVersion || '버전 미상'})`], ['카탈로그 키', catalog.key],
      ['엔드포인트·엔터티', catalog.endpoint || catalog.entityRef || '—'], ['위치(제출자 기록)', catalog.locator || '—'],
      ['위치와 엔드포인트 호스트 일치', catalog.locatorMatchesEndpoint === true ? '일치' : catalog.locatorMatchesEndpoint === false ? '불일치' : '확인 안 함'],
      ['문서 digest', catalog.documentDigest], ['항목 digest', catalog.entityDigest],
      ['서명', signatureLabels[catalog.signature?.status] || '미확인'],
      ['서명 키', list(catalog.signature?.signatures).map(x => `${x.alg || '?'} ${x.kid || ''} ${x.keyThumbprint || ''}`.trim()).join(', ') || '—'],
      ['가져온 사람·시각', `${catalog.importedBy} · ${date(catalog.importedAt)}`],
      ['반영한 필드', list(catalog.mapped).join(', ') || '—'], ['버린 필드', list(catalog.dropped).join(', ') || '—'],
    ]));
    return box;
  }
  function importReport(report) {
    const node = el('div');
    const summary = report.summary || {};
    node.append(el('p', 'message', `${report.dryRun ? '미리보기(기록하지 않음)' : '가져오기 완료'} · 새로 ${summary.created || 0} · 새 버전 ${summary.updated || 0}`
      + ` · 변경 없음 ${summary.unchanged || 0} · 충돌 ${summary.conflict || 0} · 에이전트 아님 ${summary.skipped || 0} · 거부 ${summary.rejected || 0}`
      + ` · 읽지 못한 문서 ${summary.rejectedDocuments || 0}`));
    for (const document of list(report.documents).filter(d => d.rejected)) {
      node.append(el('p', 'message error', `문서 ${document.index + 1}: ${document.rejected.code} ${document.rejected.message}`));
    }
    node.append(table(['문서', '결과', '등록 ID', '카탈로그 키', '사유', '서명', '버린 필드', '상세'], list(report.results).map(result => [
      `${result.documentIndex + 1}.${result.entityIndex + 1}`, outcomeLabels[result.outcome] || '미확인', result.entry?.id || '—',
      result.key || result.entityRef || '—', result.reason || '—', signatureLabels[result.signature?.status] || '—',
      list(result.dropped).map(d => `${d.field}(${d.reason})`).join(', ') || '—',
      result.entry?.id && !report.dryRun ? button('상세', () => openEntry(result.entry.id), 'ghost') : '—',
    ])), limits(report.limitations));
    return node;
  }
  function importForm() {
    return form([
      field('형식', 'format', { choices: [{ value: 'a2a', label: 'A2A Agent Card (JSON)' }, { value: 'backstage', label: 'Backstage 엔터티 (YAML·JSON)' }],
        value: 'a2a' }),
      field('문서 내용', 'content', { required: true, multiline: true, wide: true, maxLength: 262144 }),
      field('가져온 위치 (URL 또는 파일 이름, 기록용)', 'locator', { maxLength: 1000 }),
      field('에이전트로 볼 Backstage spec.type (쉼표 구분, 비우면 기본값)', 'agentTypes', { maxLength: 700 }),
      field('A2A 서명 확인용 공개 키 (JWK Set JSON, 선택)', 'keys', { multiline: true, wide: true, maxLength: 20000 }),
      field('방식', 'mode', { choices: [{ value: 'preview', label: '미리보기(기록하지 않음)' }, { value: 'import', label: '가져오기(서명 기록)' }],
        value: 'preview' }),
    ], '카탈로그 가져오기', async (values, result) => {
      let keys;
      if (text(values.keys)) { try { keys = JSON.parse(values.keys); } catch { throw new Error('공개 키는 JWK Set JSON이어야 합니다'); } }
      const types = words(values.agentTypes);
      const body = { documents: [{ format: values.format === 'backstage' ? 'backstage' : 'a2a', content: String(values.content || ''),
        ...(text(values.locator) ? { locator: text(values.locator) } : {}) }], ...(keys ? { keys } : {}), ...(types.length ? { agentTypes: types } : {}),
        dryRun: values.mode !== 'import' };
      const report = await api('/api/registry/import', 'POST', body);
      result.append(importReport(report));
      if (!report.dryRun) navigate('registry');
    });
  }
  function entryNode(data) {
    const entry = data.entry, risk = data.risk || {}, node = el('div');
    const tools = list(entry.tools).map(t => t.enforcement === 'required' ? `${t.name}(결정 필수)` : t.name).join(', ');
    const override = risk.override ? ` (재지정: ${risk.override.by}, 계산값 ${tierLabels[risk.computed] || risk.computed})` : '';
    node.append(core.factList([
      ['상태', stateLabels[entry.state] || entry.state], ['버전', String(entry.version)],
      ['책임자', `${ownerLabels[data.ownership?.status] || '미확인'} · ${ownerText(data.ownership)}`], ['목적', entry.purpose],
      ['출처 자격', join(entry.sources)], ['행위자 이름(자기 보고)', join(entry.actors)], ['자산', join(entry.assetIds)], ['거버넌스 시스템', entry.systemId],
      ['모델', join(entry.models)], ['도구', tools], ['데이터 범주', join(entry.dataCategories)], ['목적지', join(entry.destinations)],
      ['위험 등급', `${tierLabels[risk.tier] || risk.tier}${override}`],
      ['위험 근거', list(risk.reasons).map(r => `${r.rule}: ${r.value}`).join(', ') || '규칙에 걸린 항목 없음'],
      ['생애주기 검증', data.lifecycle?.valid ? '이상 없음' : `문제 ${list(data.lifecycle?.problems).length}건`],
    ]));
    if (data.lifecycle && !data.lifecycle.valid) node.append(limits(list(data.lifecycle.problems).map(p => `seq ${p.seq}: ${p.message}`)));
    if (entry.catalog) node.append(provenanceNode(entry.catalog));
    node.append(transitionForms(data), stopNode(data), ownerNode(data), historyNode(data), jsonDetails('등록 항목 원문', entry));
    return node;
  }
  // Executors seen and the accountable owner (docs/agent-registry.md, "실행자와 책임자"). An inferred owner is a guess with its basis;
  // a reviewer confirms it, or enters another owner, with a reason. Approval gates read only a confirmed owner.
  function ownerNode(data) {
    const entry = data.entry, o = data.ownership || { status: 'unknown' };
    const box = card('책임자·실행자', '실행자는 훅의 자기 보고(OS 계정·PC·저장소·git 사용자)입니다. 추정은 매핑 표의 결과일 뿐이며, 책임자는 검토자가 확정합니다.');
    const basis = o.basis ? basisLabels[o.basis] || o.basis : '—';
    box.append(core.factList([
      ['상태', ownerLabels[o.status] || '미확인'], ['책임자(팀)', ownerText(o)],
      ['근거', o.rule ? `${basis} · 규칙 ${o.rule.id} (${fieldLabels[o.rule.field] || o.rule.field}=${o.rule.value})` : basis],
      ['확정한 사람·시각', o.status === 'confirmed' ? `${o.confirmedBy || '—'} · ${date(o.confirmedAt)}` : '—'],
      ...(entry.discoveredFrom ? [['발견 출처', `${entry.discoveredFrom.source || '출처 미상'} / ${entry.discoveredFrom.actor || '행위자 미상'}`]] : []),
    ]));
    box.append(table(['실행자', '행위자', '출처', '기록 수', '최근 수신'], list(data.executors).map(g => [executorText(g.executor), g.actor || '—',
      g.source || '—', String(g.events), date(g.lastSeen)])));
    if (entry.state !== 'retired') {
      const accept = o.status === 'inferred';
      box.append(form([
        field(accept ? `책임자 (비우면 추정값 ${o.owner} 확정)` : '책임자', 'owner', { maxLength: 200 }), field('팀 (선택)', 'team', { maxLength: 200 }),
        field('확정 사유', 'reason', { required: true, multiline: true, maxLength: 1000 }),
      ], accept ? '책임자 확정' : '책임자 지정', async (values, result) => {
        const body = { reason: values.reason, ...(text(values.owner) ? { owner: text(values.owner) } : {}),
          ...(text(values.team) ? { team: text(values.team) } : {}) };
        const saved = await api(`/api/registry/${encodeURIComponent(entry.id)}/owner`, 'POST', body);
        result.append(el('div', 'message', `책임자 ${saved.owner}를 확정한 v${saved.version}을 서명했습니다.`)); await openEntry(entry.id); navigate('registry');
      }));
    }
    return box;
  }
  // The owner map (admin): rules in priority order, executor field / actor / source → team and owner. Edited as JSON lines.
  function ownersNode(data) {
    const node = el('div'), map = data.map || { version: 0, rules: [] }, counts = data.counts || {};
    const box = card('책임자 매핑 표', `v${map.version} · 규칙 ${list(map.rules).length}개 · 확정 ${counts.confirmed || 0} · 추정 ${counts.inferred || 0}`
      + ` · 충돌 ${counts.conflict || 0} · 미확인 ${counts.unknown || 0}`);
    box.append(table(['순서', '규칙 ID', '대상', '방식', '값', '팀', '책임자'], list(map.rules).map((r, i) => [String(i + 1), r.id, fieldLabels[r.field] || r.field,
      r.op, r.value, r.team || '—', r.owner])));
    box.append(form([
      field('규칙 (한 줄에 하나: 규칙ID, 대상, 방식, 값, 팀, 책임자 / 대상은 account·host·repository·gitUser·actor·source, 방식은 eq·prefix·suffix)', 'rules',
        { multiline: true, wide: true, maxLength: 60000,
          value: list(map.rules).map(r => [r.id, r.field, r.op, r.value, r.team || '', r.owner].join(', ')).join('\n') }),
    ], '매핑 표 저장(관리자)', async (values, result) => {
      const rules = String(values.rules || '').split('\n').map(line => line.trim()).filter(Boolean).map(line => {
        const [id, field_, op, value, team, owner] = line.split(',').map(part => part.trim());
        if (!owner) throw new Error(`규칙은 여섯 칸이어야 합니다: ${line}`);
        return { id, field: field_, op, value, ...(team ? { team } : {}), owner };
      });
      const saved = await api('/api/registry/owners', 'POST', { rules });
      result.append(el('div', 'message', `매핑 표 v${saved.version}을 서명했습니다.`)); navigate('registry');
    }));
    box.append(limits(data.limitations));
    node.append(box);
    node.append(table(['등록 ID', '상태', '책임자', '실행자', '상세'], list(data.items).map(item => [item.id, pill(item.state, stateLabels), ownerCell(item.owner),
      list(item.executors).slice(0, 3).map(g => executorText(g.executor)).join(' / ') || '—', button('상세', () => openEntry(item.id), 'ghost')])));
    return node;
  }
  async function openOwners() {
    showDetail('책임자 매핑', el('div', 'loading', '매핑 표와 책임자 상태를 조회하고 있습니다…'));
    try { showDetail('책임자 매핑', ownersNode(await api('/api/registry/owners'))); }
    catch (error) { showDetail('책임자 매핑 조회 실패', empty('매핑 표를 불러오지 못했습니다', error.message)); }
  }
  function discoverNode(policy) {
    const box = card('자동 등록', `현재 ${policy.autoRegister === 'discovered' ? '켜짐: 새 후보를 발견됨(discovered) 항목으로 1분마다 등록합니다' : '꺼짐: 후보를 목록으로만 보여 줍니다'}.`
      + ' 자동 등록한 항목은 책임자·출처 자격·행위자가 비어 있어 발견(finding)을 바꾸지 않으며, 책임자는 검토자가 확정합니다.');
    box.append(form([field('방식', 'mode', { choices: [{ value: 'preview', label: '미리보기' }, { value: 'run', label: '지금 등록' }], value: 'preview' })],
      '후보 자동 등록', async (values, result) => {
        const run = await api('/api/registry/discover', 'POST', { dryRun: values.mode !== 'run' });
        result.append(el('p', 'message', `${run.dryRun ? '미리보기' : '등록'} ${list(run.registered).length}개 · 건너뜀 ${list(run.skipped).length}개`),
          table(['등록 ID', '출처 / 행위자', '책임자'], list(run.registered).map(r => [r.id, `${r.source || '—'} / ${r.actor || '—'}`, ownerCell(r.owner)])));
        if (!run.dryRun) navigate('registry');
      }));
    box.append(form([field('자동 등록 정책', 'autoRegister', { choices: [{ value: 'discovered', label: '켜기(발견됨으로 등록)' }, { value: 'off', label: '끄기' }],
      value: policy.autoRegister === 'discovered' ? 'off' : 'discovered' })], '정책 저장(관리자)', async (values, result) => {
      const saved = await api('/api/registry/policy', 'POST', { autoRegister: values.autoRegister === 'discovered' ? 'discovered' : 'off' });
      result.append(el('div', 'message', `레지스트리 정책 v${saved.version}을 서명했습니다.`)); navigate('registry');
    }));
    return box;
  }
  function createForm(prefill = {}) {
    return form([
      field('등록 ID', 'id', { required: true, value: prefill.id, maxLength: 120 }), field('이름', 'name', { value: prefill.name, maxLength: 200 }),
      field('책임자', 'owner', { maxLength: 200 }), field('목적', 'purpose', { multiline: true, maxLength: 1000 }),
      field('출처 자격 ID (쉼표 구분)', 'sources', { value: prefill.sources, maxLength: 2000 }),
      field('행위자 이름 (쉼표 구분)', 'actors', { value: prefill.actors, maxLength: 2000 }),
      field('도구 (쉼표 구분)', 'tools', { value: prefill.tools, maxLength: 4000 }),
      field('정책 결정이 필요한 도구 (쉼표 구분)', 'enforcedTools', { maxLength: 2000 }),
      field('데이터 범주 (쉼표 구분)', 'dataCategories', { maxLength: 1000 }), field('목적지 (쉼표 구분)', 'destinations', { maxLength: 4000 }),
      field('자산 ID (쉼표 구분)', 'assetIds', { maxLength: 2000 }), field('거버넌스 시스템 ID', 'systemId', { maxLength: 120 }),
      field('초기 상태', 'state', { choices: [{ value: 'draft', label: '초안' }, { value: 'discovered', label: '발견됨' }], value: prefill.state || 'draft' }),
    ], '등록 초안 만들기', async (values, result) => {
      const enforced = new Set(words(values.enforcedTools));
      const tools = [...new Set([...words(values.tools), ...enforced])].map(name => ({ name, enforcement: enforced.has(name) ? 'required' : 'not_required' }));
      const body = { id: text(values.id), name: text(values.name) || undefined, owner: text(values.owner), purpose: text(values.purpose),
        sources: words(values.sources), actors: words(values.actors), tools, dataCategories: words(values.dataCategories),
        destinations: words(values.destinations), assetIds: words(values.assetIds), state: values.state,
        ...(text(values.systemId) ? { systemId: text(values.systemId) } : {}), ...(prefill.discoveredFrom ? { discoveredFrom: prefill.discoveredFrom } : {}) };
      const entry = await api('/api/registry', 'POST', body);
      result.append(el('div', 'message', `${entry.id} v${entry.version}을 서명했습니다. 위험 등급 계산값: ${tierLabels[entry.risk?.computed] || '미확인'}`));
      await openEntry(entry.id); navigate('registry');
    });
  }
  function candidatesNode(data) {
    const node = card('미등록 후보', `이미 수집된 활동·발견에서 찾은 후보입니다. 자동 등록 ${data.autoRegister === 'discovered' ? '켜짐' : '꺼짐'}.`
      + ' 행위자 이름과 실행자는 출처의 자기 보고입니다.');
    node.append(table(['출처 / 행위자', '근거', '행동 / 이벤트', '도구', '실행자', '추정 책임자', '최근 수신', '등록'], list(data.items).map(item => [
      `${item.source || '출처 미상'} / ${item.actor || '행위자 미상'}`, list(item.reasons).join(', '), `${item.actions} / ${item.events}`,
      list(item.tools).slice(0, 5).join(', ') || '—', list(item.executors).slice(0, 2).map(g => executorText(g.executor)).join(' / ') || '—',
      ownerCell(item.owner), date(item.lastSeen),
      button('초안으로', () => showDetail('후보에서 등록', createForm({ id: item.suggestedId, name: item.actor || item.source, actors: item.actor || '',
        sources: item.sourceKinds?.includes('tool') && !item.source ? '' : item.source || '', tools: list(item.tools).join(', '), state: 'draft',
        discoveredFrom: { ...(item.source ? { source: item.source } : {}), ...(item.actor ? { actor: item.actor } : {}) } })), 'ghost'),
    ])), limits(data.limitations));
    return node;
  }
  async function registryView() {
    const [data, candidates] = await Promise.all([api('/api/registry'), api('/api/registry/candidates').catch(error => ({ error: error.message }))]);
    const node = el('div');
    const policy = data.policy || {};
    const head = card('에이전트 레지스트리', `정책 v${policy.version}${policy.source === 'built_in_default' ? ' (기본값)' : ''} · 미등록 활동 발견 `
      + (policy.enforcement === 'unregistered_activity' ? '켜짐' : '꺼짐') + ` · 자동 등록 ${policy.autoRegister === 'discovered' ? '켜짐' : '꺼짐'}`);
    head.append(limits(data.limitations));
    head.append(button('새 등록 초안', () => showDetail('에이전트 등록', createForm()), 'primary'),
      button('카탈로그 가져오기', () => showDetail('카탈로그 가져오기', importForm()), 'ghost'),
      button('자동 등록', () => showDetail('자동 등록', discoverNode(policy)), 'ghost'), button('책임자 매핑', () => openOwners(), 'ghost'));
    node.append(head);
    const items = list(data.items);
    const listCard = card('등록 항목', `${items.length}개 · 상태는 서명된 전이 기록으로만 바뀝니다.`);
    listCard.append(table(['등록 ID / 이름', '상태', '위험 등급', '책임자', '출처 / 행위자', '승인 대기', '활성 정지 명령', '버전', '상세'], items.map(entry => [
      `${entry.id}${entry.name && entry.name !== entry.id ? ` / ${entry.name}` : ''}`
        + (entry.catalog ? ` · 카탈로그(${formatLabels[entry.catalog.format] || '미확인'})` : ''),
      pill(entry.state, stateLabels), tierLabels[entry.effectiveRisk] || '미확인',
      ownerCell(entry.ownerStatus || { status: entry.owner ? 'confirmed' : 'unknown', owner: entry.owner }), `${join(entry.sources)} / ${join(entry.actors)}`,
      entry.pendingTransition ? `${entry.pendingTransition.from} → ${entry.pendingTransition.to}` : '—',
      entry.activeStopOrders ? `${entry.activeStopOrders}건` : '—', String(entry.version),
      button('상세', () => openEntry(entry.id), 'ghost'),
    ])));
    node.append(listCard);
    node.append(candidates.error ? empty('후보를 불러오지 못했습니다', candidates.error) : candidatesNode(candidates));
    return node;
  }
  core.registerView('registry', '에이전트 레지스트리', '에이전트 등록·생애주기·게이트와 승인 이력, 정지 명령과 집행 지점 전파를 확인합니다. '
    + '정지·폐기는 기록이며 EvidScope는 실행을 차단하지 않습니다.', registryView);
  window.EvidScopeRegistry = Object.freeze({ registryView, openEntry, entryNode, createForm, evidenceRefs, stopNode, importForm, importReport, ownerNode,
    ownersNode, discoverNode, executorText });
})();
