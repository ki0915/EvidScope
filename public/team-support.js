'use strict';

// AI 검토 지원과 에이전트 팀 화면. 기계 출력을 다루지만 이 모듈 자체는 서버로
// 어떤 자유 텍스트도 실행하지 않고, app.js가 노출한 안전한 DOM/네트워크 헬퍼만 사용합니다.
(() => {
  const core = window.EvidScopeCore;
  if (!core) return;
  const {
    api, el, button, badge, card, empty, limits, jsonDetails, table, field, form,
    label, date, stringify, showDetail, inspect, captureDetailContext, isCurrentDetail,
    savedNotice, downloadArtifact, navigate, factList, getRenderEpoch, getAuthEpoch, registerView,
  } = core;

  const runtimeRoleIds = ['evidence-organizer', 'evidence-reconciler', 'governance-assistant', 'report-drafter'];
  const stateText = {
    queued: '대기 중', running: '실행 중', completed: '완료', succeeded: '완료', done: '완료',
    error: '오류', failed: '오류', canceled: '취소됨', cancelled: '취소됨',
    prepared: '준비됨', dispatched: '전달됨', accept: '채택', accepted: '채택', reject: '반려', rejected: '반려',
  };
  function rlabel(value) {
    if (value === undefined || value === null || value === '') return '미확인';
    return stateText[value] || label(value);
  }
  function stateBadge(value) {
    const safeClass = /^[a-z_]+$/.test(String(value)) ? String(value) : '';
    return el('span', `badge ${safeClass}`, rlabel(value));
  }
  function renderShape(value, emptyText) {
    if (value === undefined || value === null) return el('p', 'muted', emptyText);
    if (Array.isArray(value)) {
      if (!value.length) return el('p', 'muted', emptyText);
      const list = el('ul');
      value.slice(0, 50).forEach((item) => list.append(el('li', '', typeof item === 'object' ? stringify(item) : String(item))));
      if (value.length > 50) list.append(el('li', 'muted', `외 ${value.length - 50}건 생략`));
      return list;
    }
    if (typeof value === 'object') return factList(Object.entries(value).map(([k, v]) => [k, typeof v === 'object' ? stringify(v) : String(v ?? '미확인')]));
    return el('p', '', String(value));
  }

  // ---------------------------------------------------------------------
  // 에이전트 팀
  // ---------------------------------------------------------------------
  function profileCard(profile, selected, onSelect) {
    const btn = el('button', 'role-card');
    btn.type = 'button';
    btn.append(
      el('strong', '', profile.name || profile.id),
      el('span', 'role-kind', `${profile.kind === 'runtime' ? '런타임 역할' : '개발 역할'} · v${profile.version ?? '미확인'}`),
      el('p', 'role-desc', profile.description || '설명 미제공'),
    );
    btn.setAttribute('aria-pressed', String(selected));
    btn.addEventListener('click', onSelect);
    return btn;
  }
  function profileDetail(profile) {
    const node = el('div', 'role-detail');
    node.append(
      el('h3', '', profile.name || profile.id),
      el('p', 'role-version', `${profile.id} · ${profile.kind === 'runtime' ? '런타임 역할' : '개발 역할'} · 버전 ${profile.version ?? '미확인'}`),
      el('p', '', profile.description || '설명 미제공'),
    );
    const grid = el('div', 'role-detail-grid');
    const instr = el('div', 'role-detail-block'); instr.append(el('h4', '', '지침 (Instructions)'), profile.instructions ? el('p', 'wrap', profile.instructions) : el('p', 'muted', '미확인'));
    const tools = el('div', 'role-detail-block'); tools.append(el('h4', '', '도구 (Tools)'), renderShape(profile.tools, '등록된 도구 없음 또는 미확인'));
    const knowledge = el('div', 'role-detail-block'); knowledge.append(el('h4', '', '지식 소스 (Knowledge)'), renderShape(profile.knowledge, '연결된 지식 소스 없음 또는 미확인'));
    const evalBlock = el('div', 'role-detail-block'); evalBlock.append(el('h4', '', '평가 (Eval)'), renderShape(profile.eval, '평가 결과 미확인'));
    grid.append(instr, tools, knowledge, evalBlock); node.append(grid);
    node.append(el('div', 'metric-note', '역할 자체 시험 지표(eval)는 EvidScope의 관측 기반 정책 준수율과 다른 산정입니다. 정책 준수는 "에이전트 목록"에서 별도로 확인하세요.'));
    if (profile.modelPolicy !== undefined && profile.modelPolicy !== null) {
      const policyText = typeof profile.modelPolicy === 'string' ? profile.modelPolicy : (profile.modelPolicy.description || profile.modelPolicy.summary);
      const policyBlock = el('div', 'role-detail-block');
      policyBlock.append(el('h4', '', '모델 정책'), policyText ? el('p', 'wrap', policyText) : el('p', 'muted', '안전하게 요약할 설명 필드가 없어 원문에서 확인하세요.'));
      node.append(policyBlock, jsonDetails('모델 정책 원문 (스키마 확정 전)', profile.modelPolicy));
    } else node.append(el('p', 'muted', '모델 정책 정보 미확인'));
    node.append(jsonDetails('프로필 원문', profile));
    return node;
  }
  function summaryText(summary) {
    if (summary === undefined || summary === null) return '미확인';
    if (typeof summary !== 'object') return String(summary);
    return Object.entries(summary).map(([k, v]) => `${k}: ${typeof v === 'object' ? stringify(v) : (v ?? '미확인')}`).join(' · ');
  }
  function developmentRunsSection(data) {
    const node = el('div');
    const items = data.items || [];
    if (data.summary) node.append(el('p', 'muted', `요약: ${summaryText(data.summary)}`));
    if (data.coverage) node.append(el('p', 'muted', `수집 범위: ${summaryText(data.coverage)}`));
    if (!items.length) { node.append(empty('표시할 개발 실행 기록이 없습니다', '기록이 없다는 사실이 개발이 없었음을 뜻하지 않습니다. 수집 상태를 확인하세요.')); return node; }
    const byId = new Map(items.map((i) => [i.id, i]));
    node.append(table(['실행 ID', '역할', '부모 실행', '상태', '모델', '시작 / 종료', '사용량 · 산출물', ''], items.map((item) => {
      const parent = el('div', 'dev-run-parent');
      if (item.parentRunId) {
        parent.append(el('span', '', item.parentRunId));
        if (byId.has(item.parentRunId)) parent.append(button('상위 실행 보기', () => inspect('개발 실행 · 상위 실행', byId.get(item.parentRunId)), 'small'));
      } else parent.append(el('span', 'muted', '최상위 실행'));
      const usageNote = el('div');
      usageNote.append(el('p', 'muted', item.usage ? stringify(item.usage) : '사용량 텔레메트리 미확인'), el('p', 'muted', item.artifacts && item.artifacts.length ? `산출물 ${item.artifacts.length}건` : '산출물 미확인'));
      return [item.id, item.roleId || '미확인', parent, stateBadge(item.status || 'unknown'), item.model || '미확인', `${date(item.startedAt)} / ${item.finishedAt ? date(item.finishedAt) : '진행 중 또는 종료 미확인'}`, usageNote, button('원문', () => inspect('개발 실행 원문', item), 'small')];
    })));
    return node;
  }
  async function teamView() {
    const viewEpoch = getRenderEpoch(); const authAtStart = getAuthEpoch();
    const node = el('div');
    const roleSection = card('역할 프로필', '런타임 역할은 사건 지원 요청에 배정할 수 있는 역할입니다. 개발 역할은 팀 구성을 만드는 개발 과정에서 사용합니다.');
    const grid = el('div'); roleSection.append(grid); node.append(roleSection);
    const devSection = card('개발 실행 이력', '개발 단계 실행 기록입니다. 부모-자식 관계, 상태, 원격 측정(usage·artifacts) 누락 여부를 표시합니다.');
    node.append(devSection);
    node.append(limits([
      '역할의 평가(eval) 지표는 팀 자체 시험 결과이며 EvidScope의 관측 기반 정책 준수율과는 다른 산정입니다.',
      '초기 역할 튜닝은 프로필 · 검색(retrieval) · 평가만 사용합니다. 사람이 검토한 최소 데이터셋을 확보하기 전까지 LoRA 등 파라미터 미세조정은 적용하지 않습니다.',
    ]));

    let profiles = [];
    try {
      const data = await api('/api/assistance/profiles');
      if (viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return node;
      profiles = data.items || [];
    } catch (error) {
      if (viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return node;
      grid.replaceChildren(empty('역할 프로필을 불러오지 못했습니다', error.message));
    }
    if (profiles.length) {
      const runtimeProfiles = profiles.filter((p) => p.kind === 'runtime');
      const developmentProfiles = profiles.filter((p) => p.kind !== 'runtime');
      let selectedId = runtimeProfiles[0]?.id || developmentProfiles[0]?.id || null;
      const detailHost = el('div');
      function renderGrid() {
        grid.replaceChildren();
        const section = (title, list) => {
          if (!list.length) return;
          grid.append(el('p', 'role-group-label', title));
          const row = el('div', 'role-grid');
          list.forEach((p) => row.append(profileCard(p, p.id === selectedId, () => { selectedId = p.id; renderGrid(); })));
          grid.append(row);
        };
        section('런타임 역할 · 사건 지원에 배정', runtimeProfiles);
        section('개발 역할 · 팀 구성 개발', developmentProfiles);
        const selected = profiles.find((p) => p.id === selectedId);
        detailHost.replaceChildren(selected ? profileDetail(selected) : empty('역할을 선택하세요', '카드를 눌러 지침 · 도구 · 지식 · 평가 범위를 확인합니다.'));
      }
      renderGrid();
      roleSection.append(detailHost);
    } else if (!grid.children.length) {
      grid.append(empty('등록된 역할 프로필이 없습니다', '접속 권한과 수집 상태를 확인하세요.'));
    }

    try {
      const runs = await api('/api/development-runs');
      if (viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return node;
      devSection.append(developmentRunsSection(runs));
    } catch (error) {
      if (viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return node;
      devSection.append(empty('개발 실행 이력을 불러오지 못했습니다', error.message));
    }
    return node;
  }

  // ---------------------------------------------------------------------
  // AI 검토 지원
  // ---------------------------------------------------------------------
  let pendingCaseId = null;

  function packagePreview(pkg) {
    const node = el('div', 'bundle-preview');
    node.append(el('p', '', `묶음 상태: ${rlabel(pkg.status)} · 생성 ${date(pkg.createdAt)} · 생성자 ${pkg.createdBy || '미확인'}`));
    node.append(factList([
      ['묶음 ID', pkg.id], ['사건 ID', pkg.caseId], ['행동 ID', pkg.actionId],
      ['근거 해시 (contextHash)', pkg.contextHash], ['묶음 해시 (bundleHash)', pkg.bundleHash],
      ['사건 스냅샷 해시', pkg.caseSnapshotHash || '미제공'], ['프로필 해시', pkg.profileSnapshotHash || '미제공'],
      ['역할 실행 해시', pkg.roleExecutionHash || '미제공'], ['규정집 해시', pkg.governanceSnapshot?.catalogHash || '미제공'],
    ]));
    if (pkg.operatorQuestion) node.append(el('h3', '', '사람이 작성한 감사 질문'), el('p', 'wrap', pkg.operatorQuestion));
    const evidenceItems = pkg.evidence || [];
    node.append(el('p', 'muted', `포함된 근거 ${evidenceItems.length}건 · 선택 시점 스냅샷이며 이후 근거 변경을 반영하지 않습니다.`));
    if (evidenceItems.length) {
      const list = el('ul');
      evidenceItems.forEach((item) => list.append(el('li', '', typeof item === 'string' ? item : stringify(item))));
      node.append(list);
    }
    node.append(el('h3', '', '실행에 전달되는 고정 스냅샷'));
    const snapshots = el('div', 'package-snapshot-grid');
    for (const [key, title] of [['profileSnapshot', '역할 프로필'], ['roleExecutionSnapshot', '역할 실행 계약'], ['analysisSnapshot', '분석'], ['governanceSnapshot', '거버넌스·요구사항']]) {
      snapshots.append(pkg[key] == null ? el('p', 'muted', `${title} 스냅샷 미제공`) : jsonDetails(`${title} 스냅샷 전체`, pkg[key]));
    }
    node.append(snapshots, jsonDetails('고정된 근거 묶음 전체 원문', pkg));
    node.append(limits(pkg.limitations));
    node.append(el('p', 'muted', '이 미리보기는 API가 반환한 불변 스냅샷 전체입니다. 거버넌스 자료는 적용성·준수 여부의 자동 판정이 아니며, 실행 전 사람이 포함 범위를 확인합니다.'));
    return node;
  }
  function credentialPanel(result) {
    let credential = result.credential;
    const node = el('div', 'credential-panel');
    node.append(el('h3', '', '실행 큐에 등록됨'));
    node.append(el('p', '', `실행 ID ${result.run.id} · 상태 ${rlabel(result.run.state)} · 큐에 등록만 되었으며, 로컬 CLI가 시작하기 전까지 실제로 실행되지 않습니다.`));
    node.append(el('div', 'message warning', '자격 증명은 이 화면에 표시되지 않고 다운로드 시 한 번만 제공됩니다. 다시 조회할 수 없으니 안전한 위치에 보관하세요.'));
    const done = el('div', 'credential-done', '다운로드한 파일은 이 세션의 메모리에서 즉시 삭제되었습니다. 아래 안내에 따라 로컬에서 직접 실행하세요.');
    done.hidden = true;
    const dlBtn = button('자격 증명 JSON 다운로드', () => {
      if (!credential) throw new Error('자격 증명이 이미 다운로드되어 메모리에서 삭제되었습니다.');
      downloadArtifact(`evidscope-assistance-credential-${result.run.id}.json`, 'application/json', JSON.stringify(credential, null, 2));
      credential = null; dlBtn.disabled = true; dlBtn.textContent = '다운로드 완료 · 다시 표시되지 않음'; done.hidden = false;
    }, 'primary');
    node.append(dlBtn, done);
    node.append(el('h3', '', '로컬 CLI 실행 안내'));
    node.append(el('code', 'cli-command', 'node scripts/assistance-run.mjs --credential <다운로드한 파일 경로> --base-url http://127.0.0.1:8080'));
    node.append(el('p', 'muted', '기본 게이트웨이는 http://127.0.0.1:8080 입니다. 자동화된 테스트 뷰포트에서만 --base-url http://127.0.0.1:9080 처럼 재정의합니다. 9080은 테스트 전용 재정의이며 운영 대상 주소가 아닙니다.'));
    node.append(el('p', 'muted', 'CLI는 다운로드한 자격 증명 파일을 읽어 큐에 등록된 실행을 시작합니다. 결과(초안)는 "지원 실행 목록"에서 사람이 검토해야 하며, 그 자체로 승인 · 정책 점수 · 실행 게이트 · 법적 결론이 아닙니다.'));
    return node;
  }
  function dispatchPanel(pkg, viewEpoch, authAtStart) {
    const node = el('div');
    node.append(el('div', 'message warning', '로컬 실행 전달은 사람이 명시적으로 시작하는 조치입니다. 자동으로 실행되지 않으며, 자격 증명을 내려받은 뒤 로컬 CLI로 직접 시작해야 합니다.'));
    const dispatchBtn = button('로컬 실행으로 전달', async () => {
      const result = await api(`/api/assistance/packages/${encodeURIComponent(pkg.id)}/dispatch`, 'POST', { contextHash: pkg.contextHash });
      if (viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return;
      dispatchBtn.disabled = true; dispatchBtn.textContent = '전달 완료 · 아래에서 자격 증명 다운로드';
      node.append(credentialPanel(result));
    }, 'primary');
    node.append(dispatchBtn);
    return node;
  }
  function governanceRequirementPicker(data, onChange) {
    const node = el('div', 'requirement-picker'), choices = [];
    const maximum = Number.isSafeInteger(data?.maxSelected) && data.maxSelected > 0 ? Math.min(3, data.maxSelected) : 0;
    node.append(el('h3', '', '검토할 거버넌스 요구사항'), el('p', 'muted', '적용성·증거 검토를 지원할 요구사항을 직접 선택하세요. 선택은 법적 적용성 판정이 아닙니다.'));
    const status = el('p', 'selection-count'); status.setAttribute('role', 'status');
    const list = el('div', 'evidence-checklist');
    const value = () => choices.filter(item => item.input.checked).map(item => item.id);
    function refresh() {
      const selected = value(); status.textContent = `선택 ${selected.length}개 / 최대 ${maximum}개`;
      choices.forEach(item => { item.input.disabled = !item.input.checked && selected.length >= maximum; });
    }
    if (!maximum || !Array.isArray(data?.items) || !data.items.length) node.append(empty('요구사항 목록을 확인하지 못했습니다', data?.error || '거버넌스 역할의 요청을 만들려면 규정집을 다시 불러와야 합니다.'));
    else for (const requirement of data.items) {
      const row = el('label'), input = el('input'); input.type = 'checkbox'; input.value = requirement.id;
      const caption = el('span'); caption.append(el('strong', '', requirement.title || requirement.id), el('span', 'muted', `${requirement.id} · ${requirement.jurisdiction || requirement.framework || '분류 미제공'} · ${requirement.binding || '구속력 확인 필요'}`));
      row.append(input, caption); list.append(row); choices.push({ id: requirement.id, input });
      input.addEventListener('change', () => { refresh(); onChange(); });
    }
    refresh(); node.append(status, list); return { node, value };
  }
  function assistanceRequestOptions(profileId, requirementIds, question) {
    const result = {}, operatorQuestion = String(question || '').trim();
    if (operatorQuestion.length > 500) throw new Error('감사 질문은 500자 이내로 작성하세요.');
    if (operatorQuestion) result.operatorQuestion = operatorQuestion;
    if (profileId === 'governance-assistant') {
      if (!Array.isArray(requirementIds) || requirementIds.length < 1 || requirementIds.length > 3 || new Set(requirementIds).size !== requirementIds.length) throw new Error('검토할 요구사항을 1개에서 3개까지 선택하세요.');
      result.selectedRequirementIds = [...requirementIds];
    }
    return result;
  }
  async function requestBuilder(presetCaseId, viewEpoch, authAtStart) {
    const [casesData, profilesData, requirementsData] = await Promise.all([api('/api/cases'), api('/api/assistance/profiles'), api('/api/assistance/requirements').catch(error => ({ error: error.message }))]);
    if (viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return el('div');
    const cases = casesData.items || [];
    const runtimeProfiles = (profilesData.items || []).filter((p) => p.kind === 'runtime' && runtimeRoleIds.includes(p.id));
    const node = el('div');
    const intro = card('1. 사건과 지원 역할 선택', '선택 시점의 근거가 스냅샷으로 고정됩니다. 새 근거가 도착하면 새 요청을 다시 만드세요.');
    node.append(intro);
    if (!cases.length) { intro.append(empty('선택할 사건이 없습니다', '먼저 "사건 · 인간 감사"에서 사건을 생성하세요.')); return node; }
    if (!runtimeProfiles.length) { intro.append(empty('사용 가능한 런타임 역할이 없습니다', '역할 프로필 수집 상태를 확인하세요.')); return node; }

    const caseField = field('사건 선택', 'caseId', { choices: cases.map((c) => ({ value: c.id, label: `${c.title} · ${c.id}` })) });
    const caseSelect = caseField.querySelector('select');
    if (presetCaseId && cases.some((c) => c.id === presetCaseId)) caseSelect.value = presetCaseId;
    const profileField = field('지원 역할 선택', 'profileId', { choices: runtimeProfiles.map((p) => ({ value: p.id, label: `${p.name || p.id} · v${p.version ?? '미확인'}` })) });
    const profileSelect = profileField.querySelector('select');
    const selectionGrid = el('div', 'form-grid'); selectionGrid.append(caseField, profileField); intro.append(selectionGrid);
    const roleDescNode = el('p', 'muted'); intro.append(roleDescNode);
    function updateRoleDesc() { const p = runtimeProfiles.find((x) => x.id === profileSelect.value); roleDescNode.textContent = p ? (p.description || '설명 미제공') : ''; }
    profileSelect.addEventListener('change', updateRoleDesc); updateRoleDesc();

    const evidenceCard = card('2. 근거 선택', '사건 상세와 동일한 원본 이벤트 목록입니다. 지원 요청에 포함할 근거만 선택하세요.');
    const checklist = el('div', 'evidence-checklist');
    const buildRow = el('div', 'actions');
    const previewHost = el('div');
    evidenceCard.append(checklist, buildRow, previewHost);
    node.append(evidenceCard);
    const dispatchHost = el('div');
    node.append(dispatchHost);

    let currentContext = null; let selectionEpoch = 0; let contextEpoch = 0; const selections = [];
    function invalidatePreview() { selectionEpoch++; previewHost.replaceChildren(); dispatchHost.replaceChildren(); }
    const requirementPicker = governanceRequirementPicker(requirementsData, invalidatePreview);
    requirementPicker.node.hidden = profileSelect.value !== 'governance-assistant';
    const questionField = field('사람이 작성하는 감사 질문 · 선택 · 최대 500자', 'operatorQuestion', { multiline: true, wide: true, maxLength: 500, placeholder: '예: 이 사건의 제31조 고지 근거와 빠진 증거를 검토해 주세요.' });
    const questionInput = questionField.querySelector('textarea'); questionInput.addEventListener('input', invalidatePreview);
    intro.append(requirementPicker.node, questionField, el('p', 'muted', '질문은 고정된 감사 묶음과 검토 이력에 저장됩니다. 업무 AI의 원문 프롬프트·응답을 자동으로 가져오지 않습니다.'));
    profileSelect.addEventListener('change', () => { invalidatePreview(); requirementPicker.node.hidden = profileSelect.value !== 'governance-assistant'; });
    function renderChecklist(context) {
      checklist.replaceChildren(); selections.length = 0;
      const events = context.events || [];
      if (!events.length) { checklist.append(empty('선택할 원본 근거가 없습니다', '근거가 없는 상태로는 지원 요청을 만들 수 없습니다.')); return; }
      for (const event of events) {
        const row = el('label'); const cb = el('input'); cb.type = 'checkbox';
        cb.addEventListener('change', invalidatePreview);
        const ref = `${event.source}/${event.id}`;
        const caption = el('span');
        caption.append(el('strong', '', ref), el('span', 'muted', `${label(event.kind)} · ${date(event.occurredAt)} · ${event.actor || '행위자 미확인'} → ${event.tool || event.resource || '대상 미확인'}`));
        row.append(cb, caption); checklist.append(row);
        selections.push({ ref, checkbox: cb });
      }
    }
    async function loadContext() {
      const epoch = ++contextEpoch; selectionEpoch++; const caseId = caseSelect.value;
      checklist.replaceChildren(el('div', 'loading', '사건 근거를 조회하고 있습니다…'));
      previewHost.replaceChildren(); dispatchHost.replaceChildren(); currentContext = null;
      try {
        const context = await api(`/api/cases/${encodeURIComponent(caseId)}/review-context`);
        if (epoch !== contextEpoch || viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return;
        currentContext = context; renderChecklist(context);
      } catch (error) {
        if (epoch !== contextEpoch || viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return;
        checklist.replaceChildren(el('div', 'message error', error.message));
      }
    }
    caseSelect.addEventListener('change', loadContext);
    await loadContext();

    buildRow.append(button('축소된 근거 묶음 미리보기 만들기', async () => {
      if (!currentContext) throw new Error('먼저 사건 근거를 조회하세요.');
      const refs = selections.filter((s) => s.checkbox.checked).map((s) => s.ref);
      if (!refs.length) throw new Error('묶음에 포함할 근거를 하나 이상 선택하세요.');
      const requestOptions = assistanceRequestOptions(profileSelect.value, requirementPicker.value(), questionInput.value);
      const epoch = selectionEpoch; const profile = runtimeProfiles.find((p) => p.id === profileSelect.value);
      previewHost.replaceChildren(el('div', 'loading', '미리보기를 만들고 있습니다…')); dispatchHost.replaceChildren();
      const pkg = await api('/api/assistance/packages', 'POST', {
        caseId: caseSelect.value, contextHash: currentContext.contextHash, profileId: profileSelect.value,
        profileVersion: profile?.version, selectedEvidenceRefs: refs,
        ...requestOptions,
      });
      if (epoch !== selectionEpoch || viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return;
      previewHost.replaceChildren(packagePreview(pkg));
      dispatchHost.replaceChildren(card('3. 로컬 실행 전달', '이 단계부터는 명시적인 사람의 조치입니다.'));
      dispatchHost.lastChild.append(dispatchPanel(pkg, viewEpoch, authAtStart));
    }, 'primary small'));
    return node;
  }

  function runStateOf(item) { return item.state || item.status || 'unknown'; }
  async function runsList(viewEpoch, authAtStart) {
    const node = card('지원 실행 목록', '로컬 CLI가 자격 증명으로 실행한 작업입니다. 기계 출력은 사람의 승인이 아닙니다.');
    const data = await api('/api/assistance/runs');
    if (viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return node;
    const items = data.items || [];
    if (!items.length) { node.append(empty('실행 기록이 없습니다', '"새 지원 요청 만들기"에서 근거 묶음을 만들고 로컬 CLI로 실행하세요.')); return node; }
    node.append(table(['실행 ID', '역할 / 사건', '상태', '시작 / 갱신', '검토'], items.map((item) => {
      const stateNode = el('div', 'run-row-state'); stateNode.append(stateBadge(runStateOf(item)));
      if (item.stale) stateNode.append(el('span', 'stale-flag', item.reason || '최신 근거와 다를 수 있음 · 재확인 필요'));
      return [
        item.id, `${item.roleId || item.profileId || '미확인'} / ${item.caseId || '미확인'}`, stateNode,
        `${date(item.startedAt || item.createdAt)} / ${item.updatedAt ? date(item.updatedAt) : '미확인'}`,
        button('상세 · 검토', () => runDetail(item.id), 'small'),
      ];
    })));
    return node;
  }
  async function submitReview(run, pkg, payload) {
    const dialogContext = captureDetailContext();
    const caseId = pkg?.caseId || run.caseId;
    if (!caseId) throw new Error('사건 식별자를 확인할 수 없어 최신 근거 해시를 조회하지 못했습니다.');
    const context = await api(`/api/cases/${encodeURIComponent(caseId)}/review-context`);
    await api(`/api/assistance/runs/${encodeURIComponent(run.id)}/review`, 'POST', { ...payload, contextHash: context.contextHash });
    if (isCurrentDetail(dialogContext)) await runDetail(run.id);
    savedNotice(dialogContext, '검토 판단을 기록했습니다. 이 기록은 업무 AI의 실행 승인이나 정책 판정이 아닙니다.');
  }
  function draftContents(draft) {
    const node = el('div', 'raw-language');
    if (!draft || typeof draft !== 'object') { node.append(el('p', 'muted', '저장된 초안이 없습니다.')); return node; }
    if (draft.abstained) node.append(el('div', 'message warning', '초안 작성을 보류했습니다 (abstained).'));
    node.append(el('p', 'wrap', draft.summary || '요약 없음'));
    for (const finding of Array.isArray(draft.findings) ? draft.findings : []) {
      const item = el('div', 'finding-item');
      item.append(el('p', 'wrap', finding.claim || '내용 없음'), badge(finding.confidence || 'unknown'));
      if (finding.relation) item.append(el('span', 'muted', ` 근거 관계: ${label(finding.relation)}`));
      const refs = el('div', 'actions');
      for (const ref of Array.isArray(finding.evidenceRefs) ? finding.evidenceRefs : []) refs.append(el('span', 'mono wrap', ref));
      item.append(refs); node.append(item);
    }
    if (draft.findings?.length) node.append(el('p', 'confidence-note', '신뢰도(confidence)는 작성자가 보고한 값이며 사실 확인 결과와 다릅니다.'));
    if (draft.uncertainties?.length) node.append(jsonDetails('불확실 사항', draft.uncertainties));
    if (draft.limitations?.length) node.append(limits(draft.limitations));
    if (Array.isArray(draft.recommendedFollowUps) && draft.recommendedFollowUps.length) {
      const followUps = el('ul'); draft.recommendedFollowUps.forEach(text => followUps.append(el('li', '', text)));
      node.append(el('p', 'muted', '권장 후속 조치 · 검토를 위한 제안'), followUps);
    }
    node.append(jsonDetails('초안 전체 원문 · 불확실성·한계·후속 제안 포함', draft));
    return node;
  }
  function draftDiff(previous, current, previousLabel = '기계 원문') {
    const node = el('div');
    if (!previous || !current) { node.append(el('p', 'muted', '비교할 초안이 기록되지 않았습니다.')); return node; }
    const keys = [...new Set([...Object.keys(previous), ...Object.keys(current)])];
    const changed = keys.filter(key => stringify(previous[key]) !== stringify(current[key]));
    if (!changed.length) { node.append(el('p', 'muted', '초안 필드 변경 없음 · 원문 그대로 채택')); return node; }
    node.append(el('p', 'muted', `변경된 필드 ${changed.length}개 · 원문을 그대로 대조합니다.`));
    for (const key of changed) {
      const block = el('div', 'draft-diff');
      for (const [title, draft, className] of [[previousLabel, previous, ''], ['이 검토에 저장된 초안', current, 'changed-value']]) {
        const side = el('div', className);
        side.append(el('h5', '', `${key} · ${title}`), el('pre', '', Object.hasOwn(draft, key) ? stringify(draft[key]) : '(필드 없음)'));
        block.append(side);
      }
      node.append(block);
    }
    return node;
  }
  function reviewHistory(reviews, original) {
    const node = el('div'); let previous = original;
    if (!reviews.length) { node.append(el('p', 'muted', '아직 사람의 검토가 기록되지 않았습니다.')); return node; }
    const latest = reviews[reviews.length - 1];
    if ((latest.action || latest.decision) === 'accept') {
      const adopted = el('div', 'adopted-draft'); adopted.append(el('h4', '', '현재 채택된 사람 검토본'), draftContents(latest.draft)); node.append(adopted);
    } else if ((latest.action || latest.decision) === 'reject') node.append(el('p', 'message warning', '가장 최근 검토는 반려입니다. 이전 채택본은 이력으로만 표시합니다.'));
    else node.append(el('p', 'message warning', '최근 검토 상태를 확인할 수 없습니다. 저장된 기록을 확인하세요.'));
    reviews.forEach((review, index) => {
      const version = el('article', 'review-version');
      version.append(el('p', 'wrap', `${index + 1}차 검토 · ${rlabel(review.action || review.decision)} · ${review.reviewedBy || '검토자 미확인'} · ${date(review.createdAt || review.reviewedAt)}`));
      if (review.reason) version.append(el('p', 'wrap', review.reason));
      if (review.draft) {
        const comparison = el('details'); comparison.append(el('summary', '', index === 0 ? '기계 원문과 변경점' : '직전 저장 초안과 변경점'), draftDiff(previous, review.draft, previous === original ? '기계 원문' : '직전 저장 초안'));
        version.append(comparison, jsonDetails('이 검토에 저장된 초안 전체', review.draft)); previous = review.draft;
      }
      version.append(jsonDetails('검토 기록 원문', review)); node.append(version);
    });
    return node;
  }
  function runDetailNode(run, pkg) {
    const node = el('div');
    node.append(el('p', 'selection-note', `실행 ${run.id} · 상태 ${rlabel(runStateOf(run))}${run.stale ? ' · 최신성 불확실' : ''}`));
    if (run.stale) node.append(el('div', 'message warning', run.reason || run.staleReason || '이 실행 결과는 사건의 최신 근거와 달라졌을 수 있습니다. 최신 근거 기준으로 재확인하세요.'));
    node.append(el('p', 'muted', `묶음 ${run.packageId || '미확인'} · 사건 ${pkg?.caseId || run.caseId || '미확인'} · 등록 ${date(run.createdAt || run.queuedAt)} · 갱신 ${run.updatedAt ? date(run.updatedAt) : '미확인'}`));
    node.append(el('div', 'message warning', '아래 초안은 로컬 CLI 실행의 기계 출력입니다. 사람의 승인, 정책 점수, 실행 게이트, 법적 결론이 아니며 신뢰도 표시는 검증된 사실을 뜻하지 않습니다.'));

    const compare = el('div', 'review-compare');
    const evidenceSection = el('section'); evidenceSection.append(el('h4', '', '고정된 근거 (제출 시점 스냅샷)'));
    if (!pkg) evidenceSection.append(el('p', 'muted', '근거 묶음을 조회하지 못해 스냅샷을 표시할 수 없습니다.'));
    else { const snapshot = el('details'); snapshot.append(el('summary', '', `고정 근거 ${(pkg.evidence || []).length}건 · 역할·거버넌스 스냅샷 전체 확인`), packagePreview(pkg)); evidenceSection.append(snapshot); }
    const draftSection = el('section'); draftSection.append(el('h4', '', '기계가 생성한 원본 초안'), el('p', 'draft-language-note', '영문 분석을 포함한 원문을 번역 없이 보존합니다. 사람이 수정한 내용은 검토본과 변경 이력에서 따로 확인합니다.'));
    const draft = run.draft || run.result?.draft || null;
    const state = runStateOf(run);
    if (state === 'error' || state === 'failed') draftSection.append(el('p', 'message error', run.error || '실행 오류로 초안을 생성하지 못했습니다.'));
    else if (!draft) draftSection.append(el('p', 'muted', ['queued', 'running', 'pending'].includes(state) ? '아직 실행이 완료되지 않았습니다.' : '초안 데이터가 없습니다.'));
    else draftSection.append(draftContents(draft));

    const reviewSection = el('section'); reviewSection.append(el('h4', '', '사람의 검토'));
    const reviews = run.reviews || (run.review ? [run.review] : []);
    reviewSection.append(reviewHistory(reviews, draft));
    compare.append(evidenceSection, draftSection, reviewSection);
    node.append(compare);

    if (draft && state !== 'error' && state !== 'failed') {
      const actionsCard = el('div');
      actionsCard.append(el('h3', '', '검토 판단 기록'));
      const editableDraft = reviews.at(-1)?.action === 'accept' && reviews.at(-1)?.draft ? reviews.at(-1).draft : draft;
      actionsCard.append(button('기계 원문 그대로 채택', () => submitReview(run, pkg, { action: 'accept' }), 'primary small'));
      const editDetails = el('details');
      editDetails.append(el('summary', '', '현재 검토본의 요약을 수정한 뒤 채택'), form([
        field('수정한 요약', 'summary', { multiline: true, wide: true, value: editableDraft.summary || '', required: true, maxLength: 4000 }),
      ], '요약 수정 후 채택 기록', (values) => submitReview(run, pkg, { action: 'accept', editedDraft: { ...editableDraft, summary: values.summary.trim() } })));
      const rejectDetails = el('details');
      rejectDetails.append(el('summary', '', '반려 사유를 남기고 반려'), form([
        field('반려 사유', 'reason', { multiline: true, wide: true, required: true, maxLength: 2000 }),
      ], '반려로 기록', (values) => submitReview(run, pkg, { action: 'reject', reason: values.reason.trim() })));
      actionsCard.append(editDetails, rejectDetails); node.append(actionsCard);
    }
    return node;
  }
  async function runDetail(id) {
    showDetail('지원 실행 상세', el('div', 'loading', '실행과 근거 스냅샷을 조회하고 있습니다…'));
    const context = captureDetailContext();
    let run; let pkg = null;
    try {
      run = await api(`/api/assistance/runs/${encodeURIComponent(id)}`);
      if (!isCurrentDetail(context)) return;
      if (run.packageId) { try { pkg = await api(`/api/assistance/packages/${encodeURIComponent(run.packageId)}`); } catch { pkg = null; } }
      if (!isCurrentDetail(context)) return;
    } catch (error) { if (isCurrentDetail(context)) showDetail('실행 조회 실패', el('div', 'message error', error.message)); return; }
    showDetail('지원 실행 상세', runDetailNode(run, pkg));
  }

  async function assistanceView() {
    const viewEpoch = getRenderEpoch(); const authAtStart = getAuthEpoch();
    const requestedCaseId = pendingCaseId; pendingCaseId = null;
    const root = el('div');
    const tabs = el('div', 'assistance-tabs');
    const requestBtn = button('새 지원 요청 만들기', () => choose('request'));
    const runsBtn = button('지원 실행 목록', () => choose('runs'));
    tabs.append(requestBtn, runsBtn);
    const content = el('div');
    root.append(tabs, content);
    let mode = requestedCaseId ? 'request' : 'runs'; let modeEpoch = 0;
    async function choose(next) {
      mode = next; const requestEpoch = ++modeEpoch;
      requestBtn.setAttribute('aria-pressed', String(mode === 'request'));
      runsBtn.setAttribute('aria-pressed', String(mode === 'runs'));
      content.replaceChildren(el('div', 'loading', '불러오는 중…'));
      try {
        const rendered = mode === 'request' ? await requestBuilder(requestedCaseId, viewEpoch, authAtStart) : await runsList(viewEpoch, authAtStart);
        if (requestEpoch !== modeEpoch || viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return;
        content.replaceChildren(rendered);
      } catch (error) {
        if (requestEpoch !== modeEpoch || viewEpoch !== getRenderEpoch() || authAtStart !== getAuthEpoch()) return;
        content.replaceChildren(empty('불러오지 못했습니다', error.message));
      }
    }
    await choose(mode);
    return root;
  }

  registerView('team', '에이전트 팀', '개발 · 런타임 역할의 모델, 지침, 도구, 지식, 평가 범위와 개발 실행 이력을 확인합니다.', teamView);
  registerView('assistance', 'AI 검토 지원', '사건과 역할을 골라 근거 묶음을 만들고, 로컬 CLI 실행 결과를 사람이 검토합니다. 기계 출력은 승인이나 정책 판정이 아닙니다.', assistanceView);

  window.EvidScopeTeamSupport = Object.freeze({
    openForCase(caseId) { pendingCaseId = caseId; navigate('assistance'); },
  });
})();
