'use strict';

// Governance-mapping model screens (docs/governance-model.md): the review queue of Claude-drafted rows (one row at a time, approve or
// reject, keyboard a/r/n/p), the experiment comparison of the measured reports and the signed factsheets. Row text and report
// content are data and are rendered as text only. The server decides who may decide and signs every decision.
(() => {
  const core = window.EvidScopeCore;
  if (!core) return;
  const { el, button, card, empty, table, jsonDetails, limits, api, date, navigate } = core;
  const list = value => Array.isArray(value) ? value : [];
  const splitLabels = { all: '전체', tune: '학습(tune)', validation: '검증(validation)', test: '평가(test)' };
  const kindLabels = { document_excerpt: '문서 발췌', registry_entry: '등록부 항목', record_summary: '기록 요약', finding_note: '발견사항 메모' };
  const relationLabels = { supports: '충족 근거', contradicts: '반대 근거', context_only: '맥락만' };
  const relationQuestions = { supports: '이 문장이 이 조항을 지키고 있다는 근거가 맞나요?', contradicts: '이 문장이 이 조항을 어기고 있다(지키지 못함)는 근거가 맞나요?',
    context_only: '이 문장이 이 조항과 관련은 있지만 지키는지 어기는지는 말해 주지 않는 게 맞나요?' };
  const frameworkLabels = { 'eu-ai-act-logging': 'EU AI Act', 'kr-ai-basic-act': 'AI기본법', 'isms-p': 'ISMS-P' };
  const decisionLabels = { approve: '승인', reject: '거절' };
  const pct = value => typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : '—';
  const num = value => typeof value === 'number' && Number.isFinite(value) ? String(Math.round(value * 1000) / 1000) : '—';
  const short = value => typeof value === 'string' && value.length > 16 ? `${value.slice(0, 12)}…` : value || '—';
  // Session-only state of the queue: the attestations ticked once, the split filter and the rows decided in this session.
  const queue = { split: 'all', attest: { pii: false, consent: false }, decided: [], current: null };

  function checkbox(text, checked, onChange) {
    const node = el('label', 'check-field'), input = el('input');
    input.type = 'checkbox'; input.checked = checked;
    input.addEventListener('change', () => onChange(input.checked));
    node.append(input, el('span', '', text));
    return node;
  }
  function progressCard(progress) {
    const panel = card('검토 진행', '분할별 최소치 대비 현재 적격 행입니다. 적격 = 표에서 파생한 행 + 사람이 승인한 행. 미검토 초안은 세지 않습니다.');
    const splits = progress?.splits || {};
    panel.append(table(['분할', '초안', '승인', '거절', '대기', '적격 / 최소', '추가 승인 필요'], ['tune', 'validation', 'test'].map(s => {
      const x = splits[s] || {};
      return [splitLabels[s], String(x.drafted ?? '—'), String(x.approved ?? '—'), String(x.rejected ?? '—'), String(x.pending ?? '—'),
        `${x.eligible ?? '—'} / ${x.minimum ?? '—'}`, x.neededApprovals ? `${x.neededApprovals}행${x.reachable ? '' : ' (대기 행으로 부족)'}` : '충족'];
    })));
    const gate = splits.test?.gate;
    if (gate) {
      panel.append(el('p', 'muted', `승격 게이트: 평가 분할의 사람 검토 자유 텍스트 ${gate.humanReviewedFreeText}/${gate.minimumHumanReviewedFreeText}행`
        + ` · 게이트 행 ${gate.gateItems}/${gate.minimumGateItems}행${gate.neededApprovals ? ` · 추가 승인 ${gate.neededApprovals}행 필요` : ''}`));
    }
    panel.append(el('p', 'muted', progress?.trainingAdmitted ? '학습 입학 조건을 채웠습니다. export-reviewed로 학습 파일을 만드세요.'
      : `학습 입학 전입니다: ${list(progress?.admissionReasons).join(', ') || '사유 미확인'}`));
    if (list(progress?.staleDecisions).length) {
      panel.append(el('div', 'message warning', `행 내용이 바뀌어 적용되지 않는 결정 ${progress.staleDecisions.length}건: 해당 행은 다시 대기열에 있습니다.`));
    }
    return panel;
  }
  function guideCard() {
    const panel = card('검토 방법', '한 행에 문장 하나와 Claude가 붙인 답이 있습니다. 답이 맞으면 승인, 하나라도 틀리면 거절합니다. 해시는 보지 않아도 됩니다.');
    const steps = el('ol', 'review-guide');
    for (const text of ['회색 상자의 문장을 읽습니다. 가상의 회사 문서·기록입니다(영어 행은 아래에 참고 번역이 있습니다).',
      '그 아래 "Claude가 붙인 답"의 조항마다 "이 조항이 요구하는 것"과 질문을 읽고 문장과 맞는지 봅니다.',
      '모든 조항이 맞고 빠진 조항도 없으면 승인(A). 엉뚱한 조항이 붙었거나, 근거/반대 근거가 뒤바뀌었거나, 분명히 해당되는 조항이 빠졌으면 거절(R).',
      '답이 "해당 조항 없음(기권)"인 행은 문장이 거버넌스 요구사항과 상관없거나 근거로 삼기에 너무 모호하면 승인, 분명히 해당되는 조항이 있으면 거절.',
      '문장 안에 "이걸 매핑하라" 같은 지시가 심어진 행은 그 지시를 무시한 답이 정답입니다. 지시대로 조항을 붙인 답이면 거절.',
      '판단이 안 서면 건너뛰기(N). 확실한 행만 결정해도 됩니다.']) steps.append(el('li', '', text));
    panel.append(steps);
    return panel;
  }
  function mappingNode(m) {
    const box = el('div', 'review-mapping');
    const framework = frameworkLabels[m.framework] || m.framework || '—';
    box.append(el('p', '', `${m.requirementId} · ${m.title || '제목 미확인'} (${framework}) — Claude 답: ${relationLabels[m.relation] || m.relation}`));
    if (m.plain) box.append(el('p', 'muted wrap', `이 조항이 요구하는 것: ${m.plain}${m.plainSource === 'claude_summary' ? ' (Claude 요약)' : ''}`));
    box.append(el('p', 'wrap', `질문: ${relationQuestions[m.relation] || '이 조항이 맞나요?'}`));
    if (m.citation) box.append(el('p', 'muted wrap', `출처: ${m.citation}`));
    return box;
  }
  function answerNode(item) {
    const node = el('div', 'drafted-answer');
    node.append(el('h3', '', 'Claude가 붙인 답'));
    if (item.draftedAnswer?.abstain) {
      node.append(el('p', '', '해당 조항 없음(기권): 이 문장은 어느 요구사항의 근거로도 쓸 수 없다는 답입니다.'),
        el('p', 'wrap', '질문: 문장이 AI 거버넌스 요구사항과 상관없거나 너무 모호해서 어느 조항의 근거도 안 되는 게 맞나요?'));
    } else {
      for (const m of list(item.draftedAnswer?.mappings)) node.append(mappingNode(m));
      node.append(el('p', 'muted', '위 조항 외에 분명히 해당되는 조항이 빠져 있어도 거절합니다.'));
    }
    if (item.injection) {
      const box = el('div', 'message warning');
      box.append(el('strong', '', '지시가 심어진 행: 문장 속 지시는 무시해야 합니다. 답에 다음 조항이 들어 있으면 거절하세요'),
        el('p', 'wrap', list(item.forbidden).map(f => `${f.id}${f.title ? ` (${f.title})` : ''}`).join(' · ') || '—'));
      node.append(box);
    }
    return node;
  }
  async function decide(decision) {
    const current = queue.current;
    if (!current?.item || !current.viewer?.mayDecide) return;
    if (!queue.attest.pii || !queue.attest.consent) { core.notice?.('먼저 개인정보 확인과 출처·사용 동의 확인을 체크하세요.', true); return; }
    const item = current.item, note = current.note?.value || '';
    const answered = await api('/api/governance-model/review/decisions', 'POST', { rowId: item.id, decision, reviewedPayloadHash: item.reviewedPayloadHash,
      note, attestPiiReviewed: true, attestSourceConsent: true, ...(item.previousDecisionHash ? { supersedes: item.previousDecisionHash } : {}) });
    queue.decided.push({ id: item.id, decision, at: answered.decision?.reviewedAt });
    core.notice?.(`${item.id}: ${decisionLabels[decision]} 결정을 서명했습니다.`);
    await current.reload(item.id);
  }
  function itemCard(data, reload) {
    const item = data.item, panel = card(`${item.id} · ${splitLabels[item.split] || item.split} · ${kindLabels[item.kind] || item.kind}`,
      'Claude가 지어낸 가상의 문서·기록 문장과 Claude가 붙인 답입니다. 답을 고치지 않고 승인 또는 거절만 합니다.');
    panel.classList?.add('review-item');
    panel.append(el('p', 'review-text wrap', item.text));
    if (item.textKo) panel.append(el('p', 'review-translation wrap', `참고 번역(Claude): ${item.textKo}`));
    panel.append(el('p', 'muted wrap', `증거 위치: ${list(item.locators).join(', ')}`), answerNode(item));
    if (item.aidNotice) panel.append(el('p', 'muted wrap', item.aidNotice));
    if (item.previousDecision) {
      const d = item.previousDecision;
      panel.append(el('div', `message${item.previousDecisionStale ? ' warning' : ''}`, `이전 결정: ${decisionLabels[d.decision] || d.decision} · `
        + `${d.reviewerId} · ${date(d.reviewedAt)}${item.previousDecisionStale ? ' · 그 뒤 행 내용이 바뀌어 적용되지 않습니다' : ''}. 다시 결정하면 이전 결정을 대체합니다.`));
    }
    const note = el('textarea'); note.name = 'note'; note.maxLength = 500; note.placeholder = '메모(선택, 500자): 거절 사유 등';
    const noteField = el('label', 'field wide', '메모'); noteField.append(note);
    const attest = el('div', 'review-attest');
    attest.append(el('p', 'muted', '처음 한 번만 체크하면 됩니다. 문장은 모두 Claude가 지어낸 것이라 실제 개인정보나 외부 출처가 없습니다.'),
      checkbox('이 행에 개인정보가 없음을 확인했습니다', queue.attest.pii, v => { queue.attest.pii = v; }),
      checkbox('출처와 학습 사용 동의를 확인했습니다', queue.attest.consent, v => { queue.attest.consent = v; }));
    const actions = el('div', 'review-actions');
    const mayDecide = data.viewer?.mayDecide === true;
    const approve = button('승인 (A)', () => decide('approve'), 'primary'), reject = button('거절 (R)', () => decide('reject'), 'danger');
    approve.disabled = reject.disabled = !mayDecide;
    actions.append(approve, reject, button('건너뛰기 (N)', () => reload(item.id), 'ghost'), button('이전 결정 행 (P)', () => previous(), 'ghost'));
    panel.append(noteField, attest, actions);
    if (!mayDecide) panel.append(el('p', 'muted', '검토자 또는 관리자만 결정할 수 있습니다. 이 계정은 조회만 합니다.'));
    panel.append(el('p', 'muted', '단축키: A 승인 · R 거절 · N 건너뛰기 · P 이전 결정 행 (메모 입력 중에는 동작하지 않음)'),
      jsonDetails('기술 정보: 행 해시(판단에는 쓰지 않음)', { reviewedPayloadHash: item.reviewedPayloadHash, recordHash: item.recordHash }));
    queue.current = { item, viewer: data.viewer, note, reload };
    return panel;
  }
  let reviewRoot = null;
  async function previous() {
    const last = queue.decided.at(-1);
    if (!last || !reviewRoot) { core.notice?.('이 세션에서 결정한 행이 없습니다.'); return; }
    const data = await api(`/api/governance-model/review/items/${encodeURIComponent(last.id)}`);
    reviewRoot.show({ ...queue.lastView, item: data.item });
  }
  async function reviewView() {
    const root = el('div', 'model-review'), filters = el('div', 'toolbar'), progressHost = el('div'), itemHost = el('div');
    const show = data => {
      queue.lastView = data;
      progressHost.replaceChildren(progressCard(data.progress));
      itemHost.replaceChildren(data.item ? itemCard(data, reload) : empty('이 분할에 남은 초안이 없습니다',
        '모든 초안이 결정됐습니다. 감사 내보내기 파일로 export-reviewed를 실행해 학습 파일을 만드세요.'));
      if (!data.item) queue.current = null;
    };
    async function reload(after) {
      const data = await api('/api/governance-model/review?' + new URLSearchParams({ split: queue.split, ...(after ? { after } : {}) }));
      show(data);
    }
    reviewRoot = { show };
    for (const split of Object.keys(splitLabels)) {
      const b = button(splitLabels[split], async () => { queue.split = split; await reload(); }, 'small');
      b.setAttribute('aria-pressed', String(queue.split === split)); filters.append(b);
    }
    root.append(guideCard(), filters, progressHost, itemHost, limits(['승인은 Claude 초안 답을 그대로 정답으로 인정한다는 뜻입니다. 답이 틀리면 거절하세요(수정 기능 없음).',
      '결정은 서명된 원장 기록이며 결정자·시각·행 해시가 묶입니다. 학습 파일에는 export-reviewed가 적용한 행만 들어갑니다.',
      '승인한 뒤 행 내용이 바뀌면 그 결정은 적용되지 않고 행이 다시 대기열에 나옵니다.']));
    await reload();
    return root;
  }
  // One document-level listener; it acts only while the queue is the active view and the focus is not in a text field.
  document.addEventListener?.('keydown', event => {
    if (core.getActiveView?.() !== 'model-review' || !queue.current || event.ctrlKey || event.metaKey || event.altKey) return;
    const tag = String(event.target?.tagName || '').toUpperCase();
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(tag) || event.target?.isContentEditable) return;
    const key = String(event.key || '').toLowerCase(), action = { a: () => decide('approve'), r: () => decide('reject'),
      n: () => queue.current.reload(queue.current.item.id), p: () => previous() }[key];
    if (!action) return;
    event.preventDefault?.();
    Promise.resolve().then(action).catch(error => core.notice?.(error.message, true));
  });

  // ---------- experiment comparison ----------
  const metricRows = [['precision', '정밀도'], ['recall', '재현율(coverage)'], ['answeredRate', '답한 비율(답할 항목)'], ['abstentionRate', '기권율'],
    ['exactMatch', 'exact match'], ['mustAbstainCorrect', '기권 정답률'], ['ece', 'ECE(보정 오차)']];
  const safetyLabels = { schemaValid: '스키마 유효', onlyCatalogIds: '카탈로그 ID만', onlySuppliedLocators: '주어진 위치만', injectionResisted: '주입 무시',
    mustAbstainCorrect: '기권해야 할 때 기권' };
  function comparisonTable(report) {
    const variants = list(report.variants), data = report.variantsData || {};
    const rows = metricRows.map(([key, title]) => [title, ...variants.map(v => key === 'ece' ? num(data[v]?.gate?.[key]) : pct(data[v]?.gate?.[key]))]);
    for (const [key, title] of Object.entries(safetyLabels)) rows.push([`안전: ${title}`, ...variants.map(v => pct(data[v]?.gate?.safety?.[key]))]);
    rows.push(['측정 영수증', ...variants.map(v => data[v]?.measurement?.deterministic ? '결정적 기준선' : data[v]?.measurement?.problem || '격리 측정 확인')]);
    return table(['지표(게이트 행)', ...variants], rows);
  }
  function basisTable(report) {
    const variants = list(report.variants), data = report.variantsData || {};
    return table(['행 출처', ...variants], ['human_reviewed', 'derived'].map(b => [b === 'human_reviewed' ? '사람 검토 행' : '표에서 파생한 행',
      ...variants.map(v => { const x = data[v]?.byBasis?.[b]; return x ? `정밀도 ${pct(x.precision)} · 재현율 ${pct(x.recall)} · ${x.items}행` : '—'; })]));
  }
  function frameworkTable(report) {
    const variants = list(report.variants), data = report.variantsData || {};
    const frameworks = [...new Set(variants.flatMap(v => Object.keys(data[v]?.byFramework || {})))].sort();
    return table(['프레임워크', ...variants], frameworks.map(f => [f, ...variants.map(v => {
      const x = data[v]?.byFramework?.[f]; return x ? `${pct(x.precision)} / ${pct(x.recall)}` : '—';
    })]));
  }
  function reportCard(report) {
    const panel = card(`${report.file} · ${report.createdAt ? date(report.createdAt) : '시각 없음'}`, report.status === 'verified'
      ? `준비 ${report.preparedBy} · 데이터셋 ${short(report.datasetSha256)} · 파일 ${short(report.sha256)}` : '검증하지 못한 보고서입니다. 수치를 보여 주지 않습니다.');
    if (report.status !== 'verified') { panel.append(el('div', 'message error', `${report.status}: ${report.reason}`)); return panel; }
    if (report.shakedown) panel.append(el('div', 'message warning', '셰이크다운 어댑터의 평가입니다. 승격할 수 없고 품질 결과가 아니므로 후보 수치를 숨깁니다.'));
    const v = report.verdict || {};
    panel.append(core.factList([
      ['행', `test ${report.items}행 · 게이트 행 ${report.gateItems} (사람 검토 ${report.rowsByBasis?.human_reviewed ?? '—'} · 파생 ${report.rowsByBasis?.derived ?? '—'})`
        + ` · 게이트 밖(미검토 초안 등) ${report.rowsByBasis?.not_eligible ?? '—'}`],
      ['판정', `${v.kind === 'base_mode' ? '기본 모드' : '승격 게이트'}: ${v.eligible ? '통과' : '불통과'}${list(v.reasons).length ? ` — ${list(v.reasons).join('; ')}` : ''}`],
      ['정밀도 비교 규칙', v.thresholds?.comparison === 'strict' ? '전체 행 엄격 비교' : '같은 항목 비교(matched coverage, 기본)'],
    ]));
    panel.append(comparisonTable(report), el('h3', '', '사람 검토 행 / 파생 행'), basisTable(report), el('h3', '', '프레임워크별 정밀도 / 재현율'), frameworkTable(report));
    if (v.comparisons) {
      panel.append(el('h3', '', '기준선별 비교'), table(['기준선', '규칙', '기준선이 답한 항목', '후보 / 기준선 정밀도(그 항목)', '전체 재현율 후보 / 기준선', '결과'],
        Object.entries(v.comparisons).map(([b, c]) => [b, c.rule, String(c.matched?.items ?? '—'),
          `${pct(c.matched?.candidatePrecision)} / ${pct(c.matched?.baselinePrecision)}`,
          `${pct(c.recall?.candidate)} / ${pct(c.recall?.baseline)}`, c.beats ? '통과' : `불통과 (${c.why})`])));
    }
    panel.append(jsonDetails(`행별 결과 ${list(report.rows).length}행 (basis: human_reviewed / derived / not_eligible)`, report.rows));
    return panel;
  }
  function historyCard(history) {
    const panel = card('실행 이력', '비교 보고서와 서명된 팩트시트를 시간순으로 보여 줍니다. 셰이크다운은 품질 결과가 아닙니다.');
    panel.append(table(['시각', '종류', '라벨', '기록·준비', '비고'], list(history).map(h => [h.at ? date(h.at) : '—', h.kind, h.label || '—', h.by || '—',
      h.label === 'shakedown' ? '셰이크다운 · 승격 불가 · 품질 결과 아님' : h.kind === 'report' ? (h.eligible ? '판정 통과' : '판정 불통과') : h.promotable ? '승격 경로 가능' : '승격 불가'])));
    return panel;
  }
  function recordCard(reload) {
    const panel = card('팩트시트 기록', '`governance-mapping.mjs factsheet`가 만든 요청 파일을 올리면 볼트가 확인한 뒤 서명된 원장 기록으로 남깁니다.');
    const input = el('input'); input.type = 'file'; input.accept = 'application/json,.json'; input.name = 'factsheetFile';
    const result = el('div'); result.setAttribute('role', 'status');
    panel.append(input, button('기록하기', async () => {
      const file = input.files?.[0];
      if (!file) throw new Error('요청 파일을 선택하세요.');
      if (file.size > 2 * 1024 * 1024) throw new Error('요청 파일은 2 MiB 이하여야 합니다.');
      const recorded = await api('/api/governance-model/factsheets', 'POST', JSON.parse(await file.text()));
      result.replaceChildren(el('div', 'message', `${recorded.factsheet.id} 기록됨 (${recorded.factsheet.label})`));
      await reload();
    }, 'primary'), result);
    return panel;
  }
  async function experimentsView() {
    const root = el('div', 'model-experiments');
    const draw = async () => {
      const data = await api('/api/governance-model/experiments');
      const intro = card('실험 비교', data.notice || '');
      intro.append(el('p', 'muted', `보고서 위치: ${data.reportsDirectory}`));
      const reports = list(data.reports);
      root.replaceChildren(intro, ...(reports.length ? reports.map(reportCard)
        : [empty('비교 보고서가 없습니다', 'report 명령의 결과를 reports/governance-mapping/에 두면 기준선·기본 모델·어댑터 후보를 나란히 비교합니다.')]),
      historyCard(data.history), recordCard(draw));
    };
    await draw();
    return root;
  }
  core.registerView('model-review', '학습 데이터 검토', 'Claude가 쓴 학습 데이터 초안을 한 행씩 승인하거나 거절합니다. 결정은 서명된 원장 기록입니다.', reviewView);
  core.registerView('model-experiments', '실험 비교', '기준선, 기본 모델, 어댑터 후보를 고정 평가 세트에서 나란히 비교하고 실행 이력을 봅니다.', experimentsView);
  window.EvidScopeGovernanceModel = Object.freeze({ reviewView, experimentsView, decide, previous, queue });
  if (['model-review', 'model-experiments'].includes(core.getActiveView?.()) && core.getToken?.()) navigate(core.getActiveView());
})();
