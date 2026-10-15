'use strict';

// Operations views (Datadog/Grafana style): the dashboard of activity and risk over a time window, and the log explorer with
// search, automatic categories, facets, a time histogram and live tail. Both read /api/dashboard and /api/logs only; categories
// are a reading aid computed by the server, never a verdict. Everything is rendered through DOM text nodes.
(() => {
  const core = window.EvidScopeCore;
  if (!core) return;
  const { el, button, empty, limits, api, navigate } = core;
  const SVG = 'http://www.w3.org/2000/svg';
  const store = {
    get(key, fallback) {
      try {
        return localStorage.getItem(`evidscope.${key}`) || fallback;
      } catch {
        return fallback;
      }
    },
    set(key, value) {
      try {
        localStorage.setItem(`evidscope.${key}`, value);
      } catch {
        /* private window: keep the choice for this page only */
      }
    },
  };

  const RANGES = [
    ['15m', '최근 15분'],
    ['1h', '최근 1시간'],
    ['4h', '최근 4시간'],
    ['24h', '최근 24시간'],
    ['7d', '최근 7일'],
    ['30d', '최근 30일'],
  ];
  const REFRESH = [
    ['0', '자동 새로고침 끔'],
    ['10', '10초마다'],
    ['30', '30초마다'],
    ['60', '1분마다'],
  ];
  const AGENTS = { 'claude-code': 'Claude Code', codex: 'Codex' };
  const LABELS = {
    category: {
      secret: '비밀정보 접근',
      delete: '삭제·강제 변경',
      network: '외부 전송·접속',
      package: '패키지 설치',
      git: 'Git',
      build: '빌드·실행',
      system: '시스템 설정',
      shell: '기타 셸 명령',
      file_read: '파일 읽기',
      file_write: '파일 수정',
      file_search: '파일 검색',
      web: '웹 조회',
      subagent: '하위 에이전트',
      mcp: 'MCP 도구',
      tool_call: '기타 도구',
      authority: '권한·승인',
      collection_gap: '수집 공백',
      tool_record: '도구 실행 기록',
      telemetry: '텔레메트리',
      enforcement: '집행 지점',
      other: '기타',
    },
    kind: {
      intent: '실행 전 기록',
      self_report: '실행 후 결과',
      execution: '도구 실행',
      result: '도구 결과',
      grant: '권한 부여',
      revoke: '권한 회수',
      human_approval: '사람 승인',
      automated_review: '자동 검토',
      delegation: '위임',
      gap: '수집 공백',
      heartbeat: '생존 신호',
      notice: '알림',
    },
    status: { requested: '요청됨', success: '성공', failure: '실패', none: '상태 없음' },
    risk: { none: '위험 없음', critical: '치명', high: '높음', medium: '중간', low: '낮음', info: '정보' },
    collection: { live: '실시간 수집', history_import: '과거 기록 가져오기' },
    data: { real: '실제 기록', synthetic: '합성(데모·시험)' },
    agent: AGENTS,
  };
  const FACET_TITLES = [
    ['agent', '에이전트'],
    ['category', '분류'],
    ['risk', '위험'],
    ['status', '상태'],
    ['kind', '기록 종류'],
    ['collection', '수집 방식'],
    ['actor', '행위자'],
    ['data', '데이터'],
  ];
  const labelOf = (facet, value) => LABELS[facet]?.[value] || value;
  const agentClass = value => (value === 'claude-code' ? 'a-claude' : value === 'codex' ? 'a-codex' : 'a-other');
  const count = n => (Number.isFinite(n) ? n.toLocaleString('ko-KR') : '—');
  const pad = n => String(n).padStart(2, '0');
  function clock(ms, withDate) {
    const d = new Date(ms),
      time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    return withDate ? `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}` : time;
  }
  function stamp(iso) {
    const d = new Date(iso),
      today = new Date().toDateString() === d.toDateString();
    return `${today ? '' : `${pad(d.getMonth() + 1)}-${pad(d.getDate())} `}${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }
  function ago(iso) {
    const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    return s < 60
      ? `${s}초 전`
      : s < 3600
        ? `${Math.floor(s / 60)}분 전`
        : s < 86400
          ? `${Math.floor(s / 3600)}시간 전`
          : `${Math.floor(s / 86400)}일 전`;
  }
  const svg = (tag, attrs = {}) => {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    return n;
  };
  const sev = value => el('span', `sev sev-${/^[a-z]+$/.test(value) ? value : 'none'}`, labelOf('risk', value));

  // --- Shared state: time range, refresh interval, theme ---------------------------------------------------------------------
  const state = { range: store.get('range', '24h'), refresh: store.get('refresh', '30') };
  if (!RANGES.some(([v]) => v === state.range)) state.range = '24h';
  const logState = { q: '', filters: {}, from: null, to: null, live: false };

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.content = theme === 'light' ? 'light' : 'dark';
    const toggle = document.querySelector('#theme-toggle');
    if (toggle) toggle.textContent = theme === 'light' ? '어둡게' : '밝게';
  }
  function select(choices, value, onChange, title) {
    const node = el('select', 'ops-select');
    node.title = title;
    node.setAttribute('aria-label', title);
    for (const [v, text] of choices) {
      const o = el('option', '', text);
      o.value = v;
      node.append(o);
    }
    node.value = value;
    node.addEventListener('change', () => onChange(node.value));
    return node;
  }
  function topbarControls() {
    const host = document.querySelector('.top-actions');
    if (!host || host.querySelector('.ops-time')) return;
    const group = el('div', 'ops-time');
    group.append(
      select(
        RANGES,
        state.range,
        value => {
          state.range = value;
          store.set('range', value);
          logState.from = logState.to = null;
          rerender();
        },
        '조회 기간',
      ),
      select(
        REFRESH,
        state.refresh,
        value => {
          state.refresh = value;
          store.set('refresh', value);
          rerender();
        },
        '자동 새로고침',
      ),
    );
    const theme = el('button', 'ghost', '');
    theme.type = 'button';
    theme.id = 'theme-toggle';
    theme.addEventListener('click', () => {
      const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
      store.set('theme', next);
      applyTheme(next);
    });
    host.prepend(group);
    host.append(theme);
    const sync = () => {
      group.hidden = !['dashboard', 'logs'].includes(document.body.dataset.workspaceView);
    };
    new MutationObserver(sync).observe(document.body, { attributes: true, attributeFilter: ['data-workspace-view'] });
    sync();
  }
  const rerender = () => {
    const view = core.getActiveView();
    if (view === 'dashboard' || view === 'logs') navigate(view);
  };
  // Runs fn every `seconds` while the view that started it is still on screen.
  function every(seconds, fn) {
    const epoch = core.getRenderEpoch();
    if (!seconds) return;
    const tick = async () => {
      if (core.getRenderEpoch() !== epoch) return;
      if (!document.hidden) {
        try {
          await fn();
        } catch {
          /* the next tick tries again; the panel keeps its last values */
        }
      }
      if (core.getRenderEpoch() === epoch) setTimeout(tick, seconds * 1000);
    };
    setTimeout(tick, seconds * 1000);
  }

  // --- Charts --------------------------------------------------------------------------------------------------------------
  // Stacked bars over the histogram points. series: [{key, label, cls, value(point)}]. onPick(point, index) zooms in.
  function barChart(points, series, { height = 160, bucketMs, onPick, empty: emptyText = '기간 안에 기록이 없습니다' } = {}) {
    const wrap = el('div', 'chart');
    const totals = points.map(p => series.reduce((n, s) => n + s.value(p), 0)),
      max = Math.max(1, ...totals);
    if (!totals.some(Boolean)) wrap.classList.add('chart-empty');
    const nice = max <= 5 ? max : Math.ceil(max / Math.pow(10, Math.floor(Math.log10(max)) - 1)) * Math.pow(10, Math.floor(Math.log10(max)) - 1);
    const plot = el('div', 'chart-plot');
    plot.style.height = `${height}px`;
    const yAxis = el('div', 'chart-y');
    for (const f of [1, 0.5, 0]) {
      const t = el('span', '', count(Math.round(nice * f)));
      yAxis.append(t);
    }
    const W = Math.max(points.length, 1) * 10,
      s = svg('svg', { viewBox: `0 0 ${W} 100`, preserveAspectRatio: 'none', class: 'chart-svg', role: 'img' });
    for (const f of [0, 0.5, 1]) s.append(svg('line', { x1: 0, x2: W, y1: 100 - f * 100, y2: 100 - f * 100, class: 'grid' }));
    points.forEach((p, i) => {
      let y = 100;
      for (const ser of series) {
        const v = ser.value(p);
        if (!v) continue;
        const h = (v / nice) * 100;
        y -= h;
        s.append(svg('rect', { x: i * 10 + 1, y, width: 8, height: h, class: `bar ${ser.cls}` }));
      }
      const hit = svg('rect', { x: i * 10, y: 0, width: 10, height: 100, class: 'hit' });
      hit.dataset.i = i;
      s.append(hit);
    });
    const tip = el('div', 'chart-tip');
    tip.hidden = true;
    const withDate = bucketMs >= 3600e3 * 4 || (points.length && Date.parse(points.at(-1).at) - Date.parse(points[0].at) > 86400e3);
    s.addEventListener('mousemove', event => {
      const i = Number(event.target?.dataset?.i);
      if (!Number.isInteger(i)) {
        tip.hidden = true;
        return;
      }
      const p = points[i],
        start = Date.parse(p.at);
      tip.replaceChildren(el('strong', '', `${clock(start, withDate)} – ${clock(start + (bucketMs || 0), withDate)}`));
      for (const ser of series) {
        const row = el('div', 'tip-row');
        row.append(el('i', `dot ${ser.cls}`), el('span', '', ser.label), el('b', '', count(ser.value(p))));
        tip.append(row);
      }
      if (onPick) tip.append(el('small', '', '클릭하면 이 구간의 기록을 봅니다'));
      tip.hidden = false;
      const box = plot.getBoundingClientRect(),
        x = event.clientX - box.left;
      tip.style.left = `${Math.min(Math.max(x + 12, 0), box.width - 190)}px`;
    });
    s.addEventListener('mouseleave', () => {
      tip.hidden = true;
    });
    if (onPick) {
      s.classList.add('pickable');
      s.addEventListener('click', event => {
        const i = Number(event.target?.dataset?.i);
        if (Number.isInteger(i)) onPick(points[i], i);
      });
    }
    plot.append(s, tip);
    const body = el('div', 'chart-body');
    body.append(yAxis, plot);
    wrap.append(body);
    const xAxis = el('div', 'chart-x');
    const ticks = Math.min(6, points.length);
    for (let k = 0; k < ticks; k++) {
      const i = Math.round((k * (points.length - 1)) / Math.max(1, ticks - 1));
      xAxis.append(el('span', '', clock(Date.parse(points[i].at), withDate)));
    }
    wrap.append(xAxis);
    if (!totals.some(Boolean)) wrap.append(el('div', 'chart-empty-text', emptyText));
    const legend = el('div', 'legend');
    for (const ser of series) {
      const item = el('span', '');
      item.append(el('i', `dot ${ser.cls}`), document.createTextNode(ser.label));
      legend.append(item);
    }
    wrap.append(legend);
    return wrap;
  }
  function sparkline(values, cls) {
    const max = Math.max(1, ...values),
      W = Math.max(values.length - 1, 1) * 4;
    const s = svg('svg', { viewBox: `0 0 ${W} 30`, preserveAspectRatio: 'none', class: `spark ${cls}` });
    const pts = values.map((v, i) => `${i * 4},${(28 - (v / max) * 26).toFixed(1)}`);
    s.append(
      svg('polygon', { points: `0,30 ${pts.join(' ')} ${W},30`, class: 'spark-area' }),
      svg('polyline', { points: pts.join(' '), class: 'spark-line' }),
    );
    return s;
  }
  function panel(title, options = {}) {
    const node = el('section', `ops-panel ${options.span ? `span-${options.span}` : ''} ${options.cls || ''}`.trim());
    const head = el('header', 'ops-panel-head');
    head.append(el('h2', '', title));
    if (options.hint) {
      const hint = el('span', 'ops-hint', 'ⓘ');
      hint.title = options.hint;
      hint.setAttribute('aria-label', options.hint);
      head.append(hint);
    }
    if (options.action) head.append(options.action);
    const body = el('div', 'ops-panel-body');
    node.append(head, body);
    node.body = body;
    return node;
  }
  function stat(title, value, { spark, sparkCls = 'k-total', tone = '', sub, onClick, hint } = {}) {
    const node = panel(title, { cls: `ops-stat ${tone}`, hint });
    node.body.append(el('div', 'stat-big', count(value)));
    if (sub) node.body.append(sub);
    if (spark) node.body.append(sparkline(spark, sparkCls));
    if (onClick) {
      node.classList.add('clickable');
      node.tabIndex = 0;
      node.addEventListener('click', onClick);
      node.addEventListener('keydown', e => {
        if (e.key === 'Enter') onClick();
      });
    }
    return node;
  }
  const openLogs = (preset = {}) => {
    Object.assign(logState, { q: '', filters: {}, from: null, to: null, live: false }, preset);
    return navigate('logs');
  };

  // --- Dashboard -----------------------------------------------------------------------------------------------------------
  async function dashboard() {
    const root = el('div', 'ops ops-dashboard');
    const load = async () => {
      const [board, recent] = await Promise.all([
        api(`/api/dashboard?range=${state.range}`),
        api(`/api/logs?range=${state.range}&limit=200&data=real`),
      ]);
      return { board, recent };
    };
    const draw = ({ board, recent }) => {
      const pts = board.histogram.points,
        st = board.stats,
        bucketMs = board.histogram.bucketMs;
      const grid = el('div', 'ops-grid');
      const severity = el('div', 'sev-row');
      for (const key of ['critical', 'high', 'medium', 'low']) {
        const chip = el('span', `sev-chip sev-${key}`);
        chip.append(el('b', '', count(st.bySeverity[key] || 0)), document.createTextNode(labelOf('risk', key)));
        severity.append(chip);
      }
      grid.append(
        stat('수집된 기록', st.events, {
          spark: pts.map(p => p.total),
          hint: '기간 안에 수신된 실제 기록(합성 데모 제외)',
          onClick: () => openLogs(),
        }),
        stat('AI 도구 호출', st.agentEvents, {
          spark: pts.map(p =>
            Object.entries(p.byAgent)
              .filter(([a]) => a in AGENTS)
              .reduce((n, [, v]) => n + v, 0),
          ),
          hint: 'Claude Code·Codex가 보낸 실행 전·후 기록',
          onClick: () => openLogs({ filters: { agent: ['claude-code', 'codex'] } }),
        }),
        stat('세션', st.sessions, { sub: el('div', 'stat-sub', `행위자 ${count(st.actors)}명 · 행동 ${count(st.actions)}건`) }),
        stat('위험 행동', st.riskyActions, {
          spark: pts.map(p => p.risky),
          sparkCls: 'k-risky',
          tone: st.riskyActions ? 'tone-bad' : 'tone-ok',
          hint: '최신 평가에서 열린 발견이 있는 행동',
          onClick: () => openLogs({ filters: { risk: ['critical', 'high', 'medium', 'low', 'info'] } }),
        }),
        stat('실패한 호출', st.failures, {
          spark: pts.map(p => p.failures),
          sparkCls: 'k-fail',
          tone: st.failures ? 'tone-warn' : '',
          onClick: () => openLogs({ filters: { status: ['failure'] } }),
        }),
        stat('열린 경보', st.alerts, {
          sub: severity,
          tone: st.bySeverity.critical || st.bySeverity.high ? 'tone-bad' : '',
          onClick: () => navigate('alerts'),
        }),
      );

      const agentsSeen = [...new Set(pts.flatMap(p => Object.keys(p.byAgent)))].sort((a, b) => (b in AGENTS) - (a in AGENTS) || a.localeCompare(b));
      const activity = panel('에이전트별 활동', {
        span: 8,
        hint: '시간 구간마다 받은 기록 수를 에이전트별로 쌓았습니다. 막대를 클릭하면 그 구간의 로그로 이동합니다',
      });
      activity.body.append(
        barChart(
          pts,
          agentsSeen.map(a => ({ key: a, label: labelOf('agent', a), cls: agentClass(a), value: p => p.byAgent[a] || 0 })),
          { height: 190, bucketMs, onPick: p => openLogs({ from: p.at, to: new Date(Date.parse(p.at) + bucketMs).toISOString() }) },
        ),
      );
      grid.append(activity, sourcesPanel(recent, st));

      const risk = panel('위험·실패 추이', { span: 6 });
      risk.body.append(
        barChart(
          pts,
          [
            { label: '위험 발견', cls: 'k-risky', value: p => p.risky },
            { label: '실패', cls: 'k-fail', value: p => p.failures },
          ],
          {
            height: 130,
            bucketMs,
            empty: '기간 안에 위험 발견이나 실패가 없습니다',
            onPick: p =>
              openLogs({
                from: p.at,
                to: new Date(Date.parse(p.at) + bucketMs).toISOString(),
                filters: { risk: ['critical', 'high', 'medium', 'low', 'info'] },
              }),
          },
        ),
      );
      grid.append(risk, categoriesPanel(board.categories));
      grid.append(rulesPanel(board.rules), signalsPanel(board.signals), sessionsPanel(board.sessions));
      const foot = el('div', 'span-12');
      foot.append(limits(board.limitations));
      grid.append(foot);
      root.replaceChildren(grid);
    };
    draw(await load());
    every(Number(state.refresh), async () => draw(await load()));
    return root;
  }
  function sourcesPanel(recent, st) {
    const node = panel('수집 상태', { span: 4, hint: '에이전트별 마지막 수신 기록입니다. 기록이 없다고 그 에이전트가 쉬었다는 뜻은 아닙니다' });
    const last = new Map();
    for (const item of recent.items) {
      const a = item.tool || item.sourceKind;
      if (!last.has(a)) last.set(a, item);
    }
    const counts = Object.fromEntries((recent.facets.agent || []).map(f => [f.value, f.count]));
    const list = el('div', 'source-list');
    for (const agent of ['claude-code', 'codex', ...[...last.keys()].filter(a => !(a in AGENTS))].slice(0, 6)) {
      const item = last.get(agent),
        row = el('div', 'source-row'),
        fresh = item && Date.now() - item.at < 15 * 60e3;
      row.append(
        el('i', `pulse ${item ? (fresh ? 'on' : 'idle') : 'off'}`),
        el('span', `source-name ${agentClass(agent)}`, labelOf('agent', agent)),
        el('span', 'source-count', `${count(counts[agent] || 0)}건`),
        el('span', 'source-age', item ? ago(item.receivedAt) : '기간 안 기록 없음'),
      );
      row.title = item ? `마지막 기록: ${item.note || item.kind}` : '';
      if (item) {
        row.classList.add('clickable');
        row.addEventListener('click', () => openLogs({ filters: { agent: [agent] } }));
      }
      list.append(row);
    }
    node.body.append(list);
    const facts = el('dl', 'source-facts');
    for (const [k, v] of [
      ['과거 기록 가져오기', `${count(st.historyImports)}건`],
      ['제외한 합성(데모) 기록', `${count(st.syntheticEvents)}건`],
    ])
      facts.append(el('dt', '', k), el('dd', '', v));
    node.body.append(facts);
    const live = button('실시간 로그 보기', () => openLogs({ live: true }), 'primary small');
    node.body.append(live);
    return node;
  }
  function categoriesPanel(categories) {
    const node = panel('분류별 AI 행동', {
      span: 6,
      hint: '보고된 도구와 명령 단어로 자동 분류했습니다(판정 아님). 클릭하면 그 분류의 로그로 이동합니다',
    });
    if (!categories.length) {
      node.body.append(el('p', 'ops-empty', '기간 안에 AI 도구 호출 기록이 없습니다'));
      return node;
    }
    const max = Math.max(...categories.map(c => c.count)),
      list = el('div', 'gauge-list');
    for (const c of categories.slice(0, 10)) {
      const row = el('button', 'gauge-row');
      row.type = 'button';
      const bar = el('span', 'gauge-bar'),
        fill = el('span', `gauge-fill ${c.risky ? 'risky' : ''}`);
      fill.style.width = `${Math.max(2, (c.count / max) * 100)}%`;
      bar.append(fill);
      row.append(el('span', 'gauge-label', labelOf('category', c.category)), bar, el('span', 'gauge-value', count(c.count)));
      row.append(el('span', 'gauge-risk', c.risky ? `위험 ${count(c.risky)}` : ''));
      row.addEventListener('click', () => openLogs({ filters: { category: [c.category] } }));
      list.append(row);
    }
    node.body.append(list);
    return node;
  }
  function rulesPanel(rules) {
    const node = panel('많이 걸린 탐지 규칙', { span: 6, action: button('규칙 관리', () => navigate('rules'), 'ghost small') });
    if (!rules.length) {
      node.body.append(el('p', 'ops-empty', '기간 안에 열린 발견이 없습니다. 수집되지 않은 행동은 여기에 나오지 않습니다'));
      return node;
    }
    const t = el('table', 'ops-table'),
      body = el('tbody');
    t.append(el('thead'));
    t.tHead.append(headRow(['중요도', '규칙', '발견', '행동']));
    for (const r of rules) {
      const tr = row([sev(r.severity), ruleCell(r), el('span', 'num', count(r.count)), el('span', 'num', count(r.actions))]);
      tr.classList.add('clickable');
      tr.addEventListener('click', () => openLogs({ q: r.code }));
      body.append(tr);
    }
    t.append(body);
    node.body.append(t);
    return node;
  }
  function ruleCell(r) {
    const n = el('div', 'rule-cell');
    n.append(el('code', '', r.code), el('span', '', r.message || ''));
    return n;
  }
  function headRow(titles) {
    const tr = el('tr');
    for (const t of titles) {
      const th = el('th', '', t);
      th.scope = 'col';
      tr.append(th);
    }
    return tr;
  }
  function row(cells) {
    const tr = el('tr');
    for (const c of cells) {
      const td = el('td');
      td.append(c);
      tr.append(td);
    }
    return tr;
  }
  function signalsPanel(signals) {
    const node = panel('최근 위험 신호', { span: 6, action: button('경보 전체', () => navigate('alerts'), 'ghost small') });
    if (!signals.length) {
      node.body.append(el('p', 'ops-empty', '기간 안에 위험 신호가 없습니다'));
      return node;
    }
    const list = el('div', 'signal-list');
    for (const s of signals) {
      const item = el('button', `signal sev-border-${s.severity}`);
      item.type = 'button';
      const top = el('div', 'signal-top');
      top.append(sev(s.severity), el('code', '', s.code), el('span', 'signal-time', ago(s.at)));
      item.append(top, el('div', 'signal-note', s.note || s.message || ''), el('div', 'signal-actor', s.actor || ''));
      item.addEventListener('click', () => core.openAction(s.actionId));
      list.append(item);
    }
    node.body.append(list);
    return node;
  }
  function sessionsPanel(sessions) {
    const node = panel('최근 세션', { span: 12, hint: '같은 세션(trace)의 AI 도구 호출을 묶었습니다. 클릭하면 그 세션의 로그를 시간순으로 봅니다' });
    if (!sessions.length) {
      node.body.append(el('p', 'ops-empty', '기간 안에 세션 기록이 없습니다'));
      return node;
    }
    const t = el('table', 'ops-table'),
      body = el('tbody');
    t.append(el('thead'));
    t.tHead.append(headRow(['에이전트', '세션', '행위자', '기록', '위험', '처음', '마지막']));
    for (const s of sessions) {
      const tr = row([
        el('span', `agent-pill ${agentClass(s.tool)}`, labelOf('agent', s.tool || '기타')),
        el('code', '', s.traceId.slice(0, 18)),
        el('span', '', s.actor || '—'),
        el('span', 'num', count(s.events)),
        s.risky ? el('span', 'num risky-text', count(s.risky)) : el('span', 'num muted', '0'),
        el('span', 'mono', stamp(s.firstAt)),
        el('span', 'mono', ago(s.lastAt)),
      ]);
      tr.classList.add('clickable');
      tr.addEventListener('click', () => openLogs({ q: `trace:${s.traceId}` }));
      body.append(tr);
    }
    t.append(body);
    node.body.append(t);
    return node;
  }

  // --- Log explorer --------------------------------------------------------------------------------------------------------
  function logsQuery(extra = {}) {
    const params = new URLSearchParams();
    if (logState.from) {
      params.set('from', logState.from);
      params.set('to', logState.to);
    } else params.set('range', state.range);
    if (logState.q) params.set('q', logState.q);
    for (const [k, v] of Object.entries(logState.filters)) if (v?.length) params.set(k, v.join(','));
    for (const [k, v] of Object.entries(extra)) params.set(k, String(v));
    return params;
  }
  async function logs() {
    const root = el('div', 'ops ops-logs'),
      epoch = core.getRenderEpoch();
    // Search bar
    const bar = el('form', 'log-search'),
      input = el('input', 'log-q');
    input.type = 'search';
    input.name = 'q';
    input.maxLength = 300;
    input.value = logState.q;
    input.placeholder = '검색: curl  -localhost  "git push"  category:secret  agent:codex  trace:세션ID   ( / 키로 바로 입력 )';
    input.setAttribute('aria-label', '로그 검색');
    const submit = el('button', 'primary', '검색');
    submit.type = 'submit';
    const live = el('button', `live-toggle ${logState.live ? 'on' : ''}`);
    live.type = 'button';
    live.append(el('i', 'pulse on'), document.createTextNode(' 실시간'));
    live.setAttribute('aria-pressed', String(logState.live));
    const help = el('details', 'log-help');
    help.append(el('summary', '', '검색 문법'));
    const helpList = el('ul');
    for (const line of [
      '단어: 내용·대상·행위자·규칙 코드 어디든 포함 (대소문자 무시)',
      '-단어: 그 단어가 있는 기록 제외',
      '"여러 단어": 붙어 있는 구절 그대로',
      'agent:codex · tool:bash · category:network · status:failure · actor:이름 · trace:세션 · id:행동ID',
      '왼쪽 목록에서 분류·에이전트·위험을 골라 함께 거를 수 있습니다',
    ])
      helpList.append(el('li', '', line));
    help.append(helpList);
    bar.append(input, submit, live, help);
    const chips = el('div', 'log-chips');
    const layout = el('div', 'log-layout'),
      side = el('aside', 'log-facets'),
      mainCol = el('div', 'log-main');
    const histo = el('div', 'ops-panel log-histo'),
      summary = el('div', 'log-summary'),
      list = el('div', 'log-table-wrap'),
      more = el('div', 'log-more');
    mainCol.append(histo, summary, list, more);
    layout.append(side, mainCol);
    const foot = el('div', 'log-foot');
    root.append(bar, chips, layout, foot);

    let data = null,
      items = [],
      latestSeq = 0,
      liveCount = 0,
      openId = null;
    const tbody = el('tbody');
    const table = el('table', 'ops-table log-table');
    const head = el('thead');
    head.append(headRow(['시각', '에이전트', '분류', '내용', '위험', '상태']));
    table.append(head, tbody);

    function renderChips() {
      chips.replaceChildren();
      const add = (text, clear) => {
        const c = el('span', 'chip');
        const x = el('button', 'chip-x', '×');
        x.type = 'button';
        x.setAttribute('aria-label', `${text} 해제`);
        x.addEventListener('click', clear);
        c.append(document.createTextNode(text), x);
        chips.append(c);
      };
      if (logState.from)
        add(`구간 ${stamp(logState.from)} – ${stamp(logState.to)}`, () => {
          logState.from = logState.to = null;
          reload();
        });
      for (const [facet, values] of Object.entries(logState.filters))
        for (const v of values || [])
          add(`${FACET_TITLES.find(([f]) => f === facet)?.[1] || facet}: ${labelOf(facet, v)}`, () => toggleFilter(facet, v));
      if (logState.q)
        add(`검색: ${logState.q}`, () => {
          logState.q = '';
          input.value = '';
          reload();
        });
      if (chips.childNodes.length > 1)
        chips.append(
          button(
            '모두 해제',
            () => {
              Object.assign(logState, { q: '', filters: {}, from: null, to: null });
              input.value = '';
              return reload();
            },
            'ghost small',
          ),
        );
    }
    function toggleFilter(facet, value) {
      const current = new Set(logState.filters[facet] || []);
      if (current.has(value)) current.delete(value);
      else current.add(value);
      logState.filters = { ...logState.filters, [facet]: [...current] };
      reload();
    }
    function renderFacets() {
      side.replaceChildren();
      for (const [facet, title] of FACET_TITLES) {
        const values = data.facets[facet] || [];
        if (!values.length) continue;
        const box = el('details', 'facet');
        box.open = !['actor', 'data', 'kind', 'collection'].includes(facet) || values.some(v => v.selected);
        box.append(el('summary', '', title));
        const total = values.reduce((n, v) => n + v.count, 0);
        for (const v of values.slice(0, 15)) {
          const item = el('label', `facet-item ${v.selected ? 'selected' : ''}`),
            check = el('input');
          check.type = 'checkbox';
          check.checked = v.selected;
          check.addEventListener('change', () => toggleFilter(facet, v.value));
          const name = el(
            'span',
            `facet-name ${facet === 'agent' ? agentClass(v.value) : facet === 'risk' ? `sev-text-${v.value}` : ''}`,
            labelOf(facet, v.value),
          );
          const meter = el('span', 'facet-meter'),
            fill = el('span', '');
          fill.style.width = `${Math.max(3, (v.count / total) * 100)}%`;
          meter.append(fill);
          item.append(check, name, el('span', 'facet-count', count(v.count)), meter);
          box.append(item);
        }
        side.append(box);
      }
      if (!side.childNodes.length) side.append(el('p', 'ops-empty', '거를 항목이 없습니다'));
    }
    function renderHisto() {
      const h = data.histogram;
      histo.replaceChildren();
      const headRow = el('header', 'ops-panel-head');
      headRow.append(el('h2', '', `기록 ${count(data.total)}건`));
      if (liveCount) headRow.append(el('span', 'live-count', `실시간 +${count(liveCount)}`));
      headRow.append(el('span', 'ops-hint-text', h.points.length ? '막대를 클릭하면 그 구간만 봅니다' : ''));
      histo.append(headRow);
      if (h.points.length)
        histo.append(
          barChart(
            h.points,
            [
              { label: '정상', cls: 'k-ok', value: p => p.ok },
              { label: '실패', cls: 'k-fail', value: p => p.failures },
              { label: '위험 발견', cls: 'k-risky', value: p => p.risky },
            ],
            {
              height: 90,
              bucketMs: h.bucketMs,
              onPick: p => {
                logState.from = p.at;
                logState.to = new Date(Date.parse(p.at) + h.bucketMs).toISOString();
                reload();
              },
            },
          ),
        );
    }
    function logRow(item, fresh = false) {
      const tr = el('tr', `log-row risk-${item.risk} ${fresh ? 'fresh' : ''}`);
      tr.tabIndex = 0;
      const agent = item.tool || item.sourceKind || '기타';
      const content = el('div', 'log-content');
      content.append(el('span', 'log-note', item.note || item.resource || `${labelOf('kind', item.kind)}`));
      if (item.destination) content.append(el('span', 'log-dest', `→ ${item.destination}`));
      if (item.collection === 'history_import') content.append(el('span', 'tag-mini', '과거 기록'));
      if (item.data === 'synthetic') content.append(el('span', 'tag-mini', '합성'));
      const cat = el('span', `cat cat-${item.category}`, labelOf('category', item.category));
      const status = el('span', `st st-${item.status || 'none'}`, labelOf('status', item.status || 'none'));
      for (const [i, cell] of [
        el('span', 'mono', stamp(item.occurredAt)),
        el('span', `agent-pill ${agentClass(agent)}`, labelOf('agent', agent)),
        cat,
        content,
        item.risk === 'none' ? el('span', 'muted', '') : sev(item.risk),
        status,
      ].entries()) {
        const td = el('td', ['c-time', 'c-agent', 'c-cat', 'c-content', 'c-risk', 'c-status'][i]);
        td.append(cell);
        tr.append(td);
      }
      const toggle = () => toggleDetail(tr, item);
      tr.addEventListener('click', toggle);
      tr.addEventListener('keydown', e => {
        if (e.key === 'Enter') toggle();
      });
      return tr;
    }
    function toggleDetail(tr, item) {
      const next = tr.nextElementSibling;
      if (next?.classList.contains('log-detail')) {
        next.remove();
        tr.classList.remove('open');
        openId = null;
        return;
      }
      tbody.querySelectorAll('tr.log-detail').forEach(n => {
        n.previousElementSibling?.classList.remove('open');
        n.remove();
      });
      openId = item.id;
      tr.classList.add('open');
      const detail = el('tr', 'log-detail'),
        td = el('td');
      td.colSpan = 6;
      const dl = el('dl', 'kv');
      const fields = [
        ['발생 시각(보고)', new Date(item.occurredAt).toLocaleString('ko-KR', { hour12: false })],
        ['수신 시각', new Date(item.receivedAt).toLocaleString('ko-KR', { hour12: false })],
        ['에이전트', labelOf('agent', item.tool || '—')],
        ['행위자', item.actor],
        ['도구', item.toolName],
        ['행동 종류', item.action],
        ['기록 종류', labelOf('kind', item.kind)],
        ['분류 태그', item.tags.map(t => labelOf('category', t)).join(', ')],
        ['상태', labelOf('status', item.status || 'none')],
        ['대상', item.resource],
        ['목적지', item.destination],
        ['위험 발견', item.findings.join(', ')],
        ['수집 방식', labelOf('collection', item.collection)],
        ['세션', item.traceId],
        ['행동 ID', item.actionId],
        ['기록 ID', item.id],
      ];
      for (const [k, v] of fields) if (v) dl.append(el('dt', '', k), el('dd', k === '대상' || k.endsWith('ID') || k === '세션' ? 'mono' : '', v));
      const note = el('pre', 'log-raw', item.note || '');
      const actions = el('div', 'detail-actions');
      if (item.actionId) actions.append(button('행동 조사 열기 (근거·참고 자료·규칙)', () => core.openAction(item.actionId), 'primary small'));
      if (item.traceId)
        actions.append(
          button(
            '같은 세션 기록 보기',
            () => {
              logState.q = `trace:${item.traceId}`;
              input.value = logState.q;
              logState.from = logState.to = null;
              return reload();
            },
            'small',
          ),
        );
      actions.append(
        button(
          `'${labelOf('category', item.category)}'만 보기`,
          () => {
            logState.filters = { ...logState.filters, category: [item.category] };
            return reload();
          },
          'small',
        ),
      );
      td.append(dl, note, actions);
      detail.append(td);
      tr.after(detail);
    }
    function renderRows() {
      tbody.replaceChildren(...items.map(item => logRow(item)));
      list.replaceChildren(
        items.length
          ? table
          : empty('조건에 맞는 기록이 없습니다', '기간을 넓히거나 검색어·필터를 줄여 보세요. 기록이 없다는 것은 안전하다는 뜻이 아닙니다.'),
      );
      more.replaceChildren();
      if (items.length < data.total) more.append(button(`더 보기 (${count(items.length)} / ${count(data.total)})`, loadMore, 'small'));
      summary.textContent = data.total ? `최신순 · ${count(items.length)}건 표시${logState.live ? ' · 실시간 수신 중' : ''}` : '';
    }
    async function loadMore() {
      const page = await api(`/api/logs?${logsQuery({ offset: items.length, limit: 100 })}`);
      if (core.getRenderEpoch() !== epoch) return;
      const seen = new Set(items.map(i => i.id));
      items.push(...page.items.filter(i => !seen.has(i.id)));
      data.total = page.total;
      renderRows();
    }
    async function reload() {
      logState.q = input.value.trim();
      renderChips();
      const result = await api(`/api/logs?${logsQuery({ limit: 100 })}`);
      if (core.getRenderEpoch() !== epoch) return;
      data = result;
      items = result.items.slice();
      latestSeq = result.latestSeq;
      liveCount = 0;
      renderFacets();
      renderHisto();
      renderRows();
      foot.replaceChildren(limits(result.limitations));
    }
    async function poll() {
      if (!logState.live || core.getRenderEpoch() !== epoch) return;
      const params = logsQuery({ after: latestSeq, limit: 200 });
      params.delete('range');
      params.delete('from');
      params.delete('to');
      const result = await api(`/api/logs?${params}`);
      if (core.getRenderEpoch() !== epoch) return;
      latestSeq = Math.max(latestSeq, result.latestSeq);
      if (!result.items.length) return;
      const seen = new Set(items.map(i => i.id)),
        fresh = result.items.filter(i => !seen.has(i.id));
      if (!fresh.length) return;
      liveCount += fresh.length;
      data.total += fresh.length;
      items = [...fresh, ...items].slice(0, 500);
      if (items.length === fresh.length) {
        renderRows();
      } else {
        if (!list.contains(table)) list.replaceChildren(table);
        for (const item of fresh.slice().reverse()) tbody.prepend(logRow(item, true));
        while (tbody.children.length > 500) tbody.lastElementChild.remove();
        summary.textContent = `최신순 · ${count(items.length)}건 표시 · 실시간 수신 중`;
      }
      const live = histo.querySelector('.live-count');
      if (live) live.textContent = `실시간 +${count(liveCount)}`;
      else histo.querySelector('.ops-panel-head h2')?.after(el('span', 'live-count', `실시간 +${count(liveCount)}`));
    }
    function liveLoop() {
      const tick = async () => {
        if (!logState.live || core.getRenderEpoch() !== epoch) return;
        try {
          await poll();
        } catch {
          /* keep polling: a failed tick leaves the list as it was */
        }
        if (logState.live && core.getRenderEpoch() === epoch) setTimeout(tick, 2000);
      };
      setTimeout(tick, 2000);
    }
    live.addEventListener('click', () => {
      logState.live = !logState.live;
      live.classList.toggle('on', logState.live);
      live.setAttribute('aria-pressed', String(logState.live));
      summary.textContent = data?.total ? `최신순 · ${count(items.length)}건 표시${logState.live ? ' · 실시간 수신 중' : ''}` : '';
      if (logState.live) liveLoop();
    });
    bar.addEventListener('submit', async event => {
      event.preventDefault();
      try {
        await reload();
      } catch (error) {
        list.replaceChildren(empty('검색하지 못했습니다', error.message));
      }
    });
    const slash = event => {
      if (core.getRenderEpoch() !== epoch) {
        document.removeEventListener('keydown', slash);
        return;
      }
      if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
        event.preventDefault();
        input.focus();
      }
    };
    document.addEventListener('keydown', slash);
    await reload();
    if (logState.live) liveLoop();
    else
      every(Number(state.refresh), async () => {
        if (!openId && !logState.live) await reload();
      });
    return root;
  }

  core.registerView(
    'dashboard',
    '대시보드',
    'AI 에이전트 활동, 위험 신호, 실패와 수집 상태를 기간별로 봅니다. 합성(데모) 기록은 빠져 있습니다.',
    dashboard,
  );
  core.registerView(
    'logs',
    '로그 탐색',
    '모든 수집 기록을 검색하고 자동 분류·에이전트·위험으로 거릅니다. 실시간 보기를 켜면 새 기록이 바로 위에 붙습니다.',
    logs,
  );
  window.EvidScopeOps = Object.freeze({ openLogs });
  applyTheme(store.get('theme', document.documentElement.dataset.theme || 'dark'));
  topbarControls();
  // The dashboard is the landing view; app.js has already drawn its fallback before this file loaded.
  if (core.getActiveView() === 'home') navigate('dashboard');
})();
