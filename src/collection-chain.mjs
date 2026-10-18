// Collection continuity of agent hooks (docs/agent-monitoring.md, "수집 연속성"). Every hook record carries chain {stream, seq, prev}
// (src/agent-hook-runner.mjs hookChain): a random stream id per hook state file, a number from 1 and the digest of the record numbered
// before it. The signed ledger already shows that nothing was removed or changed after a record arrived; the chain shows what was lost
// or changed before, between the PC and the vault: a number that never arrived (missing), a record whose predecessor is not the record
// it names (broken) and a number used twice (reused). Pure functions, no I/O: the vault passes the retained records and its fingerprint
// comparison (store.compareEventFingerprint), and turns the problems into signed telemetry gap records (COLLECTION_GAP findings).
//
// What it cannot see, said in every report: records deleted from the end of a stream before they were sent (nothing later arrives
// to show the hole), a hook whose state file was removed (a new stream starts, shown as a restart), and anyone holding the PC's hook
// credentials, who can write a consistent chain of invented records.
export const CHAIN_FORMAT = 'evidscope-collection-chain-v1';
// A hole is confirmed only this long after the first later record arrived: a spooled backlog is sent after the current record.
export const CHAIN_GRACE_MS = 60 * 60 * 1000;
export const CHAIN_CHECK_PRINCIPAL = 'collection-chain-check';
const LIMITS = {holes: 50, broken: 50};
export const CHAIN_LIMITATIONS = Object.freeze([
  '스트림 끝부분이 보내지기 전에 지워지면 그 뒤 기록이 없어 빈 곳이 드러나지 않습니다',
  '훅 상태 파일이 지워지면 새 스트림이 1부터 시작합니다. 이것은 재시작으로만 보입니다',
  'PC의 훅 자격 증명을 가진 사람은 앞뒤가 맞는 가짜 기록 사슬을 만들 수 있습니다. 연결은 전송 중 유실·변경을 보여 줄 뿐, 내용이 참이라는 증명이 아닙니다',
  '보존 기간이 지나 지워진 앞부분 기록은 빠진 것으로 세지 않습니다(원장이 삭제를 기록합니다)']);

const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const chained = e => plain(e?.chain) && typeof e.chain.stream === 'string' && Number.isSafeInteger(e.chain.seq) && e.chain.seq >= 1;
const agentRecord = e => e?.sourceKind === 'agent';
const ms = t => { const n = Date.parse(t); return Number.isFinite(n) ? n : 0; };

// events: retained ledger events (any order) with source, actor, tool, id, chain, fingerprint (as stored) and receivedAt.
// compare(storedFingerprint, rawDigest): 'same' | 'different' | 'unverifiable'. now: ms. graceMs: see CHAIN_GRACE_MS.
export function analyzeChains(events, {compare, now = Date.now(), graceMs = CHAIN_GRACE_MS} = {}) {
  const streams = new Map(), bySource = new Map();
  for (const e of events) {
    if (!agentRecord(e)) continue;
    const s = bySource.get(e.source) || {source: e.source, records: 0, chained: 0, unchained: 0, unchainedAfterChain: 0, firstChainedAt: null};
    s.records++;
    if (chained(e)) {
      s.chained++;
      if (!s.firstChainedAt || e.receivedAt < s.firstChainedAt) s.firstChainedAt = e.receivedAt;
      const key = `${e.source}\u0000${e.chain.stream}`;
      if (!streams.has(key)) streams.set(key, {source: e.source, stream: e.chain.stream, records: []});
      streams.get(key).records.push(e);
    } else s.unchained++;
    bySource.set(e.source, s);
  }
  for (const e of events) {
    if (!agentRecord(e) || chained(e)) continue;
    const s = bySource.get(e.source);
    if (s.firstChainedAt && e.receivedAt > s.firstChainedAt) s.unchainedAfterChain++;
  }
  const out = [];
  for (const {source, stream, records} of streams.values()) {
    const bySeq = new Map(), reused = [];
    for (const e of records) {
      const at = bySeq.get(e.chain.seq);
      if (!at) bySeq.set(e.chain.seq, [e]); else { at.push(e); if (at.length === 2) reused.push(e.chain.seq); }
    }
    const seqs = [...bySeq.keys()].sort((a, b) => a - b), first = seqs[0], last = seqs.at(-1);
    const one = seq => bySeq.get(seq)?.length === 1 ? bySeq.get(seq)[0] : null;
    const holes = [];
    for (let i = 1; i < seqs.length; i++) {
      if (seqs[i] === seqs[i - 1] + 1) continue;
      const after = bySeq.get(seqs[i]).reduce((a, b) => ms(a.receivedAt) <= ms(b.receivedAt) ? a : b);
      const age = now - ms(after.receivedAt);
      holes.push({from: seqs[i - 1] + 1, to: seqs[i] - 1, count: seqs[i] - seqs[i - 1] - 1, status: age >= graceMs ? 'confirmed' : 'pending',
        before: {seq: seqs[i - 1], id: bySeq.get(seqs[i - 1])[0].id}, after: {seq: seqs[i], id: after.id, receivedAt: after.receivedAt}});
    }
    const broken = [];
    for (const seq of seqs) {
      const e = one(seq);
      if (!e) continue;
      const prev = e.chain.prev;
      if (seq === 1 || prev === 'genesis') {
        const reason = seq === 1 ? 'first_without_genesis' : 'genesis_after_first';
        if (seq !== 1 || prev !== 'genesis') broken.push({seq, id: e.id, reason, result: 'different'});
        continue;
      }
      const before = one(seq - 1);
      if (!before) continue;
      const result = compare(before.fingerprint, prev);
      if (result !== 'same') broken.push({seq, id: e.id, previousId: before.id, reason: 'previous_record_differs', result});
    }
    const sample = records[0], lastAt = records.reduce((t, e) => e.receivedAt > t ? e.receivedAt : t, '');
    out.push({source, stream, actor: sample.actor || null, tool: sample.tool || null, records: records.length, firstSeq: first, lastSeq: last,
      firstReceivedAt: records.reduce((t, e) => !t || e.receivedAt < t ? e.receivedAt : t, ''), lastReceivedAt: lastAt,
      startsAtOne: first === 1, missing: holes.slice(0, LIMITS.holes), missingRanges: holes.length,
      missingRecords: holes.reduce((n, h) => n + h.count, 0), broken: broken.slice(0, LIMITS.broken), brokenLinks: broken.length,
      reused: reused.sort((a, b) => a - b).slice(0, LIMITS.broken)});
  }
  out.sort((a, b) => a.source.localeCompare(b.source) || a.firstReceivedAt.localeCompare(b.firstReceivedAt) || a.stream.localeCompare(b.stream));
  // A later stream of the same source and actor started after an earlier one: the hook lost (or someone removed) its state file.
  const restarts = [];
  for (const s of out) {
    const earlier = out.filter(o => o !== s && o.source === s.source && o.actor === s.actor && o.firstReceivedAt < s.firstReceivedAt);
    if (earlier.length) restarts.push({source: s.source, actor: s.actor, stream: s.stream, previousStream: earlier.at(-1).stream, at: s.firstReceivedAt});
  }
  const sources = [...bySource.values()].sort((a, b) => a.source.localeCompare(b.source)).map(({firstChainedAt, ...s}) => s);
  const sum = k => out.reduce((n, s) => n + s[k], 0);
  return {format: CHAIN_FORMAT, graceMs, generatedAt: new Date(now).toISOString(),
    counts: {agentRecords: sources.reduce((n, s) => n + s.records, 0), chained: sum('records'), unchained: sources.reduce((n, s) => n + s.unchained, 0),
      streams: out.length, restarts: restarts.length, missingRecords: sum('missingRecords'),
      confirmedMissingRanges: out.reduce((n, s) => n + s.missing.filter(h => h.status === 'confirmed').length, 0),
      pendingMissingRanges: out.reduce((n, s) => n + s.missing.filter(h => h.status === 'pending').length, 0),
      brokenLinks: out.reduce((n, s) => n + s.broken.filter(b => b.result === 'different').length, 0),
      unverifiableLinks: out.reduce((n, s) => n + s.broken.filter(b => b.result === 'unverifiable').length, 0),
      reusedNumbers: out.reduce((n, s) => n + s.reused.length, 0)},
    streams: out, restarts, sources, limitations: CHAIN_LIMITATIONS};
}

// The problems a report raises as signed gap records, each with a stable id so a later check never records it twice: a confirmed hole,
// a broken link (not an unverifiable one: its key epoch was erased) and a reused number.
export function chainProblems(report) {
  const out = [];
  for (const s of report.streams) {
    const base = {actor: s.actor, tool: s.tool, stream: s.stream, source: s.source};
    for (const h of s.missing) if (h.status === 'confirmed') out.push({...base, id: `chain.gap.${s.stream}.${h.from}-${h.to}`, problem: 'missing',
      note: `수집 연속성: ${s.source}의 기록 ${h.from}~${h.to}번(${h.count}건)이 도착하지 않았습니다. ${h.before.seq}번 다음 ${h.after.seq}번이 먼저 왔습니다`});
    for (const b of s.broken) if (b.result === 'different') out.push({...base, id: `chain.break.${s.stream}.${b.seq}`, problem: 'broken',
      note: b.reason === 'previous_record_differs'
        ? `수집 연속성: ${s.source}의 기록 ${b.seq}번이 가리키는 앞 기록과 실제 저장된 ${b.seq - 1}번 내용이 다릅니다`
        : `수집 연속성: ${s.source}의 기록 ${b.seq}번의 시작 표시가 순번과 맞지 않습니다`});
    for (const seq of s.reused) out.push({...base, id: `chain.reuse.${s.stream}.${seq}`, problem: 'reused',
      note: `수집 연속성: ${s.source}의 기록 번호 ${seq}번이 서로 다른 두 기록에 쓰였습니다`});
  }
  return out;
}
// The telemetry gap record of one problem, as the vault's chain check submits it (src/model.mjs validateEvent, kind gap).
export const chainGapEvent = (problem, at) => ({id: problem.id, kind: 'gap', occurredAt: at, traceId: `chain.${problem.stream}`,
  actionId: `chain.${problem.stream}`, ...(problem.actor ? {actor: problem.actor} : {}), ...(problem.tool ? {tool: problem.tool} : {}),
  action: `collection_chain_${problem.problem}`, resource: `chain:${problem.stream}`, note: problem.note});
