// 세션 학습용 변형(augmentation) 생성. 설계 시나리오의 위협 단계(gold)는 그대로 두고 주위에 정상 단계(benign 베이스의 단계)를 섞어 세션 모양만
// 바꾼다. 정상 단계는 delayMs 0이라 위협 단계의 시간 간격이 유지된다. 새 공격 문자열을 만들지 않는다 -- 명령 verb는 모두 기존 카탈로그에서 온다.
// familyId=베이스 id라 계열 분할이 변형 누수를 막고, 한 베이스를 통째로 미학습 평가(unseen)로 뺄 수 있다.
//
// 적대적 감사(2026-10-17)에서 고친 세 가지:
//  1. 잡음 풀은 poolExclude(평가·검증 계열)를 뺀 정상 베이스에서만 뽑는다. 예전엔 분할 전 전체 카탈로그에서 뽑아 평가용 정상 단계가 학습에 섞였다.
//  2. 같은 단계열의 변형은 한 번만 남긴다(예전 k=0·9·18·27은 잡음 0개로 원본과 같았다).
//  3. 섞은 뒤 다시 판단한다: 잡음이 새 연쇄(SEQ_) 경보를 만들거나 골드 조항·증적을 바꾸면 그 변형은 버린다. 예전 "라벨 보존 확인"은 설계
//     라벨을 그대로 돌려받아 아무것도 거르지 못했고, 위험 연쇄 경보가 붙은 세션이 정상 정답으로 학습됐다.
import {sessionGold, sessionInput} from './session-inference.mjs';

const stepKey = st => JSON.stringify([st.toolName, st.command ?? null, st.filePath ?? null, st.url ?? null, st.delayMs ?? 0, !!st.gold,
  !!st.prompt, st.content ? [st.content.source ?? null, st.content.signals ?? null, st.content.chars ?? null] : null]);
// 잡음 풀은 정상 베이스의 단계에서 온다. 화면 검사(content)·프롬프트 단계는 잡음으로 쓰지 않는다(새 LLM 신호를 세션에 끼워넣지 않도록).
const benignPool = (catalog, exclude) => catalog.scenarios.filter(s => s.class === 'benign' && !exclude.has(s.id))
  .flatMap(s => s.steps.filter(st => !st.content && !st.prompt).map(st => ({...st, gold: false, expectRule: undefined, delayMs: 0})));
const seqCodes = (s, rules) => [...new Set(sessionInput(s, rules).actions.flatMap(a => a.findings.map(f => f.code))
  .filter(c => c.startsWith('SEQ_')))].sort().join(',');

// k번째 변형: 풀에서 순환해 앞 p개·뒤 q개 정상 단계를 끼운다. 위협 단계는 순서·타이밍 그대로. p,q는 k에서 결정(무작위 없음 -> 재현 가능).
function wrap(base, pool, k) {
  const steps = base.steps.map(s => ({...s}));
  if (!pool.length || k === 0) return {...base, id: `${base.id}#v${k}`, name: `${base.id} v${k}`, familyId: base.id, steps};
  const p = k % 3, q = Math.floor(k / 3) % 3;
  // filler: 잡음 표시. 학습 세트 빌더의 누수 검사는 평가 세션의 잡음(학습 계열에서 온 단계)을 평가 고유 단계로 치지 않는다.
  const pick = (n, off) => Array.from({length: n}, (_, i) => ({...pool[(off + i) % pool.length], filler: true}));
  return {...base, id: `${base.id}#v${k}`, name: `${base.id} v${k}`, familyId: base.id, steps: [...pick(p, k), ...steps, ...pick(q, k + p + 1)]};
}

// 변형 카탈로그를 만든다(카탈로그와 같은 형식, scenarios만 변형으로 교체). perThreat/perBenign: 베이스당 서로 다른 변형 수(목표). poolExclude:
// 잡음 풀에서 뺄 정상 베이스 id(평가·검증 계열을 반드시 넣는다). 결과에 poolFamilies를 기록해 학습 세트 빌더가 누수를 검사할 수 있게 한다.
export function buildVariantCatalog(catalog, rules, {perThreat = 24, perBenign = 24, poolExclude = []} = {}) {
  const exclude = new Set(poolExclude);
  const pool = benignPool(catalog, exclude);
  const kept = [];
  const dropped = {seqDrift: 0, goldDrift: 0, duplicate: 0};
  for (const base of catalog.scenarios) {
    const n = base.class === 'benign' ? perBenign : perThreat;
    const baseSeq = seqCodes(base, rules);
    const baseGold = JSON.stringify(sessionGold(base, rules));
    const seen = new Set();
    let made = 0;
    for (let k = 0; made < n && k < n * 6; k++) {
      const v = wrap(base, pool, k);
      const key = v.steps.map(stepKey).join('|');
      if (seen.has(key)) { dropped.duplicate++; continue; }
      seen.add(key);
      if (seqCodes(v, rules) !== baseSeq) { dropped.seqDrift++; continue; }
      const g = sessionGold(v, rules);
      // 골드 증적 actionId는 변형마다 다르므로(세션 id가 다름) 조항·판정·유형만 비교한다.
      const bg = JSON.parse(baseGold);
      if (g.verdict !== bg.verdict || g.type !== bg.type || g.requirementIds.join() !== bg.requirementIds.join()
        || g.evidenceActionIds.length !== bg.evidenceActionIds.length) { dropped.goldDrift++; continue; }
      kept.push(v);
      made++;
    }
  }
  const poolFamilies = catalog.scenarios.filter(s => s.class === 'benign' && !exclude.has(s.id)).map(s => s.id);
  return {schemaVersion: catalog.schemaVersion, catalog: `${catalog.catalog}-variants`, version: catalog.version,
    rulePackVersion: catalog.rulePackVersion, classes: catalog.classes, poolFamilies, scenarios: kept,
    droppedVariantCount: dropped.seqDrift + dropped.goldDrift, dropped};
}
