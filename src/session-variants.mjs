// 세션 학습용 변형(augmentation) 생성. 설계 시나리오의 위협 단계(gold)는 그대로 두고 주위에 정상 단계(benign 베이스의 단계)를 섞어 세션 모양만
// 바꾼다. 정상 단계는 delayMs 0이라 위협 단계의 시간 간격이 유지되고(시퀀스 창 유지), 규칙·시퀀스가 똑같이 발동하므로 골드(매핑 v4 도출)가 보존된다.
// 새 공격 문자열을 만들지 않는다 -- 명령 verb는 모두 기존 카탈로그에서 온다. familyId=베이스 id라 계열 분할이 변형 누수를 막고, 한 베이스를 통째로
// 미학습 평가(unseen)로 뺄 수 있다. 마지막에 변형마다 골드를 다시 도출해 베이스 라벨과 어긋나는 변형은 버린다(라벨 정확성 보장).
import {sessionGold} from './session-inference.mjs';

const benignPool = catalog => catalog.scenarios.filter(s => s.class === 'benign')
  .flatMap(s => s.steps.map(st => ({...st, gold: false, expectRule: undefined, delayMs: 0})));

// k번째 변형: 풀에서 순환해 앞 p개·뒤 q개 정상 단계를 끼운다. 위협 단계는 순서·타이밍 그대로. p,q는 k에서 결정(무작위 없음 -> 재현 가능).
function wrap(base, pool, k) {
  if (!pool.length || k === 0) return {...base, id: `${base.id}#v${k}`, name: `${base.id} v${k}`, familyId: base.id, steps: base.steps.map(s => ({...s}))};
  const p = k % 3, q = Math.floor(k / 3) % 3;
  const pick = (n, off) => Array.from({length: n}, (_, i) => ({...pool[(off + i) % pool.length]}));
  return {...base, id: `${base.id}#v${k}`, name: `${base.id} v${k}`, familyId: base.id,
    steps: [...pick(p, k), ...base.steps.map(s => ({...s})), ...pick(q, k + p + 1)]};
}

// 변형 카탈로그를 만든다(카탈로그와 같은 형식, scenarios만 변형으로 교체). perThreat/perBenign: 베이스당 변형 수. 라벨이 보존된 변형만 남긴다.
export function buildVariantCatalog(catalog, rules, {perThreat = 24, perBenign = 24} = {}) {
  const pool = benignPool(catalog);
  const kept = [], dropped = [];
  for (const base of catalog.scenarios) {
    const n = base.class === 'benign' ? perBenign : perThreat;
    for (let k = 0; k < n; k++) {
      const v = wrap(base, pool, k);
      const g = sessionGold(v, rules);
      const want = base.label.verdict === 'violation'
        ? g.verdict === 'violation' && g.type === (base.label.type || null)
        : g.verdict === 'clean';
      (want ? kept : dropped).push(want ? v : v.id);
    }
  }
  return {schemaVersion: catalog.schemaVersion, catalog: `${catalog.catalog}-variants`, version: catalog.version,
    rulePackVersion: catalog.rulePackVersion, classes: catalog.classes, scenarios: kept, droppedVariantCount: dropped.length};
}
