// Requirement mappings of evidence packages (docs/evidence-pack.md): which EvidScope evidence kinds (src/evidence-inventory.mjs)
// an auditor can look at for each item. A mapping is a reading aid drafted for human review, not a legal interpretation;
// "evidence present" never means that an item is met. Published with the offline verifier together with the data files it reads.
import {readFileSync} from 'node:fs';
import {canonical} from './crypto.mjs';
import {EVIDENCE_TYPES} from './evidence-inventory.mjs';
import {krGovernanceCheckDefinitions} from './kr-governance-evidence.mjs';

export const MAPPING_FORMAT = 'evidscope-evidence-pack-mapping-v1';
export const FRAMEWORKS = ['eu-ai-act-logging', 'kr-ai-basic-act', 'isms-p'];
const data = name => JSON.parse(readFileSync(new URL(`../data/${name}`, import.meta.url), 'utf8'));
const record = name => ({type: 'record', name}), kind = (name, source) => ({type: 'eventKind', name, source}), finding = code => ({type: 'finding', code});
const LEDGER = {type: 'integrityCheck', name: 'signed_ledger'};
const RETENTION = [LEDGER, record('retention_policy'), record('retention_hold'), record('retention_disposition')];
const OVERSIGHT = [record('approval_request'), kind('human_approval', 'authority'), kind('human_oversight_review', 'authority'), record('case_decision')];
const STOP = [record('agent_stop_order'), kind('stop_requested', 'safety'), kind('block_registered', 'safety'), kind('stop_confirmed', 'safety'),
  finding('STOP_UNCONFIRMED'), finding('EXECUTION_AFTER_STOP_REQUEST')];

// ---------- EU AI Act (Regulation (EU) 2024/1689), logging and oversight articles ----------
// Read on 2026-10-08 on the Commission's AI Act Service Desk article pages, which show the OJ text of 13 June 2024 (some pages
// the consolidated text of 27 July 2026); EUR-Lex itself was not reachable from the build container. See docs/evidence-pack.md.
const SERVICE_DESK = n => `https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-${n}`;
const READ = 'text_read', AMENDED = 'text_read_amendment_unverified';
const eu = (id, article, status, en, ko, evidence) => ({id, citation: `Regulation (EU) 2024/1689, ${article}`, url: SERVICE_DESK(article.match(/\d+/)[0]),
  sourceStatus: status, title: {en, ko}, evidence, judgement: null});
function euMapping() {
  return {id: 'eu-ai-act-logging', title: {en: 'EU AI Act: record-keeping, logs and human oversight', ko: 'EU AI Act: 기록 보존·로그·사람 감독'},
    sources: [{title: 'Regulation (EU) 2024/1689 (Artificial Intelligence Act)', official: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj',
      readVia: 'https://ai-act-service-desk.ec.europa.eu/en/ai-act', readAt: '2026-10-08',
      note: 'Article 12 and an Article 72 paragraph carry Digital Omnibus amendment notices on the Service Desk; the amended text was not read.'}],
    items: [
      eu('EU-AIA-12-1', 'Article 12(1)', AMENDED, 'Automatic recording of events (logs) over the lifetime of the system',
        '시스템 수명 동안 이벤트(로그)의 자동 기록', [LEDGER, record('event'), record('event_receipt')]),
      eu('EU-AIA-12-2-A', 'Article 12(2)(a)', AMENDED, 'Events relevant for identifying risk situations (Article 79(1)) or a substantial modification',
        '위험 상황(제79조제1항) 또는 실질적 변경을 식별하는 데 관련된 이벤트',
        [record('evaluation'), record('agent_registry'), record('agent_transition'), kind('safety_alert', 'safety'), record('agent_stop_order')]),
      eu('EU-AIA-12-2-B', 'Article 12(2)(b)', AMENDED, 'Events relevant for post-market monitoring (Article 72)', '시판 후 모니터링(제72조)에 관련된 이벤트',
        [record('evaluation'), kind('heartbeat', 'telemetry'), kind('gap', 'telemetry'), finding('COLLECTION_GAP')]),
      eu('EU-AIA-12-2-C', 'Article 12(2)(c)', AMENDED, 'Events relevant for monitoring the operation (Article 26(5))', '운영 모니터링(제26조제5항)에 관련된 이벤트',
        [kind('intent', 'agent'), kind('execution', 'tool'), kind('result', 'tool'), kind('policy_decision', 'enforcement'),
          kind('guardrail_decision', 'enforcement')]),
      eu('EU-AIA-19-1', 'Article 19(1)', READ, 'Providers keep the automatically generated logs under their control (at least six months)',
        '제공자의 자동 생성 로그 보관(최소 6개월)', RETENTION),
      eu('EU-AIA-26-6', 'Article 26(6)', READ, 'Deployers keep the automatically generated logs under their control (at least six months)',
        '배포자의 자동 생성 로그 보관(최소 6개월)', RETENTION),
      eu('EU-AIA-72-1-2', 'Article 72(1) and (2)', AMENDED, 'Post-market monitoring: collect, document and analyse data on performance',
        '시판 후 모니터링: 성능 자료의 수집·문서화·분석', [record('evaluation'), record('case'), record('case_decision'), kind('safety_alert', 'safety')]),
      eu('EU-AIA-14-4-A', 'Article 14(4)(a)', READ, 'Overseers monitor the operation and detect anomalies, dysfunctions and unexpected performance',
        '감독자가 운영을 모니터링하고 이상·오작동·예상 밖 성능을 탐지', [record('case'), record('case_decision'), kind('human_oversight_review', 'authority')]),
      eu('EU-AIA-14-4-D', 'Article 14(4)(d)', READ, 'Overseers decide not to use, or disregard, override or reverse the output',
        '감독자가 사용하지 않거나 출력을 무시·무효화·되돌리기로 결정', OVERSIGHT),
      eu('EU-AIA-14-4-E', 'Article 14(4)(e)', READ, 'Overseers intervene or interrupt the system through a stop button or similar procedure',
        '감독자가 정지 버튼 등으로 개입하거나 시스템을 중단', STOP),
    ],
    notMapped: [
      {ref: 'Article 12(3), Article 14(5)', reason: {
        en: 'Annex III point 1(a) systems (remote biometric identification): the listed log content and two-person verification are not modelled.',
        ko: '부속서 III 1(a) 원격 생체 식별 시스템의 지정 로그 내용과 2인 확인은 EvidScope가 모델링하지 않습니다.'}},
      {ref: 'Article 19(2), Article 26(6) second subparagraph', reason: {
        en: 'Financial institutions keep logs in the documentation of financial services law, outside EvidScope.',
        ko: '금융기관은 금융 서비스 법령의 문서로 로그를 보관하며 EvidScope 밖입니다.'}},
      {ref: 'Article 14(4)(b) and (c)', reason: {
        en: 'Awareness of automation bias and interpretation of output are design and training measures, not recorded events.',
        ko: '자동화 편향 인식과 출력 해석은 설계·교육 조치이며 기록되는 이벤트가 아닙니다.'}},
    ]};
}

// ---------- Korean AI Basic Act: the requirements already registered in data/requirements.json ----------
const KR_EXTRA = {
  'KR-32-RISK': [record('evaluation'), record('agent_registry_policy')],
  'KR-32-MONITOR': [record('evaluation'), record('case'), record('case_decision'), kind('safety_alert', 'safety')],
  'KR-34-RISK': [record('evaluation'), record('agent_registry_policy')],
  'KR-34-OVERSIGHT': [...OVERSIGHT, ...STOP.slice(0, 1)],
  'KR-34-DOCUMENT': [record('governance_document'), record('retention_policy'), LEDGER],
  'KR-40-ORDER': [...STOP.slice(0, 4)],
};
function krMapping() {
  const items = data('requirements.json').filter(r => r.jurisdiction === 'KR').map(r => ({
    id: r.id, citation: `인공지능기본법 ${r.article}`, url: r.sourceUrl,
    // Read and checked by an earlier round on verifiedAt (data/requirements.json); not re-read for packages.
    sourceStatus: `requirements_catalog_${r.sourceTextStatus}_${r.verifiedAt}`, title: {ko: r.title, en: null},
    evidence: [...krGovernanceCheckDefinitions.filter(d => d.requirementId === r.id).map(d => ({type: 'checkType', name: d.checkType})),
      ...(KR_EXTRA[r.id] || [])],
    judgement: [r.id]}));
  return {id: 'kr-ai-basic-act', title: {ko: '인공지능기본법(법률 제21311호)·시행령 등록 요구사항', en: 'Korean AI Basic Act: registered requirements'},
    sources: [{title: 'data/requirements.json (인공지능기본법 법률 제21311호, 시행령 제36580호)', readVia: 'requirements catalog of EvidScope',
      note: 'Article references and source URLs are those of the catalog; they were not re-read for evidence packages.'}],
    items, notMapped: []};
}

// ---------- ISMS-P: data/isms-p-alignment.json ----------
function ismsMapping() {
  const a = data('isms-p-alignment.json'), legal = a.sources.legal, titles = new Map(a.officialItems.map(i => [i.number, i.title]));
  const notice = legal.notices.find(n => n.number === '제2024-8호');
  const items = a.alignments.map(al => {
    const evidence = new Map();
    for (const s of al.supports) {
      for (const e of s.evidence) {
        const key = canonical({...e, what: null}), seen = evidence.get(key);
        if (seen) seen.checkItems = [...new Set([...seen.checkItems, ...s.checkItems])].sort((x, y) => x - y);
        else evidence.set(key, {...e, checkItems: [...s.checkItems]});
      }
    }
    return {id: `ISMS-P-${al.item}`, citation: `${legal.title}(${notice.issuer}고시 ${notice.number}) ${legal.annex} ${al.item}`, url: legal.url,
      sourceStatus: a.sources.verifiedLevel, title: {ko: titles.get(al.item), en: null}, evidence: [...evidence.values()], judgement: null,
      supports: al.supports.map(s => ({checkItems: s.checkItems, shows: s.shows})), manual: al.manual};
  });
  return {id: 'isms-p', title: {ko: 'ISMS-P 인증기준(정렬한 항목)', en: 'ISMS-P certification criteria (aligned items)'},
    sources: [{title: `${legal.title} ${legal.annex}`, notice: `${notice.issuer}고시 ${notice.number}`, url: legal.url,
      alignment: `data/isms-p-alignment.json (${a.id} schema ${a.schemaVersion}, ${a.mappingStatus}, checked ${a.checkedAt})`}],
    items, notMapped: [{ref: `${a.notAligned.length} items`, reason: {ko: '이유는 docs/isms-p-alignment.md를 보세요.', en: 'see docs/isms-p-alignment.md'}}]};
}

const BUILDERS = {'eu-ai-act-logging': euMapping, 'kr-ai-basic-act': krMapping, 'isms-p': ismsMapping};
// The mapping object written to mapping.json of a package; the same input always gives the same bytes.
export function frameworkMapping(id) {
  if (!Object.hasOwn(BUILDERS, id)) throw Error('Unknown framework ' + JSON.stringify(id) + '; use one of ' + FRAMEWORKS.join(', '));
  return checkMapping({format: MAPPING_FORMAT, mappingStatus: 'draft_requires_human_review', ...BUILDERS[id]()});
}
export const mappingBytes = mapping => Buffer.from(JSON.stringify(mapping, null, 1) + '\n', 'utf8');

const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const text = v => typeof v === 'string' && v.length > 0 && v.length <= 2000;
// Structural check of a mapping, also applied to one read from a package with --mapping-from-pack.
export function checkMapping(m) {
  if (!plain(m) || m.format !== MAPPING_FORMAT || !FRAMEWORKS.includes(m.id) || !Array.isArray(m.items) || !m.items.length) throw Error('Malformed mapping');
  const ids = new Set();
  for (const item of m.items) {
    if (!plain(item) || !/^[A-Z][A-Z0-9.-]{1,63}$/.test(item.id) || ids.has(item.id) || !text(item.citation) || !plain(item.title) || !text(item.title.ko)) {
      throw Error('Malformed mapping item ' + JSON.stringify(item?.id));
    }
    ids.add(item.id);
    if (!Array.isArray(item.evidence) || item.evidence.some(e => !plain(e) || !EVIDENCE_TYPES.includes(e.type))) {
      throw Error('Malformed evidence in ' + item.id);
    }
    if (item.judgement !== null && !(Array.isArray(item.judgement) && item.judgement.every(text))) throw Error('Malformed judgement in ' + item.id);
  }
  if (!plain(m.title) || !text(m.title.ko) || !Array.isArray(m.notMapped)
    || m.notMapped.some(n => !plain(n) || !text(n.ref) || !plain(n.reason) || !text(n.reason.ko) || !text(n.reason.en))) throw Error('Malformed mapping');
  return m;
}
