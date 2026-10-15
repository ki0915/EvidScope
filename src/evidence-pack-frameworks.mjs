// Requirement mappings of evidence packages (docs/evidence-pack.md): which EvidScope evidence kinds (src/evidence-inventory.mjs)
// an auditor can look at for each item. A mapping is a reading aid drafted for human review, not a legal interpretation;
// "evidence present" never means that an item is met. Published with the offline verifier together with the data files it reads.
import {readFileSync} from 'node:fs';
import {canonical} from './crypto.mjs';
import {sha256Hex} from './dsse.mjs';
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
// ---------- AI agent risk findings (mapping version 3) ----------
// The risk rules of AI coding agents (data/risk-rules/ai-agent-baseline.json, docs/agent-monitoring.md) are tenant rules, so their
// findings are CUSTOM:<rule id>:v<version>. A codePrefix entry counts the findings of every rule of a group (CUSTOM:risk.out.) or of
// one rule in every version (CUSTOM:risk.defense.defender:). They are evidence that the agent's actions were analysed and flagged,
// never that an item is met; the mapping is a draft for human review like the rest.
const agentRisk = (group, what) => ({type: 'finding', codePrefix: `CUSTOM:risk.${group}.`, what});
const agentRule = (id, what) => ({type: 'finding', codePrefix: `CUSTOM:${id}:`, what});
export const AGENT_RISK = Object.freeze({
  cred: agentRisk('cred', 'AI 에이전트의 자격증명·비밀 파일 접근 탐지'),
  destroy: agentRisk('destroy', 'AI 에이전트의 파괴적 명령 탐지'),
  out: agentRisk('out', 'AI 에이전트의 데이터 외부 전송 명령 탐지'),
  defense: agentRisk('defense', 'AI 에이전트의 보안 설정 변경·기록 삭제 명령 탐지'),
  audit: agentRisk('audit', 'AI 에이전트의 감시 설정 접근 탐지'),
});
const AGENT_RISK_ALL = Object.values(AGENT_RISK);
const SECURITY_TOOL_CHANGES = [agentRule('risk.defense.defender', 'AI 에이전트의 Windows Defender 설정 변경 명령'),
  agentRule('risk.defense.firewall', 'AI 에이전트의 Windows 방화벽 설정 변경 명령'), agentRule('risk.defense.iptables-flush', 'AI 에이전트의 iptables 규칙 삭제 명령'),
  agentRule('risk.defense.selinux-off', 'AI 에이전트의 SELinux 해제 명령')];
const LOG_TAMPERING = [agentRule('risk.defense.clear-eventlog', 'AI 에이전트의 Windows 이벤트 로그 삭제 명령'),
  agentRule('risk.defense.clear-eventlog-ps', 'AI 에이전트의 PowerShell 이벤트 로그 삭제 명령'),
  agentRule('risk.defense.history-clear', 'AI 에이전트의 셸 명령 기록 삭제'), AGENT_RISK.audit];
// ISMS-P supports added to data/isms-p-alignment.json's, kept out of that file: its evidence texts are also inputs of the
// governance-mapping dataset (src/governance-mapping-data.mjs), which must not change under a trained model.
const AGENT_RISK_ISMS = {
  '2.6.7': [{checkItems: [2], evidence: [AGENT_RISK.out],
    shows: 'AI 에이전트 명령 중 데이터 외부 전송(curl 본문·업로드, scp, netcat, 붙여넣기 사이트)을 발견사항으로 표시(탐지만 하며 차단하지 않음)'}],
  '2.9.4': [{checkItems: [2], evidence: LOG_TAMPERING,
    shows: 'AI 에이전트가 이벤트 로그·명령 기록을 지우거나 EvidScope 수집·hook 설정에 접근하면 발견사항으로 표시'}],
  '2.10.1': [{checkItems: [3], evidence: SECURITY_TOOL_CHANGES,
    shows: 'AI 에이전트가 공식 절차 밖에서 백신·방화벽·iptables·SELinux 설정을 바꾸는 명령을 발견사항으로 표시'}],
  '2.11.3': [{checkItems: [1], evidence: AGENT_RISK_ALL,
    shows: 'AI 에이전트의 도구 호출(명령·파일·URL)을 승인된 위험 규칙으로 분석해 자격증명 접근·파괴 명령·외부 전송·보안 설정 변경·감시 우회를 발견사항으로 표시'}],
};

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
        [record('evaluation'), record('agent_registry'), record('agent_transition'), kind('safety_alert', 'safety'), record('agent_stop_order'),
          ...AGENT_RISK_ALL]),
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
        '감독자가 운영을 모니터링하고 이상·오작동·예상 밖 성능을 탐지',
        [record('case'), record('case_decision'), kind('human_oversight_review', 'authority'), ...AGENT_RISK_ALL]),
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
  'KR-32-MONITOR': [record('evaluation'), record('case'), record('case_decision'), kind('safety_alert', 'safety'), ...AGENT_RISK_ALL],
  'KR-34-RISK': [record('evaluation'), record('agent_registry_policy'), ...AGENT_RISK_ALL],
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
  for (const item of Object.keys(AGENT_RISK_ISMS)) if (!a.alignments.some(al => al.item === item)) throw Error(`ISMS-P ${item} is not aligned`);
  const notice = legal.notices.find(n => n.number === '제2024-8호');
  const items = a.alignments.map(al => {
    const evidence = new Map(), supports = [...al.supports, ...(AGENT_RISK_ISMS[al.item] || [])];
    for (const s of supports) {
      for (const e of s.evidence) {
        const key = canonical({...e, what: null}), seen = evidence.get(key);
        if (seen) seen.checkItems = [...new Set([...seen.checkItems, ...s.checkItems])].sort((x, y) => x - y);
        else evidence.set(key, {...e, checkItems: [...s.checkItems]});
      }
    }
    return {id: `ISMS-P-${al.item}`, citation: `${legal.title}(${notice.issuer}고시 ${notice.number}) ${legal.annex} ${al.item}`, url: legal.url,
      sourceStatus: a.sources.verifiedLevel, title: {ko: titles.get(al.item), en: null}, evidence: [...evidence.values()], judgement: null,
      supports: supports.map(s => ({checkItems: s.checkItems, shows: s.shows})), manual: al.manual};
  });
  return {id: 'isms-p', title: {ko: 'ISMS-P 인증기준(정렬한 항목)', en: 'ISMS-P certification criteria (aligned items)'},
    sources: [{title: `${legal.title} ${legal.annex}`, notice: `${notice.issuer}고시 ${notice.number}`, url: legal.url,
      alignment: `data/isms-p-alignment.json (${a.id} schema ${a.schemaVersion}, ${a.mappingStatus}, checked ${a.checkedAt})`}],
    items, notMapped: [{ref: `${a.notAligned.length} items`, reason: {ko: '이유는 docs/isms-p-alignment.md를 보세요.', en: 'see docs/isms-p-alignment.md'}}]};
}

const BUILDERS = {'eu-ai-act-logging': euMapping, 'kr-ai-basic-act': krMapping, 'isms-p': ismsMapping};
// Mapping versions shipped with the verifier: data/evidence-pack-mappings/<framework>-v<n>.json, the exact mapping.json bytes of
// packages that name the version (version 1: the mappings of round 6, which carry no version field). A package verifies against the
// version it names; a version this verifier does not ship is refused unless the auditor accepts the package's own mapping.
// Version 3 (2026-10-15) adds the AI agent risk findings (AGENT_RISK) to EU 12(2)(a) and 14(4)(a), KR-32-MONITOR and KR-34-RISK, and
// ISMS-P 2.6.7, 2.9.4, 2.10.1 and 2.11.3.
export const MAPPING_VERSION = 3;
export const MAPPING_VERSIONS = {
  'eu-ai-act-logging': {1: '54b474415247708702aa4a0df6079cd3447794269ffeceb0a0c6a2a4717e4b5f',
    2: 'e9e4a7305536ec7e09cfbaa2ab07a145b1a7a3a2e031654620283c40da77d0fc', 3: 'ae76367e216bd4fac78a47dacb73417cd471bbbb40087f9e1720969821474a1f'},
  'kr-ai-basic-act': {1: '0a3bcb097f605a65393996242d13a6a251b3258b08257d2de46b87da32c49d93',
    2: '0b34923d153fe0fb80cd103efdbd75425b8b6d332621645691a5dcad48f29b6c', 3: 'b6c9f49b5ea0f21659524e6825e4980f447d0b8e8ccd231e0828797d8ba3100e'},
  'isms-p': {1: '2276885b8d3e3a4cbfce6884ddb3411b32dc79167b5e278234172453841b7aaa',
    2: '4bd27ad7a29c036f2f2074e8deca3ff9c72cd5cf9fbf453c25ac88b9d2fdfd21', 3: 'd9539ec10a89c753cc283eb68cc167280ed5331d59359a01b5444f1a7b1de8ce'},
};
export const mappingVersionFile = (id, version) => `data/evidence-pack-mappings/${id}-v${version}.json`;
// The shipped bytes of a mapping version, or null when this verifier does not ship it.
export function shippedMapping(id, version) {
  const sha256 = Object.hasOwn(MAPPING_VERSIONS, id) && Number.isSafeInteger(version) ? MAPPING_VERSIONS[id][version] : undefined;
  if (!sha256) return null;
  const bytes = readFileSync(new URL(`../${mappingVersionFile(id, version)}`, import.meta.url));
  if (sha256Hex(bytes) !== sha256) throw Error(`Shipped mapping ${id} version ${version} differs from its recorded digest`);
  return bytes;
}
// The mapping object written to mapping.json of a new package; the same input always gives the same bytes.
export function frameworkMapping(id) {
  if (!Object.hasOwn(BUILDERS, id)) throw Error('Unknown framework ' + JSON.stringify(id) + '; use one of ' + FRAMEWORKS.join(', '));
  return checkMapping({format: MAPPING_FORMAT, version: MAPPING_VERSION, mappingStatus: 'draft_requires_human_review', ...BUILDERS[id]()});
}
export const mappingBytes = mapping => Buffer.from(JSON.stringify(mapping, null, 1) + '\n', 'utf8');
// Builders write only the current shipped version: a changed catalog or alignment file needs a new version, not new bytes under an old one.
export function currentMappingBytes(id) {
  const bytes = mappingBytes(frameworkMapping(id));
  if (sha256Hex(bytes) !== MAPPING_VERSIONS[id][MAPPING_VERSION]) {
    throw Error(`The ${id} mapping built from the data files differs from shipped version ${MAPPING_VERSION}; ship it as a new mapping version`);
  }
  return bytes;
}

const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const text = v => typeof v === 'string' && v.length > 0 && v.length <= 2000;
// A finding entry names one code or one code prefix (version 3), never both: an empty prefix would count every finding.
const findingKey = e => (e.code === undefined) !== (e.codePrefix === undefined)
  && [e.code, e.codePrefix].some(v => typeof v === 'string' && /^[A-Za-z0-9_.:-]{3,160}$/.test(v));
// Structural check of a mapping, also applied to one read from a package with --mapping-from-pack.
export function checkMapping(m) {
  if (!plain(m) || m.format !== MAPPING_FORMAT || !FRAMEWORKS.includes(m.id) || !Array.isArray(m.items) || !m.items.length
    || (m.version !== undefined && !(Number.isSafeInteger(m.version) && m.version >= 2))) throw Error('Malformed mapping');
  const ids = new Set();
  for (const item of m.items) {
    if (!plain(item) || !/^[A-Z][A-Z0-9.-]{1,63}$/.test(item.id) || ids.has(item.id) || !text(item.citation) || !plain(item.title) || !text(item.title.ko)) {
      throw Error('Malformed mapping item ' + JSON.stringify(item?.id));
    }
    ids.add(item.id);
    if (!Array.isArray(item.evidence) || item.evidence.some(e => !plain(e) || !EVIDENCE_TYPES.includes(e.type) || (e.type === 'finding' && !findingKey(e)))) {
      throw Error('Malformed evidence in ' + item.id);
    }
    if (item.judgement !== null && !(Array.isArray(item.judgement) && item.judgement.every(text))) throw Error('Malformed judgement in ' + item.id);
  }
  if (!plain(m.title) || !text(m.title.ko) || !Array.isArray(m.notMapped)
    || m.notMapped.some(n => !plain(n) || !text(n.ref) || !plain(n.reason) || !text(n.reason.ko) || !text(n.reason.en))) throw Error('Malformed mapping');
  return m;
}
