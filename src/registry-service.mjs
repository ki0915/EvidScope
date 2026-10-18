// Agent registry API (docs/agent-registry.md). One signed registry object per agent with every version kept in the ledger,
// a lifecycle whose transitions are separate signed records, gate conditions and risk-tier rules kept as data, and a list
// of discovered candidates that a registry policy can register automatically as discovered entries without an owner, and an owner
// map that infers who answers for an agent from who runs it; only a reviewer confirms an owner (src/agent-ownership.mjs). Reviewers and admins write; every human role reads;
// the registry policy (enforcement mode, gates, risk rules) is admin-only. EvidScope records and evaluates; it blocks nothing.
import {randomUUID} from 'node:crypto';
import {canonical,digest} from './crypto.mjs';
import {fail,cleanText,identifier} from './model.mjs';
import {CONFIGURATION_FIELDS,DEFAULT_GATES,DEFAULT_RISK_RULES,ENFORCEMENT_MODES,GATE_CHECKS,GATE_TARGETS,REGISTRY_STATES,RISK_RULE_FIELDS,RISK_RULE_OPS,
 RISK_TIERS,allowedTransition,approvalRequired,computeRisk,riskBasis,tierAtLeast,verifyRegistryHistory} from './agent-registry.mjs';
import {isDecision} from './decision-rules.mjs';
import {createStopOrders} from './stop-order-service.mjs';
import {STOP_PROPAGATION_DEFAULTS} from './stop-orders.mjs';
import {normalizeApprovalPolicy} from './approval-service.mjs';
import {createCatalogImport} from './catalog-import-service.mjs';
import {AUTO_DISCOVERY_PRINCIPAL,OWNER_MAP_LIMITS,OWNER_MAP_TYPE,OWNER_MATCH_FIELDS,OWNER_MATCH_OPS,agentActivity,belongsTo,entryFor,executorOf,
 groupExecutors,inferOwner,ownershipOf,recordAccountability} from './agent-ownership.mjs';

const RESERVED=new Set(['candidates','policy','transitions','stops','import','owners','discover']);
// Registry policy autoRegister (docs/agent-registry.md, "자동 등록"): off, or register each new candidate as a discovered entry.
export const AUTO_REGISTER_MODES=Object.freeze(['off','discovered']);
const AUTO_REGISTER_MAX=50;
const SOURCE_KINDS=['agent','tool','authority','safety','telemetry','otlp','enforcement'];
const ENTRY_FIELDS=['name','owner','purpose','sources','actors','assetIds','systemId','models','tools','dataCategories','destinations','fingerprint'];
const GATE_FIELDS=['owner','purpose','systemId','assetIds','fingerprint','models','tools','dataCategories','destinations'];
const EVIDENCE_TYPES=['event','asset','system','case','governance_document','external'];
const ACTIVITY_KINDS=['intent','execution','self_report','result','delegation'];
const DIGEST=/^(?:sha256:)?[a-f0-9]{64}$/;

const object=(x,name)=>{if(!x||typeof x!=='object'||Array.isArray(x))fail(400,`${name}는 JSON 객체여야 합니다`);return x;};
const only=(x,allowed,name)=>{for(const k of Object.keys(object(x,name)))if(!allowed.includes(k))fail(400,`${name}에 허용되지 않은 필드: ${k}`);return x;};
const list=(value,max,item,name)=>{
 if(value===undefined||value===null)return [];
 if(!Array.isArray(value)||value.length>max)fail(400,`${name}는 최대 ${max}개 배열입니다`);
 return [...new Set(value.map(item))];
};
const label=max=>v=>cleanText(v,max);
const integer=(v,min,max,name)=>{if(!Number.isSafeInteger(v)||v<min||v>max)fail(400,`${name}는 ${min}~${max} 정수입니다`);return v;};
const present=v=>Array.isArray(v)?v.length>0:v&&typeof v==='object'?Object.keys(v).length>0:!!v;
const attributed=(e,entry)=>entry.sources.includes(e.source)||!!e.actor&&entry.actors.includes(e.actor);

function normalizeTool(t){
 if(typeof t==='string')return {name:cleanText(t,256),enforcement:'not_required'};
 only(t,['name','enforcement'],'tools 항목');
 if(t.enforcement!==undefined&&!['required','not_required'].includes(t.enforcement))fail(400,'도구 enforcement는 required 또는 not_required');
 return {name:cleanText(t.name,256),enforcement:t.enforcement||'not_required'};
}
function normalizeFingerprint(f){
 if(f===undefined||f===null)return {};
 only(f,['codeCommit','promptDigest','configDigest','version'],'fingerprint');const out={};
 if(f.codeCommit!==undefined){
  if(typeof f.codeCommit!=='string'||!/^[a-f0-9]{7,64}$/.test(f.codeCommit))fail(400,'codeCommit은 7~64자리 16진수입니다');out.codeCommit=f.codeCommit;
 }
 for(const k of ['promptDigest','configDigest'])if(f[k]!==undefined){
  if(typeof f[k]!=='string'||!DIGEST.test(f[k]))fail(400,`${k}는 SHA-256 digest입니다`);out[k]=f[k];
 }
 if(f.version!==undefined)out.version=cleanText(f.version,100);
 return out;
}
// Content of one registry version: fields given replace, absent fields keep the previous version's value.
function normalizeContent(x,previous){
 const has=k=>Object.hasOwn(x,k),value=(k,fallback)=>has(k)?x[k]:previous?previous[k]:fallback;
 const tools=list(value('tools'),50,normalizeTool,'tools');
 if(new Set(tools.map(t=>t.name)).size!==tools.length)fail(400,'도구 이름이 중복됩니다');
 const systemId=value('systemId',null);
 return {name:cleanText(value('name',x.id),200),owner:cleanText(value('owner',''),200),purpose:cleanText(value('purpose',''),1000),
  sources:list(value('sources'),20,identifier,'sources'),actors:list(value('actors'),20,label(256),'actors'),
  assetIds:list(value('assetIds'),50,identifier,'assetIds'),
  systemId:systemId===null?null:identifier(systemId),models:list(value('models'),20,label(200),'models'),tools,
  dataCategories:list(value('dataCategories'),16,label(64),'dataCategories'),destinations:list(value('destinations'),30,label(256),'destinations'),
  fingerprint:has('fingerprint')?normalizeFingerprint(x.fingerprint):previous?previous.fingerprint:{}};
}
function normalizeCondition(c){
 only(c,['id','check','fields','state','sourceKinds','min','tier'],'게이트 조건');
 if(!GATE_CHECKS.includes(c.check))fail(400,'지원하지 않는 게이트 검사입니다');
 const out={id:identifier(c.id),check:c.check};
 if(c.fields!==undefined){if(c.check!=='fields_present')fail(400,'fields는 fields_present 검사에만 씁니다');
  out.fields=list(c.fields,GATE_FIELDS.length,f=>GATE_FIELDS.includes(f)?f:fail(400,'게이트 필드 오류'),'fields');}
 else if(c.check==='fields_present')fail(400,'fields_present 검사에는 fields가 필요합니다');
 if(c.state!==undefined){
  if(!['events_in_state','decisions_received'].includes(c.check)||!REGISTRY_STATES.includes(c.state))fail(400,'게이트 state 오류');out.state=c.state;
 }
 else if(c.check==='events_in_state')fail(400,'events_in_state 검사에는 state가 필요합니다');
 if(c.sourceKinds!==undefined){if(c.check!=='events_in_state')fail(400,'sourceKinds는 events_in_state 검사에만 씁니다');
  out.sourceKinds=list(c.sourceKinds,SOURCE_KINDS.length,k=>SOURCE_KINDS.includes(k)?k:fail(400,'출처 종류 오류'),'sourceKinds');}
 if(c.min!==undefined){
  if(!['events_in_state','decisions_received','evidence_attached'].includes(c.check))fail(400,'min을 쓸 수 없는 검사입니다');out.min=integer(c.min,1,1000,'min');
 }
 if(c.tier!==undefined){if(c.check!=='approval_rule_for_tools'||!RISK_TIERS.includes(c.tier))fail(400,'게이트 tier 오류');out.tier=c.tier;}
 return out;
}
function normalizeGates(gates){
 only(gates,RISK_TIERS,'gates');const out={};
 for(const tier of RISK_TIERS){
  const targets=only(gates[tier]??{},GATE_TARGETS,`gates.${tier}`);out[tier]={};
  for(const target of GATE_TARGETS){
   const conditions=list(targets[target],20,normalizeCondition,`gates.${tier}.${target}`);
   if(new Set(conditions.map(c=>c.id)).size!==conditions.length)fail(400,'게이트 조건 id가 중복됩니다');
   if(conditions.length)out[tier][target]=conditions;
  }
 }
 return out;
}
function normalizeRiskRule(r){
 only(r,['id','field','op','values','tier'],'위험 규칙');
 if(!RISK_RULE_FIELDS.includes(r.field)||!RISK_RULE_OPS.includes(r.op)||!RISK_TIERS.includes(r.tier))fail(400,'위험 규칙의 field·op·tier 오류');
 if(r.op==='not_suffix'&&r.field!=='destination')fail(400,'not_suffix는 destination 규칙에만 씁니다');
 const values=list(r.values,100,label(128),'values');if(!values.length)fail(400,'위험 규칙 values가 필요합니다');
 return {id:identifier(r.id),field:r.field,op:r.op,values,tier:r.tier};
}

export function createRegistry({store,principals,policyObjects,dirty,reviewer,admin}){
 const now=()=>new Date().toISOString();
 const sources=p=>principals.filter(q=>q.tenant===p.tenant&&q.role==='source');
 function rows(p){
  let result;try{result=store.cachedRegistryRows(p.tenant);}catch(error){if(error?.status)throw error;fail(409,'레지스트리 서명 원장을 검증할 수 없습니다');}
  if(result.oversized)fail(413,'레지스트리 기록 한도 초과: 부분 검증으로 조회하거나 변경할 수 없습니다');
  return result.rows;
 }
 function retained(p){
  try{return [...store.verifiedFacets(p.tenant,['keys','events']).eventsBySequence.values()];}
  catch{fail(409,'이벤트 조회 사본 또는 색인이 서명 원장과 일치하지 않습니다');}
 }
 // The signed policy, or the built-in defaults (named as such) for a tenant that never set one.
 function policy(p){
  const signed=policyObjects(p,'agent_registry_policy').get('current');
  if(signed)return {...signed,source:'signed'};
  return {id:'current',version:0,enforcement:'off',gates:DEFAULT_GATES,riskRules:DEFAULT_RISK_RULES,source:'built_in_default'};
 }
 // Effective tier: a reviewer override for this exact configuration, else the tier the current rules compute.
 function effectiveRisk(entry,current){
  const computed=computeRisk(entry,current.riskRules),override=entry.risk?.override;
  const valid=override&&override.basisHash===riskBasis(entry);
  return {...computed,tier:valid?override.tier:computed.computed,override:valid?override:null};
 }
 function stateWindow(registryRows,id,state){
  let window=null,previous=null;
  for(const row of registryRows){if(row.type!=='agent_registry'||row.payload.id!==id)continue;const v=row.payload;
   if(v.state===state&&previous!==state)window={from:v.effectiveFrom,to:null};else if(previous===state&&v.state!==state&&window)window.to=v.effectiveFrom;
   previous=v.state;}
  return window;
 }
 // Gate conditions for the target state at the entry's effective tier, checked against the records signed so far.
 function gate(p,entry,to,evidence,current){
  const risk=effectiveRisk(entry,current),conditions=current.gates?.[risk.tier]?.[to]||[];
  let events,registryRows;const assets=policyObjects(p,'asset'),systems=policyObjects(p,'system'),at=Date.now();
  const inWindow=(e,window)=>!window||e.receivedAt>=window.from&&(!window.to||e.receivedAt<window.to);
  const results=conditions.map(c=>{
   if(c.check==='fields_present'){const missing=c.fields.filter(f=>!present(entry[f]));return {met:!missing.length,detail:{missing}};}
   if(c.check==='events_in_state'||c.check==='decisions_received'){
    registryRows??=rows(p);events??=retained(p);const window=c.state?stateWindow(registryRows,entry.id,c.state):null;
    if(c.state&&!window)return {met:false,detail:{count:0,reason:'never_in_state',state:c.state}};
    const count=events.filter(e=>inWindow(e,window)&&(c.check==='decisions_received'?isDecision(e)&&entry.actors.includes(e.actor)
     :attributed(e,entry)&&(!c.sourceKinds||c.sourceKinds.includes(e.sourceKind)))).length;
    return {met:count>=(c.min||1),detail:{count,min:c.min||1,...(window?{window}:{})}};
   }
   if(c.check==='approval_rule_for_tools'){
    const tools=risk.tools.filter(t=>tierAtLeast(t.tier,c.tier||'high')).map(t=>({name:t.name,tier:t.tier,met:[...assets.values()].some(a=>a.tool===t.name&&
     entry.actors.includes(a.actor)&&a.approvalRequired===true&&Date.parse(a.validFrom)<=at&&(!a.validUntil||at<Date.parse(a.validUntil)))}));
    return {met:tools.every(t=>t.met),detail:{tools}};
   }
   if(c.check==='assets_linked'){
    const missing=entry.assetIds.filter(id=>!assets.has(id));return {met:entry.assetIds.length>0&&!missing.length,detail:{missing}};
   }
   if(c.check==='system_linked')return {met:!!entry.systemId&&systems.has(entry.systemId),detail:{systemId:entry.systemId}};
   if(c.check==='fingerprint_recorded')return {met:['codeCommit','promptDigest','configDigest'].some(k=>entry.fingerprint?.[k]),detail:{}};
   return {met:evidence.length>=(c.min||1),detail:{count:evidence.length,min:c.min||1}};
  });
  const checked=conditions.map((c,i)=>({id:c.id,check:c.check,...results[i]}));
  return {tier:risk.tier,target:to,policyVersion:current.version,policySource:current.source,met:checked.every(c=>c.met),
   conditions:checked,unmet:checked.filter(c=>!c.met).map(c=>c.id),checkedAt:now()};
 }
 function links(p,content,id){
  for(const s of content.sources)if(!sources(p).some(q=>q.id===s))fail(400,`등록되지 않은 출처 자격입니다: ${s}`);
  const assets=policyObjects(p,'asset');for(const a of content.assetIds)if(!assets.has(a))fail(400,`등록되지 않은 자산입니다: ${a}`);
  if(content.systemId&&!policyObjects(p,'system').has(content.systemId))fail(400,`등록되지 않은 거버넌스 시스템입니다: ${content.systemId}`);
  // One attribution per source principal and actor name: a second live entry would make point-in-time findings ambiguous.
  for(const other of policyObjects(p,'agent_registry').values()){
   if(other.id===id||other.state==='retired')continue;
   const shared=[...content.sources.filter(s=>other.sources.includes(s)),...content.actors.filter(a=>other.actors.includes(a))];
   if(shared.length)fail(409,`다른 등록 항목(${other.id})이 이미 포함한 출처·행위자입니다: ${shared.slice(0,5).join(', ')}`);
  }
 }
 function evidenceRefs(p,value){
  return list(value,20,item=>{
   only(item,['type','ref'],'evidence 항목');if(!EVIDENCE_TYPES.includes(item.type))fail(400,'증거 참조 유형 오류');
   const ref=cleanText(item.ref,1000);let verification='self_asserted';
   if(item.type==='event'){let index;try{index=store.cachedEventIndex(p.tenant);}catch{fail(409,'이벤트 조회 사본 또는 색인이 서명 원장과 일치하지 않습니다');}
    if(!index.has(ref))fail(400,`보관된 이벤트가 아닙니다: ${ref}`);verification='retained_event_at_request';}
   else if(['asset','system','case'].includes(item.type)){
    if(!policyObjects(p,item.type).has(ref))fail(400,`서명된 ${item.type} 객체가 아닙니다: ${ref}`);verification='signed_object_at_request';
   }
   return canonical({type:item.type,ref,verification});
  },'evidence').map(s=>JSON.parse(s));
 }
 const putVersion=(p,entry)=>{store.put(p,'agent_registry',entry.id,entry);dirty(p.tenant);return entry;};
 // Any new registry version makes a pending request stale; it is closed on the record rather than left to fail at approval.
 function supersede(p,id,reason){
  for(const t of policyObjects(p,'agent_transition').values())if(t.agentId===id&&t.status==='pending')
   store.put(p,'agent_transition',t.id,{...t,status:'superseded',supersededBy:p.id,supersededAt:now(),supersededReason:reason});
 }
 // Risk as computed when this version was written; an override survives only while the configuration it was given for does.
 function riskRecord(p,entry){
  const current=policy(p),risk=computeRisk(entry,current.riskRules),basisHash=riskBasis(entry);
  const override=entry.risk?.override?.basisHash===basisHash?entry.risk.override:null;
  return {computed:risk.computed,tier:override?.tier||risk.computed,tools:risk.tools,reasons:risk.reasons,rulesHash:digest(current.riskRules),
   basisHash,override};
 }
 function version(p,previous,changes,change){
  const entry={...previous,...changes,version:previous.version+1,effectiveFrom:now(),change};
  return {...entry,risk:riskRecord(p,entry)};
 }
 const pendingOf=(p,id)=>[...policyObjects(p,'agent_transition').values()].filter(t=>t.agentId===id&&t.status==='pending');
 const entryOf=(p,id)=>policyObjects(p,'agent_registry').get(identifier(id))||fail(404,'등록 항목을 찾을 수 없습니다');

 function create(p,x){
  only(x,['id',...ENTRY_FIELDS,'state','discoveredFrom'],'등록 요청');
  const id=identifier(x.id);if(RESERVED.has(id))fail(400,'예약된 식별자입니다');
  const state=x.state??'draft';if(!['discovered','draft'].includes(state))fail(400,'새 등록 항목은 discovered 또는 draft 상태로만 만듭니다');
  const content=normalizeContent(x,null),discoveredFrom=x.discoveredFrom===undefined?undefined:only(x.discoveredFrom,['source','actor'],'discoveredFrom');
  return store.transaction(()=>{
   if(policyObjects(p,'agent_registry').has(id))fail(409,'이미 등록된 식별자입니다');links(p,content,id);
   const at=now(),origin=discoveredFrom&&{source:discoveredFrom.source===undefined?null:cleanText(discoveredFrom.source,256),
    actor:discoveredFrom.actor===undefined?null:cleanText(discoveredFrom.actor,256)};
   const base={id,...content,state,registeredBy:p.id,registeredAt:at,editedBy:p.id,editedAt:at,version:1,effectiveFrom:at,change:'created',
    ...(origin?{discoveredFrom:origin}:{})};
   return putVersion(p,{...base,risk:riskRecord(p,base)});
  });
 }
 function update(p,id,x){
  only(x,ENTRY_FIELDS,'수정 요청');
  return store.transaction(()=>{
   const previous=entryOf(p,id);if(previous.state==='retired')fail(409,'폐기된 등록 항목은 수정할 수 없습니다');
   const content=normalizeContent(x,previous);
   const changed=CONFIGURATION_FIELDS.filter(k=>canonical(content[k])!==canonical(previous[k]));
   if(['approved','production'].includes(previous.state)&&changed.length)
    fail(409,`approved/production 상태에서는 구성(${changed.join(', ')})을 바꿀 수 없습니다. 정지(suspended) 후 수정하고 다시 승인받으세요`);
   links(p,content,previous.id);supersede(p,previous.id,'registry_version_changed');
   // A reviewer who types a new owner confirms it (src/agent-ownership.mjs); the team of an earlier confirmation stays only for the same owner.
   const at=now(),ownership=content.owner&&content.owner!==previous.owner?{ownership:{status:'confirmed',owner:content.owner,
    team:previous.ownership?.owner===content.owner?previous.ownership.team??null:null,by:p.id,at,basis:'entered_by_reviewer'}}:{};
   return putVersion(p,version(p,previous,{...content,...ownership,editedBy:p.id,editedAt:at},'updated'));
  });
 }
 function overrideRisk(p,id,x){
  only(x,['tier','reason'],'위험 등급 재지정');const reason=cleanText(x.reason,1000);if(!reason.trim())fail(400,'재지정 사유가 필요합니다');
  if(x.tier!==null&&!RISK_TIERS.includes(x.tier))fail(400,'위험 등급은 low, medium, high 또는 null(해제)입니다');
  return store.transaction(()=>{
   const previous=entryOf(p,id);if(previous.state==='retired')fail(409,'폐기된 등록 항목입니다');
   if([previous.registeredBy,previous.editedBy].includes(p.id))fail(403,'등록하거나 구성을 수정한 사람은 위험 등급을 재지정할 수 없습니다(4-eyes)');
   if(x.tier===null&&!previous.risk?.override)fail(409,'해제할 재지정이 없습니다');
   supersede(p,previous.id,'registry_version_changed');
   const at=now(),override=x.tier===null?null:{tier:x.tier,reason,by:p.id,at,basisHash:riskBasis(previous)};
   const next=version(p,previous,{risk:{...previous.risk,override}},'risk_override');
   // A cleared override names who cleared it on this version only; later versions recompute the risk record.
   return putVersion(p,x.tier===null?{...next,risk:{...next.risk,cleared:{by:p.id,at,reason}}}:next);
  });
 }
 function apply(p,entry,t){
  const lastTransition={id:t.id,from:t.from,to:t.to,requestedBy:t.requestedBy,...(t.reviewedBy?{approvedBy:t.reviewedBy}:{}),at:now()};
  return putVersion(p,version(p,entry,{state:t.to,lastTransition},'transition'));
 }
 // production→suspended applied by a stop order in the order's commit; the transition names the order.
 function suspend(p,entry,{id,reason,evidence,stopOrderId}){
  const t={id,agentId:entry.id,from:entry.state,to:'suspended',reason,evidence,requestedBy:p.id,requestedAt:now(),registryVersion:entry.version,
   registeredBy:entry.registeredBy,editedBy:entry.editedBy,approvalRequired:false,
   gate:gate(p,entry,'suspended',evidence,policy(p)),status:'applied',stopOrderId};
  store.put(p,'agent_transition',t.id,t);
  return {transition:t,entry:apply(p,entry,t)};
 }
 function request(p,id,x){
  only(x,['to','reason','evidence'],'전이 요청');const reason=cleanText(x.reason,1000);if(!reason.trim())fail(400,'전이 사유가 필요합니다');
  if(!REGISTRY_STATES.includes(x.to))fail(400,'알 수 없는 상태입니다');
  return store.transaction(()=>{
   const entry=entryOf(p,id),from=entry.state,to=x.to;
   if(!allowedTransition(from,to))fail(409,`${from}에서 ${to}로 전이할 수 없습니다`);
   stops.assertPromotion(p,entry,to);
   const evidence=evidenceRefs(p,x.evidence),needs=approvalRequired(from,to),current=policy(p),result=gate(p,entry,to,evidence,current);
   if(needs&&pendingOf(p,entry.id).length)fail(409,'승인 대기 중인 전이 요청이 이미 있습니다');
   if(!needs&&!result.met)fail(409,`전이 조건 미충족: ${result.unmet.join(', ')}`);
   const t={id:randomUUID(),agentId:entry.id,from,to,reason,evidence,requestedBy:p.id,requestedAt:now(),registryVersion:entry.version,
    registeredBy:entry.registeredBy,editedBy:entry.editedBy,approvalRequired:needs,gate:result,status:needs?'pending':'applied'};
   if(!needs)supersede(p,entry.id,'state_changed');
   store.put(p,'agent_transition',t.id,t);
   return needs?{transition:t,gate:result}:{transition:t,gate:result,entry:apply(p,entry,t)};
  });
 }
 function decide(p,tid,operation,x){
  only(x,['reason'],'전이 결정');const reason=cleanText(x.reason??'',1000);if(!reason.trim())fail(400,'결정 사유가 필요합니다');
  return store.transaction(()=>{
   const t=policyObjects(p,'agent_transition').get(identifier(tid))||fail(404,'전이 요청을 찾을 수 없습니다');
   if(t.status!=='pending')fail(409,'승인 대기 중인 전이 요청만 결정할 수 있습니다');
   const entry=entryOf(p,t.agentId),reviewed={reviewedBy:p.id,reviewedAt:now(),reviewReason:reason};
   if(operation==='refuse')return {transition:store.put(p,'agent_transition',t.id,{...t,status:'refused',...reviewed})};
   if(entry.version!==t.registryVersion||entry.state!==t.from)fail(409,'요청 이후 등록 항목이 바뀌었습니다. 새로 요청하세요');
   if([entry.registeredBy,entry.editedBy,t.requestedBy].includes(p.id))fail(403,'등록·구성 수정·전이 요청을 한 사람은 이 전이를 승인할 수 없습니다(4-eyes)');
   stops.assertPromotion(p,entry,t.to);
   const result=gate(p,entry,t.to,t.evidence,policy(p));
   if(!result.met)fail(409,`전이 조건 미충족: ${result.unmet.join(', ')}`);
   const approved=store.put(p,'agent_transition',t.id,{...t,status:'approved',...reviewed,approvalGate:result});
   const applied=apply(p,entry,approved);
   // The approved resume is the four-eyes lift of the agent's whole-agent stop orders (docs/kill-switch.md).
   const lifted=t.from==='suspended'&&t.to==='production'?stops.liftOnResume(p,entry.id,approved):[];
   return {transition:approved,gate:result,entry:applied,...(lifted.length?{liftedStopOrders:lifted}:{})};
  });
 }
 function setPolicy(p,x){
  admin(p);only(x,['enforcement','gates','riskRules','approvals','stopPropagation','autoRegister'],'레지스트리 정책');
  if(x.autoRegister!==undefined&&!AUTO_REGISTER_MODES.includes(x.autoRegister))fail(400,'autoRegister는 off 또는 discovered입니다');
  if(x.enforcement!==undefined&&!ENFORCEMENT_MODES.includes(x.enforcement))fail(400,'enforcement는 off 또는 unregistered_activity입니다');
  const gates=x.gates===undefined?undefined:normalizeGates(x.gates);
  const riskRules=x.riskRules===undefined?undefined:list(x.riskRules,100,normalizeRiskRule,'riskRules');
  if(riskRules&&new Set(riskRules.map(r=>r.id)).size!==riskRules.length)fail(400,'위험 규칙 id가 중복됩니다');
  // Who may answer approval requests (docs/approval-queue.md); written only once set, so earlier policy records keep their shape.
  const approvals=x.approvals===undefined?undefined:normalizeApprovalPolicy(x.approvals);
  return store.transaction(()=>{
   const previous=policy(p),at=now();
   // stopPropagation (docs/kill-switch.md) is written only once set, so other policy records keep their earlier shape.
   const stopPropagation=x.stopPropagation===undefined?previous.stopPropagation:normalizeStopPropagation(p,x.stopPropagation,previous.stopPropagation);
   const next={id:'current',version:previous.version+1,enforcement:x.enforcement??previous.enforcement,gates:gates??previous.gates,
    riskRules:riskRules??previous.riskRules,...(approvals??previous.approvals?{approvals:approvals??previous.approvals}:{}),
    ...(stopPropagation?{stopPropagation}:{}),
    // autoRegister is written only once set, like approvals and stopPropagation.
    ...((x.autoRegister??previous.autoRegister)!==undefined?{autoRegister:x.autoRegister??previous.autoRegister}:{}),updatedBy:p.id,updatedAt:at,effectiveFrom:at};
   store.put(p,'agent_registry_policy','current',next);dirty(p.tenant);return next;
  });
 }
 function normalizeStopPropagation(p,x,previous){
  only(x,['windowSeconds','enforcementPoints'],'stopPropagation');const base={...STOP_PROPAGATION_DEFAULTS,...(previous||{})};
  const points=x.enforcementPoints===undefined?base.enforcementPoints:list(x.enforcementPoints,20,identifier,'enforcementPoints');
  for(const id of points)if(!sources(p).some(q=>q.id===id&&q.kind==='enforcement'))fail(400,`등록되지 않은 집행 지점(enforcement 출처 자격)입니다: ${id}`);
  return {windowSeconds:x.windowSeconds===undefined?base.windowSeconds:integer(x.windowSeconds,10,86400,'windowSeconds'),enforcementPoints:[...points].sort()};
 }
 // ---------- executors and owners (src/agent-ownership.mjs) ----------
 const ownerMap=p=>policyObjects(p,OWNER_MAP_TYPE).get('current')||null;
 // Executors seen for every entry, from the retained agent records: Map(entry id -> grouped executors).
 function executorsByEntry(p,entries){
  const seen=new Map();
  for(const e of retained(p)){
   if(!agentActivity(e))continue;const entry=entryFor(entries,e);if(!entry)continue;
   if(!seen.has(entry.id))seen.set(entry.id,[]);seen.get(entry.id).push({executor:executorOf(e),actor:e.actor||null,source:e.source,at:e.receivedAt});
  }
  return new Map([...seen].map(([id,list])=>[id,groupExecutors(list)]));
 }
 const ownership=(entry,map,executors)=>ownershipOf(entry,inferOwner(map,executors||[]));
 function normalizeOwnerRule(r){
  only(r,['id','field','op','value','team','owner'],'책임자 매핑 규칙');
  if(!OWNER_MATCH_FIELDS.includes(r.field))fail(400,`매핑 field는 ${OWNER_MATCH_FIELDS.join(', ')} 중 하나입니다`);
  const op=r.op??'eq';if(!OWNER_MATCH_OPS.includes(op))fail(400,'매핑 op는 eq, prefix, suffix 중 하나입니다');
  const value=cleanText(r.value,OWNER_MAP_LIMITS.value),owner=cleanText(r.owner,OWNER_MAP_LIMITS.label);
  if(!value.trim()||!owner.trim())fail(400,'매핑 규칙에는 value와 owner가 필요합니다');
  return {id:identifier(r.id),field:r.field,op,value,team:r.team===undefined||r.team===null?null:cleanText(r.team,OWNER_MAP_LIMITS.label),owner};
 }
 // The owner map (admin only): rules in priority order, each mapping an executor field, actor or source to a team and an owner.
 // It changes no entry and no evaluation; it only feeds the inferred owner shown beside the confirmed one.
 function setOwnerMap(p,x){
  admin(p);only(x,['rules'],'책임자 매핑 표');
  const rules=list(x.rules,OWNER_MAP_LIMITS.rules,normalizeOwnerRule,'rules');
  if(new Set(rules.map(r=>r.id)).size!==rules.length)fail(400,'매핑 규칙 id가 중복됩니다');
  return store.transaction(()=>{
   const previous=ownerMap(p);
   return store.put(p,OWNER_MAP_TYPE,'current',{id:'current',version:(previous?.version||0)+1,rules,updatedBy:p.id,updatedAt:now()});
  });
 }
 function owners(p){
  const map=ownerMap(p),entries=[...policyObjects(p,'agent_registry').values()],seen=executorsByEntry(p,entries);
  const items=entries.filter(v=>v.state!=='retired').map(v=>({id:v.id,name:v.name,state:v.state,owner:ownership(v,map,seen.get(v.id)),
   executors:seen.get(v.id)||[]}));
  const tally=s=>items.filter(i=>i.owner.status===s).length;
  return {map:map||{id:'current',version:0,rules:[]},items,counts:{agents:items.length,confirmed:tally('confirmed'),inferred:tally('inferred'),
   conflict:tally('conflict'),unknown:tally('unknown')},fields:OWNER_MATCH_FIELDS,ops:OWNER_MATCH_OPS,
   limitations:['실행자(OS 계정·PC·저장소·git 사용자)는 에이전트 훅의 자기 보고입니다','추정(inferred)은 매핑 표의 결과일 뿐 책임 확정이 아닙니다. 확정은 검토자가 기록합니다',
    '매핑 표는 관리자 한 사람이 바꿉니다(4-eyes 없음). 표를 바꾸면 추정이 다시 계산되며 확정된 책임자는 그대로입니다']};
 }
 // A reviewer confirms who answers for the agent: the owner given, or (without one) the owner the map infers now. The new version records
 // who confirmed it, when, why and on what basis; configuration and state stay as they are.
 function confirmOwner(p,id,x){
  only(x,['owner','team','reason'],'책임자 확정');const reason=cleanText(x.reason??'',1000);if(!reason.trim())fail(400,'확정 사유가 필요합니다');
  return store.transaction(()=>{
   const previous=entryOf(p,id);if(previous.state==='retired')fail(409,'폐기된 등록 항목입니다');
   const inferred=x.owner===undefined?ownership(previous,ownerMap(p),executorsByEntry(p,[...policyObjects(p,'agent_registry').values()]).get(previous.id)):null;
   if(inferred&&inferred.status!=='inferred')
    fail(409,inferred.status==='conflict'?'추정 책임자가 여럿입니다. owner를 직접 지정하세요':inferred.status==='confirmed'?'이미 확정된 책임자입니다':'추정 책임자가 없습니다. owner를 지정하세요');
   const owner=x.owner===undefined?inferred.owner:cleanText(x.owner,200);if(!owner.trim())fail(400,'책임자(owner)가 필요합니다');
   const team=x.team===undefined?inferred?.team??null:x.team===null?null:cleanText(x.team,200),at=now();
   const basis=inferred?{kind:inferred.basis,...(inferred.rule?{rule:inferred.rule}:{})}:{kind:'entered_by_reviewer'};
   supersede(p,previous.id,'registry_version_changed');
   return putVersion(p,version(p,previous,{owner,ownership:{status:'confirmed',owner,team,by:p.id,at,reason,basis}},'owner_confirmed'));
  });
 }
 // Auto-registration (registry policy autoRegister 'discovered', or a reviewer's POST /api/registry/discover): every candidate that no
 // entry covers or was registered from becomes a discovered entry with no owner, sources or actors, so it changes no finding. A
 // candidate a retired entry covers or was registered from is not registered again.
 function discover(p,{dryRun=false,max=AUTO_REGISTER_MAX}={}){
  return store.transaction(()=>{
   const all=[...policyObjects(p,'agent_registry').values()],found=candidates(p).items,ids=new Set(all.map(v=>v.id)),registered=[],skipped=[];
   const map=ownerMap(p),system={id:AUTO_DISCOVERY_PRINCIPAL,tenant:p.tenant};
   for(const c of found){
    const who={source:c.source,actor:c.actor};
    if(registered.length>=max){skipped.push({...who,reason:'run_limit'});continue;}
    if(all.some(v=>v.state==='retired'&&belongsTo(v,who))){skipped.push({...who,reason:'retired_before'});continue;}
    let id=c.suggestedId;for(let n=2;ids.has(id)||RESERVED.has(id);n++)id=`${c.suggestedId.slice(0,100)}-${n}`;ids.add(id);
    const at=now(),base={id,name:c.actor||c.source,owner:'',purpose:'',sources:[],actors:[],assetIds:[],systemId:null,models:[],tools:[],
     dataCategories:[],destinations:[],fingerprint:{},state:'discovered',registeredBy:system.id,registeredAt:at,editedBy:system.id,editedAt:at,version:1,
     effectiveFrom:at,change:'created',discoveredFrom:who,
     discovery:{reasons:c.reasons,events:c.events,firstSeen:c.firstSeen,lastSeen:c.lastSeen,observedTools:c.tools.slice(0,20),observedModels:c.models.slice(0,20)}};
    const entry={...base,risk:riskRecord(system,base)};
    if(!dryRun)putVersion(system,entry);
    registered.push({id,...who,owner:ownershipOf(entry,inferOwner(map,c.executors))});
   }
   return {dryRun,registered,skipped,principal:system.id};
  });
 }
 // Accountability of records (alerts): the entry, the executor and the owner of the first agent record among the refs (`source/id`).
 function accountabilityFor(p){
  const entries=[...policyObjects(p,'agent_registry').values()],map=ownerMap(p);let seen=null,byRef=null;
  return refs=>{
   byRef??=new Map(retained(p).map(e=>[`${e.source}/${e.id}`,e]));
   const e=(refs||[]).map(r=>byRef.get(r)).find(x=>x&&agentActivity(x));if(!e)return null;
   seen??=executorsByEntry(p,entries);
   return recordAccountability(entries,map,e,seen);
  };
 }
 // Unregistered agents EvidScope already sees: agent/OTLP sources and reported actors with activity, tool records' actors,
 // UNREGISTERED_ASSET / AI_UNREGISTERED_ASSET findings, and agent source principals without any entry. Listed, never registered.
 function candidates(p){
  const entries=[...policyObjects(p,'agent_registry').values()].filter(v=>v.state!=='retired');
  // Covered: an entry names the source or actor, or a live entry was registered from this candidate (discoveredFrom).
  const covered=(source,actor)=>entries.some(v=>source&&v.sources.includes(source)||actor&&v.actors.includes(actor)||
   v.discoveredFrom&&belongsTo({discoveredFrom:v.discoveredFrom},{source,actor}));
  const map=ownerMap(p);
  const groups=new Map(),byRef=new Map(),active=new Set();
  const group=(source,actor)=>{
   const key=canonical([source,actor]);
   if(!groups.has(key))groups.set(key,{source,actor,sourceKinds:new Set(),events:0,actions:new Set(),tools:new Set(),models:new Set(),reasons:new Set(),
    firstSeen:null,lastSeen:null,observed:[]});
   return groups.get(key);
  };
  for(const e of retained(p)){
   if(!ACTIVITY_KINDS.includes(e.kind)||!['agent','otlp','tool'].includes(e.sourceKind))continue;
   const source=e.sourceKind==='tool'?null:e.source,actor=e.actor&&e.actor!=='unknown'?e.actor:null;
   if(source)active.add(source);
   if(!source&&!actor||covered(source,actor))continue;
   const g=group(source,actor);g.sourceKinds.add(e.sourceKind);g.events++;g.actions.add(e.actionId);g.reasons.add('observed_activity');
   if(e.tool)g.tools.add(e.tool);if(e.model)g.models.add(e.model);
   g.observed.push({executor:executorOf(e),actor:e.actor||null,source:e.source,at:e.receivedAt});
   if(!g.firstSeen||e.receivedAt<g.firstSeen)g.firstSeen=e.receivedAt;if(!g.lastSeen||e.receivedAt>g.lastSeen)g.lastSeen=e.receivedAt;
   byRef.set(`${e.source}/${e.id}`,g);
  }
  let evaluations=[];try{const result=store.cachedEvaluations(p.tenant,{latest:true});evaluations=result.oversized?[]:result.values;}catch{}
  for(const v of evaluations)for(const f of v.findings||[])
   if(['UNREGISTERED_ASSET','AI_UNREGISTERED_ASSET'].includes(f.code))for(const ref of f.evidence||[])byRef.get(ref)?.reasons.add(f.code);
  for(const q of sources(p).filter(q=>q.kind==='agent'))if(!covered(q.id,null)&&!active.has(q.id))
   group(q.id,null).reasons.add('configured_source_without_activity');
  const suggestedId=g=>String(g.actor||g.source).toLowerCase().replace(/[^a-z0-9._:@/-]+/g,'-').slice(0,100)||'agent';
  const items=[...groups.values()].map(g=>{const executors=groupExecutors(g.observed,10);return {source:g.source,actor:g.actor,state:'discovered',
   registered:false,suggestedId:suggestedId(g),executors,owner:inferOwner(map,executors),
   sourceKinds:[...g.sourceKinds].sort(),events:g.events,actions:g.actions.size,tools:[...g.tools].sort().slice(0,50),models:[...g.models].sort().slice(0,20),
   reasons:[...g.reasons].sort(),firstSeen:g.firstSeen,lastSeen:g.lastSeen};})
   .sort((a,b)=>(b.lastSeen||'').localeCompare(a.lastSeen||'')||canonical([a.source,a.actor]).localeCompare(canonical([b.source,b.actor])));
  return {items:items.slice(0,200),total:items.length,autoRegister:policy(p).autoRegister||'off',
   limitations:['자동 등록(autoRegister)이 꺼져 있으면 목록만 보여 줍니다. 켜져 있으면 discovered 항목으로 등록되며 책임자는 사람이 확정해야 합니다. 행위자 이름과 실행자는 출처의 자기 보고입니다',
   '보관 중인 이벤트와 최신 평가만 봅니다. 파기된 이벤트나 수집되지 않은 에이전트는 나타나지 않습니다']};
 }
 function detail(p,id){
  const entry=entryOf(p,id),current=policy(p);
  const registryRows=rows(p).filter(r=>r.type==='agent_registry'&&r.payload?.id===entry.id||r.type==='agent_transition'&&r.payload?.agentId===entry.id);
  const versions=registryRows.filter(r=>r.type==='agent_registry').map(r=>({seq:r.seq,recordedAt:r.recordedAt,principal:r.principal,...r.payload}));
  const records=registryRows.filter(r=>r.type==='agent_transition'),transitions=[...new Map(records.map(r=>[r.payload.id,r.payload])).values()];
  const next=REGISTRY_STATES.filter(to=>allowedTransition(entry.state,to))
   .map(to=>({to,approvalRequired:approvalRequired(entry.state,to),gate:gate(p,entry,to,[],current)}));
  const transitionRecords=records.map(r=>({seq:r.seq,recordedAt:r.recordedAt,principal:r.principal,...r.payload}));
  const seen=executorsByEntry(p,[...policyObjects(p,'agent_registry').values()]).get(entry.id)||[];
  return {entry,risk:effectiveRisk(entry,current),ownership:ownership(entry,ownerMap(p),seen),executors:seen,versions,transitions,transitionRecords,next,lifecycle:verifyRegistryHistory(registryRows),
   policy:{version:current.version,source:current.source,enforcement:current.enforcement},stopOrders:stops.forAgent(p,entry.id)};
 }
 // Stop orders and their propagation (src/stop-order-service.mjs, docs/kill-switch.md) share this storage and four-eyes path.
 const stops=createStopOrders({store,principals,policyObjects,dirty,rows,retained,policy,entryOf,suspend,supersede,evidenceRefs,now});
 // Catalog import (src/catalog-import-service.mjs): A2A Agent Cards and Backstage entities as discovered entries with provenance.
 const catalog=createCatalogImport({store,policyObjects,putVersion,riskRecord,supersede,now});
 function handle(p,method,url,x){
  const path=url.pathname;if(path!=='/api/registry'&&!path.startsWith('/api/registry/'))return undefined;
  const parts=path.split('/').slice(3).map(decodeURIComponent);
  if(method==='GET'){
   return store.transaction(()=>{
    if(!parts.length){const current=policy(p),pending=[...policyObjects(p,'agent_transition').values()].filter(t=>t.status==='pending');
     const stopped=entry=>{const n=stops.activeOf(p,entry.id).length;return n?{activeStopOrders:n}:{};};
     const all=[...policyObjects(p,'agent_registry').values()],map=ownerMap(p),seen=executorsByEntry(p,all);
     return {items:all.map(entry=>({...entry,effectiveRisk:effectiveRisk(entry,current).tier,
      pendingTransition:pending.find(t=>t.agentId===entry.id)||null,...stopped(entry),ownerStatus:ownership(entry,map,seen.get(entry.id))})),
     policy:{version:current.version,source:current.source,enforcement:current.enforcement,autoRegister:current.autoRegister||'off'},
      states:REGISTRY_STATES,limitations:['등록·상태 전이는 서명 원장의 기록입니다. EvidScope는 실행을 차단하지 않으며 차단은 게이트웨이·정책 엔진이 합니다',
       '위험 등급은 등록된 도구·데이터 범주·목적지에 대한 규칙 계산이며 법적 위험 판정이 아닙니다']};}
    if(parts.length===1&&parts[0]==='candidates')return candidates(p);
    if(parts.length===1&&parts[0]==='policy')return policy(p);
    if(parts.length===1&&parts[0]==='owners')return owners(p);
    if(parts[0]==='stops')return stops.handle(p,'GET',parts,x);
    if(parts.length===1)return detail(p,parts[0]);
    fail(404,'지원하지 않는 레지스트리 경로입니다');
   });
  }
  if(method!=='POST')fail(405,'허용되지 않은 메서드');
  if(parts.length===1&&parts[0]==='policy')return setPolicy(p,x);
  if(parts.length===1&&parts[0]==='owners')return setOwnerMap(p,x);
  reviewer(p);
  if(parts.length===1&&parts[0]==='discover'){only(x,['dryRun'],'자동 등록 요청');return discover(p,{dryRun:x.dryRun===true});}
  if(!parts.length)return create(p,x);
  if(parts.length===1&&parts[0]==='import')return catalog.importCatalog(p,x);
  if(parts.length===3&&parts[0]==='transitions'&&['approve','refuse'].includes(parts[2]))return decide(p,parts[1],parts[2],x);
  if(parts[0]==='stops')return stops.handle(p,'POST',parts,x);
  if(parts.length===2&&parts[1]==='stop')return stops.issue(p,parts[0],x);
  if(parts.length===1&&!RESERVED.has(parts[0]))return update(p,parts[0],x);
  if(parts.length===2&&parts[1]==='risk')return overrideRisk(p,parts[0],x);
  if(parts.length===2&&parts[1]==='owner')return confirmOwner(p,parts[0],x);
  if(parts.length===2&&parts[1]==='transitions')return request(p,parts[0],x);
  fail(404,'지원하지 않는 레지스트리 경로입니다');
 }
 // Read-only view for the console home (src/home-service.mjs): stop-order propagation.
 // autoRegister: the discovery run of one tenant (src/service.mjs runs it on a timer); null when the tenant's policy has it off.
 return {handle,stopPropagation:p=>stops.propagation(p),accountabilityFor,
  autoRegister:tenant=>{const p={id:AUTO_DISCOVERY_PRINCIPAL,tenant};return policy(p).autoRegister==='discovered'?discover(p):null;}};
}
