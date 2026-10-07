// Agent registry lifecycle (docs/agent-registry.md). Pure functions shared by the vault, the analysis engine and the offline
// verifier: the state machine, risk-tier rules, the compact analysis input, the point-in-time registry state of an event,
// the registry findings and the check of the signed lifecycle history. No I/O.
import {canonical,digest} from './crypto.mjs';

export const REGISTRY_STATES=Object.freeze(['discovered','draft','testing','approved','production','suspended','retired']);
export const REGISTRY_TYPES=Object.freeze(['agent_registry','agent_transition','agent_registry_policy']);
// Records that change evaluation input. Like an asset version, each one re-evaluates the tenant's actions.
export const REGISTRY_INPUT_TYPES=Object.freeze(['agent_registry','agent_registry_policy']);
export const RISK_TIERS=Object.freeze(['low','medium','high']);
export const GATE_TARGETS=Object.freeze(['testing','approved','production']);
export const ENFORCEMENT_MODES=Object.freeze(['off','unregistered_activity']);
// Fields that define what the agent is and does. They change only outside approved/production (suspend, edit, re-approve).
export const CONFIGURATION_FIELDS=Object.freeze(['sources','actors','models','tools','dataCategories','destinations','fingerprint']);
const NEXT={discovered:['draft'],draft:['testing'],testing:['approved'],approved:['production'],production:['suspended'],suspended:['production']};
export const allowedTransition=(from,to)=>REGISTRY_STATES.includes(from)&&from!=='retired'&&(to==='retired'||(NEXT[from]||[]).includes(to));
// Four-eyes: approved, production and every transition out of suspended take effect only when a second reviewer approves.
// Everything else (including suspending and retiring a running agent) applies at once, so a stop is never held up.
export const approvalRequired=(from,to)=>to==='approved'||to==='production'||from==='suspended';

// Risk tier rules are data: keyword or exact matches on tool names, data categories and destinations; the highest match wins.
// op not_suffix matches a destination outside every listed internal suffix ('.corp' covers corp and x.corp).
export const DEFAULT_RISK_RULES=Object.freeze([
 {id:'tool-payment',field:'tool',op:'contains',values:['payment','transfer','wire','refund','payout'],tier:'high'},
 {id:'tool-destructive',field:'tool',op:'contains',values:['delete','drop','truncate','shell','exec','deploy','sudo','admin'],tier:'high'},
 {id:'tool-outbound',field:'tool',op:'contains',values:['email','send','post','publish','message','upload'],tier:'medium'},
 {id:'tool-write',field:'tool',op:'contains',values:['write','update','create','insert','modify'],tier:'medium'},
 {id:'data-sensitive',field:'dataCategory',op:'eq',values:['personal','sensitive','health','biometric','financial','credential','credentials',
  'resident_registration_number','unique_identifier','location','minor'],tier:'high'},
 {id:'data-internal',field:'dataCategory',op:'eq',values:['confidential','internal','customer'],tier:'medium'},
 {id:'destination-external',field:'destination',op:'not_suffix',values:['.internal','.local','.corp','.lan','localhost'],tier:'medium'},
]);
export const RISK_RULE_FIELDS=Object.freeze(['tool','dataCategory','destination']);
export const RISK_RULE_OPS=Object.freeze(['eq','contains','not_suffix']);
const rank=tier=>RISK_TIERS.indexOf(tier);
const higher=(a,b)=>rank(b)>rank(a)?b:a;
export const tierAtLeast=(tier,minimum)=>rank(tier)>=rank(minimum);
function ruleMatches(rule,value){
 const v=String(value).toLowerCase(),values=rule.values.map(x=>String(x).toLowerCase());
 if(rule.op==='eq')return values.includes(v);
 if(rule.op==='contains')return values.some(x=>v.includes(x));
 return !values.some(x=>{const s=x.replace(/^\./,'');return v===s||v.endsWith('.'+s);});
}
export function computeRisk(entry,rules=DEFAULT_RISK_RULES){
 const values={tool:(entry.tools||[]).map(t=>t.name),dataCategory:entry.dataCategories||[],destination:entry.destinations||[]};
 const reasons=[],tools=new Map(values.tool.map(name=>[name,'low']));let tier='low';
 for(const rule of rules)for(const value of values[rule.field]||[])if(ruleMatches(rule,value)){
  reasons.push({rule:rule.id,field:rule.field,value,tier:rule.tier});tier=higher(tier,rule.tier);
  if(rule.field==='tool')tools.set(value,higher(tools.get(value),rule.tier));
 }
 return {computed:tier,tools:[...tools].map(([name,t])=>({name,tier:t})),reasons};
}
// An override is bound to the configuration it was given for; a changed configuration drops it.
export const riskBasis=entry=>digest({tools:entry.tools||[],dataCategories:entry.dataCategories||[],destinations:entry.destinations||[]});

// Gate conditions are data: per risk tier and target state, a list of checks from this closed set (docs/agent-registry.md).
export const GATE_CHECKS=Object.freeze(['fields_present','events_in_state','decisions_received','approval_rule_for_tools','assets_linked','system_linked',
 'fingerprint_recorded','evidence_attached']);
const ownerPurpose={id:'owner-purpose',check:'fields_present',fields:['owner','purpose']};
const telemetry={id:'telemetry-in-testing',check:'events_in_state',state:'testing',sourceKinds:['otlp','agent','tool'],min:1};
const decisions={id:'decision-log-received',check:'decisions_received',min:1};
export const DEFAULT_GATES=Object.freeze({
 low:{approved:[ownerPurpose],production:[]},
 medium:{approved:[ownerPurpose,telemetry,decisions],production:[{id:'assets-linked',check:'assets_linked'}]},
 high:{approved:[ownerPurpose,{id:'otlp-in-testing',check:'events_in_state',state:'testing',sourceKinds:['otlp'],min:1},decisions,
  {id:'approval-rule-high-risk-tools',check:'approval_rule_for_tools',tier:'high'},{id:'governance-system-linked',check:'system_linked'}],
 production:[{id:'assets-linked',check:'assets_linked'},{id:'version-fingerprint',check:'fingerprint_recorded'},
  {id:'evidence-attached',check:'evidence_attached',min:1}]},
});

// Compact evaluation input from signed agent_registry / agent_registry_policy rows in ledger order; undefined without any,
// so a tenant without a registry keeps its v1 snapshot (and snapshot hash) unchanged. Forged shapes degrade, never throw.
const strings=v=>Array.isArray(v)?v.filter(x=>typeof x==='string'):[];
const text=v=>typeof v==='string'?v:null;
export function registryAnalysisInput(rows){
 const entries=[],policies=[];
 for(const row of rows){
  const v=row.payload&&typeof row.payload==='object'?row.payload:{};
  if(row.type==='agent_registry')entries.push({id:String(v.id),version:Number.isSafeInteger(v.version)?v.version:null,state:text(v.state),
   effectiveFrom:text(v.effectiveFrom),sources:strings(v.sources),actors:strings(v.actors),
   enforcedTools:(Array.isArray(v.tools)?v.tools:[]).filter(t=>t?.enforcement==='required'&&typeof t.name==='string').map(t=>t.name)});
  else if(row.type==='agent_registry_policy')policies.push({version:Number.isSafeInteger(v.version)?v.version:null,enforcement:text(v.enforcement),
   effectiveFrom:text(v.effectiveFrom)});
 }
 return entries.length||policies.length?{entries,policies}:undefined;
}

// Registry state that covers an event at time t: for each entry the last version (ledger order) effective at t, and the
// enforcement mode then in force. An entry covers an event by authenticated source principal or by reported actor name.
const effective=value=>{const t=Date.parse(value);return Number.isFinite(t)?t:Infinity;};
function viewAt(registry,event,t){
 const current=new Map();for(const v of registry.entries)if(effective(v.effectiveFrom)<=t)current.set(v.id,v);
 let enforcement='off';for(const v of registry.policies)if(effective(v.effectiveFrom)<=t)enforcement=v.enforcement;
 const covers=v=>v.sources.includes(event.source)||!!event.actor&&v.actors.includes(event.actor);
 const covering=[...current.values()].filter(covers).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
 // A retired entry is history once a live entry covers the same source or actor (re-registration under a new id).
 const live=covering.filter(v=>v.state!=='retired'),applies=live.length?live:covering;
 return {suspended:applies.filter(v=>v.state==='suspended').map(v=>v.id),retired:applies.filter(v=>v.state==='retired').map(v=>v.id),
  unregistered:!covering.length&&enforcement==='unregistered_activity',enforcedTools:[...new Set(applies.flatMap(v=>v.enforcedTools))].sort()};
}
// Views at every instant where the state could differ within the event's clock bound [t-bound, t+bound].
export function registryViews(registry,event,bound){
 const t=Date.parse(event.occurredAt),lo=t-bound,hi=t+bound;
 const changes=[...registry.entries,...registry.policies].map(v=>effective(v.effectiveFrom)).filter(x=>x>lo&&x<=hi);
 return [...new Set([lo,...changes,hi])].map(x=>viewAt(registry,event,x));
}
export const enforcedToolsAt=(registry,event)=>registry?viewAt(registry,event,Date.parse(event.occurredAt)).enforcedTools:[];

const ACTIVITY_KINDS=['intent','execution','self_report','result','delegation'];
// Agent and OTLP sources are the agent itself; a tool record is attributed only through the actor it names.
export const attributable=e=>ACTIVITY_KINDS.includes(e.kind)&&(e.sourceKind==='agent'||e.sourceKind==='otlp'||e.sourceKind==='tool'&&!!e.actor);
const names=ids=>ids.slice(0,5).join(', ')+(ids.length>5?` 외 ${ids.length-5}개`:'');
export function registryFindings(events,registry,{add,clockBound}){
 if(!registry)return;
 const signature=v=>canonical([v.suspended,v.retired,v.unregistered]),flagged=v=>v.suspended.length||v.retired.length||v.unregistered;
 for(const e of events){
  if(!attributable(e))continue;
  const views=registryViews(registry,e,clockBound(e));
  if(views.some(v=>signature(v)!==signature(views[0]))){
   if(views.some(flagged))add('AGENT_REGISTRY_STATE_UNCERTAIN','medium','시계 오차 범위 안에서 에이전트 등록 상태가 바뀌어 행동 당시 상태를 확정할 수 없습니다',[e]);
   continue;
  }
  const v=views[0];
  if(v.suspended.length)add('AGENT_SUSPENDED_ACTIVITY','high',`행동 시점에 정지(suspended) 상태로 등록된 에이전트의 활동입니다: ${names(v.suspended)}`,[e]);
  if(v.retired.length)add('AGENT_RETIRED_ACTIVITY','high',`행동 시점에 폐기(retired) 상태로 등록된 에이전트의 활동입니다: ${names(v.retired)}`,[e]);
  if(v.unregistered)add('AGENT_UNREGISTERED_ACTIVITY','medium','레지스트리 적용이 설정된 시점에 이 출처·행위자를 포함하는 등록 항목이 없습니다. 미등록 후보이며 악성 확정이 아닙니다',[e]);
 }
}

// Offline check of the signed lifecycle history (any rows; non-registry rows are skipped). It confirms what the vault API
// always writes: versions in order, a state changed only by an applied or approved transition recorded before it, four-eyes
// on approvals, no approval of a stale request, configuration frozen in approved/production, and record principals that
// match the actors the bodies name. A holder of the signing key can still sign a consistent false history.
export function verifyRegistryHistory(rows){
 const problems=[],entries=new Map(),transitions=new Map(),applied=new Set();let policyVersion=0,policyRecords=0;
 const problem=(row,message)=>{if(problems.length<100)problems.push({seq:row.seq,type:row.type,message});};
 const configuration=v=>canonical(CONFIGURATION_FIELDS.map(k=>v[k]??null));
 for(const row of rows){
  if(!REGISTRY_TYPES.includes(row.type))continue;
  const v=row.payload&&typeof row.payload==='object'?row.payload:{};
  if(row.type==='agent_registry_policy'){
   policyRecords++;if(v.version!==policyVersion+1)problem(row,'registry policy version is not consecutive');policyVersion=v.version;
   if(row.principal!==v.updatedBy)problem(row,'registry policy principal differs from updatedBy');
   if(!ENFORCEMENT_MODES.includes(v.enforcement))problem(row,'unknown enforcement mode');
  }else if(row.type==='agent_transition'){
   const before=transitions.get(v.id),entry=entries.get(v.agentId);
   if(!before){
    if(!allowedTransition(v.from,v.to))problem(row,'transition is not allowed by the lifecycle');
    if(v.status!==(approvalRequired(v.from,v.to)?'pending':'applied'))problem(row,'transition starts with the wrong status');
    if(row.principal!==v.requestedBy)problem(row,'transition principal differs from requestedBy');
    if(!entry||entry.state!==v.from||entry.version!==v.registryVersion)problem(row,'transition does not start from the current registry version');
   }else{
    const request=['agentId','to','requestedBy','registryVersion'];
    if(v.from!==before.from||request.some(k=>canonical(v[k]??null)!==canonical(before[k]??null)))problem(row,'transition request changed');
    if(before.status!=='pending'||!['approved','refused','superseded'].includes(v.status))problem(row,'transition status change is not allowed');
    if(['approved','refused'].includes(v.status)&&row.principal!==v.reviewedBy)problem(row,'transition review principal differs from reviewedBy');
    if(v.status==='approved'){
     if(!entry||entry.state!==v.from||entry.version!==v.registryVersion)problem(row,'approval of a stale transition request');
     if([v.requestedBy,entry?.registeredBy,entry?.editedBy].includes(v.reviewedBy))
      problem(row,'four-eyes: approver registered, edited or requested this change');
    }
   }
   transitions.set(v.id,{...v,seq:row.seq});
  }else{
   const previous=entries.get(v.id);
   if(!previous){
    if(v.version!==1||v.change!=='created'||!['discovered','draft'].includes(v.state))problem(row,'registry entry does not start as a created draft');
    if(row.principal!==v.registeredBy||v.editedBy!==v.registeredBy)problem(row,'registry creation principal differs');
   }else{
    if(v.version!==previous.version+1)problem(row,'registry version is not consecutive');
    if(previous.state==='retired')problem(row,'retired registry entry changed');
    if(v.registeredBy!==previous.registeredBy)problem(row,'registrant changed');
    if(v.state!==previous.state){
     const t=transitions.get(v.lastTransition?.id);
     if(v.change!=='transition'||!t||applied.has(t.id)||!['applied','approved'].includes(t.status)||t.agentId!==v.id||t.from!==previous.state||t.to!==v.state)
      problem(row,'state changed without an applied or approved transition');
     else{
      applied.add(t.id);
      if(row.principal!==(t.status==='approved'?t.reviewedBy:t.requestedBy))problem(row,'state change principal differs from the transition');
     }
     if(v.editedBy!==previous.editedBy||configuration(v)!==configuration(previous))problem(row,'transition version changed the configuration');
    }else if(v.change==='updated'){
     if(row.principal!==v.editedBy)problem(row,'registry edit principal differs from editedBy');
     if(['approved','production'].includes(v.state)&&configuration(v)!==configuration(previous))problem(row,'configuration changed in approved or production');
    }else if(v.change==='risk_override'){
     const by=v.risk?.override?.by??v.risk?.cleared?.by;
     if(row.principal!==by||by===v.registeredBy||by===previous.editedBy)problem(row,'risk override not recorded by an independent reviewer');
     if(v.editedBy!==previous.editedBy||configuration(v)!==configuration(previous))problem(row,'risk override changed the configuration');
    }else problem(row,'unknown registry change');
   }
   entries.set(v.id,v);
  }
 }
 for(const t of transitions.values())
  if(['applied','approved'].includes(t.status)&&!applied.has(t.id))problem({seq:t.seq,type:'agent_transition'},'transition was not applied');
 return {valid:!problems.length,entries:entries.size,transitions:transitions.size,policyRecords,problems,
  limitations:['Checks what the vault API writes; a holder of the signing key can still sign a consistent false history.']};
}
