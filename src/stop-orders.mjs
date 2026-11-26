// Stop orders and their propagation to enforcement points (docs/kill-switch.md). Pure functions shared by the vault, the
// analysis engine and the offline verifier: the bundle revision derived from the ledger, the stop-order analysis input and
// its findings, the propagation view and the check of the signed stop-order history. No I/O. EvidScope blocks nothing:
// gateways and policy engines pull the orders and enforce them; these functions record and compare what they reported.
import {canonical,isEncryptedEvent} from './crypto.mjs';
import {attributable} from './agent-registry.mjs';
import {executed} from './decision-rules.mjs';

export const STOP_ORDER_TYPE='agent_stop_order';
export const STOP_SCOPES=Object.freeze(['agent','tools']);
export const STOP_STATUSES=Object.freeze(['active','lifted','superseded']);
// Records whose content the enforcement bundle carries; the latest of them names the bundle revision.
export const BUNDLE_CONTENT_TYPES=Object.freeze(['agent_registry','agent_registry_policy',STOP_ORDER_TYPE]);
export const ACTIVATION_KIND='bundle_activation';
// Registry-policy data (agent_registry_policy.stopPropagation): the window in which a covering enforcement point must activate
// a revision that contains an order, and enforcement points that cover every agent. Defaults apply until a policy sets them.
export const STOP_PROPAGATION_DEFAULTS=Object.freeze({windowSeconds:300,enforcementPoints:Object.freeze([])});
export const stopPropagationOf=policy=>({...STOP_PROPAGATION_DEFAULTS,...(policy?.stopPropagation||{})});

const strings=v=>Array.isArray(v)?v.filter(x=>typeof x==='string'):[];
const text=v=>typeof v==='string'?v:null;
const object=v=>v&&typeof v==='object'&&!Array.isArray(v)?v:{};
const byId=(a,b)=>a.id<b.id?-1:a.id>b.id?1:0;
const names=ids=>ids.slice(0,5).join(', ')+(ids.length>5?` 외 ${ids.length-5}개`:'');

// Revision of the enforcement bundle: the ledger sequence and hash prefix of the latest content record. It grows with every
// registry, registry-policy or stop-order version, and an activation report naming it can be checked against the ledger.
export const revisionOf=row=>row?`${row.seq}-${String(row.hash).slice(0,16)}`:'0-0000000000000000';
export const parseRevision=value=>{
 const m=typeof value==='string'&&/^([1-9][0-9]{0,14})-([a-f0-9]{16})$/.exec(value);return m?{seq:Number(m[1]),hash:m[2]}:null;
};
export function latestContentRow(rows){let last=null;for(const row of rows)if(BUNDLE_CONTENT_TYPES.includes(row.type))last=row;return last;}
// Every revision this ledger could have served, with the time its content record was signed.
export function contentRevisions(rows){
 const revisions=new Map();
 for(const row of rows)if(BUNDLE_CONTENT_TYPES.includes(row.type)&&typeof row.hash==='string')
  revisions.set(revisionOf(row),{seq:row.seq,recordedAt:Date.parse(row.recordedAt)});
 return revisions;
}
// An activation cannot precede the content it activated nor follow the report of it: the claimed time is raised to the signing
// time of the revision and lowered to the vault's receipt time.
const activationTime=(e,revision)=>{
 const at=Math.max(Date.parse(e.occurredAt),Number.isFinite(revision.recordedAt)?revision.recordedAt:-Infinity),received=Date.parse(e.receivedAt);
 return Number.isFinite(received)?Math.min(at,received):at;
};
const isActivation=e=>e?.sourceKind==='enforcement'&&e.kind===ACTIVATION_KIND&&typeof e.bundleRevision==='string';
const windowMsOf=v=>{const s=v?.propagation?.windowSeconds;return (Number.isSafeInteger(s)&&s>0?s:STOP_PROPAGATION_DEFAULTS.windowSeconds)*1000;};
// A revision contains an order from the record that issued it until the record that ended it.
const contains=(order,seq)=>order.issueSeq<=seq&&(order.endSeq===null||seq<order.endSeq);

// Stop orders folded from their signed versions in ledger order: the issued content, the current version and the end.
export function foldStopOrders(rows){
 const orders=new Map();
 for(const row of rows){
  if(row.type!==STOP_ORDER_TYPE)continue;
  const v=object(row.payload),id=String(v.id);let o=orders.get(id);
  if(!o){o={id,issued:v,current:v,issueSeq:row.seq,endSeq:null,endedAt:null,versions:[]};orders.set(id,o);}
  else if(o.endSeq===null&&v.status!=='active'){o.endSeq=row.seq;o.endedAt=text(v.effectiveFrom);}
  o.current=v;o.versions.push({seq:row.seq,recordedAt:row.recordedAt,principal:row.principal,...v});
 }
 return orders;
}

// Compact evaluation input: every stop order (as issued, with its end) and, per order and covering enforcement point, the
// first activation of a revision that contains it. Undefined without any stop order, so other snapshots stay unchanged.
export function stopOrderAnalysisInput(rows,events){
 const folded=foldStopOrders(rows);if(!folded.size)return undefined;
 const orders=[...folded.values()].map(o=>{const v=o.issued,target=object(v.target);
  return {id:o.id,agentId:text(v.agentId),scope:v.scope==='tools'?'tools':'agent',tools:strings(v.tools),
   sources:strings(target.sources),actors:strings(target.actors),
   enforcementPoints:(Array.isArray(v.enforcementPoints)?v.enforcementPoints:[]).map(x=>x?.id).filter(x=>typeof x==='string').sort(),
   windowMs:windowMsOf(v),issuedAt:text(v.issuedAt),issueSeq:o.issueSeq,endedAt:o.endedAt,endSeq:o.endSeq};}).sort(byId);
 const revisions=contentRevisions(rows),first=new Map();
 for(const e of events){
  if(!isActivation(e))continue;const revision=revisions.get(e.bundleRevision);if(!revision)continue;
  const at=activationTime(e,revision);if(!Number.isFinite(at))continue;
  for(const o of orders){
   if(!o.enforcementPoints.includes(e.source)||!contains(o,revision.seq))continue;
   const key=canonical([o.id,e.source]),prior=first.get(key);
   if(!prior||at<prior.at||at===prior.at&&e.seq<prior.e.seq)first.set(key,{at,e,revision});
  }
 }
 const activations=new Map();
 for(const {at,e,revision} of first.values())activations.set(e.seq,{seq:e.seq,source:e.source,enforcementPointId:text(e.enforcementPointId),
  revision:e.bundleRevision,revisionSeq:revision.seq,activatedAt:new Date(at).toISOString()});
 return {orders,activations:[...activations.values()].sort((a,b)=>a.seq-b.seq)};
}

// Findings, point in time at the event (its clock bound included); the evidence is the action's own event:
// - STOP_ORDER_NOT_HELD: a tool execution by the stopped agent after a covering enforcement point had activated the order.
// - STOP_PROPAGATION_MISSING: activity after the propagation deadline while no covering point activated the order in time.
// - STOP_PROPAGATION_TIME_UNCERTAIN: the activation falls within the execution's clock bound.
export function stopOrderFindings(events,input,{add,clockBound}){
 if(!input)return;
 const activations=input.activations.map(a=>({...a,at:Date.parse(a.activatedAt)}));
 for(const e of events){
  if(!attributable(e))continue;
  const t=Date.parse(e.occurredAt),bound=clockBound(e);if(!Number.isFinite(t)||!Number.isFinite(bound))continue;
  for(const o of input.orders){
   if(!(o.sources.includes(e.source)||!!e.actor&&o.actors.includes(e.actor))||o.scope==='tools'&&!o.tools.includes(e.tool))continue;
   const issued=Date.parse(o.issuedAt),ended=o.endedAt?Date.parse(o.endedAt):Infinity;
   if(!(t-bound>=issued&&t+bound<ended))continue;
   const covering=activations.filter(a=>o.enforcementPoints.includes(a.source)&&contains(o,a.revisionSeq));
   if(executed(e)){
    const held=covering.filter(a=>a.at<t-bound);
    if(held.length)add('STOP_ORDER_NOT_HELD','high',`정지 명령 ${o.id}을 집행 지점(${names([...new Set(held.map(a=>a.source))])})이 활성화한 뒤 `
     +'이 에이전트의 도구 실행 기록이 있습니다. 정지가 집행되지 않았거나 우회 경로가 있는지 검토하세요',[e]);
    else if(covering.some(a=>a.at<=t+bound))add('STOP_PROPAGATION_TIME_UNCERTAIN','medium',
     `시계 오차 때문에 정지 명령 ${o.id}의 활성화와 도구 실행의 순서를 확정할 수 없습니다`,[e]);
   }
   const deadline=issued+o.windowMs;
   if(t-bound>deadline&&!covering.some(a=>a.at<=deadline))add('STOP_PROPAGATION_MISSING','high',o.enforcementPoints.length
    ?`정지 명령 ${o.id}을 ${o.windowMs/1000}초 안에 활성화했다고 보고한 집행 지점(${names(o.enforcementPoints)})이 없는 상태에서 이 에이전트의 활동이 있습니다`
    :`정지 명령 ${o.id}에 이 에이전트를 담당하는 집행 지점이 지정되지 않아 정지가 전파되었다는 기록이 없는 상태에서 활동이 있습니다`,[e]);
  }
 }
}

// Propagation view of every order (registry API, screen and offline verifier): which enforcement points activated a revision
// that contains the order, when, and how long after the order. `now` decides only pending versus overdue.
export function stopOrderPropagation(rows,events,now){
 const revisions=contentRevisions(rows),activations=[];
 for(const e of events){
  if(!isActivation(e))continue;const revision=revisions.get(e.bundleRevision);if(!revision)continue;
  const at=activationTime(e,revision);
  if(Number.isFinite(at))activations.push({seq:e.seq,source:e.source,instance:text(e.enforcementPointId),revision:e.bundleRevision,revisionSeq:revision.seq,at,
   receivedAt:text(e.receivedAt)});
 }
 return [...foldStopOrders(rows).values()].map(o=>{
  const v=o.issued,issued=Date.parse(v.issuedAt),windowMs=windowMsOf(v),deadline=issued+windowMs,ended=o.endedAt?Date.parse(o.endedAt):null;
  const listed=new Map((Array.isArray(v.enforcementPoints)?v.enforcementPoints:[]).filter(x=>typeof x?.id==='string').map(x=>[x.id,strings(x.basis)]));
  const bySource=new Map();
  for(const a of activations)if(contains(o,a.revisionSeq)){
   const group=bySource.get(a.source)||{first:null,instances:new Set()};
   if(!group.first||a.at<group.first.at||a.at===group.first.at&&a.seq<group.first.seq)group.first=a;
   if(a.instance&&group.instances.size<20)group.instances.add(a.instance);bySource.set(a.source,group);
  }
  const statusOf=first=>first?(first.at<=deadline?'activated_in_window':'activated_late'):ended!==null&&ended<=Math.min(now,deadline)?'ended_before_activation'
   :now<=deadline?'pending':'overdue';
  const points=[...new Set([...listed.keys(),...bySource.keys()])].sort().map(id=>{const group=bySource.get(id),first=group?.first||null;
   return {id,covering:listed.has(id),basis:listed.get(id)||[],status:statusOf(first),instances:group?[...group.instances].sort():[],
    firstActivation:first&&{seq:first.seq,revision:first.revision,instance:first.instance,activatedAt:new Date(first.at).toISOString(),
     latencyMs:first.at-issued,
     receivedAt:first.receivedAt}};});
  const covering=points.filter(p=>p.covering),statuses=new Set(covering.map(p=>p.status));
  // The order's summary is its worst covering point: one gateway that never activated leaves a path open.
  const propagation=!covering.length?'no_enforcement_point':['overdue','activated_late','pending','ended_before_activation','activated_in_window']
   .find(s=>statuses.has(s));
  return {orderId:o.id,agentId:text(v.agentId),status:text(o.current.status),scope:text(v.scope),tools:strings(v.tools),issuedAt:text(v.issuedAt),
   issuedBy:text(v.issuedBy),issueSeq:o.issueSeq,endSeq:o.endSeq,endedAt:o.endedAt,windowSeconds:windowMs/1000,
   deadline:Number.isFinite(deadline)?new Date(deadline).toISOString():null,
   propagation,points};
 });
}

// Offline check of the signed stop-order history (any rows; other types only feed the registry and transition state). It
// confirms what the vault API writes: one issuer per order, the suspension it applied, a lift only by an independent
// approval or by an approved suspended→production transition, supersession only by a later order of the same agent, no
// change after an order ended, and a resumed agent whose whole-agent orders were lifted. The signing key holder can still
// sign a consistent false history.
const STATIC_FIELDS=['agentId','registryVersion','entryState','scope','tools','reason','evidence','target','enforcementPoints',
 'propagation','issuedBy','issuedAt','suspension'];
export function verifyStopOrderHistory(rows){
 const problems=[],entries=new Map(),transitions=new Map(),orders=new Map(),suspensions=[],resumes=new Map();
 const problem=(row,message)=>{if(problems.length<100)problems.push({seq:row.seq,type:row.type,message});};
 const active=agentId=>[...orders.values()].filter(o=>o.agentId===agentId&&o.status==='active');
 for(const row of rows){
  const v=object(row.payload);
  if(row.type==='agent_registry'){
   const previous=entries.get(v.id);
   if(previous&&previous.state!==v.state&&['approved','production'].includes(v.state)){
    const stops=active(v.id).filter(o=>o.scope==='agent');
    if(previous.state==='suspended'&&v.state==='production')resumes.set(v.lastTransition?.id,{row,orders:new Set(stops.map(o=>o.id))});
    else if(stops.length)problem(row,'agent promoted while a whole-agent stop order was active');
   }
   entries.set(v.id,v);continue;
  }
  if(row.type==='agent_transition'){transitions.set(v.id,{...v,seq:row.seq});continue;}
  if(row.type!==STOP_ORDER_TYPE)continue;
  const previous=orders.get(v.id);
  if(!previous){
   const entry=entries.get(v.agentId);
   if(v.version!==1||v.change!=='issued'||v.status!=='active')problem(row,'stop order does not start as an issued active order');
   if(row.principal!==v.issuedBy)problem(row,'stop order principal differs from issuedBy');
   if(!entry||entry.state==='retired'||entry.version!==v.registryVersion||entry.state!==v.entryState)
    problem(row,'stop order does not name the current registry version');
   if(!STOP_SCOPES.includes(v.scope)||v.scope==='tools'&&(!Array.isArray(v.tools)||!v.tools.length)||v.scope==='agent'&&strings(v.tools).length)
    problem(row,'stop order scope is malformed');
   const suspends=v.scope==='agent'&&v.entryState==='production';
   if(suspends!==!!v.suspension?.transitionId)problem(row,'stop order suspension does not match the agent state');
   if(suspends)suspensions.push({row,order:v});
  }else{
   if(v.version!==previous.version+1)problem(row,'stop order version is not consecutive');
   if(previous.status!=='active')problem(row,'stop order changed after it ended');
   if(STATIC_FIELDS.some(k=>canonical(v[k]??null)!==canonical(previous[k]??null)))problem(row,'stop order content changed');
   if(v.change==='lift_requested'){
    if(v.status!=='active'||previous.liftRequest||row.principal!==v.liftRequest?.by)problem(row,'lift request is malformed');
   }else if(v.change==='lift_refused'){
    if(v.status!=='active'||!previous.liftRequest||v.liftRequest||row.principal!==v.liftRefused?.by)problem(row,'lift refusal is malformed');
   }else if(v.change==='lifted'&&v.lift?.via==='approval'){
    if(v.status!=='lifted'||!previous.liftRequest||v.lift.requestedBy!==previous.liftRequest.by||row.principal!==v.lift.approvedBy)
     problem(row,'lift approval is malformed');
    if(v.lift.approvedBy===v.lift.requestedBy)problem(row,'four-eyes: the lift requester approved the lift');
    if(v.scope==='agent'&&entries.get(v.agentId)?.state==='suspended')problem(row,'a suspended agent is resumed only by an approved transition');
   }else if(v.change==='lifted'&&v.lift?.via==='transition'){
    const t=transitions.get(v.lift.transitionId),resume=resumes.get(v.lift.transitionId);
    if(v.status!=='lifted'||v.scope!=='agent'||!t||t.status!=='approved'||t.from!=='suspended'||t.to!=='production'||t.agentId!==v.agentId
     ||row.principal!==t.reviewedBy||v.lift.approvedBy!==t.reviewedBy)problem(row,'lift by transition does not name an approved resume of this agent');
    resume?.orders.delete(v.id);
   }else if(v.change==='superseded'){
    const by=orders.get(v.supersededBy?.orderId);
    const covers=by&&(by.scope==='agent'||v.scope==='tools'&&strings(v.tools).every(tool=>strings(by.tools).includes(tool)));
    if(v.status!=='superseded'||!by||by.id===v.id||by.agentId!==v.agentId||!covers||row.principal!==by.issuedBy)
     problem(row,'supersession does not name a covering later order');
   }else problem(row,'unknown stop order change');
  }
  orders.set(v.id,{...v,seq:row.seq});
 }
 for(const {row,order} of suspensions){
  const t=transitions.get(order.suspension.transitionId);
  if(!t||t.seq<row.seq||t.status!=='applied'||t.from!=='production'||t.to!=='suspended'||t.agentId!==order.agentId||t.stopOrderId!==order.id
   ||t.requestedBy!==order.issuedBy)problem(row,'stop order suspension transition is missing or differs');
 }
 for(const {row,orders:left} of resumes.values())if(left.size)problem(row,'agent resumed without lifting its whole-agent stop orders');
 return {valid:!problems.length,orders:orders.size,active:[...orders.values()].filter(o=>o.status==='active').length,problems,
  limitations:['Checks what the vault API writes; a holder of the signing key can still sign a consistent false history.',
   'Activation times are claimed by the enforcement point and raised to the signing time of the revision they name.']};
}

// Stop-order section of the offline verifiers for an export bundle that holds stop orders: the history check, and the
// propagation as of the last signed record, from the activation reports the export discloses.
export function verifyExportStopOrders(bundle){
 const disclosed=new Map((bundle.disclosures||[]).map(d=>[d.seq,d.event])),events=[];let last=NaN;
 for(const row of bundle.records){
  last=Date.parse(row.recordedAt);
  if(row.type!=='event')continue;
  const event=isEncryptedEvent(row.payload)?disclosed.get(row.seq):row.payload;if(event)events.push({...event,seq:row.seq});
 }
 return {...verifyStopOrderHistory(bundle.records),propagation:stopOrderPropagation(bundle.records,events,last)};
}
