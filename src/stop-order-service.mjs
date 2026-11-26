// Stop orders (docs/kill-switch.md): one reviewer or admin stops an agent, or listed tools of it, with a reason and evidence
// references. A whole-agent stop of a production entry applies production→suspended in the same commit; lifting keeps four
// eyes (the suspended→production approval, or an independent lift approval when nothing was suspended). Every version is a
// signed agent_stop_order record. Enforcement points pull the active orders (src/enforcement-service.mjs); EvidScope itself
// blocks nothing.
import {randomUUID} from 'node:crypto';
import {fail,cleanText,identifier} from './model.mjs';
import {isDecision} from './decision-rules.mjs';
import {STOP_ORDER_TYPE,STOP_SCOPES,stopOrderPropagation,stopPropagationOf,verifyStopOrderHistory} from './stop-orders.mjs';

const only=(x,allowed,name)=>{
 if(!x||typeof x!=='object'||Array.isArray(x))fail(400,`${name}는 JSON 객체여야 합니다`);
 for(const k of Object.keys(x))if(!allowed.includes(k))fail(400,`${name}에 허용되지 않은 필드: ${k}`);return x;
};
const reasonOf=x=>{const reason=cleanText(x.reason??'',1000);if(!reason.trim())fail(400,'사유가 필요합니다');return reason;};
const LIMITATIONS=['정지 명령은 서명된 기록이며 EvidScope가 실행을 차단하지 않습니다. 집행 지점이 묶음·거부 목록을 받아 적용해야 합니다',
 '활성화 시각은 집행 지점의 보고이며, 그 리비전이 서명된 시각과 vault가 보고를 받은 시각 사이로 묶어 계산합니다',
 'IdP 비활성화(CAEP)·컨테이너 중지는 EvidScope가 호출하지 않습니다. 운영자가 수행하고 정지 명령을 기록으로 씁니다'];

// ctx: registry internals (src/registry-service.mjs) that keep one storage, four-eyes and transition path.
export function createStopOrders({store,principals,policyObjects,dirty,rows,retained,policy,entryOf,suspend,supersede,evidenceRefs,now}){
 const enforcementPoints=p=>new Set(principals.filter(q=>q.tenant===p.tenant&&q.role==='source'&&q.kind==='enforcement').map(q=>q.id));
 const orders=p=>[...policyObjects(p,STOP_ORDER_TYPE).values()];
 const activeOf=(p,agentId)=>orders(p).filter(o=>o.agentId===agentId&&o.status==='active');
 const orderOf=(p,id)=>policyObjects(p,STOP_ORDER_TYPE).get(identifier(id))||fail(404,'정지 명령을 찾을 수 없습니다');
 const putVersion=(p,previous,changes,change)=>{
  const next={...previous,...changes,version:previous.version+1,change,effectiveFrom:now()};
  store.put(p,STOP_ORDER_TYPE,next.id,next);dirty(p.tenant);return next;
 };
 // Covering enforcement points, frozen into the order: listed in the request, listed in the registry policy, and every
 // enforcement source that already recorded a decision for the agent's actors. Coverage does not grow after issuance.
 function coverage(p,entry,listed,settings){
  const known=enforcementPoints(p),basis=new Map(),add=(id,why)=>{if(!known.has(id))return;if(!basis.has(id))basis.set(id,new Set());basis.get(id).add(why);};
  for(const id of listed)add(id,'listed');for(const id of settings.enforcementPoints)add(id,'policy');
  if(entry.actors.length)for(const e of retained(p))if(isDecision(e)&&entry.actors.includes(e.actor))add(e.source,'decisions_seen');
  return [...basis].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([id,why])=>({id,basis:[...why].sort()}));
 }
 function issue(p,id,x){
  only(x,['scope','tools','reason','evidence','enforcementPoints'],'정지 명령');
  const reason=reasonOf(x),scope=x.scope??'agent';if(!STOP_SCOPES.includes(scope))fail(400,'정지 범위는 agent 또는 tools입니다');
  const list=(value,max,name)=>{if(value===undefined)return [];if(!Array.isArray(value)||value.length>max)fail(400,`${name}는 최대 ${max}개 배열입니다`);return value;};
  const tools=[...new Set(list(x.tools,50,'tools').map(t=>cleanText(t,256)))].sort();
  if(scope==='tools'&&!tools.length||scope==='agent'&&tools.length)fail(400,'도구 정지(scope tools)에만 도구 목록을 줍니다');
  const listed=[...new Set(list(x.enforcementPoints,20,'enforcementPoints').map(identifier))];
  return store.transaction(()=>{
   const entry=entryOf(p,id),known=enforcementPoints(p);
   if(entry.state==='retired')fail(409,'폐기된 등록 항목은 정지할 수 없습니다. 묶음에서는 폐기 상태로 이미 거부됩니다');
   for(const ep of listed)if(!known.has(ep))fail(400,`등록되지 않은 집행 지점(enforcement 출처 자격)입니다: ${ep}`);
   const evidence=evidenceRefs(p,x.evidence),current=policy(p),settings=stopPropagationOf(current),at=now(),orderId=randomUUID();
   const suspends=scope==='agent'&&entry.state==='production',transitionId=suspends?randomUUID():null;
   // A covering order replaces earlier active ones of the same agent, so one lift ends what one stop started. It inherits the
   // names they stopped: re-issuing after an edit must not release a source or actor without the four-eyes lift.
   const replaced=activeOf(p,entry.id).filter(o=>scope==='agent'||o.scope==='tools'&&o.tools.every(t=>tools.includes(t)));
   const names=k=>[...new Set([...entry[k],...replaced.flatMap(o=>o.target?.[k]||[])])];
   const order={id:orderId,agentId:entry.id,registryVersion:entry.version,entryState:entry.state,scope,tools,reason,evidence,
    target:{sources:names('sources'),actors:names('actors')},enforcementPoints:coverage(p,entry,listed,settings),
    propagation:{windowSeconds:settings.windowSeconds,policyVersion:current.version,policySource:current.source},
    issuedBy:p.id,issuedAt:at,status:'active',version:1,change:'issued',effectiveFrom:at,...(suspends?{suspension:{transitionId}}:{})};
   store.put(p,STOP_ORDER_TYPE,orderId,order);dirty(p.tenant);
   const superseded=replaced.map(o=>putVersion(p,o,{status:'superseded',supersededBy:{orderId,by:p.id,at}},'superseded').id);
   // A whole-agent stop also closes pending promotion or resume requests: they must be asked again after the lift.
   if(scope==='agent')supersede(p,entry.id,suspends?'state_changed':'stop_order_issued');
   const applied=suspends?suspend(p,entry,{id:transitionId,reason,evidence,stopOrderId:orderId}):null;
   return {order,superseded,...(applied||{})};
  });
 }
 // A suspended agent's whole-agent orders are lifted only by the approved suspended→production transition.
 const resumeOnly=(p,o)=>o.scope==='agent'&&entryOf(p,o.agentId).state==='suspended';
 function requestLift(p,id,x){
  only(x,['reason'],'정지 해제 요청');const reason=reasonOf(x);
  return store.transaction(()=>{
   const o=orderOf(p,id);if(o.status!=='active')fail(409,'활성 정지 명령만 해제할 수 있습니다');
   if(o.liftRequest)fail(409,'승인 대기 중인 해제 요청이 이미 있습니다');
   if(resumeOnly(p,o))fail(409,'정지(suspended) 상태 에이전트의 전체 정지는 suspended→production 전이 승인으로 해제됩니다');
   return {order:putVersion(p,o,{liftRequest:{by:p.id,at:now(),reason}},'lift_requested')};
  });
 }
 function decideLift(p,id,operation,x){
  only(x,['reason'],'정지 해제 결정');const reason=reasonOf(x);
  return store.transaction(()=>{
   const o=orderOf(p,id);if(o.status!=='active'||!o.liftRequest)fail(409,'승인 대기 중인 해제 요청이 없습니다');
   const request=o.liftRequest,at=now();
   if(operation==='refuse')return {order:putVersion(p,o,{liftRequest:null,liftRefused:{by:p.id,at,reason,requestedBy:request.by}},'lift_refused')};
   if(request.by===p.id)fail(403,'해제를 요청한 사람은 해제를 승인할 수 없습니다(4-eyes)');
   if(resumeOnly(p,o))fail(409,'정지(suspended) 상태 에이전트의 전체 정지는 suspended→production 전이 승인으로 해제됩니다');
   return {order:putVersion(p,o,{status:'lifted',liftRequest:null,lift:{via:'approval',requestedBy:request.by,requestReason:request.reason,
    approvedBy:p.id,reason,at}},'lifted')};
  });
 }
 // Registry hooks: no promotion while a whole-agent order is active; the approved resume lifts the agent's whole-agent orders.
 function assertPromotion(p,entry,to){
  if(['approved','production'].includes(to)&&entry.state!=='suspended'&&activeOf(p,entry.id).some(o=>o.scope==='agent'))
   fail(409,'활성 전체 정지 명령이 있는 에이전트는 승격할 수 없습니다. 정지 명령을 먼저 해제하세요');
 }
 function liftOnResume(p,agentId,t){
  return activeOf(p,agentId).filter(o=>o.scope==='agent').map(o=>putVersion(p,o,{status:'lifted',liftRequest:null,
   lift:{via:'transition',transitionId:t.id,requestedBy:t.requestedBy,approvedBy:t.reviewedBy,reason:t.reviewReason,at:now()}},'lifted').id);
 }
 // Propagation view from the signed records and the retained activation reports, as of now.
 function propagation(p,filter=()=>true){
  const signed=rows(p),current=new Map(orders(p).map(o=>[o.id,o]));
  return stopOrderPropagation(signed,retained(p),Date.now()).filter(v=>filter(current.get(v.orderId))).map(v=>{
   const o=current.get(v.orderId);
   return {...v,reason:o.reason,evidence:o.evidence,liftRequest:o.liftRequest||null,lift:o.lift||null,supersededBy:o.supersededBy||null,version:o.version};
  });
 }
 const forAgent=(p,agentId)=>propagation(p,o=>o.agentId===agentId);
 function handle(p,method,parts,x){
  if(method==='GET'){
   if(parts.length===1)return {items:propagation(p),limitations:LIMITATIONS};
   if(parts.length===2){
    const o=orderOf(p,parts[1]),signed=rows(p);
    const versions=signed.filter(r=>r.type===STOP_ORDER_TYPE&&r.payload?.id===o.id)
     .map(r=>({seq:r.seq,recordedAt:r.recordedAt,principal:r.principal,...r.payload}));
    return {order:o,versions,propagation:propagation(p,v=>v.id===o.id)[0],history:verifyStopOrderHistory(signed),limitations:LIMITATIONS};
   }
   fail(404,'지원하지 않는 정지 명령 경로입니다');
  }
  if(parts.length===3&&parts[2]==='lift')return requestLift(p,parts[1],x);
  if(parts.length===4&&parts[2]==='lift'&&['approve','refuse'].includes(parts[3]))return decideLift(p,parts[1],parts[3],x);
  fail(404,'지원하지 않는 정지 명령 경로입니다');
 }
 return {issue,handle,assertPromotion,liftOnResume,forAgent,activeOf,propagation};
}
