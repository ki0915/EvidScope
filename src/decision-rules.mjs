// Policy-decision evidence (docs/agent-registry.md). Enforcement points (gateways, policy engines, guardrails) report
// allow / deny / require_approval / modify decisions as authenticated `enforcement` source records; these rules compare them
// with the independent tool records of the same action. EvidScope blocks nothing: the decisions are enforced elsewhere.
// Pure; evaluate() in src/model.mjs passes its clock-order and approval helpers.
export const DECISION_KINDS=Object.freeze(['policy_decision','guardrail_decision']);
export const DECISIONS=Object.freeze(['allow','deny','require_approval','modify']);
export const DECISION_FIELDS=Object.freeze(['decision','engine','engineVersion','policyId','bundleDigest','enforcementPointId','decisionId','latencyMs',
 'recordedBeforeExecution']);
// Engine constants (a change is a new evaluation engine): denies for one actor within the window, counted across actions.
export const REPEATED_DENIES=Object.freeze({windowMs:10*60*1000,threshold:3,related:50});
export const isDecision=e=>e?.sourceKind==='enforcement'&&DECISION_KINDS.includes(e.kind);
const isDeny=e=>isDecision(e)&&e.decision==='deny'&&typeof e.actor==='string';
// A tool record of an execution: an execution report, or a successful result.
export const executed=e=>e.sourceKind==='tool'&&(e.kind==='execution'||e.kind==='result'&&e.status==='success');
// A decision names the actor and the parts of the target it decided on; each named part must match the tool record.
const targets=(d,e)=>!!d.actor&&d.actor===e.actor&&['tool','action','resource','destination'].every(k=>d[k]===undefined||d[k]===e[k]);
const time=e=>Date.parse(e.occurredAt);

// Snapshot input for the repeated-deny rule: deny decisions of other actions for the same actors within the window of this
// action's denies, as minimal summaries in ledger order (the latest `related`). Undefined when the action has no deny, so
// snapshots without decisions stay unchanged.
export function relatedDenyInput(actionEvents,retained){
 const here=actionEvents.filter(isDeny);if(!here.length)return undefined;
 const actionId=here[0].actionId,range=new Map();
 for(const d of here){const t=time(d),r=range.get(d.actor);range.set(d.actor,r?[Math.min(r[0],t),Math.max(r[1],t)]:[t,t]);}
 const related=[];
 for(const e of retained){
  if(!isDeny(e)||e.actionId===actionId||!range.has(e.actor))continue;
  const t=time(e),[from,to]=range.get(e.actor);if(!(t>=from-REPEATED_DENIES.windowMs&&t<=to+REPEATED_DENIES.windowMs))continue;
  related.push({seq:e.seq,source:e.source,id:e.id,actionId:e.actionId,actor:e.actor,occurredAt:e.occurredAt});
 }
 return related.sort((a,b)=>a.seq-b.seq).slice(-REPEATED_DENIES.related);
}

// vaultApproved / requested: approvals answered in the EvidScope queue (src/approvals.mjs); absent, the rule is as before.
export function decisionFindings(events,{add,order,validity,approvals,enforcedTools,related,vaultApproved=()=>false,requested=()=>false}){
 const decisions=events.filter(isDecision);
 for(const e of events.filter(executed)){
  const matching=decisions.filter(d=>targets(d,e)),denies=matching.filter(d=>d.decision==='deny');
  // A later allow/modify for the same target from the same enforcement point (for example after an approval) clears an earlier
  // deny; another source or enforcement point cannot clear it.
  const samePoint=(a,d)=>a.source===d.source&&a.enforcementPointId===d.enforcementPointId;
  const cleared=d=>matching.some(a=>['allow','modify'].includes(a.decision)&&samePoint(a,d)&&order(d,a)==='before'&&order(a,e)==='before');
  const violated=denies.filter(d=>order(d,e)==='before'&&!cleared(d));
  if(violated.length)add('EXECUTION_AFTER_DENY','high','정책 결정 지점이 거부한 행동의 실행 기록이 이후에 있습니다. 실제 차단 효력과 우회 경로를 검토하세요',[e,...violated]);
  else{const unknown=denies.filter(d=>order(d,e)==='unknown');
   if(unknown.length)add('DECISION_ORDER_UNCERTAIN','medium','시계 오차 때문에 거부 결정과 실행의 순서를 확정할 수 없습니다',[e,...unknown]);}
  if(e.tool&&enforcedTools(e).includes(e.tool)&&!matching.some(d=>order(d,e)!=='after'))
   add('ENFORCEMENT_DECISION_MISSING','high','행동 당시 등록 항목이 정책 결정을 요구한 도구의 실행에 앞선 정책 결정 기록이 없습니다',[e]);
  const required=matching.filter(d=>d.decision==='require_approval'&&order(d,e)!=='after');
  if(required.length&&!approvals.some(g=>validity(g,e)==='valid')&&!vaultApproved(e)&&!required.every(d=>requested(d,e))){
   const uncertain=required.some(d=>order(d,e)==='unknown')||approvals.some(g=>validity(g,e)==='unknown');
   add(uncertain?'REQUIRED_APPROVAL_TIME_UNCERTAIN':'REQUIRED_APPROVAL_MISSING',uncertain?'medium':'high',uncertain
    ?'승인 요구 결정·사람 승인·실행의 순서나 유효기간을 시계 오차 범위에서 확정할 수 없습니다'
    :'정책 결정 지점이 사람 승인을 요구했지만 실행 시점의 정책·범위와 일치하는 사람 승인 기록이 없습니다',[e,...required]);
  }
 }
 const byActor=new Map();for(const d of decisions.filter(isDeny)){if(!byActor.has(d.actor))byActor.set(d.actor,[]);byActor.get(d.actor).push(d);}
 for(const [actor,denies] of byActor){
  const all=[...denies,...(related||[]).filter(r=>r.actor===actor)];
  const count=Math.max(...denies.map(d=>all.filter(x=>Math.abs(time(x)-time(d))<=REPEATED_DENIES.windowMs).length));
  const window=REPEATED_DENIES.windowMs/60000,cap=REPEATED_DENIES.related+denies.length;
  if(count>=REPEATED_DENIES.threshold)
   add('REPEATED_DENIES','medium',`같은 행위자에 대한 거부 결정이 ${window}분 안에 ${count}건 있습니다(다른 행동 포함, 최대 ${cap}건 집계). 반복 시도 여부를 검토하세요`,denies);
 }
}
