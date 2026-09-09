import {digest} from './crypto.mjs';
export class HttpError extends Error {constructor(status,message){super(message);this.status=status;}}
export const fail=(status,message)=>{throw new HttpError(status,message);};
export const cleanText=(s,max=1000)=>{if(typeof s!=='string'||s.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(s)) fail(400,'문자열 형식 또는 길이가 유효하지 않습니다');return s;};
export const identifier=s=>{if(typeof s!=='string'||!/^[a-zA-Z0-9._:@/-]{1,120}$/.test(s))fail(400,'잘못된 식별자');return s;};
export const date=s=>{if(typeof s!=='string'||!/^\d{4}-\d\d-\d\dT/.test(s)||!Number.isFinite(Date.parse(s)))fail(400,'ISO 시각이 필요합니다');return new Date(s).toISOString();};
const kindBySource={agent:['intent','self_report','delegation'],tool:['execution','result'],authority:['grant','revoke','human_approval','automated_review'],safety:['stop_requested','block_registered','stop_confirmed','safety_alert'],telemetry:['heartbeat','gap','notice']};
const fields=['id','kind','occurredAt','traceId','actionId','parentActionId','actor','model','tool','action','resource','destination','status','dataCategories','dataRefs','policyVersion','validFrom','validUntil','scope','authorityId','reviewer','targetVersion','note','purpose'];
export function validateReference(ref){
 if(!ref||Array.isArray(ref)||typeof ref!=='object'||Object.keys(ref).some(k=>!['id','kind','version','hash','role','locator','description'].includes(k)))fail(400,'참고 데이터는 허용된 참조 메타데이터만 제출할 수 있습니다');
 if(!['document','dataset','record','retrieval','artifact'].includes(ref.kind)||!['input','retrieved','output'].includes(ref.role))fail(400,'참고 데이터 종류 또는 역할 오류');
 const r={id:identifier(ref.id),kind:ref.kind,role:ref.role,version:cleanText(ref.version||'unknown',100),hash:ref.hash||'not_provided'};
 if(r.hash!=='not_provided'&&!/^[a-f0-9]{64}$/.test(r.hash))fail(400,'참고 데이터 hash는 SHA-256 hex 또는 not_provided');
 if(ref.locator)r.locator=cleanText(ref.locator,1000);if(ref.description)r.description=cleanText(ref.description,256);return r;
}
export function validateEvent(raw,p) {
 if(!raw||Array.isArray(raw)||typeof raw!=='object')fail(400,'이벤트 객체가 필요합니다');
 for(const k of Object.keys(raw))if(!fields.includes(k))fail(400,`미수집 또는 예약 필드: ${k}`);
 if(!kindBySource[p.kind]?.includes(raw.kind))fail(403,'출처 자격에 허용되지 않은 이벤트 유형');
 const e={};for(const [k,v] of Object.entries(raw)){
  if(k==='dataCategories'){if(!Array.isArray(v)||v.length>16)fail(400,'데이터 범주 최대 16개');e[k]=v.map(s=>cleanText(s,64));}
  else if(k==='dataRefs'){if(!Array.isArray(v)||v.length>16)fail(400,'참고 데이터 참조는 최대 16개');e[k]=v.map(validateReference);}
  else if(k==='scope'){if(!v||Array.isArray(v)||typeof v!=='object')fail(400,'scope 객체 필요');e.scope={};for(const [f,x] of Object.entries(v)){if(!['actor','tool','action','resource','destination','parentActionId'].includes(f))fail(400,'지원하지 않는 scope 필드');e.scope[f]=cleanText(x,256);}}
  else e[k]=cleanText(v,k==='note'?1024:256);
 }
 ['id','actionId','traceId'].forEach(k=>identifier(e[k]));date(e.occurredAt);
 if(Date.parse(e.occurredAt)>Date.now()+300000)fail(400,'미래 시각 오차가 5분을 초과했습니다');
 if(e.validFrom)date(e.validFrom);if(e.validUntil)date(e.validUntil);
 if(e.validFrom&&e.validUntil&&Date.parse(e.validFrom)>=Date.parse(e.validUntil))fail(400,'유효기간 역전');
 if(['grant','human_approval','automated_review'].includes(e.kind)&&(!e.validFrom||!e.validUntil||!e.scope||!e.policyVersion))fail(400,'권한/검토에는 당시 정책 버전·범위·유효기간이 필요합니다');
 if(e.kind==='human_approval'&&!e.reviewer)fail(400,'외부 사람 검토자 참조 필요');
 return {...e,tenant:p.tenant,source:p.id,sourceKind:p.kind,receivedAt:new Date().toISOString(),fingerprint:digest(raw),assurance:p.kind==='agent'?'authenticated_self_report':'authenticated_service_record',late:Date.now()-Date.parse(e.occurredAt)>300000,payload:{minimization:'allowlist_metadata_only',originalContentStored:false}};
}
export const ruleFields=['kind','tool','action','resource','destination','status','actor','note'];
export function validateRule(x,p,version) {
 identifier(x.id);cleanText(x.title,200);if(!ruleFields.includes(x.field)||!['eq','contains','neq'].includes(x.op)||!['low','medium','high'].includes(x.severity))fail(400,'제한된 룰 DSL만 허용됩니다');cleanText(x.value,200);
 return {id:x.id,title:x.title,field:x.field,op:x.op,value:x.value,severity:x.severity,version,status:'draft',author:p.id,createdAt:new Date().toISOString()};
}
export function matches(rule,event){const v=String(event[rule.field]??'');return rule.op==='eq'?v===rule.value:rule.op==='neq'?v!==rule.value:v.includes(rule.value);}

export function evaluate(events,assets,rules,exceptions,now=Date.now()) {
 const findings=[];const add=(code,severity,message,refs)=>findings.push({code,severity,message,evidence:refs.map(e=>`${e.source}/${e.id}`)});
 const actions=events.filter(e=>['intent','execution','self_report','result'].includes(e.kind));
 const executions=events.filter(e=>e.sourceKind==='tool'&&['execution','result'].includes(e.kind));
 const grants=events.filter(e=>e.sourceKind==='authority'&&e.kind==='grant');
 const approvals=events.filter(e=>e.sourceKind==='authority'&&e.kind==='human_approval');
 // Policy and delegation scope are historical evidence, never inherited from parent links.
 const matchesScope=(g,e)=>g.scope&&Object.keys(g.scope).length>0&&['actor','tool','action','resource'].every(k=>g.scope[k]&&g.scope[k]===e[k])&&(!g.scope.destination||g.scope.destination===e.destination)&&((g.scope.parentActionId||e.parentActionId)?g.scope.parentActionId===e.parentActionId:true);
 const validAt=(g,e)=>!!e.policyVersion&&g.policyVersion===e.policyVersion&&Date.parse(g.occurredAt)<=Date.parse(e.occurredAt)&&Date.parse(g.validFrom)<=Date.parse(e.occurredAt)&&Date.parse(e.occurredAt)<Date.parse(g.validUntil)&&!events.some(r=>r.kind==='revoke'&&r.sourceKind==='authority'&&r.authorityId===g.id&&r.source===g.source&&Date.parse(r.occurredAt)<=Date.parse(e.occurredAt));
 for(const e of actions){
  if(e.tool&&!assets.some(a=>a.tool===e.tool&&a.actor===e.actor))add('UNREGISTERED_ASSET','medium','미등록 AI 또는 도구 조합입니다',[e]);
  const registrations=assets.filter(a=>a.tool===e.tool&&a.actor===e.actor);
  const atTime=registrations.filter(a=>e.policyVersion&&a.policyVersion===e.policyVersion&&Date.parse(a.validFrom)<=Date.parse(e.occurredAt)&&(!a.validUntil||Date.parse(e.occurredAt)<Date.parse(a.validUntil)));
  const policies=[...new Map(atTime.map(a=>[digest(a.destinations||[]),a])).values()];
  if(e.destination&&registrations.length&&policies.length!==1)add('POLICY_CONTEXT_UNVERIFIED','medium','행동 시점의 목적지 정책 버전·유효기간이 없거나 등록 기록이 상충합니다. 현재 설정으로 과거를 확정하지 않습니다',[e]);
  if(e.destination&&policies.length===1&&policies[0].destinations?.length&&!policies[0].destinations.includes(e.destination))add('DESTINATION_OUTSIDE_POLICY','high','행동 시점에 유효한 등록 정책 밖 목적지입니다',[e]);
  if(e.parentActionId&&!grants.some(g=>g.scope?.parentActionId===e.parentActionId&&validAt(g,e)&&matchesScope(g,e)))add('DELEGATION_UNVERIFIED','medium','당시 정책·부모·대상 범위와 일치하는 독립 권한 증거가 없습니다. 위임 자기보고만으로 확정하지 않습니다',[e]);
 }
 for(const e of executions){
  if(!grants.some(g=>validAt(g,e)&&matchesScope(g,e)))add(grants.length?'AUTHORITY_MISMATCH':'AUTHORITY_MISSING','high',grants.length?'실행 시점의 권한 발급·정책 버전·유효기간·범위를 확인할 수 없거나 행동과 일치하지 않습니다':'독립 권한 증거가 없습니다',[e,...grants]);
  if(!approvals.some(g=>validAt(g,e)&&matchesScope(g,e)))add(approvals.length?'APPROVAL_MISMATCH':'HUMAN_APPROVAL_MISSING','medium',approvals.length?'사람 승인의 발급 시점·정책·범위·기간을 확인할 수 없거나 실제 행동과 일치하지 않습니다':'독립 사람 승인 증거가 없습니다. 자동 검토는 사람 승인이 아닙니다',[e,...approvals]);
 }
 for(const report of events.filter(e=>e.kind==='self_report'&&e.status==='success')){
  const comparable=executions.filter(e=>e.tool===report.tool&&e.action===report.action&&e.resource===report.resource&&e.kind==='result');
  if(comparable.some(e=>e.status==='failure')&&!comparable.some(e=>e.status==='success'))add('CONTRADICTING_RESULT','high','동일 행동·대상의 성공 자기보고와 독립 실패 결과가 상충합니다',[report,...comparable]);
 }
 for(const report of events.filter(e=>e.sourceKind==='agent'&&e.kind==='self_report'))for(const ref of report.dataRefs||[]){
  const observed=events.filter(e=>e.sourceKind==='tool'&&['execution','result'].includes(e.kind)&&e.tool===report.tool&&e.action===report.action&&e.resource===report.resource&&(e.dataRefs||[]).some(r=>r.id===ref.id&&r.role===ref.role&&((r.version!=='unknown'&&ref.version!=='unknown'&&r.version!==ref.version)||(r.hash!=='not_provided'&&ref.hash!=='not_provided'&&r.hash!==ref.hash))));
  if(observed.length)add('REFERENCE_METADATA_CONFLICT','medium','동일 행동의 참고 자료 버전 또는 해시가 AI 자기보고와 도구 기록에서 다릅니다. 실제 원문은 별도 대조가 필요합니다',[report,...observed]);
 }
 for(const request of events.filter(e=>['stop_requested','block_registered'].includes(e.kind))){
  const confirmed=events.some(e=>e.kind==='stop_confirmed'&&e.sourceKind==='safety'&&e.actionId===request.actionId&&['actor','tool','action','resource'].every(k=>request[k]&&e[k]===request[k])&&(!request.destination||e.destination===request.destination)&&Date.parse(e.occurredAt)>=Date.parse(request.occurredAt));
  if(!confirmed)add('STOP_UNCONFIRMED','medium','이 대상의 중단/차단 등록 이후 실제 실행 중단 확인이 없습니다',[request]);
 }
 for(const e of events){
  if(e.kind==='gap')add('COLLECTION_GAP','high','수집 출처가 관측 공백을 보고했습니다',[e]);
  if(e.late)add('LATE_EVIDENCE','low','행동 시각보다 5분 이상 늦게 접수된 증거입니다',[e]);
  if(/<script|javascript:|ignore.{0,30}instructions|감사.{0,20}룰.{0,20}변경|\bonerror\s*=/i.test(e.note||''))add('LOG_INJECTION_SIGNAL','medium','지시 또는 실행 payload 형태의 비신뢰 로그입니다. 의미적 공격 확정은 아닙니다',[e]);
  for(const r of rules)if(matches(r,e))add(`CUSTOM:${r.id}:v${r.version}`,r.severity,r.title,[e]);
 }
 const unique=[...new Map(findings.map(f=>[f.code+'|'+f.evidence.join(','),f])).values()];
 for(const f of unique){const exception=exceptions.find(x=>x.status==='approved'&&Date.parse(x.expiresAt)>now&&x.actionId===events[0]?.actionId&&(x.ruleId===f.code||f.code.startsWith(`CUSTOM:${x.ruleId}:`)));if(exception){f.suppressedBy=exception.id;f.message+=' (승인된 한시 예외; 원본·법적 판단은 유지)';}}
 const reportedSuccess=executions.some(e=>e.kind==='result'&&e.status==='success'),reportedFailure=executions.some(e=>e.kind==='result'&&e.status==='failure');
 return {findings:unique,authority:executions.length?(unique.some(f=>f.code.startsWith('AUTHORITY'))?'unverified_or_mismatch':'matched_at_event_time'):'not_observed',effect:reportedSuccess&&reportedFailure?'mixed_results':reportedSuccess?'independently_reported_success':reportedFailure?'independently_reported_failure':'unconfirmed',limitations:['출처 인증은 내용의 진실성을 보증하지 않습니다','각 source가 같은 actionId를 정확히 연결했다는 가정','승인 대조는 수집된 증거에 한정하며 법적 인간 감독 충족 판정이 아닙니다']};
}
