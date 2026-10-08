// Approval queue API (docs/approval-queue.md). An `enforcement` source credential opens a request for one target action
// (HMAC-signed like /api/ingest) and polls for the answer CIBA-style; reviewers and admins approve or refuse in the workspace.
// Requests and answers are signed ledger objects (every version kept). The poll answers from the verified cached state of one
// request: no tenant-wide work, no ledger write, a per-request interval with slow_down, and an error for anything but a
// vault-signed answer, so a gateway that acts only on a verified approval fails closed. No outbound calls.
import {verify} from 'node:crypto';
import {canonical,equal,mac} from './crypto.mjs';
import {HttpError,fail,cleanText,identifier} from './model.mjs';
import {INTOTO_PAYLOAD_TYPE,pae,signEnvelope} from './dsse.mjs';
import {RISK_TIERS} from './agent-registry.mjs';
import {ANSWER_ROLES,APPROVAL_LIMITS,APPROVAL_TYPE,CIBA_GRANT_TYPE,DEFAULT_APPROVAL_POLICY,EXCLUSIONS,TARGET_FIELDS,answerStatement,approvalEligibility,
 approvalPolicyOf,approvalRequestId,approvalStatus,approvalTarget,coveringEntry,targetDigest} from './approvals.mjs';

export const APPROVAL_PATHS=Object.freeze({request:'/api/approvals/requests',token:'/api/approvals/token'});
const REQUEST_BODY=['decisionId','actionId','traceId','enforcementPointId','policyId','policyVersion','target','binding_message','requested_expiry'];
// Named so a gateway that forwards a tool call learns why it was refused: the queue stores the target, never the call.
const PAYLOAD_LIKE=['input','inputs','arguments','args','params','parameters','payload','body','content','prompt','messages','request','response','output',
 'result','data','headers','query'];
const ciba=(status,error,description,details={})=>{throw new HttpError(status,error,{error_description:description,...details});};
const object=(x,name)=>{if(!x||typeof x!=='object'||Array.isArray(x))fail(400,`${name}는 JSON 객체여야 합니다`);return x;};
const integer=(v,min,max,name)=>{if(!Number.isSafeInteger(v)||v<min||v>max)fail(400,`${name}는 ${min}~${max} 정수입니다`);return v;};

// The `approvals` part of the registry policy (admin-only, signed with it). Unknown fields, tiers, roles or exclusions are refused.
export function normalizeApprovalPolicy(x){
 object(x,'approvals');
 const allowed=['defaultLifetimeSeconds','maxLifetimeSeconds','intervalSeconds','executionWindowSeconds','unregisteredTier','answer'];
 for(const k of Object.keys(x))if(!allowed.includes(k))fail(400,`approvals에 허용되지 않은 필드: ${k}`);
 const d=DEFAULT_APPROVAL_POLICY,value=(k,min,max)=>x[k]===undefined?d[k]:integer(x[k],min,max,k);
 const out={defaultLifetimeSeconds:value('defaultLifetimeSeconds',1,86400),maxLifetimeSeconds:value('maxLifetimeSeconds',1,86400),
  intervalSeconds:value('intervalSeconds',1,APPROVAL_LIMITS.maxIntervalSeconds),executionWindowSeconds:value('executionWindowSeconds',1,86400),
  unregisteredTier:x.unregisteredTier===undefined?d.unregisteredTier:RISK_TIERS.includes(x.unregisteredTier)?x.unregisteredTier:fail(400,
   'unregisteredTier 오류'),answer:{}};
 if(out.defaultLifetimeSeconds>out.maxLifetimeSeconds)fail(400,'defaultLifetimeSeconds는 maxLifetimeSeconds 이하여야 합니다');
 const answer=x.answer===undefined?{}:object(x.answer,'approvals.answer');
 for(const k of Object.keys(answer))if(!RISK_TIERS.includes(k))fail(400,`approvals.answer의 위험 등급 오류: ${k}`);
 for(const tier of RISK_TIERS){
  const r=answer[tier]===undefined?d.answer[tier]:object(answer[tier],`approvals.answer.${tier}`);
  for(const k of Object.keys(r))if(!['approvers','roles','exclude'].includes(k))fail(400,`approvals.answer.${tier}에 허용되지 않은 필드: ${k}`);
  const roles=r.roles??d.answer[tier].roles,exclude=r.exclude??d.answer[tier].exclude;
  if(!Array.isArray(roles)||!roles.length||roles.some(role=>!ANSWER_ROLES.includes(role))||new Set(roles).size!==roles.length)fail(400,
   'roles는 reviewer·admin 중에서 고릅니다');
  if(!Array.isArray(exclude)||exclude.some(k=>!EXCLUSIONS.includes(k))||new Set(exclude).size!==exclude.length)fail(400,
   'exclude는 registrant·editor·owner 중에서 고릅니다');
  out.answer[tier]={approvers:r.approvers===undefined?d.answer[tier].approvers:integer(r.approvers,1,3,'approvers'),roles:[...roles],exclude:[...exclude]};
 }
 return out;
}

export function createApprovals({store,principals,policyObjects,signer,now=()=>Date.now()}){
 const sources=p=>{if(p.role!=='source'||p.kind!=='enforcement')fail(403,'enforcement 출처 자격이 필요합니다');};
 const answerer=p=>{if(!ANSWER_ROLES.includes(p.role))fail(403,'검토자 또는 관리자만 승인 요청에 답할 수 있습니다');};
 const iso=t=>new Date(t).toISOString();
 const current=p=>approvalPolicyOf(policyObjects(p,'agent_registry_policy').get('current'));
 function approvals(p,options){
  let result;try{result=store.cachedApprovals(p.tenant,options);}catch(error){if(error?.status)throw error;fail(409,'승인 요청 서명 원장을 검증할 수 없습니다');}
  if(result.oversized)fail(413,'승인 요청 기록 한도 초과: 부분 검증으로 조회하거나 답할 수 없습니다');
  return result.values;
 }
 const one=(p,id)=>approvals(p,{id})[0];
 // A version of a request bumps only its own action (an action without events yet gets one when its first event arrives).
 const put=(p,v)=>{store.put(p,APPROVAL_TYPE,v.id,v);
  store.projectionMutation(()=>store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=? AND id=?').run(p.tenant,v.actionId));return v;};

 function normalizeRequest(x){
  object(x,'승인 요청');
  for(const k of Object.keys(x)){
   if(PAYLOAD_LIKE.includes(k))fail(400,`승인 요청에 호출 본문(${k})을 보낼 수 없습니다. 대상 메타데이터만 보냅니다`);
   if(!REQUEST_BODY.includes(k))fail(400,`승인 요청에 허용되지 않은 필드: ${k}`);
  }
  const target=object(x.target,'target');
  for(const k of Object.keys(target)){if(PAYLOAD_LIKE.includes(k))fail(400,`target에 호출 본문(${k})을 보낼 수 없습니다`);if(!TARGET_FIELDS.includes(k))fail(400,
   `target에 허용되지 않은 필드: ${k}`);}
  for(const k of TARGET_FIELDS)if(target[k]!==undefined&&(typeof target[k]!=='string'||!target[k].trim()))fail(400,`target.${k}는 비어 있지 않은 문자열입니다`);
  if(!target.actor||!target.tool&&!target.action)fail(400,'target에는 actor와 tool 또는 action이 필요합니다');
  for(const k of TARGET_FIELDS)if(target[k]!==undefined)cleanText(target[k],256);
  const message=x.binding_message;
  if(typeof message!=='string'||!message.trim())fail(400,'binding_message(사람이 읽을 짧은 요약)가 필요합니다');
  cleanText(message,APPROVAL_LIMITS.bindingMessage);
  if(x.requested_expiry!==undefined&&(!Number.isSafeInteger(x.requested_expiry)||x.requested_expiry<1))fail(400,'requested_expiry는 양의 정수(초)입니다');
  const out={decisionId:identifier(x.decisionId),actionId:identifier(x.actionId),enforcementPointId:identifier(x.enforcementPointId),
   target:approvalTarget(target),bindingMessage:message,...(x.requested_expiry!==undefined?{requestedExpiry:x.requested_expiry}:{})};
  if(x.traceId!==undefined)out.traceId=identifier(x.traceId);
  if(x.policyId!==undefined)out.policyId=identifier(x.policyId);
  if(x.policyVersion!==undefined)out.policyVersion=cleanText(x.policyVersion,256);
  return out;
 }
 const ack=(v,at,extra={})=>({auth_req_id:v.id,expires_in:Math.max(0,Math.ceil((Date.parse(v.expiresAt)-at)/1000)),interval:v.intervalSeconds,
  status:approvalStatus(v,at),targetDigest:v.targetDigest,eligibility:{tier:v.eligibility.tier,approvers:v.eligibility.approvers},...extra});
 // CIBA backchannel authentication request: {auth_req_id, expires_in, interval}. The id is derived from the decision id, so a
 // retry returns the same request; the same id with a different target or message is a conflict.
 function open(p,headers,body){
  sources(p);
  const ts=headers['x-evid-timestamp'],nonce=headers['x-evid-nonce'],signature=headers['x-evid-signature'],at=now();
  if(!/^\d{13}$/.test(ts||'')||Math.abs(at-Number(ts))>300000||!nonce||!/^[a-zA-Z0-9-]{16,80}$/.test(nonce))fail(401,'서명 시각 또는 nonce가 유효하지 않습니다');
  if(!p.hmacSecret||!equal(mac(p.hmacSecret,ts,nonce,body),signature||''))fail(401,'출처 서명 검증 실패');
  let raw;try{raw=JSON.parse(body);}catch{fail(400,'JSON 형식 오류');}
  const request=normalizeRequest(raw);
  return store.transaction(()=>{
   store.db.prepare('DELETE FROM nonces WHERE expires<?').run(at);
   if(store.db.prepare('SELECT 1 FROM nonces WHERE source=? AND nonce=?').get(p.id,nonce))fail(409,'이미 사용한 nonce입니다');
   store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(p.id,nonce,at+600000);
   const id=approvalRequestId(p.tenant,p.id,request.decisionId),existing=one(p,id)?.body;
   const same=v=>canonical(['actionId','traceId','enforcementPointId','policyId','policyVersion','target','bindingMessage',
    'requestedExpiry'].map(k=>v[k]??null));
   if(existing){
    if(same(existing)!==same(request))fail(409,'같은 결정 id로 다른 대상의 승인 요청이 이미 있습니다');
    return ack(existing,at,{duplicate:true});
   }
   if(approvals(p,{actionId:request.actionId}).length>=APPROVAL_LIMITS.requestsPerAction)fail(409,`한 행동에 승인 요청은 최대 ${APPROVAL_LIMITS.requestsPerAction}개입니다`);
   const policy=current(p),limits=policy.approvals;
   const lifetime=Math.min(request.requestedExpiry??limits.defaultLifetimeSeconds,limits.maxLifetimeSeconds);
   const entry=coveringEntry(policyObjects(p,'agent_registry').values(),request.target.actor);
   const v={id,version:1,change:'requested',status:'pending',requestedBy:p.id,...request,targetDigest:targetDigest(request.target),requestedAt:iso(at),
    expiresAt:iso(at+lifetime*1000),intervalSeconds:limits.intervalSeconds,executionWindowSeconds:limits.executionWindowSeconds,
    eligibility:approvalEligibility(entry,policy),approvals:[],refusal:null,decidedAt:null,executionWindow:null};
   return ack(put(p,v),at,{duplicate:false});
  });
 }

 // Poll pacing per request (memory only; a restart forgets it). An early poll gets slow_down and a longer interval (CIBA). It is
 // checked before the request is read, so polling too fast costs no database work.
 const pace=new Map(),PACE_ENTRIES=10000,paceKey=(p,id)=>canonical([p.tenant,p.id,id]);
 function early(p,id,at){
  const key=paceKey(p,id),entry=pace.get(key);
  // Up to half a second early still counts as on time (network jitter).
  if(!entry||at+500>=entry.next)return;
  const longer=Math.min(entry.interval+APPROVAL_LIMITS.slowDownSeconds,APPROVAL_LIMITS.maxIntervalSeconds);pace.set(key,{next:at+longer*1000,interval:longer});
  ciba(400,'slow_down',`폴링 간격 ${longer}초 이상을 지키세요`,{interval:longer});
 }
 function schedule(p,id,interval,at){
  const key=paceKey(p,id),step=Math.max(pace.get(key)?.interval??interval,interval);
  if(!pace.has(key)&&pace.size>=PACE_ENTRIES){for(const [k,v] of pace)if(v.next+v.interval*1000<at)pace.delete(k);
   if(pace.size>=PACE_ENTRIES)ciba(400,'slow_down','폴링 상태 한도에 도달했습니다. 간격을 늘려 다시 요청하세요');}
  pace.set(key,{next:at+step*1000,interval:step});
 }
 const envelopes=new Map();
 async function sign(statement){
  const body=Buffer.from(canonical(statement),'utf8'),envelope=await signEnvelope(INTOTO_PAYLOAD_TYPE,body,signer);
  if(!verify(null,pae(INTOTO_PAYLOAD_TYPE,body),signer.publicKey,Buffer.from(envelope.signatures[0].sig,'base64')))
   throw Error('Approval signer returned a signature that does not verify with the vault key');
  return envelope;
 }
 // CIBA token request in poll mode: {grant_type, auth_req_id}. Errors are HTTP 400 with an OAuth `error` code; an answered
 // request returns its vault-signed answer (approved: HTTP 200; refused: access_denied carrying the signed refusal).
 function poll(p,body){
  sources(p);const at=now();
  let x;try{x=JSON.parse(body);}catch{ciba(400,'invalid_request','JSON 형식 오류');}
  if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).some(k=>!['grant_type','auth_req_id'].includes(k)))ciba(400,'invalid_request',
   'grant_type과 auth_req_id만 보냅니다');
  if(x.grant_type!==CIBA_GRANT_TYPE)ciba(400,'unsupported_grant_type',`grant_type은 ${CIBA_GRANT_TYPE}입니다`);
  if(typeof x.auth_req_id!=='string'||!/^apr_[A-Za-z0-9_-]{27}$/.test(x.auth_req_id))ciba(400,'invalid_grant','auth_req_id 형식 오류');
  early(p,x.auth_req_id,at);
  const found=store.transaction(()=>one(p,x.auth_req_id));
  // Another credential's or tenant's request is indistinguishable from an unknown one (CIBA invalid_grant).
  if(!found||found.body.requestedBy!==p.id)ciba(400,'invalid_grant','이 출처 자격이 연 승인 요청이 아닙니다');
  const v=found.body,status=approvalStatus(v,at);
  schedule(p,v.id,v.intervalSeconds,at);
  if(status==='expired')ciba(400,'expired_token','승인 요청이 만료되었습니다. 거절로 처리하세요');
  if(status==='pending')ciba(400,'authorization_pending','사람의 답을 기다리는 중입니다',{expires_in:Math.max(1,Math.ceil((Date.parse(v.expiresAt)-at)/1000))});
  const key=canonical([p.tenant,v.id,found.seq]);
  const signed=envelopes.get(key)??sign(answerStatement(p.tenant,v,{seq:found.seq,hash:found.hash})).then(envelope=>{
   if(envelopes.size>=1000)envelopes.delete(envelopes.keys().next().value);envelopes.set(key,envelope);return envelope;});
  return Promise.resolve(signed).then(envelope=>{
   const answer={auth_req_id:v.id,decision:v.status,answer:envelope,executionWindow:v.executionWindow,ledger:{seq:found.seq,recordHash:found.hash}};
   if(v.status==='refused')ciba(400,'access_denied','사람이 승인 요청을 거절했습니다',answer);
   return answer;
  });
 }

 // ---------- reviewer side ----------
 function view(p,value,at){
  const v=value.body;
  return {...v,state:approvalStatus(v,at),remainingSeconds:Math.max(0,Math.ceil((Date.parse(v.expiresAt)-at)/1000)),seq:value.seq,
   approvalsNeeded:Math.max(0,v.eligibility.approvers-new Set(v.approvals.map(a=>a.by)).size),
   mayAnswer:mayAnswer(p,v,at)};
 }
 function refusal(p,v,at,operation='approve'){
  if(approvalStatus(v,at)!=='pending')return [409,'답할 수 없는 상태입니다(이미 결정되었거나 만료됨)'];
  if(!ANSWER_ROLES.includes(p.role)||!v.eligibility.roles.includes(p.role))return [403,'이 위험 등급의 승인 요청에 답할 수 없는 역할입니다'];
  const entry=coveringEntry(policyObjects(p,'agent_registry').values(),v.target.actor);
  if(v.eligibility.excluded.includes(p.id)||entry&&[entry.registeredBy,entry.editedBy].includes(p.id))
   return [403,'에이전트 등록자·구성 수정자·책임자 등 정책이 제외한 사람은 답할 수 없습니다'];
  if(v.eligibility.basis?.overrideBy===p.id)return [403,'위험 등급을 재지정해 이 요청의 등급을 정한 사람은 답할 수 없습니다'];
  if(operation==='approve'&&v.approvals.some(a=>a.by===p.id))return [403,'같은 사람이 두 번 승인할 수 없습니다(서로 다른 승인자 필요)'];
  return null;
 }
 const mayAnswer=(p,v,at)=>{const r=refusal(p,v,at);return r?{allowed:false,reason:r[1]}:{allowed:true};};
 function answer(p,id,operation,x){
  answerer(p);object(x,'답변');
  for(const k of Object.keys(x))if(!['reason','version'].includes(k))fail(400,`답변에 허용되지 않은 필드: ${k}`);
  const reason=cleanText(x.reason??'',APPROVAL_LIMITS.reason);if(!reason.trim())fail(400,'답변 사유가 필요합니다');
  integer(x.version,1,1000,'version');
  return store.transaction(()=>{
   const at=now(),found=one(p,identifier(id))||fail(404,'승인 요청을 찾을 수 없습니다'),v=found.body;
   if(v.version!==x.version)fail(409,'요청이 그 사이 바뀌었습니다. 최신 내용을 확인하고 다시 답하세요');
   const refused=refusal(p,v,at,operation);if(refused)fail(...refused);
   const by={by:p.id,role:p.role,at:iso(at),reason},next={...v,version:v.version+1};
   if(operation==='refuse')return put(p,{...next,change:'refused',status:'refused',refusal:by,decidedAt:by.at});
   const list=[...v.approvals,by],done=new Set(list.map(a=>a.by)).size>=v.eligibility.approvers;
   return put(p,{...next,change:done?'approved':'approval_added',status:done?'approved':'pending',approvals:list,
    ...(done?{decidedAt:by.at,executionWindow:{notBefore:by.at,notAfter:iso(at+v.executionWindowSeconds*1000)}}:{})});
  });
 }
 function queue(p){
  const at=now(),values=approvals(p,{}).map(value=>view(p,value,at)),policy=current(p);
  const pending=values.filter(v=>v.state==='pending').sort((a,b)=>a.expiresAt.localeCompare(b.expiresAt)||a.id.localeCompare(b.id));
  const answered=values.filter(v=>v.state!=='pending').sort((a,b)=>(b.decidedAt||b.expiresAt).localeCompare(a.decidedAt||a.expiresAt)).slice(0,100);
  return {pending:pending.slice(0,500),pendingTotal:pending.length,recent:answered,total:values.length,
   policy:{version:policy.version,source:policy.source,...policy.approvals},
   limitations:['EvidScope는 실행 경로에서 답만 줍니다. 실제 실행·차단은 서명된 답을 검증한 게이트웨이가 합니다',
    '만료된 요청은 거절입니다. EvidScope가 응답하지 않으면 게이트웨이는 거절로 처리해야 합니다(fail closed)']};
 }
 function detail(p,id){
  const at=now(),found=approvals(p,{id:identifier(id),history:true})[0]||fail(404,'승인 요청을 찾을 수 없습니다'),v=found.body;
  const history=found.versions.map(r=>({seq:r.seq,recordedAt:r.recordedAt,principal:r.principal,version:r.payload.version,change:r.payload.change,
   status:r.payload.status,approvals:r.payload.approvals,refusal:r.payload.refusal}));
  const entry=coveringEntry(policyObjects(p,'agent_registry').values(),v.target.actor);
  const others=approvals(p,{actionId:v.actionId}).filter(o=>o.id!==v.id).map(o=>view(p,o,at));
  let decisions=[];
  try{decisions=store.cachedEvents(p.tenant,{actionId:v.actionId}).filter(e=>e.sourceKind==='enforcement')
   .map(e=>({source:e.source,id:e.id,kind:e.kind,decision:e.decision,decisionId:e.decisionId,engine:e.engine,policyId:e.policyId,
    occurredAt:e.occurredAt}));}catch{}
  return {request:view(p,found,at),history,registry:entry?{id:entry.id,name:entry.name,state:entry.state,version:entry.version,owner:entry.owner,
   registeredBy:entry.registeredBy,tier:v.eligibility.tier}:null,otherRequests:others,decisions:decisions.slice(-50)};
 }
 function handle(p,method,url,x){
  const path=url.pathname;if(path!=='/api/approvals'&&!path.startsWith('/api/approvals/'))return undefined;
  const parts=path.split('/').slice(3).map(decodeURIComponent);
  if(method==='GET'){
   return store.transaction(()=>{if(!parts.length)return queue(p);if(parts.length===1)return detail(p,parts[0]);fail(404,'지원하지 않는 승인 경로입니다');});
  }
  if(method!=='POST')fail(405,'허용되지 않은 메서드');
  if(parts.length===2&&['approve','refuse'].includes(parts[1]))return answer(p,parts[0],parts[1],x);
  fail(404,'지원하지 않는 승인 경로입니다');
 }
 return {open,poll,handle};
}
