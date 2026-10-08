// Human approval queue for enforcement points (docs/approval-queue.md). A gateway or policy engine that decided
// require_approval opens a request; reviewers approve or refuse it in EvidScope; the gateway polls CIBA-style and acts only on a
// vault-signed answer it verifies offline. Pure functions shared by the vault, the analysis engine, the offline verifier and
// gateways: identifiers and target digests, who may answer (policy data), the compact analysis input, the approval findings,
// the check of the signed request history, and the signed answer (DSSE / in-toto Statement v1). No I/O.
import {canonical,digest} from './crypto.mjs';
import {ed25519Verifier,intotoStatement,openEnvelope,parseStatement,sha256Hex} from './dsse.mjs';
import {DEFAULT_RISK_RULES,RISK_TIERS,computeRisk,riskBasis} from './agent-registry.mjs';
import {executed} from './decision-rules.mjs';

export const APPROVAL_TYPE='approval_request';
export const APPROVAL_STATUSES=Object.freeze(['pending','approved','refused']);
// OpenID Connect CIBA Core 1.0 poll mode: the grant type a CIBA client sends to the token endpoint, and its error codes.
export const CIBA_GRANT_TYPE='urn:openid:params:grant-type:ciba';
export const CIBA_ERRORS=Object.freeze(['authorization_pending','slow_down','access_denied','expired_token','invalid_grant','invalid_request',
 'unsupported_grant_type']);
export const TARGET_FIELDS=Object.freeze(['actor','tool','action','resource','destination']);
export const EXCLUSIONS=Object.freeze(['registrant','editor','owner']);
export const ANSWER_ROLES=Object.freeze(['reviewer','admin']);
const DOC='https://github.com/ki0915/EvidScope/blob/main/docs/approval-queue.md';
export const ANSWER_PREDICATE=`${DOC}#approval-answer-v1`,ANSWER_FORMAT='evidscope-approval-answer-v1';
// requestsPerAction bounds the analysis input of one action; the poll interval grows by slowDownSeconds per early poll (CIBA).
export const APPROVAL_LIMITS=Object.freeze({requestsPerAction:10,bindingMessage:200,reason:1000,slowDownSeconds:5,maxIntervalSeconds:60});
const rule=(approvers,roles=ANSWER_ROLES)=>Object.freeze({approvers,roles:Object.freeze([...roles]),exclude:Object.freeze([...EXCLUSIONS])});
// Built-in answer policy, used until an admin signs `approvals` into the registry policy (POST /api/registry/policy).
export const DEFAULT_APPROVAL_POLICY=Object.freeze({defaultLifetimeSeconds:300,maxLifetimeSeconds:900,intervalSeconds:5,executionWindowSeconds:300,
 unregisteredTier:'high',answer:Object.freeze({low:rule(1),medium:rule(1),high:rule(2)})});
// Fields of a request record. Everything but the answer fields is fixed when the request is opened.
export const REQUEST_FIELDS=Object.freeze(['id','version','change','status','requestedBy','enforcementPointId','decisionId','actionId','traceId','policyId',
 'policyVersion','target','targetDigest','bindingMessage','requestedAt','expiresAt','requestedExpiry','intervalSeconds','executionWindowSeconds','eligibility',
 'approvals','refusal','decidedAt','executionWindow']);
const ANSWER_FIELDS=['version','change','status','approvals','refusal','decidedAt','executionWindow'];
const FIXED_FIELDS=REQUEST_FIELDS.filter(k=>!ANSWER_FIELDS.includes(k));

const plain=v=>!!v&&typeof v==='object'&&!Array.isArray(v);
const time=v=>typeof v==='string'?Date.parse(v):NaN;
// auth_req_id (CIBA: at least 128 bits, A-Z a-z 0-9 . - _): 160 bits derived from tenant, requesting credential and decision id,
// so a retried request finds the request it already opened. Polling still requires the same credential.
export const approvalRequestId=(tenant,source,decisionId)=>'apr_'+Buffer.from(sha256Hex(canonical(['evidscope-approval-request-v1',tenant,source,decisionId])),
 'hex').subarray(0,20).toString('base64url');
// The approved target is the named fields only; an execution matches when every named field is equal.
export const approvalTarget=target=>Object.fromEntries(TARGET_FIELDS.filter(k=>plain(target)&&typeof target[k]==='string').map(k=>[k,target[k]]));
export const targetDigest=target=>digest(approvalTarget(target));
export const approvalStatus=(v,now)=>v.status==='pending'&&!(now<time(v.expiresAt))?'expired':v.status;

// ---------- who may answer ----------
// The policy in force: the signed registry policy's `approvals` and risk rules, or the built-in defaults (named as such).
export function approvalPolicyOf(signed){
 return {approvals:signed?.approvals??DEFAULT_APPROVAL_POLICY,riskRules:signed?.riskRules??DEFAULT_RISK_RULES,version:signed?.version??0,
  source:signed?.approvals?'signed':'built_in_default'};
}
// The live registry entry that names the actor (the registry keeps at most one), else null.
export function coveringEntry(entries,actor){
 return [...entries].filter(v=>v&&v.state!=='retired'&&Array.isArray(v.actors)&&v.actors.includes(actor)).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0)[0]??null;
}
export function effectiveTier(entry,rules){
 const override=entry.risk?.override;
 return override&&override.basisHash===riskBasis(entry)&&RISK_TIERS.includes(override.tier)?override.tier:computeRisk(entry,rules).computed;
}
// The reviewer whose risk override set a tier other than the computed one. One person may override alone, so that person must
// not also answer the requests the tier governs (lower the tier to one approver, then be that approver).
export function overrideAuthor(entry,rules){
 const override=entry?.risk?.override;
 return override&&typeof override.by==='string'&&effectiveTier(entry,rules)===override.tier&&override.tier!==computeRisk(entry,rules).computed
  ?override.by:null;
}
// Frozen into the request when it is opened, so the offline check can recompute it from the ledger prefix. basis.overrideBy
// (round 4) is outside the recomputed key, so requests opened before it keep verifying.
export function approvalEligibility(entry,policy){
 const tier=entry?effectiveTier(entry,policy.riskRules):policy.approvals.unregisteredTier,answer=policy.approvals.answer[tier];
 const values={registrant:entry?.registeredBy,editor:entry?.editedBy,owner:entry?.owner},overrideBy=overrideAuthor(entry,policy.riskRules);
 const excluded=[...new Set(answer.exclude.map(k=>values[k]).filter(v=>typeof v==='string'&&v))].sort();
 return {tier,approvers:answer.approvers,roles:[...answer.roles],exclude:[...answer.exclude],excluded,
  basis:{entryId:entry?.id??null,entryVersion:entry?.version??null,entryState:entry?.state??null,policyVersion:policy.version,policySource:policy.source,
   ...(overrideBy?{overrideBy}:{})}};
}

// ---------- evaluation (engine v3) ----------
// Latest version of each request of one action, in the order the requests were opened; undefined without any, so snapshots of
// actions without requests stay unchanged. Forged shapes degrade, never throw.
const text=v=>typeof v==='string'?v:null;
const entryOf=x=>plain(x)?{by:text(x.by),role:text(x.role),at:text(x.at)}:{by:null,role:null,at:null};
export function approvalAnalysisInput(values){
 const list=values.filter(plain).map(v=>({id:text(v.id),version:Number.isSafeInteger(v.version)?v.version:null,status:text(v.status),
  decisionId:text(v.decisionId),policyVersion:text(v.policyVersion),target:approvalTarget(v.target),targetDigest:text(v.targetDigest),
   requestedAt:text(v.requestedAt),
  expiresAt:text(v.expiresAt),decidedAt:text(v.decidedAt),
  executionWindow:plain(v.executionWindow)?{notBefore:text(v.executionWindow.notBefore),notAfter:text(v.executionWindow.notAfter)}:null,
  approvals:(Array.isArray(v.approvals)?v.approvals:[]).map(entryOf),refusal:plain(v.refusal)?entryOf(v.refusal):null,
  eligibility:{approvers:Number.isSafeInteger(v.eligibility?.approvers)?v.eligibility.approvers:null,
   roles:(Array.isArray(v.eligibility?.roles)?v.eligibility.roles:[]).filter(x=>typeof x==='string'),
   excluded:(Array.isArray(v.eligibility?.excluded)?v.eligibility.excluded:[]).filter(x=>typeof x==='string')}}));
 return list.length?list:undefined;
}
const sameTarget=(a,e)=>!!a.target.actor&&Object.entries(a.target).every(([k,v])=>e[k]===v);
// An approved answer counts only with distinct approvers in the number, roles and exclusions the request recorded.
function improper(a){
 const approvers=a.approvals.map(x=>x.by),distinct=new Set(approvers),window=a.executionWindow;
 return distinct.size!==approvers.length||!(distinct.size>=(a.eligibility.approvers??Infinity))||approvers.some(by=>!by||a.eligibility.excluded.includes(by))
  ||a.approvals.some(x=>!a.eligibility.roles.includes(x.role))||!window||!Number.isFinite(time(window.notBefore))||!Number.isFinite(time(window.notAfter));
}
// Where the execution lies relative to the request, within its clock bound: before the answer, inside the approved window, after
// the window, after a refusal or after expiry; 'unknown' when the bound straddles a boundary. Vault times are taken as exact.
function timing(a,e,bound){
 const at=time(e.occurredAt),b=bound(e),point=x=>!Number.isFinite(x)?'unknown':at-b>=x?'after':at+b<x?'before':'unknown';
 if(a.status==='approved'){
  const start=point(time(a.executionWindow.notBefore));if(start!=='after')return start;
  const until=time(a.executionWindow.notAfter);return at-b>until?'after_window':at+b<=until?'valid':'unknown';
 }
 const end=point(time(a.status==='refused'?a.decidedAt:a.expiresAt));
 return end==='after'?(a.status==='refused'?'after_refusal':'after_expiry'):end;
}
// policyVersion: also require the policy version the request named (the asset rule's per-action human approval).
export const approvalSatisfied=(approvals,e,bound,{policyVersion=false}={})=>!!approvals&&approvals.some(a=>a.status==='approved'&&sameTarget(a,e)
 &&!improper(a)&&timing(a,e,bound)==='valid'&&(!policyVersion||!!e.policyVersion&&a.policyVersion===e.policyVersion));
// A require_approval decision the gateway turned into an EvidScope request for this execution's target: the approval findings
// below report it, so the generic REQUIRED_APPROVAL_MISSING rule does not report it again.
export const approvalRequested=(approvals,d,e)=>!!approvals&&approvals.some(a=>a.decisionId===d.decisionId&&sameTarget(a,e));
const FINDINGS={
 before:['EXECUTION_BEFORE_APPROVAL','high','승인 요청에 사람의 답이 나기 전에 실행되었습니다'],
 after_refusal:['EXECUTION_AFTER_APPROVAL_REFUSED','high','사람이 거절한 승인 요청의 대상이 거절 이후 실행되었습니다'],
 after_expiry:['EXECUTION_AFTER_APPROVAL_EXPIRED','high','승인 요청이 만료(거절로 처리)된 뒤 대상이 실행되었습니다'],
 after_window:['APPROVAL_WINDOW_EXCEEDED','high','승인된 실행 창이 끝난 뒤 실행되었습니다'],
 unknown:['APPROVAL_TIME_UNCERTAIN','medium','시계 오차 때문에 승인 요청의 답·만료·실행 창과 실행의 순서를 확정할 수 없습니다'],
};
export function approvalFindings(events,approvals,{add,clockBound}){
 if(!approvals)return;
 for(const e of events.filter(executed)){
  const related=approvals.filter(a=>sameTarget(a,e));
  for(const a of related.filter(a=>a.status==='approved'&&improper(a)))
   add('APPROVAL_ANSWERER_EXCLUDED','high',`승인 요청 ${a.id}의 승인이 요청에 기록된 답변 자격(제외 대상·역할·승인자 수)을 지키지 않았습니다. 이 승인은 효력이 없습니다`,[e]);
  const states=related.filter(a=>!(a.status==='approved'&&improper(a))).map(a=>[a,timing(a,e,clockBound)]);
  if(states.some(([,state])=>state==='valid'))continue;
  for(const a of approvals.filter(a=>a.status==='approved'&&!improper(a)&&!sameTarget(a,e))){
   const start=time(a.executionWindow.notBefore);
   if(!(time(e.occurredAt)+clockBound(e)<start))
    add('APPROVAL_TARGET_MISMATCH','high',`승인 요청 ${a.id}이 승인한 대상(digest ${String(a.targetDigest).slice(0,12)})과 다른 대상이 같은 행동에서 실행되었습니다`,[e]);
  }
  for(const [a,state] of states){const [code,severity,message]=FINDINGS[state];add(code,severity,`${message} (승인 요청 ${a.id})`,[e]);}
 }
}

// ---------- offline check of the signed request history ----------
// Confirms what the vault API writes: the request id and target digest, the lifetime cap and answer rules of the registry policy
// and entry in force when it was opened (recomputed from the ledger prefix), immutable request fields, answers before expiry by
// the recorded principal, distinct eligible approvers in the required number, the execution window, and no change after a
// final answer. A holder of the signing key can still sign a consistent false history.
export function verifyApprovalHistory(rows){
 const problems=[],requests=new Map(),entries=new Map();let policy=null,answered=0;
 const problem=(row,message)=>{if(problems.length<100)problems.push({seq:row.seq,type:row.type,message});};
 const eligibilityKey=x=>canonical(plain(x)?{tier:x.tier??null,approvers:x.approvers??null,roles:x.roles??null,exclude:x.exclude??null,
  excluded:x.excluded??null}:null);
 for(const row of rows){
  const v=plain(row.payload)?row.payload:{};
  if(row.type==='agent_registry'){entries.set(v.id,v);continue;}
  if(row.type==='agent_registry_policy'){policy=v;continue;}
  if(row.type!==APPROVAL_TYPE)continue;
  const previous=requests.get(v.id),current=approvalPolicyOf(policy);
  const extra=Object.keys(v).find(k=>!REQUEST_FIELDS.includes(k));if(extra!==undefined)problem(row,`request has an unknown field ${extra}`);
  if(!plain(v.target)||Object.keys(v.target).some(k=>!TARGET_FIELDS.includes(k))||canonical(approvalTarget(v.target))!==canonical(v.target))
   problem(row,'request target has unknown or non-text fields');
  if(v.targetDigest!==targetDigest(v.target))problem(row,'target digest differs from the target');
  if(v.id!==approvalRequestId(row.tenant,v.requestedBy,v.decisionId))problem(row,'request id is not derived from tenant, requester and decision id');
  if(!previous){
   if(v.version!==1||v.status!=='pending'||v.change!=='requested'||!Array.isArray(v.approvals)||v.approvals.length||v.refusal!==null||v.decidedAt!==null
    ||v.executionWindow!==null)problem(row,'request does not start as an unanswered version 1');
   if(row.principal!==v.requestedBy)problem(row,'request principal differs from requestedBy');
   const lifetime=time(v.expiresAt)-time(v.requestedAt);
   if(!(lifetime>0&&lifetime<=current.approvals.maxLifetimeSeconds*1000))problem(row,'request lifetime exceeds the policy cap');
   if(v.executionWindowSeconds!==current.approvals.executionWindowSeconds)problem(row,'execution window differs from the policy');
   const recomputed=approvalEligibility(coveringEntry(entries.values(),v.target?.actor),current),basis=v.eligibility?.basis;
   const overrideBy=plain(basis)&&Object.hasOwn(basis,'overrideBy')?basis.overrideBy:recomputed.basis.overrideBy;
   if(eligibilityKey(v.eligibility)!==eligibilityKey(recomputed)||overrideBy!==recomputed.basis.overrideBy)
    problem(row,'who may answer differs from the registry policy and entry in force');
  }else{
   if(previous.status!=='pending')problem(row,'request changed after its final answer');
   if(v.version!==previous.version+1)problem(row,'request version is not consecutive');
   if(FIXED_FIELDS.some(k=>canonical(v[k]??null)!==canonical(previous[k]??null)))problem(row,'request fields changed after it was opened');
   if(!(time(row.recordedAt)<time(v.expiresAt)))problem(row,'answer recorded after the request expired');
   const before=Array.isArray(previous.approvals)?previous.approvals:[],after=Array.isArray(v.approvals)?v.approvals:[];
   if(canonical(after.slice(0,before.length))!==canonical(before))problem(row,'earlier approvals changed');
   const added=after.slice(before.length),answer=v.status==='refused'?v.refusal:added[0],el=plain(v.eligibility)?v.eligibility:{};
   if(added.length!==(v.status==='refused'?0:1)||!plain(answer))problem(row,'answer does not add exactly one approval or refusal');
   else{
    if(row.principal!==answer.by)problem(row,'answer principal differs from the recorded approver');
    if(answer.by===v.requestedBy||(el.excluded||[]).includes(answer.by)||answer.by===el.basis?.overrideBy||!(el.roles||[]).includes(answer.role))
     problem(row,'answered by a principal the policy excluded');
    if(v.status!=='refused'&&before.some(x=>x?.by===answer.by))problem(row,'the same principal approved twice');
    if(!(time(answer.at)<time(v.expiresAt)))problem(row,'answer time is after expiry');
   }
   const distinct=new Set(after.map(x=>x?.by)).size;
   if(v.status==='approved'){
    const at=added[0]?.at,window=v.executionWindow;
    if(distinct<el.approvers)problem(row,'approved with fewer distinct approvers than the policy requires');
    if(v.decidedAt!==at||!plain(window)||window.notBefore!==at||time(window.notAfter)-time(at)!==v.executionWindowSeconds*1000)
     problem(row,'approval time or execution window is inconsistent');
   }else if(v.status==='refused'){if(v.decidedAt!==v.refusal?.at||v.executionWindow!==null)problem(row,'refusal time is inconsistent');}
   else if(v.status!=='pending'||distinct>=el.approvers||v.decidedAt!==null||v.refusal!==null)problem(row,'pending version is inconsistent');
   if(v.status!=='pending')answered++;
  }
  requests.set(v.id,v);
 }
 return {valid:!problems.length,requests:requests.size,answered,problems,
  limitations:['Checks what the vault API writes; a holder of the signing key can still sign a consistent false history.',
   'Principal roles come from the vault configuration, which an export does not carry; the recorded role is checked against the policy only.']};
}

// ---------- the signed answer a gateway verifies ----------
// Built from one signed ledger version of an answered request; Ed25519 is deterministic, so every poll returns the same bytes.
export function answerStatement(tenant,v,ledger){
 const who=x=>({principal:x.by,role:x.role,at:x.at});
 return intotoStatement([{name:`approval/${v.id}`,sha256:v.targetDigest}],ANSWER_PREDICATE,{format:ANSWER_FORMAT,tenant,auth_req_id:v.id,
  requestVersion:v.version,decision:v.status,decisionId:v.decisionId,actionId:v.actionId,traceId:v.traceId??null,enforcementPointId:v.enforcementPointId,
  requestedBy:v.requestedBy,policyId:v.policyId??null,policyVersion:v.policyVersion??null,target:v.target,targetDigest:v.targetDigest,
  approvers:v.approvals.map(who),refusedBy:v.refusal?who(v.refusal):null,decidedAt:v.decidedAt,executionWindow:v.executionWindow,singleUse:true,
  ledger:{seq:ledger.seq,recordHash:ledger.hash}});
}
// Gateway-side check (offline, vault public key only). Throws on a bad envelope or signature; otherwise `approved` is true only
// for an approval of exactly the expected action and target inside its execution window. Anything else is a refusal.
export function verifyApprovalAnswer({envelope,publicKey,expected,now=Date.now()}){
 if(!plain(expected)||typeof expected.actionId!=='string'||!plain(expected.target))throw TypeError('expected.actionId and expected.target are required');
 const opened=openEnvelope(envelope,[ed25519Verifier(publicKey)]),statement=parseStatement(opened.body);
 if(canonical(statement)!==opened.body.toString('utf8'))throw Error('Approval answer statement is not canonical JSON');
 if(statement.predicateType!==ANSWER_PREDICATE||!plain(statement.predicate)||statement.predicate.format!==ANSWER_FORMAT)
  throw Error('Not an EvidScope approval answer');
 const a=statement.predicate;
 if(statement.subject.length!==1||statement.subject[0].digest.sha256!==a.targetDigest||targetDigest(a.target)!==a.targetDigest)
  throw Error('Approval answer target digest differs from its target');
 const reasons=[];
 for(const k of ['tenant','auth_req_id','actionId','decisionId'])if(expected[k]!==undefined&&a[k]!==expected[k])reasons.push(`${k} differs`);
 if(targetDigest(expected.target)!==a.targetDigest)reasons.push('target differs from the approved target');
 if(a.decision!=='approved')reasons.push(`decision is ${a.decision}`);
 else if(!(now>=time(a.executionWindow?.notBefore)&&now<=time(a.executionWindow?.notAfter)))reasons.push('outside the execution window');
 return {valid:true,approved:!reasons.length,reasons,decision:a.decision,keyid:opened.keyids[0],answer:a};
}
