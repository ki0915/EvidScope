// Periodic rotation of routine event classes (docs/retention-rotation.md). A rotation policy is a signed object proposed by one
// reviewer and activated by a different administrator; only then may the vault erase, on a schedule and without a further
// approval, the keys and search copies of events of the classes it names once they are older than its period. The ledger
// itself is never truncated: every erased event keeps its signed envelope, hash and receipt, as with a manual disposition.
// The same checks run before every scheduled erasure (src/retention.mjs) and offline on an export (scripts/verify.mjs).
import {DEFAULT_RISK_RULES} from './agent-registry.mjs';
import {canonical} from './crypto.mjs';

export const ROTATION_TYPE='retention_rotation';
// Ledger principal of scheduled erasures; the two people who activated the policy are named in each disposition.
export const ROTATION_PRINCIPAL='retention-rotation';
export const ROTATION_STATUSES=Object.freeze(['proposed','active','rejected','superseded','suspended']);
// Event classes that may be marked routine, by source kind. Everything else is critical and can never rotate: decisions and
// bundle activations (enforcement), grants, approvals and reviews (authority), stop and block records (safety), collection gaps
// and per-article governance checks. Registry, approval, stop-order, case and policy records are signed objects, not events,
// and have no key to erase at all.
export const ROUTINE_KINDS=Object.freeze({agent:Object.freeze(['intent','self_report','delegation']),tool:Object.freeze(['execution','result']),
 telemetry:Object.freeze(['heartbeat','notice']),otlp:Object.freeze(['notice','self_report'])});
export const CRITICAL_SOURCE_KINDS=Object.freeze(['authority','safety','enforcement']);
export const CRITICAL_KINDS=Object.freeze(['gap','governance_check','grant','revoke','human_approval','automated_review','human_oversight_review',
 'stop_requested','block_registered','stop_confirmed','safety_alert','policy_decision','guardrail_decision','bundle_activation']);
export const SENSITIVITIES=Object.freeze(['none','standard','sensitive']);
export const MAX_RETENTION_SECONDS=10*365*86400;
// Access records are personal-information processing logs; the floor follows the one-year minimum for access records
// (개인정보의 안전성 확보조치 기준 제8조). Pruning only ever removes sealed ranges (src/access-log.mjs).
export const MIN_ACCESS_LOG_RETENTION_SECONDS=365*86400;
export const MAX_ROTATION_BATCH=1000;
export const MAX_VALID_DAYS=3*365;
const SENSITIVE=new Set(DEFAULT_RISK_RULES.find(rule=>rule.id==='data-sensitive').values);
const TERM_KEYS=['classes','accessLogRetentionSeconds','maxPerRun','validDays','purpose','reason'];
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exact=(value,keys)=>object(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const integer=(value,min,max)=>Number.isSafeInteger(value)&&value>=min&&value<=max;

// null when c is an allowed class; otherwise why not. concrete: the class of one event (no '*' kind, no 'any' sensitivity).
export function rotationClassProblem(c,{concrete=false}={}){
 if(!exact(c,concrete?['sourceKind','kind','sensitivity']:['sourceKind','kind','sensitivity','retentionSeconds']))return 'invalid class fields';
 if(CRITICAL_SOURCE_KINDS.includes(c.sourceKind)||CRITICAL_KINDS.includes(c.kind))return `critical class ${c.sourceKind}/${c.kind} can never rotate`;
 const kinds=Object.hasOwn(ROUTINE_KINDS,c.sourceKind)?ROUTINE_KINDS[c.sourceKind]:null;
 if(!kinds)return `unknown source kind ${String(c.sourceKind)}`;
 if(!(kinds.includes(c.kind)||!concrete&&c.kind==='*'))return `event kind ${String(c.kind)} is not routine for ${c.sourceKind}`;
 if(!(SENSITIVITIES.includes(c.sensitivity)||!concrete&&c.sensitivity==='any'))return `unknown sensitivity ${String(c.sensitivity)}`;
 if(!concrete&&!integer(c.retentionSeconds,1,MAX_RETENTION_SECONDS))return 'retentionSeconds must be 1 second to 10 years';
 return null;
}
// null when terms are valid policy terms; otherwise why not.
export function rotationTermsProblem(terms){
 if(!exact(terms,TERM_KEYS))return 'invalid policy terms';
 if(!Array.isArray(terms.classes)||!terms.classes.length||terms.classes.length>32)return 'one to 32 classes are required';
 for(const c of terms.classes){const problem=rotationClassProblem(c);if(problem)return problem;}
 if(new Set(terms.classes.map(c=>canonical([c.sourceKind,c.kind,c.sensitivity]))).size!==terms.classes.length)return 'duplicate class';
 if(terms.accessLogRetentionSeconds!==null&&!integer(terms.accessLogRetentionSeconds,MIN_ACCESS_LOG_RETENTION_SECONDS,MAX_RETENTION_SECONDS))
  return 'access log retention must be null or 1 to 10 years';
 if(!integer(terms.maxPerRun,1,MAX_ROTATION_BATCH))return `maxPerRun must be 1 to ${MAX_ROTATION_BATCH}`;
 if(!integer(terms.validDays,1,MAX_VALID_DAYS))return `validDays must be 1 to ${MAX_VALID_DAYS}`;
 if(typeof terms.purpose!=='string'||typeof terms.reason!=='string')return 'purpose and reason are required';
 return null;
}
// The class of one decrypted event.
export function eventRotationClass(event){
 const categories=Array.isArray(event?.dataCategories)?event.dataCategories:[];
 const sensitivity=!categories.length?'none':categories.some(value=>SENSITIVE.has(String(value).toLowerCase()))?'sensitive':'standard';
 return {sourceKind:event?.sourceKind,kind:event?.kind,sensitivity};
}
// Seconds an event of class c must be kept under the policy terms: the longest period of every matching class, or null.
export function requiredRotationSeconds(terms,c){
 if(rotationClassProblem(c,{concrete:true}))return null;
 let required=null;
 for(const rule of terms.classes){
  if(rule.sourceKind===c.sourceKind&&(rule.kind==='*'||rule.kind===c.kind)&&(rule.sensitivity==='any'||rule.sensitivity===c.sensitivity))
   required=Math.max(required??0,rule.retentionSeconds);
 }
 return required;
}
const time=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))?Date.parse(value):NaN;
const invalid=detail=>{throw Error(`Retention rotation history invalid: ${detail}`);};

// One pass over signed records (in ledger order). Throws on the first violation. A transition record may only change status
// fields; the terms are those the proposer wrote and the administrator activated. Reports the policy active after the records.
export function checkRotationHistory(records){
 const policies=new Map(),holds=new Map(),cases=new Map(),events=new Map(),batches=new Map(),erasedByClass={};
 let maxVersion=0,dispositions=0,rotatedEvents=0,prunes=0,prunedThrough=0;
 for(const row of records){
  const payload=row.payload;
  if(row.type===ROTATION_TYPE){
   if(!object(payload)||typeof payload.id!=='string'||!payload.id||!ROTATION_STATUSES.includes(payload.status))invalid(`malformed policy at ${row.seq}`);
   const problem=rotationTermsProblem(payload.terms);if(problem)invalid(`policy at ${row.seq}: ${problem}`);
   const prior=policies.get(payload.id),from=prior?.current.payload.status;
   if(payload.status==='proposed'){
    if(prior||!integer(payload.version,maxVersion+1,Number.MAX_SAFE_INTEGER)||row.principal!==payload.proposedBy)invalid(`proposal at ${row.seq}`);
    maxVersion=payload.version;
   }else{
    if(!prior||payload.version!==prior.current.payload.version||payload.proposedBy!==prior.proposal.payload.proposedBy
     ||canonical(payload.terms)!==canonical(prior.proposal.payload.terms))invalid(`policy ${payload.id} changed its terms at ${row.seq}`);
    if(payload.status==='active'){
     // Two people: the activating record is signed for an approver who is not the proposer.
     if(from!=='proposed'||typeof payload.approvedBy!=='string'||!payload.approvedBy||payload.approvedBy===payload.proposedBy
      ||row.principal!==payload.approvedBy||!Number.isFinite(time(payload.validUntil)))invalid(`activation at ${row.seq} lacks a second person`);
     if(!(time(payload.approvedAt)<=time(row.recordedAt))||!(time(payload.validUntil)-time(payload.approvedAt)<=payload.terms.validDays*86400000)
      ||!(time(row.recordedAt)<=time(prior.proposal.payload.expiresAt)))invalid(`activation at ${row.seq} outlives its terms or its proposal`);
    }else if(payload.status==='rejected'){if(from!=='proposed')invalid(`rejection at ${row.seq}`);}
    else if(from!=='active')invalid(`${payload.status} at ${row.seq} of a policy that is not active`);
   }
   const entry=prior||{proposal:{payload,seq:row.seq}};entry.current={payload,seq:row.seq,hash:row.hash};policies.set(payload.id,entry);
  }else if(row.type==='retention_hold'&&object(payload)&&typeof payload.id==='string')holds.set(payload.id,payload);
  else if(row.type==='case'&&object(payload)&&typeof payload.id==='string')cases.set(payload.id,payload);
  else if(row.type==='event'&&object(payload)&&typeof payload.keyId==='string')events.set(row.seq,row);
  else if(row.type==='audit_access_batch'&&object(payload))batches.set(row.seq,payload);
  else if(row.type==='retention_disposition'&&object(payload)&&Object.hasOwn(payload,'rotation')){
   const r=payload.rotation,policy=object(r)?policies.get(r.policyId)?.current:undefined;
   if(!policy||policy.payload.status!=='active'||policy.hash!==r.policyRecordHash||policy.payload.version!==r.policyVersion)
    invalid(`scheduled disposition at ${row.seq} names no active policy`);
   const at=time(payload.executedAt),terms=policy.payload.terms;
   if(row.principal!==ROTATION_PRINCIPAL||payload.executedBy!==ROTATION_PRINCIPAL||payload.approvedBy!==policy.payload.approvedBy
    ||!(at<=time(row.recordedAt))||!(at<=time(policy.payload.validUntil)))invalid(`scheduled disposition at ${row.seq} is outside its authority`);
   const keys=payload.keyIds,sequences=payload.sequences,classes=r.classes;
   if(!Array.isArray(keys)||!Array.isArray(sequences)||!Array.isArray(classes)||!keys.length||keys.length>terms.maxPerRun
    ||sequences.length!==keys.length||classes.length!==keys.length)invalid(`scheduled disposition at ${row.seq} is malformed`);
   const activeHolds=[...holds.values()].filter(h=>h.status==='active'),openCases=[...cases.values()].filter(c=>c.status!=='closed');
   for(let index=0;index<keys.length;index++){
    const event=events.get(sequences[index]),c=classes[index],required=requiredRotationSeconds(terms,c);
    if(!event||event.payload.keyId!==keys[index])invalid(`scheduled disposition at ${row.seq} names an unknown event`);
    const problem=rotationClassProblem(c,{concrete:true});if(problem)invalid(`scheduled disposition at ${row.seq}: ${problem}`);
    if(required===null)invalid(`scheduled disposition at ${row.seq} erases a class the policy does not name`);
    if(!(at-time(event.recordedAt)>=required*1000)||!(time(event.payload.retainUntil)<=at))
     invalid(`scheduled disposition at ${row.seq} erases an event before its period`);
    const actionId=event.payload.actionId;
    if(typeof actionId!=='string'||!actionId)invalid(`scheduled disposition at ${row.seq} erases an event that cannot be checked against holds`);
    if(activeHolds.some(h=>h.scope==='tenant'||h.scope===actionId)||openCases.some(x=>x.actionId===actionId))
     invalid(`scheduled disposition at ${row.seq} erases an event under a hold or an open case`);
    const name=`${c.sourceKind}/${c.kind}/${c.sensitivity}`;erasedByClass[name]=(erasedByClass[name]||0)+1;rotatedEvents++;
   }
   dispositions++;
  }else if(row.type==='audit_access_prune'){
   // Sealed access ranges leave the side store only under the same two-person policy, past its access log period.
   const r=object(payload)?payload.rotation:undefined,policy=object(r)?policies.get(r.policyId)?.current:undefined;
   const retention=policy?.payload.terms.accessLogRetentionSeconds;
   if(!policy||policy.payload.status!=='active'||policy.hash!==r.policyRecordHash||policy.payload.version!==r.policyVersion||retention===null
    ||payload.retentionSeconds!==retention||row.principal!==ROTATION_PRINCIPAL)invalid(`access log prune at ${row.seq} names no active policy that allows it`);
   const at=time(payload.prunedAt),batch=batches.get(payload.batchSeq);
   if(!(at<=time(row.recordedAt))||!(at<=time(policy.payload.validUntil))||!batch||batch.toSeq!==payload.throughSeq||batch.head!==payload.head
    ||batch.lastAt!==payload.batchLastAt||!(time(batch.lastAt)<=at-retention*1000)||!(payload.throughSeq>prunedThrough))
    invalid(`access log prune at ${row.seq} is not an old enough sealed range`);
   if([...holds.values()].some(h=>h.status==='active'&&h.scope==='tenant'))invalid(`access log prune at ${row.seq} ignores a tenant-wide hold`);
   prunedThrough=payload.throughSeq;prunes++;
  }
 }
 const active=[...policies.values()].map(entry=>entry.current).filter(entry=>entry.payload.status==='active').sort((a,b)=>a.seq-b.seq).at(-1);
 return {valid:true,policies:policies.size,active:active?{...active.payload,recordSeq:active.seq,recordHash:active.hash}:null,
  scheduledDispositions:dispositions,rotatedEvents,erasedByClass,accessLogPrunes:prunes,accessLogPrunedThrough:prunedThrough};
}
export function verifyRotationHistory(records){
 try{return checkRotationHistory(records);}catch(error){return {valid:false,error:error.message};}
}
export const hasRotationRecords=records=>records.some(row=>row.type===ROTATION_TYPE||row.type==='audit_access_prune'
 ||row.type==='retention_disposition'&&object(row.payload)&&Object.hasOwn(row.payload,'rotation'));
