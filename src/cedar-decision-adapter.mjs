// Cedar decision adapter (docs/agent-registry.md). Converts Cedar authorization decisions into `policy_decision` records for an
// authenticated enforcement source, from two documented shapes:
// - `avp-cloudtrail`: Amazon Verified Permissions IsAuthorized / IsAuthorizedWithToken / BatchIsAuthorized(WithToken) data events
//   as CloudTrail delivers them ({"Records":[...]}; the decision is in additionalEventData, the request in requestParameters).
// - `cedar-response`: an application's own log entry that embeds a Cedar authorization response ({decision, diagnostics:
//   {reason: [policy ids], errors: [{policyId, error}]}}, as the Cedar FFI/WASM answer {type:"success", response} or as Cedar
//   Agent returns it). Cedar defines no decision log, so the trusted collector configuration names where the entry keeps its
//   id, time and response.
// Only allowlisted metadata leaves the adapter: the decision, its time and id, determining policy ids and error counts. The
// request context, entities, error messages, caller identity, IP addresses and every other field are never copied; the target
// action is read through pointers the collector configuration names. Verifies no signature, completeness or enforcement.
import {canonical,digest} from './crypto.mjs';
import {cleanText,date,identifier,validateEvent} from './model.mjs';
import {DECISION_KINDS} from './decision-rules.mjs';

export const CEDAR_ADAPTER='cedar-decision-v1';
export const CEDAR_FORMATS=Object.freeze(['avp-cloudtrail','cedar-response']);
const TARGET_FIELDS=['actor','tool','action','resource','destination','actionId','traceId'];
// AVP: pointers read the authorization request of one decision (CloudTrail requestParameters or a batch result's request).
const AVP_ROOTS=['principal','action','resource','context'];
const AVP_EVENTS=['IsAuthorized','IsAuthorizedWithToken','BatchIsAuthorized','BatchIsAuthorizedWithToken'];
const MAX_DECISIONS=1000,MAX_NOTE=1024,ID=/^[a-zA-Z0-9._:@/-]{1,120}$/;
const error=message=>{throw new Error(`Cedar decision adapter: ${message}`);};
const plain=(value,name)=>{if(!value||typeof value!=='object'||Array.isArray(value))error(`${name} must be an object`);return value;};
const isPlain=value=>!!value&&typeof value==='object'&&!Array.isArray(value);

function pointer(spec,name,roots){
 if(typeof spec!=='string'||!/^\/[^\u0000-\u001f]{1,255}$/.test(spec))error(`${name} must be a JSON pointer`);
 const parts=spec.slice(1).split('/').map(part=>part.replace(/~1/g,'/').replace(/~0/g,'~'));
 if(roots&&!roots.includes(parts[0]))error(`${name} may only read ${roots.join(', ')}`);
 return parts;
}
function resolve(value,parts){
 for(const part of parts){if(!value||typeof value!=='object'||!Object.hasOwn(value,part))return undefined;value=value[part];}
 return value;
}
// Trusted collector configuration: the enforcement point, the log format and where the target reference sits.
function collectorPlan(collector){
 plain(collector,'collector');identifier(collector.id);identifier(collector.tenant);
 if(collector.kind!=='enforcement')error('collector must be an enforcement source');
 const allowed=['id','tenant','kind','enforcementPointId','format','decisionKind','target','record','policyStoreId','recordedBeforeExecution',
  'clockUncertaintyMs'];
 for(const k of Object.keys(collector))if(!allowed.includes(k))error(`unsupported collector field ${k}`);
 identifier(collector.enforcementPointId);
 if(!CEDAR_FORMATS.includes(collector.format))error(`format must be one of ${CEDAR_FORMATS.join(', ')}`);
 const avp=collector.format==='avp-cloudtrail',roots=avp?AVP_ROOTS:undefined;
 const kind=collector.decisionKind??'policy_decision';if(!DECISION_KINDS.includes(kind))error('unsupported decision kind');
 const target={};
 for(const [field,spec] of Object.entries(plain(collector.target??{},'collector.target'))){
  if(!TARGET_FIELDS.includes(field))error(`unsupported target field ${field}`);plain(spec,`target.${field}`);
  if(Object.keys(spec).length!==1||!('value' in spec||'pointer' in spec))error(`target.${field} needs exactly one of value or pointer`);
  target[field]='pointer' in spec?{pointer:pointer(spec.pointer,`target.${field}.pointer`,roots)}:{value:spec.value};
 }
 if(!target.actor)error('target.actor is required');
 let record;
 if(avp){
  if(collector.record!==undefined)error('record applies to the cedar-response format only');
  if(collector.policyStoreId!==undefined)identifier(collector.policyStoreId);
 }else{
  if(collector.policyStoreId!==undefined)error('policyStoreId applies to the avp-cloudtrail format only');
  const r=plain(collector.record??{},'collector.record');
  for(const k of Object.keys(r))if(!['id','time','response'].includes(k))error(`unsupported record field ${k}`);
  if(r.id===undefined||r.time===undefined)error('record.id and record.time pointers are required');
  record={id:pointer(r.id,'record.id'),time:pointer(r.time,'record.time'),response:pointer(r.response??'/response','record.response')};
 }
 if(collector.recordedBeforeExecution!==undefined&&typeof collector.recordedBeforeExecution!=='boolean')error('recordedBeforeExecution must be boolean');
 const clock=collector.clockUncertaintyMs;
 if(clock!==undefined&&clock!=='unknown'&&(!Number.isSafeInteger(clock)||clock<0||clock>300000))error('clockUncertaintyMs must be unknown or 0..300000');
 return {kind,target,record,avp};
}
// Cedar answers Allow/Deny (core: "allow"/"deny"; Cedar Agent: "Allow"/"Deny"; AVP: "ALLOW"/"DENY"); nothing else is a decision.
function decisionOf(value){
 const v=typeof value==='string'?value.toLowerCase():'';
 if(v!=='allow'&&v!=='deny')error('decision is not Allow or Deny');
 return v;
}
const policyIds=list=>{
 if(list===undefined)return [];
 if(!Array.isArray(list))error('determining policies must be a list');
 return [...new Set(list.map(p=>typeof p==='string'?p:isPlain(p)&&typeof p.policyId==='string'?p.policyId:error('policy id must be a string')))].sort();
};
// One determining policy is the policy id; several are named by the digest of their sorted ids (the ids follow in the note
// while it stays within the note limit).
function policyFields(ids){
 if(!ids.length)return {};
 return {policyId:ids.length===1&&ID.test(ids[0])?ids[0]:`cedar-policies:${digest(canonical(ids)).slice(0,32)}`};
}
function note(base,ids,errorIds,errors){
 const counts={...base,determiningPolicies:ids.length,errors,adapter:CEDAR_ADAPTER,requestRetained:false,errorMessagesRetained:false};
 const safe=list=>list.filter(id=>ID.test(id)).slice(0,16);
 const full=JSON.stringify({...counts,policyIds:safe(ids),errorPolicyIds:safe(errorIds)});
 return full.length<=MAX_NOTE?full:JSON.stringify(counts);
}
function targetOf(source,plan,fallbackId){
 const target={};
 for(const [field,spec] of Object.entries(plan.target)){
  const value=spec.pointer?resolve(source,spec.pointer):spec.value;
  if(value===undefined)continue;
  if(typeof value!=='string'||!value)error(`${field} is not a non-empty string`);
  target[field]=['actionId','traceId'].includes(field)?identifier(value):cleanText(value,256);
 }
 if(!target.actor)error('actor not found in the decision');
 if(!target.tool&&!target.action)error('neither tool nor action found in the decision');
 if(!target.actionId)target.actionId=`cedar:${fallbackId}`;
 if(!target.traceId)target.traceId=target.actionId;
 return target;
}
function build({collector,plan,decisionId,occurredAt,source,decision,ids,errorIds=[],errors=errorIds.length,engine,base}){
 const out={id:`cedar-${digest({collector:collector.id,decision:decisionId}).slice(0,40)}`,kind:plan.kind,occurredAt,...targetOf(source,plan,decisionId),
  decision,decisionId,enforcementPointId:collector.enforcementPointId,engine,...policyFields(ids),
  ...(collector.recordedBeforeExecution!==undefined?{recordedBeforeExecution:collector.recordedBeforeExecution}:{}),
  ...(collector.clockUncertaintyMs!==undefined?{clockUncertaintyMs:collector.clockUncertaintyMs}:{}),note:note(base,ids,errorIds,errors)};
 validateEvent(out,collector);
 return out;
}
const errorPolicies=list=>Array.isArray(list)?[...new Set(list.map(e=>isPlain(e)&&typeof e.policyId==='string'?e.policyId:'').filter(Boolean))].sort():[];
const errorCount=list=>Array.isArray(list)?list.length:0;
const attempt=fn=>{try{return {event:fn()};}catch(e){return {reason:String(e.message).slice(0,300)};}};

// One CloudTrail record -> its decisions: one, or one per batch result, each converted or refused on its own. Throws for a
// record that cannot be read at all.
function avpDecisions(record,collector,plan){
 const decisionTime=date(record.eventTime),requestId=identifier(record.requestID);
 if(record.errorCode!==undefined)error('the authorization call failed; no decision was returned');
 const params=plain(record.requestParameters,'requestParameters'),extra=plain(record.additionalEventData,'additionalEventData');
 const store=params.policyStoreId===undefined?undefined:identifier(params.policyStoreId);
 const base={format:'avp-cloudtrail',...(store?{policyStoreId:store}:{}),eventName:record.eventName};
 const one=(request,result,decisionId)=>{
  const ids=policyIds(result.determiningPolicies);
  return build({collector,plan,decisionId,occurredAt:decisionTime,source:plain(request??{},'request'),decision:decisionOf(result.decision),ids,
   errors:errorCount(result.errors),engine:'amazon-verified-permissions',base});
 };
 if(!record.eventName.startsWith('Batch'))return [{...attempt(()=>one(params,extra,requestId)),id:requestId}];
 if(!Array.isArray(extra.results)||!extra.results.length)error('batch results are missing');
 const requests=Array.isArray(params.requests)?params.requests:[];
 return extra.results.map((result,i)=>({...attempt(()=>one(plain(result,'result').request??requests[i],result,`${requestId}:${i}`)),
  id:`${requestId}:${i}`}));
}
function cedarDecision(entry,collector,plan){
 plain(entry,'log entry');
 const rawId=resolve(entry,plan.record.id);if(typeof rawId!=='string')error('record id not found');
 const decisionId=identifier(rawId),time=resolve(entry,plan.record.time);if(typeof time!=='string')error('record time not found');
 let response=plain(resolve(entry,plan.record.response),'response');
 if(response.type==='failure')error('the authorization call failed; no decision was returned');
 if(response.type==='success')response=plain(response.response,'response.response');
 const diagnostics=plain(response.diagnostics??{},'diagnostics');
 return build({collector,plan,decisionId,occurredAt:date(time),source:entry,decision:decisionOf(response.decision),ids:policyIds(diagnostics.reason),
  errorIds:errorPolicies(diagnostics.errors),engine:'cedar',base:{format:'cedar-response'}});
}
const MAX_ENTRIES=100000;
const records=log=>{
 const items=Array.isArray(log)?log:isPlain(log)&&Array.isArray(log.Records)?log.Records:[log];
 if(items.length>MAX_ENTRIES)error(`more than ${MAX_ENTRIES} log entries`);
 return items;
};
const label=raw=>{
 const id=isPlain(raw)?raw.requestID??raw.id:undefined;
 return typeof id==='string'?id.slice(0,120):null;
};
/**
 * Returns {events, rejected, skipped, assurance}: the policy_decision records to submit through the HMAC ingest path, every
 * entry that could not be converted (index, id, reason; nothing is guessed), and for CloudTrail the count of other events
 * (other services, other API calls, other policy stores), which are not decisions and are ignored.
 */
export function adaptCedarDecisions(log,collector){
 const plan=collectorPlan(collector),items=records(log);
 const events=[],rejected=[],skipped={},seen=new Set();
 items.forEach((raw,index)=>{
  if(plan.avp){
   const name=isPlain(raw)?raw.eventName:undefined;
   const store=isPlain(raw?.requestParameters)?raw.requestParameters.policyStoreId:undefined;
   if(!isPlain(raw)||raw.eventSource!=='verifiedpermissions.amazonaws.com'||!AVP_EVENTS.includes(name)
    ||(collector.policyStoreId!==undefined&&store!==collector.policyStoreId)){
    const key=typeof name==='string'&&/^[A-Za-z]{1,64}$/.test(name)?name:'other';skipped[key]=(skipped[key]||0)+1;return;
   }
  }
  let converted;
  try{converted=plan.avp?avpDecisions(raw,collector,plan):[{...attempt(()=>cedarDecision(raw,collector,plan)),id:label(raw)}];}
  catch(e){rejected.push({index,id:label(raw),reason:String(e.message).slice(0,300)});return;}
  for(const {event,reason,id} of converted){
   const refused=reason??(seen.has(event.id)?'duplicate decision id':events.length>=MAX_DECISIONS?`more than ${MAX_DECISIONS} decisions`:undefined);
   if(refused){rejected.push({index,id:typeof id==='string'?id.slice(0,120):null,reason:refused});continue;}
   seen.add(event.id);events.push(event);
  }
 });
 if(!events.length&&!rejected.length&&!Object.keys(skipped).length)error('no decision entries');
 return {events,rejected,skipped,assurance:{adapter:CEDAR_ADAPTER,source:'external_collector_report',format:collector.format,signatureVerified:false,
  enforcementVerified:false,completenessVerified:false,requestRetained:false,errorMessagesRetained:false,targetFrom:'collector_configuration'}};
}
