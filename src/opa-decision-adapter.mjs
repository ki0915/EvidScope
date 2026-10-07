// OPA decision-log adapter (docs/agent-registry.md). Converts events in the documented OPA decision log format
// (https://www.openpolicyagent.org/docs/management-decision-logs: decision_id, labels, bundles, path or query, input, result,
// timestamp, metrics, erased, masked, trace_id ...) into `policy_decision` records for an authenticated enforcement source.
// Only allowlisted metadata leaves the adapter. The input and result bodies, the query text, request headers and every other
// field are never copied: the target action reference is read through pointers the trusted collector configuration names.
// Does not verify that OPA enforced its decision, that the decision log is complete, or any signature; it executes nothing.
import {canonical,digest} from './crypto.mjs';
import {cleanText,date,identifier,validateEvent} from './model.mjs';
import {DECISIONS,DECISION_KINDS} from './decision-rules.mjs';

export const OPA_ADAPTER='opa-decision-log-v1';
const TARGET_FIELDS=['actor','tool','action','resource','destination','actionId','traceId'];
// Pointers may read only these parts of a decision event; values must be scalars.
const POINTER_ROOTS=['input','result','trace_id','span_id','labels','path'];
const MAX_DECISIONS=1000,MAX_LATENCY_MS=3600000;
const error=message=>{throw new Error(`OPA decision adapter: ${message}`);};
const plain=(value,name)=>{if(!value||typeof value!=='object'||Array.isArray(value))error(`${name} must be an object`);return value;};

function pointer(spec,name){
 if(typeof spec!=='string'||!/^\/[^\u0000-\u001f]{1,255}$/.test(spec))error(`${name} must be a JSON pointer`);
 const parts=spec.slice(1).split('/').map(part=>part.replace(/~1/g,'/').replace(/~0/g,'~'));
 if(!POINTER_ROOTS.includes(parts[0]))error(`${name} may only read ${POINTER_ROOTS.join(', ')}`);
 return parts;
}
function resolve(event,parts){
 let value=event;
 for(const part of parts){if(!value||typeof value!=='object'||!Object.hasOwn(value,part))return undefined;value=value[part];}
 return value;
}
// Trusted collector configuration: who the enforcement point is and where the target reference sits in the decision event.
function collectorPlan(collector){
 plain(collector,'collector');identifier(collector.id);identifier(collector.tenant);
 if(collector.kind!=='enforcement')error('collector must be an enforcement source');
 const allowed=['id','tenant','kind','enforcementPointId','decisionKind','target','decision','recordedBeforeExecution','clockUncertaintyMs'];
 for(const k of Object.keys(collector))if(!allowed.includes(k))error(`unsupported collector field ${k}`);
 identifier(collector.enforcementPointId);
 const kind=collector.decisionKind??'policy_decision';if(!DECISION_KINDS.includes(kind))error('unsupported decision kind');
 const target={};
 for(const [field,spec] of Object.entries(plain(collector.target??{},'collector.target'))){
  if(!TARGET_FIELDS.includes(field))error(`unsupported target field ${field}`);plain(spec,`target.${field}`);
  if(Object.keys(spec).length!==1||!('value' in spec||'pointer' in spec))error(`target.${field} needs exactly one of value or pointer`);
  target[field]='pointer' in spec?{pointer:pointer(spec.pointer,`target.${field}.pointer`)}:{value:spec.value};
 }
 if(!target.actor)error('target.actor is required');
 const decision=plain(collector.decision??{},'collector.decision');
 for(const k of Object.keys(decision))if(!['pointer','values'].includes(k))error(`unsupported decision field ${k}`);
 const values={true:'allow',false:'deny',...plain(decision.values??{},'decision.values')};
 for(const v of Object.values(values))if(!DECISIONS.includes(v))error('decision.values must map to allow, deny, require_approval or modify');
 if(collector.recordedBeforeExecution!==undefined&&typeof collector.recordedBeforeExecution!=='boolean')error('recordedBeforeExecution must be boolean');
 const clock=collector.clockUncertaintyMs;
 if(clock!==undefined&&clock!=='unknown'&&(!Number.isSafeInteger(clock)||clock<0||clock>300000))error('clockUncertaintyMs must be unknown or 0..300000');
 return {kind,target,decisionPointer:pointer(decision.pointer??'/result','decision.pointer'),values};
}
function targetValue(event,spec,field){
 const value=spec.pointer?resolve(event,spec.pointer):spec.value;
 if(value===undefined)return undefined;
 if(typeof value!=='string'||!value)error(`${field} is not a non-empty string`);
 return ['actionId','traceId'].includes(field)?identifier(value):cleanText(value,256);
}
function decisionOf(event,plan){
 const value=resolve(event,plan.decisionPointer);
 if(!['string','boolean','number'].includes(typeof value))error('decision result is missing or not a scalar');
 const key=String(value);
 if(Object.hasOwn(plan.values,key))return plan.values[key];
 if(DECISIONS.includes(key))return key;
 error('decision result is not mapped to allow, deny, require_approval or modify');
}
// Bundle names and revisions become the policy version; their digest binds the set of bundles.
function bundleFields(bundles){
 if(bundles===undefined)return {};
 const entries=Object.entries(plain(bundles,'bundles')).map(([name,b])=>[cleanText(name,100),cleanText(plain(b,`bundles.${name}`).revision??'',200)]);
 if(!entries.length)return {};
 entries.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 const joined=entries.length===1?entries[0][1]||entries[0][0]:entries.map(([n,r])=>`${n}@${r}`).join(',');
 return {policyVersion:joined.length<=256&&joined?joined:`bundles:${digest(entries).slice(0,32)}`,
  bundleDigest:`sha256:${digest(canonical(Object.fromEntries(entries)))}`};
}
function latency(metrics){
 if(metrics===undefined||metrics===null||typeof metrics!=='object')return {};
 const ns=metrics.timer_server_handler_ns??metrics.timer_rego_query_eval_ns;
 return Number.isSafeInteger(ns)&&ns>=0?{latencyMs:Math.min(MAX_LATENCY_MS,Math.round(ns/1e6))}:{};
}
function adaptOne(raw,collector,plan){
 const event=plain(raw,'decision event');
 const decisionId=identifier(event.decision_id),occurredAt=date(event.timestamp),target={};
 for(const [field,spec] of Object.entries(plan.target)){const value=targetValue(event,spec,field);if(value!==undefined)target[field]=value;}
 if(!target.actor)error('actor not found in the decision event');
 if(!target.tool&&!target.action)error('neither tool nor action found in the decision event');
 if(!target.actionId)target.actionId=`opa:${decisionId}`;
 if(!target.traceId)target.traceId=typeof event.trace_id==='string'&&/^[a-zA-Z0-9._:@/-]{1,120}$/.test(event.trace_id)?event.trace_id:target.actionId;
 // The decision path names the policy; an ad-hoc query is named only by its digest (its text can carry data).
 const path=typeof event.path==='string'?event.path.replace(/^\/+/,''):'';
 const policyId=path?(/^[a-zA-Z0-9._:@/-]{1,120}$/.test(path)?path:`opa-path:${digest(path).slice(0,32)}`)
  :typeof event.query==='string'?`opa-query:${digest(event.query).slice(0,16)}`:undefined;
 const labels=event.labels&&typeof event.labels==='object'?event.labels:{};
 const note={opaDecisionId:decisionId,erasedFields:Array.isArray(event.erased)?event.erased.length:0,
  maskedFields:Array.isArray(event.masked)?event.masked.length:0,adapter:OPA_ADAPTER,inputRetained:false,resultRetained:false};
 const engineVersion=typeof labels.version==='string'&&labels.version?{engineVersion:cleanText(labels.version,100)}:{};
 const out={id:`opa-${digest({collector:collector.id,decision:decisionId}).slice(0,40)}`,kind:plan.kind,occurredAt,...target,decision:decisionOf(event,plan),
  decisionId,enforcementPointId:collector.enforcementPointId,engine:'opa',...engineVersion,...(policyId?{policyId}:{}),...bundleFields(event.bundles),
  ...latency(event.metrics),
  ...(collector.recordedBeforeExecution!==undefined?{recordedBeforeExecution:collector.recordedBeforeExecution}:{}),
  ...(collector.clockUncertaintyMs!==undefined?{clockUncertaintyMs:collector.clockUncertaintyMs}:{}),note:JSON.stringify(note)};
 validateEvent(out,collector);
 return out;
}
/**
 * Returns {events, rejected, assurance}: the policy_decision records to submit through the HMAC ingest path, and the index,
 * decision id and reason of every decision event that could not be converted (nothing is guessed for those).
 */
export function adaptOpaDecisions(log,collector){
 const plan=collectorPlan(collector),items=Array.isArray(log)?log:[log];
 if(!items.length||items.length>MAX_DECISIONS)error(`1 to ${MAX_DECISIONS} decision events required`);
 const events=[],rejected=[],seen=new Set();
 items.forEach((raw,index)=>{
  try{const event=adaptOne(raw,collector,plan);if(seen.has(event.id))error('duplicate decision_id');seen.add(event.id);events.push(event);}
  catch(e){
   rejected.push({index,decisionId:typeof raw?.decision_id==='string'?raw.decision_id.slice(0,120):null,reason:String(e.message).slice(0,300)});
  }
 });
 return {events,rejected,assurance:{adapter:OPA_ADAPTER,source:'external_collector_report',format:'opa_decision_log',signatureVerified:false,
  enforcementVerified:false,completenessVerified:false,inputRetained:false,resultRetained:false,targetFrom:'collector_configuration'}};
}
