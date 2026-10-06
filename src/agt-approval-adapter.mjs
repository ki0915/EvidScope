import {digest} from './crypto.mjs';
import {cleanText,date,identifier,validateEvent} from './model.mjs';

export const AGT_APPROVAL_COMMIT='662d77b496635bfcc798d9c54b3b75e590ab6cff';
const contextFields=['systemId','requestId','attemptId','modelId','modelVersion','actionId','traceId'];
const scopeFields=['actor','tool','action','resource','destination','parentActionId'];
const error=message=>{throw new Error(`AGT approval adapter: ${message}`);};
const object=(value,name)=>{
 if(!value||typeof value!=='object'||Array.isArray(value))error(`${name} must be an object`);
 return value;
};
const text=(value,name,max=256)=>{
 if(typeof value!=='string'||!value.trim())error(`${name} is required`);
 return cleanText(value,max);
};
const hash=(value,name)=>{
 if(typeof value!=='string'||!/^sha256:[a-f0-9]{64}$/.test(value))error(`${name} must be a sha256 digest`);
 return value;
};
const same=(a,b,name)=>{if(a!==b)error(`${name} mismatch`);};
const eventId=(collector,request,kind,entry='')=>'agt-'+kind+'-'+digest({source:collector.id,request:request.approval_request_id,entry}).slice(0,40);

/**
 * Read-only translation of the pinned AGT ApprovalRequest, ApprovalResolution,
 * and ApprovalChainEntry records. The external collector owns the authenticated
 * authority credential and supplies the exact scope/context/action digest it
 * observed. Never take that collector configuration from an agent's request.
 *
 * context is an EvidScope envelope, not a native AGT field. Both copies must
 * agree; this adapter cannot prove their relation to model weights or execution.
 * lifecycle is an optional collector record {kind: 'cancelled'|'revoked',
 * occurredAt}; AGT's request status alone has no revocation timestamp.
 *
 * Returns raw events for the existing HMAC submission path plus assurance.
 * Does not issue approvals, verify AGT signatures/JCS hashes, authenticate
 * approvers, decide whether a configured chain is sufficient, or execute tools.
 */
export function adaptAgtApproval(receipt,collector){
 object(receipt,'receipt');object(collector,'collector');
 identifier(collector.id);identifier(collector.tenant);
 if(collector.kind!=='authority')error('collector must be an authority source');
 const scope=object(collector.scope,'collector.scope');
 if(Object.keys(scope).some(k=>!scopeFields.includes(k)))error('unsupported collector scope field');
 for(const key of ['actor','tool','action','resource'])text(scope[key],`scope.${key}`);
 for(const key of ['destination','parentActionId'])if(scope[key]!==undefined)text(scope[key],`scope.${key}`);
 const expectedContext=object(collector.context,'collector.context');
 const submittedContext=object(receipt.context,'receipt.context');
 const context={};
 for(const key of contextFields){
  text(expectedContext[key],`collector.context.${key}`);
  same(submittedContext[key],expectedContext[key],`context.${key}`);
  context[key]=key==='modelVersion'?cleanText(expectedContext[key],256):identifier(expectedContext[key]);
 }
 if(Object.keys(submittedContext).some(k=>!contextFields.includes(k)))error('unsupported context field');
 const clock=collector.clockUncertaintyMs;
 if(clock!=='unknown'&&(!Number.isSafeInteger(clock)||clock<0||clock>300000))error('explicit bounded or unknown collector clock uncertainty required');

 const request=object(receipt.request,'request'),resolution=object(receipt.resolution,'resolution');
 for(const key of ['approval_request_id','policy_decision_id','agent_id','operation','policy_version','approval_chain_id','approval_chain_version'])text(request[key],`request.${key}`);
 for(const key of ['approval_resolution_id','approval_request_id','policy_version','approval_chain_version'])text(resolution[key],`resolution.${key}`);
 same(hash(request.action_digest,'request.action_digest'),hash(collector.actionDigest,'collector.actionDigest'),'collector action digest');
 same(hash(resolution.action_digest,'resolution.action_digest'),request.action_digest,'resolution action digest');
 same(resolution.approval_request_id,request.approval_request_id,'approval request');
 same(resolution.policy_version,request.policy_version,'policy version');
 same(resolution.approval_chain_version,request.approval_chain_version,'approval chain version');
 same(request.agent_id,scope.actor,'actor');
 same(request.operation,scope.action,'operation');
 same(request.target_resource,scope.resource,'resource');
 if(resolution.outcome!=='allow')error('unresolved or non-allow approval cannot yield authority');
 if(!['allowed','consumed','cancelled'].includes(request.status))error('request is not resolved allow');
 if(request.fail_closed_on_timeout!==true)error('fail-closed approval request required');
 const requestedAt=date(request.requested_at),resolvedAt=date(resolution.resolved_at),until=date(request.expires_at);
 if(Date.parse(requestedAt)>Date.parse(resolvedAt)||Date.parse(resolvedAt)>=Date.parse(until))error('invalid approval time window');

 if(!Array.isArray(receipt.entries)||receipt.entries.length<1||receipt.entries.length>64)error('1 to 64 approval chain entries required');
 const seen=new Set();let previous=null,terminalEntries=0;
 const entries=receipt.entries.map(raw=>{
  const entry=object(raw,'chain entry');
  for(const key of ['chain_entry_id','approval_request_id','approver_identity','identity_assurance'])text(entry[key],`entry.${key}`);
  same(entry.approval_request_id,request.approval_request_id,'entry request');
  if(seen.has(entry.chain_entry_id))error('duplicate chain entry');
  seen.add(entry.chain_entry_id);
  if(!Number.isSafeInteger(entry.stage_index)||entry.stage_index<0)error('invalid approval stage');
  if(!['human','service','llm_advisory'].includes(entry.approver_kind))error('unknown approver kind');
  if(!['allow','deny'].includes(entry.decision))error('unresolved chain entry');
  hash(entry.input_digest,'entry.input_digest');hash(entry.entry_digest,'entry.entry_digest');
  same(entry.previous_entry_digest,previous,'entry chain link');previous=entry.entry_digest;
  const at=date(entry.decided_at);
  if(Date.parse(at)<Date.parse(requestedAt)||Date.parse(at)>Date.parse(resolvedAt))error('entry outside approval window');
  if(entry.approver_kind!=='llm_advisory'){
   if(entry.decision!=='allow')error('denied chain cannot yield authority');
   if(/^(unknown|unverified|none)$/i.test(entry.identity_assurance))error('approver identity assurance is unresolved');
   terminalEntries++;
  }
  return {...entry,decided_at:at};
 });
 if(!terminalEntries)error('advisory entries cannot authorize execution');
 same(hash(resolution.final_entry_digest,'resolution.final_entry_digest'),previous,'final chain link');

 const assurance={adapter:'agt-approval-v1',upstreamCommit:AGT_APPROVAL_COMMIT,
  source:'external_collector_report',contextBinding:'matched_to_collector_configuration',
  signatureVerified:false,chainHashesVerified:false,approverIdentityVerified:false,
  executionVerified:false};
 const note=JSON.stringify({agtRequestId:request.approval_request_id,agtResolutionId:resolution.approval_resolution_id,
  actionDigest:request.action_digest,approvalChainVersion:request.approval_chain_version,...assurance});
 const common={...context,...scope,scope:{...scope},policyVersion:request.policy_version,
  validFrom:resolvedAt,validUntil:until,clockUncertaintyMs:clock,note};
 const grant={...common,id:eventId(collector,request,'grant'),kind:'grant',occurredAt:resolvedAt,status:'collector_reported_allow'};
 const reviews=entries.map(entry=>({...common,id:eventId(collector,request,'review',entry.chain_entry_id),
  kind:entry.approver_kind==='human'?'human_approval':'automated_review',
  occurredAt:entry.decided_at,status:entry.approver_kind==='llm_advisory'?`advisory_${entry.decision}`:'collector_reported_allow',
  ...(entry.approver_kind==='human'?{reviewer:entry.approver_identity}:{}),
  note:JSON.stringify({agtEntryId:entry.chain_entry_id,approverKind:entry.approver_kind,
   reportedIdentityAssurance:entry.identity_assurance,...assurance})}));
 let events=[grant,...reviews];
 if(receipt.lifecycle!==undefined){
  const lifecycle=object(receipt.lifecycle,'lifecycle');
  if(!['cancelled','revoked'].includes(lifecycle.kind))error('unsupported lifecycle record');
  const at=date(lifecycle.occurredAt);
  if(Date.parse(at)<Date.parse(resolvedAt))error('revocation precedes resolved approval');
  events=events.map(event=>({...common,id:eventId(collector,request,'revoke',event.id),kind:'revoke',
   authorityId:event.id,occurredAt:at,status:lifecycle.kind}));
 }else if(request.status==='cancelled')error('cancelled request requires collector lifecycle timestamp');
 // Reuse the ingestion contract without returning its server-owned fields.
 for(const event of events)validateEvent(event,collector);
 return {events,assurance};
}
