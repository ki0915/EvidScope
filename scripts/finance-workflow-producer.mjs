import {digest} from '../src/crypto.mjs';
import {submit} from '../src/client.mjs';

// Three local synthetic roles. Only fixture requests/configuration arrive over IPC;
// each process constructs its own events and submits them directly over HTTP.
let settings,stopping=false;
const states=new Map(),receipts=[];
const roles=new Set(['approval','ai','business']);
const required=(condition,message)=>{if(!condition)throw Error(message);};
const at=offset=>new Date(settings.clockEpochMs+offset).toISOString();
const scope=request=>({actor:`credit-actor-${request.caseId}`,tool:'synthetic-credit-service',action:'score',resource:request.applicationId,destination:'internal'});
const context=request=>({systemId:request.systemId,actionId:request.actionId,traceId:request.traceId,requestId:request.requestId,attemptId:request.attemptId,modelId:request.modelId,modelVersion:request.modelVersion,policyVersion:request.policyVersion,...scope(request),clockUncertaintyMs:0});
const event=(request,kind,suffix,offset,extra={})=>({id:`${request.caseId}-${suffix}`,kind,occurredAt:at(offset),...context(request),...extra});
function requestChecked(request){
 required(request&&typeof request==='object'&&!Array.isArray(request),'Request configuration required');
 required(!('kind'in request)&&!('occurredAt'in request)&&!('events'in request),'Completed event payloads are not accepted');
 for(const field of ['caseId','systemId','actionId','traceId','requestId','attemptId','modelId','modelVersion','policyVersion','applicationId'])required(typeof request[field]==='string'&&request[field].length>0,`Request ${field} required`);
 return request;
}
function publicState(){return [...states.entries()].map(([caseId,state])=>({caseId,...state.summary})).sort((a,b)=>a.caseId.localeCompare(b.caseId));}
async function publish(principal,raw,{invalidSignature=false,expectedStatus=202}={}){
 const response=await submit(settings.ingress,principal,raw,{timeoutMs:10000,...(invalidSignature?{signature:'0'.repeat(64)}:{})});
 const receipt={role:settings.role,pid:process.pid,source:principal.id,tenant:principal.tenant,ref:`${principal.id}/${raw.id}`,event:raw,status:response.status,accepted:response.body.accepted===true,duplicate:response.body.duplicate===true};
 receipts.push(receipt);
 required(response.status===expectedStatus,`Producer ${settings.role} HTTP ${response.status}; expected ${expectedStatus}`);
 return receipt;
}
async function operate(operation,payload={}){
 if(operation==='initialize'){
  required(!settings,'Producer already initialized');required(roles.has(payload.role),'Unknown producer role');
  required(Number.isSafeInteger(payload.clockEpochMs),'Synthetic clock epoch required');
  const origin=new URL(payload.ingress);required(origin.protocol==='http:'&&['127.0.0.1','[::1]'].includes(origin.hostname)&&origin.pathname==='/'&&!origin.search&&!origin.hash&&!origin.username&&!origin.password,'Numeric loopback ingress required');
  for(const principal of Object.values(payload.principals||{}))required(principal.role==='source'&&typeof principal.token==='string'&&typeof principal.hmacSecret==='string','Source credential required');
  if(payload.role==='approval')required(payload.principals.authority?.kind==='authority'&&payload.principals.safety?.kind==='safety','Authority and synthetic control sources required');
  else required(payload.principals.tool?.kind==='tool','Tool source required');
  if(payload.principals.foreignTool)required(payload.role==='business'&&payload.principals.foreignTool.kind==='tool'&&payload.principals.foreignTool.tenant!==payload.principals.tool.tenant,'Separate business tenant required');
  settings=payload;
  return {role:settings.role,pid:process.pid,sourceIds:Object.values(settings.principals).map(principal=>principal.id)};
 }
 required(settings,'Producer not initialized');
 if(operation==='state')return {role:settings.role,pid:process.pid,state:publicState(),stateSha256:digest(publicState()),receipts:[...receipts]};
 if(operation==='shutdown'){stopping=true;return {role:settings.role,pid:process.pid,stateSha256:digest(publicState())};}
 const request=requestChecked(payload.request),start=receipts.length;
 if(settings.role==='approval'){
  if(operation==='prepare'){
   required(!states.has(request.caseId),'Approval fixture case already prepared');
   const delayed=request.scenario==='delayed-approval',automatic=request.scenario==='automatic';
   const approvalRequest={...request,...(request.scenario==='wrong-attempt'?{attemptId:'attempt-other'}:{}),...(request.scenario==='wrong-model'?{modelId:'other-credit-model'}:{})};
   const validity={validFrom:at(-700000),validUntil:at(600000)};
   const grant=event(request,'grant','grant',delayed?-610000:-10000,{scope:scope(request),...validity});
   const approval=automatic?null:event(approvalRequest,'human_approval','approval',delayed?-600000:-9000,{scope:scope(approvalRequest),reviewer:'synthetic-reviewer',...validity});
   states.set(request.caseId,{request,grant,approval,summary:{decision:automatic?'automatic_without_per_action_approval':'synthetic_approval_recorded',approvalState:automatic?'not_required':delayed?'pending_delivery':'approved',grantRef:`${settings.principals.authority.id}/${grant.id}`,approvalRef:approval?`${settings.principals.authority.id}/${approval.id}`:null,approvalAttemptId:approvalRequest.attemptId,approvalModelId:approvalRequest.modelId,blockRecorded:false}});
   await publish(settings.principals.authority,grant);
   if(approval&&!delayed)await publish(settings.principals.authority,approval);
  }else{
   const state=states.get(request.caseId);required(state,'Approval case not prepared');
   if(operation==='revoke'){
    required(state.summary.approvalState==='approved','Only an approved synthetic case may be revoked');
    await publish(settings.principals.authority,event(state.request,'revoke','revoke',-5000,{authorityId:state.grant.id}));state.summary.approvalState='revoked';
   }else if(operation==='block'){
    await publish(settings.principals.safety,event(state.request,'block_registered','block',-1000,{note:'Synthetic control fixture reports a block; downstream continuation is deliberately injected.'}));state.summary.blockRecorded=true;
   }else if(operation==='deliver-approval'){
    required(state.summary.approvalState==='pending_delivery'&&state.approval,'No pending approval');
    await publish(settings.principals.authority,state.approval);state.summary.approvalState='approved';
   }else throw Error('Unsupported approval operation');
  }
  return {role:settings.role,pid:process.pid,receipts:receipts.slice(start),state:{...states.get(request.caseId).summary},stateSha256:digest(states.get(request.caseId).summary)};
 }
 if(settings.role==='ai'){
  required(operation==='execute','Unsupported AI operation');required(!states.has(request.caseId),'AI request already processed');
  if(request.scenario==='missing-evidence'){
   const summary={execution:'not_observed',applicationId:request.applicationId};states.set(request.caseId,{summary});return {role:settings.role,pid:process.pid,receipts:[],decision:null,state:summary,stateSha256:digest(summary)};
  }
  const features=request.features;required(Number.isSafeInteger(features?.incomeUnits)&&Number.isSafeInteger(features?.arrears),'Bounded synthetic features required');
  const score=Math.max(0,Math.min(100,50+Math.min(50,features.incomeUnits)-features.arrears*10));
  const decision={applicationId:request.applicationId,requestId:request.requestId,attemptId:request.attemptId,modelId:request.modelId,modelVersion:request.modelVersion,score};
  const summary={execution:'computed',decision,decisionSha256:digest(decision)};states.set(request.caseId,{summary});
  await publish(settings.principals.tool,event(request,'execution','ai-execution',0,{dataRefs:[{id:`decision-${request.caseId}`,kind:'record',role:'output',version:request.modelVersion,hash:digest(decision)}]}),request.scenario==='authentication-failure'?{invalidSignature:true,expectedStatus:401}:{});
  if(request.scenario==='authentication-failure')summary.execution='computed_but_collection_rejected';
  return {role:settings.role,pid:process.pid,receipts:receipts.slice(start),decision,state:{...summary},stateSha256:digest(summary)};
 }
 required(settings.role==='business'&&operation==='apply','Unsupported business operation');required(!states.has(request.caseId),'Business request already applied');
 const decision=payload.decision;
 if(!decision){const summary={processing:'not_observed',applicationId:request.applicationId};states.set(request.caseId,{summary});return {role:settings.role,pid:process.pid,receipts:[],state:summary,stateSha256:digest(summary)};}
 for(const field of ['applicationId','requestId','attemptId','modelId','modelVersion'])required(decision[field]===request[field],`AI/business ${field} mismatch`);
 required(Number.isInteger(decision.score)&&decision.score>=0&&decision.score<=100,'Synthetic score required');
 // This process owns the application map and derives its committed result from
 // actual AI output. Processing success is separate from the credit decision.
 const summary={processing:'committed',applicationId:request.applicationId,requestId:request.requestId,attemptId:request.attemptId,creditDecision:decision.score>=70?'approve':'decline',score:decision.score,decisionSha256:digest(decision)};
 states.set(request.caseId,{summary});
 const principal=request.scenario==='foreign-tenant'?settings.principals.foreignTool:settings.principals.tool;required(principal,'Business source unavailable');
 await publish(principal,event(request,'result','business-result',1000,{status:'success',dataRefs:[{id:`business-${request.caseId}`,kind:'record',role:'output',version:'synthetic-business-v1',hash:digest(summary)}],note:'Synthetic application state committed; this is processing success, not a legal or loan approval verdict.'}));
 return {role:settings.role,pid:process.pid,receipts:receipts.slice(start),state:{...summary},stateSha256:digest(summary)};
}

let queue=Promise.resolve();
process.on('message',message=>{
 queue=queue.then(async()=>{
  if(!message||typeof message.rpcId!=='string')return;
  try{
   const result=await operate(message.operation,message.payload);
   await new Promise((resolve,reject)=>process.send({rpcId:message.rpcId,ok:true,result},error=>error?reject(error):resolve()));
   if(stopping&&process.connected)process.disconnect();
  }catch(error){
   // No credentials, request headers or configuration are returned on failure.
   if(process.connected)process.send({rpcId:message.rpcId,ok:false,error:{name:error.name,message:error.message,code:error.cause?.code||error.code||null}});
  }
 }).catch(()=>{process.exitCode=1;if(process.connected)process.disconnect();});
});
process.once('disconnect',()=>{stopping=true;});
