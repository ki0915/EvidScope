// Gateway side of the approval queue (docs/approval-queue.md): open a request, poll CIBA-style and act only on an answer that
// verifies offline with the vault public key. Every other outcome, including EvidScope being unreachable, is a refusal.
import {randomUUID} from 'node:crypto';
import {mac} from './crypto.mjs';
import {CIBA_GRANT_TYPE,verifyApprovalAnswer} from './approvals.mjs';

async function post(url,path,principal,body,{timeoutMs,signed}){
 const text=JSON.stringify(body),headers={'content-type':'application/json',authorization:`Bearer ${principal.token}`};
 if(signed){const timestamp=String(Date.now()),nonce=randomUUID();
  Object.assign(headers,{'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':mac(principal.hmacSecret,timestamp,nonce,text)});}
 const response=await fetch(new URL(path,url),{method:'POST',headers,body:text,signal:AbortSignal.timeout(timeoutMs),redirect:'error'});
 let value;try{value=await response.json();}catch{value={};}
 return {status:response.status,body:value};
}
// CIBA backchannel authentication request; HMAC-signed like /api/ingest.
export const requestApproval=(url,principal,request,{timeoutMs=2000}={})=>post(url,'/api/approvals/requests',principal,request,{timeoutMs,signed:true});
// CIBA token request in poll mode.
export const pollApproval=(url,principal,authReqId,{timeoutMs=2000}={})=>
 post(url,'/api/approvals/token',principal,{grant_type:CIBA_GRANT_TYPE,auth_req_id:authReqId},{timeoutMs,signed:false});

// Opens a request and polls until a final answer or the deadline. Returns {approved, reason, ...}; approved is true only for a
// verified approval of exactly this action and target inside its execution window. Fails closed on every error.
export async function awaitApproval({url,principal,publicKey,request,deadlineMs=15*60*1000,timeoutMs=2000,sleep=ms=>new Promise(r=>setTimeout(r,ms))}){
 const refuse=(reason,extra={})=>({approved:false,reason,...extra}),stop=Date.now()+deadlineMs;
 let opened;
 try{opened=await requestApproval(url,principal,request,{timeoutMs});}catch(error){return refuse('evidscope_unreachable',{detail:error.name});}
 if(opened.status!==200||typeof opened.body.auth_req_id!=='string')return refuse('request_refused',{status:opened.status,error:opened.body.error});
 const id=opened.body.auth_req_id;let interval=Math.max(1,Number(opened.body.interval)||5);
 while(Date.now()<stop){
  await sleep(interval*1000);
  let r;try{r=await pollApproval(url,principal,id,{timeoutMs});}catch(error){return refuse('evidscope_unreachable',{auth_req_id:id,detail:error.name});}
  if(r.status===400&&r.body.error==='authorization_pending')continue;
  if(r.status===400&&r.body.error==='slow_down'){interval=Math.max(interval+5,Number(r.body.interval)||0);continue;}
  if(r.status!==200)return refuse(r.body.error||`http_${r.status}`,{auth_req_id:id});
  try{
   const result=verifyApprovalAnswer({envelope:r.body.answer,publicKey,expected:{auth_req_id:id,actionId:request.actionId,decisionId:request.decisionId,
    target:request.target}});
   return result.approved?{approved:true,auth_req_id:id,answer:result.answer}:refuse('answer_not_applicable',{auth_req_id:id,reasons:result.reasons});
  }catch(error){return refuse('answer_not_verified',{auth_req_id:id,detail:error.message});}
 }
 return refuse('deadline',{auth_req_id:id});
}
