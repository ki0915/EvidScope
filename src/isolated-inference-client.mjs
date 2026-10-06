import https from 'node:https';
import {readFileSync} from 'node:fs';
import {primaryModelPolicy} from './model-policy.mjs';

export const MODEL_ENDPOINTS=Object.freeze({primary:'foundation-sec.evidscope-models.svc.cluster.local',cipher:'cipherguard.evidscope-models.svc.cluster.local'});
const failure=code=>Object.assign(new Error(code),{code});
export function loadModelTlsConfig(path){
 try{const x=JSON.parse(readFileSync(path,'utf8'));if(Object.keys(x).some(k=>!['caFile','certFile','keyFile'].includes(k)))throw Error();return {ca:readFileSync(x.caFile),cert:readFileSync(x.certFile),key:readFileSync(x.keyFile)};}catch{throw failure('isolated_tls_configuration_invalid');}
}
function tlsOptions(tls){if(!tls||Object.keys(tls).some(k=>!['ca','cert','key'].includes(k))||['ca','cert','key'].some(k=>!(typeof tls[k]==='string'||Buffer.isBuffer(tls[k]))||!tls[k].length))throw failure('isolated_runtime_not_configured');return {ca:tls.ca,cert:tls.cert,key:tls.key,minVersion:'TLSv1.2',rejectUnauthorized:true};}

export function createModelTransport(tls){
 const options=tlsOptions(tls);
 return (model,path,payload,{signal,maxBytes=1024*1024}={})=>new Promise((resolve,reject)=>{
  const hostname=MODEL_ENDPOINTS[model];if(!hostname||!(model==='primary'?['/apply-template','/tokenize','/v1/chat/completions']:['/screen']).includes(path))return reject(failure('isolated_endpoint_not_allowed'));
  let body;try{body=JSON.stringify(payload);if(Buffer.byteLength(body)>1024*1024)throw Error();}catch{return reject(failure('isolated_request_limit'));}
  const request=https.request({hostname,servername:hostname,port:8443,path,method:'POST',...options,signal,agent:false,headers:{'content-type':'application/json','content-length':Buffer.byteLength(body)}},response=>{
   const chunks=[];let size=0;response.on('data',chunk=>{if((size+=chunk.length)>maxBytes){request.destroy(failure('isolated_response_limit'));return;}chunks.push(chunk);});
   response.on('error',()=>reject(failure(signal?.aborted?'isolated_request_aborted':'isolated_response_failed')));
   response.on('end',()=>{if(response.statusCode!==200)return reject(failure('isolated_service_unavailable'));try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch{reject(failure('isolated_response_invalid'));}});
  });
  request.setTimeout(model==='cipher'?10000:120000,()=>request.destroy(failure('isolated_request_timeout')));
  request.on('error',error=>reject(failure(signal?.aborted?'isolated_request_aborted':['isolated_request_timeout','isolated_response_limit'].includes(error.code)?error.code:'isolated_connection_failed')));request.end(body);
 });
}

export function createScreeningClient(tls){const transport=createModelTransport(tls);return (payload,{signal}={})=>transport('cipher','/screen',payload,{signal,maxBytes:16384});}

// Dependency injection is for deterministic transport tests, not a configurable URL.
export function createPrimaryInference(tls,{transport=createModelTransport(tls)}={}){
 const policy=primaryModelPolicy();let busy=false;
 return async ({messages,schema,signal}={})=>{
  if(busy)throw failure('model_concurrency_limit');
  if(!Array.isArray(messages)||messages.length!==2||messages.some((m,i)=>!m||m.role!==['system','user'][i]||typeof m.content!=='string'||Object.keys(m).some(k=>!['role','content'].includes(k))))throw failure('model_messages_invalid');
  if(Buffer.byteLength(JSON.stringify(messages))>policy.generation.maxPromptBytes)throw failure('prompt_budget_exceeded');
  busy=true;const started=performance.now(),deadline=AbortSignal.timeout(120000),combined=signal?AbortSignal.any([signal,deadline]):deadline;
  try{
   const rendered=await transport('primary','/apply-template',{messages},{signal:combined,maxBytes:128000});
   if(typeof rendered.prompt!=='string'||Buffer.byteLength(rendered.prompt)>128000)throw failure('model_template_invalid');
   const tokens=await transport('primary','/tokenize',{content:rendered.prompt,add_special:false,parse_special:true},{signal:combined,maxBytes:128000});
   if(!Array.isArray(tokens.tokens)||tokens.tokens.some(n=>!Number.isSafeInteger(n)||n<0))throw failure('model_tokenizer_invalid');
   if(tokens.tokens.length+policy.generation.numPredict>policy.generation.numCtx)throw failure('prompt_budget_exceeded');
   const response=await transport('primary','/v1/chat/completions',{model:policy.model,messages,stream:false,max_tokens:512,temperature:0.1,top_p:0.9,top_k:20,response_format:{type:'json_schema',schema},seed:0,cache_prompt:false},{signal:combined});
   if(response.model!==policy.model||response.choices?.length!==1||response.choices[0].message?.tool_calls||typeof response.choices[0].message?.content!=='string')throw failure('provider_model_or_output_mismatch');
   if(response.choices[0].finish_reason!=='stop')throw failure('model_output_incomplete');
   const usage=response.usage||{};if(!Number.isSafeInteger(usage.prompt_tokens)||!Number.isSafeInteger(usage.completion_tokens)||usage.prompt_tokens<0||usage.completion_tokens<0||usage.completion_tokens>512||usage.prompt_tokens+usage.completion_tokens>2048)throw failure('model_usage_invalid');
   return {content:response.choices[0].message.content,providerReport:{model:response.model,modelDigest:null,quantizationLevel:null,inputTokens:usage.prompt_tokens,outputTokens:usage.completion_tokens,totalDurationNs:Math.round((performance.now()-started)*1e6)}};
  }finally{busy=false;}
 };
}
