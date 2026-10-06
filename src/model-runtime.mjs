import {modelPolicy} from './model-policy.mjs';
const ids=new Set(['foundation-sec','cipherguard']);
const SHA=/^[a-f0-9]{64}$/;
const REV=/^[a-f0-9]{40}$/;
const IMAGE=/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/;
const checks=['defaultDenyEgress','crossNamespaceDenied','serviceAccountUnavailable','hostFilesystemUnavailable','tlsPeerVerified','processExitObserved'];
function id(value){if(!ids.has(value))throw Error('model_id_invalid');return value;}
function recent(value,now,maxAge=300000){const t=Date.parse(value);return Number.isFinite(t)&&t<=now&&now-t<=maxAge;}
export function validateArtifactLock(lock){const errors=[];if(!lock||!ids.has(lock.modelId))errors.push('model_id');if(!REV.test(lock?.revision||''))errors.push('revision');if(!SHA.test(lock?.sha256||''))errors.push('artifact_sha256');if(!IMAGE.test(lock?.image||''))errors.push('image_digest');if(lock?.licenseReviewed!==true)errors.push('license_review');if(!Array.isArray(lock?.files)||!lock.files.length||lock.files.some(f=>!f||typeof f.path!=='string'||!f.path||f.path.startsWith('/')||f.path.includes('..')||f.path.includes('\\')||!SHA.test(f.sha256||'')))errors.push('file_manifest');return {valid:errors.length===0,errors};}
export function modelRuntimeStatus({receipt,now=Date.now()}={}){
 const observed=receipt?.schemaVersion===1&&receipt?.source==='kubernetes_api'&&recent(receipt.observedAt,now,30000)&&Array.isArray(receipt.models);
 return {schemaVersion:1,enabledByDefault:false,cloudAllowed:false,hostInferenceAllowed:false,observationStatus:observed?'observed':'unavailable',isolationClaim:'requires current measured isolation checks; Kubernetes state is not hardware attestation',models:[modelPolicy.primary,modelPolicy.cipher].map(p=>{
  const r=observed?receipt.models.find(v=>v.id===p.id):null;const phase=r&&['Pending','Running','Succeeded','Failed','Absent'].includes(r.phase)?r.phase:null;
  const containerReady=phase==='Running'&&r?.ready===true;
  return {id:p.id,model:p.model,declaredEnabled:false,state:phase==='Absent'?'stopped':containerReady?'running':phase==='Pending'?'starting':phase==='Running'?'unready':['Succeeded','Failed'].includes(phase)?'terminated':'unavailable',observedAt:observed?receipt.observedAt:null,workloadUid:typeof r?.uid==='string'?r.uid:null,terminationConfirmed:phase==='Absent'||(['Succeeded','Failed'].includes(phase)&&r?.allContainersTerminated===true),isolationVerified:false,limits:{cpu:p.cpu,memory:p.memory,concurrency:p.concurrency,timeoutSeconds:p.timeoutSeconds,contextTokens:p.contextTokens},revision:p.revision};
 })};
}

// The adapter is a trusted control-plane capability. Model containers never get it.
// A delete request is not proof of termination: observe absence/terminated containers.
export function createModelRuntime({adapter,clock=()=>Date.now()}={}){
 if(!adapter||['create','observe','delete','list'].some(k=>typeof adapter[k]!=='function'))throw Error('runtime_adapter_required');
 const active=new Map(),pending=new Set();
 async function start({modelId,runId,artifactLock,isolationReceipt}={}){
  id(modelId);if(!/^[a-z0-9][a-z0-9-]{0,48}$/.test(runId||''))throw Error('run_id_invalid');if(active.has(modelId)||pending.has(modelId))throw Error('model_concurrency_limit');
  if(!validateArtifactLock(artifactLock).valid||artifactLock.modelId!==modelId)throw Error('artifact_lock_incomplete');
  if(isolationReceipt?.source!=='measured_cluster_probe'||!recent(isolationReceipt.observedAt,clock())||checks.some(k=>isolationReceipt.checks?.[k]!==true)||!SHA.test(isolationReceipt.manifestHash||''))throw Error('isolation_not_verified');
  if(typeof adapter.manifestHash==='function'&&adapter.manifestHash(modelId,artifactLock)!==isolationReceipt.manifestHash)throw Error('isolation_manifest_mismatch');
  pending.add(modelId);let created;
  try{created=await adapter.create({modelId,runId,artifactLock});if(!created?.uid||!created?.name)throw Error('creation_unconfirmed');const record={modelId,runId,uid:created.uid,name:created.name,deadline:clock()+(modelId==='foundation-sec'?180:90)*1000,stopRequested:false};active.set(modelId,record);return await observe(modelId);}
  catch(error){if(created?.uid&&created?.name){if(!active.has(modelId))active.set(modelId,{modelId,runId,uid:created.uid,name:created.name,deadline:clock(),stopRequested:true});try{await stop(modelId,'failed');}catch{}}throw error;}
  finally{pending.delete(modelId);}
 }
 async function observe(modelId){id(modelId);const r=active.get(modelId);if(!r)return {modelId,state:'unavailable',terminationConfirmed:false};let o;try{o=await adapter.observe({name:r.name,uid:r.uid});}catch{return {...r,state:'unavailable',terminationConfirmed:false};}if(o?.uid&&o.uid!==r.uid)throw Error('workload_uid_mismatch');const gone=o?.absent===true,terminated=o?.allContainersTerminated===true&&['Succeeded','Failed'].includes(o.phase);if(gone||terminated){active.delete(modelId);return {...r,state:'terminated',terminationConfirmed:true,observedAt:new Date(clock()).toISOString()};}return {...r,state:r.stopRequested?'stopping':o?.phase==='Running'&&o.ready===true?'running':'starting',terminationConfirmed:false,observedAt:new Date(clock()).toISOString()};}
 async function stop(modelId,reason='cancelled'){id(modelId);if(!['completed','failed','cancelled','timeout','orphaned'].includes(reason))throw Error('termination_reason_invalid');const r=active.get(modelId);if(!r)return {modelId,state:'unavailable',terminationConfirmed:false};r.stopRequested=true;r.stopReason=reason;try{await adapter.delete({name:r.name,uid:r.uid});}catch{return {...r,state:'stopping',terminationConfirmed:false,errorCode:'delete_unconfirmed'};}return observe(modelId);}
 async function reconcile({liveRunIds=[]}={}){const live=new Set(liveRunIds),results=[];for(const r of await adapter.list()){if(!ids.has(r.modelId)||!r.uid||!r.name)continue;if(!live.has(r.runId)||(Date.parse(r.expiresAt)||0)<=clock()){try{await adapter.delete({name:r.name,uid:r.uid});const observed=await adapter.observe({name:r.name,uid:r.uid});results.push({modelId:r.modelId,uid:r.uid,state:observed?.absent?'terminated':'stopping',terminationConfirmed:observed?.absent===true});if(observed?.absent&&active.get(r.modelId)?.uid===r.uid)active.delete(r.modelId);}catch{results.push({modelId:r.modelId,uid:r.uid,state:'stopping',terminationConfirmed:false});}continue;}if(!active.has(r.modelId))active.set(r.modelId,{modelId:r.modelId,runId:r.runId,uid:r.uid,name:r.name,deadline:Date.parse(r.expiresAt)||0,stopRequested:false});}for(const [modelId,r] of [...active])results.push(!live.has(r.runId)?await stop(modelId,'orphaned'):clock()>=r.deadline?await stop(modelId,'timeout'):await observe(modelId));return results;}
 return {start,observe,stop,reconcile};
}

export async function withModelSession(runtime,options,work,{signal,onReceipt=()=>{},wait=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
 let started=false,reason='failed',requestTimer;
 try{
  let receipt=await runtime.start(options);started=true;onReceipt(receipt);
  while(receipt.state!=='running'){if(signal?.aborted){reason='cancelled';throw Error('model_session_cancelled');}if(receipt.terminationConfirmed||receipt.deadline<=Date.now())throw Error('model_start_deadline');await wait(250);receipt=await runtime.observe(options.modelId);onReceipt(receipt);}
  const controller=new AbortController(),combined=signal?AbortSignal.any([signal,controller.signal]):controller.signal;
  const timeout=new Promise((_,reject)=>{requestTimer=setTimeout(()=>{reason='timeout';controller.abort();reject(Error('model_request_deadline'));},(options.modelId==='foundation-sec'?120:10)*1000);});
  const cancelled=new Promise((_,reject)=>{if(combined.aborted)reject(Error('model_session_cancelled'));else combined.addEventListener('abort',()=>reject(Error('model_session_cancelled')),{once:true});});
  const result=await Promise.race([Promise.resolve().then(()=>work({signal:combined})),timeout,cancelled]);reason='completed';return result;
 }catch(error){if(signal?.aborted)reason='cancelled';throw error;}
 finally{clearTimeout(requestTimer);if(started){let receipt=await runtime.stop(options.modelId,reason);onReceipt(receipt);for(let attempt=0;!receipt.terminationConfirmed&&attempt<40;attempt++){await wait(250);receipt=await runtime.observe(options.modelId);onReceipt(receipt);}if(!receipt.terminationConfirmed)throw Error('MODEL_STOP_UNCONFIRMED');}}
}
