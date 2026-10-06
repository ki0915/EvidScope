import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {modelRuntimeManifest} from './render.mjs';
const ns='evidscope-models',label='evidscope.io/managed=true,evidscope.io/component=isolated-model';
const image=value=>/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(value||'');
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function command(args,input){return new Promise((resolve,reject)=>{const child=spawn('kubectl',['--namespace',ns,'--request-timeout=5s',...args],{windowsHide:true,stdio:['pipe','pipe','pipe'],shell:false});let stdout='',size=0;const timer=setTimeout(()=>{child.kill();reject(Error('kubernetes_request_timeout'));},7000);child.stdout.on('data',b=>{size+=b.length;if(size>1048576){child.kill();reject(Error('kubernetes_response_limit'));}else stdout+=b;});child.stderr.resume();child.on('error',()=>{clearTimeout(timer);reject(Error('kubernetes_unavailable'));});child.on('close',code=>{clearTimeout(timer);if(code!==0)return reject(Error('kubernetes_request_failed'));try{resolve(stdout.trim()?JSON.parse(stdout):{});}catch{reject(Error('kubernetes_response_invalid'));}});child.stdin.end(input?JSON.stringify(input):undefined);});}
export function createKubectlModelAdapter({frontendImage,isolationManifestHash,execute=command}={}){
 if(!image(frontendImage))throw Error('frontend_image_digest_required');
 const leases=new Map(),leaseName='evidscope-model-execution';
 async function acquireLease(modelId,runId){
  const lease={apiVersion:'coordination.k8s.io/v1',kind:'Lease',metadata:{name:leaseName,namespace:ns,labels:{'evidscope.io/managed':'true'}},spec:{holderIdentity:`${modelId}:${runId}`,acquireTime:new Date().toISOString()}};
  let result;try{result=await execute(['create','-f','-','-o','json'],lease);}catch{throw Error('shared_execution_lease_unavailable');}
  if(!result.metadata?.uid||result.spec?.holderIdentity!==lease.spec.holderIdentity)throw Error('shared_execution_lease_unconfirmed');
  return {uid:result.metadata.uid,holderIdentity:lease.spec.holderIdentity};
 }
 async function releaseLease(record){
  const current=await execute(['get','lease',leaseName,'-o','json']);
  if(current.metadata?.uid!==record.uid||current.spec?.holderIdentity!==record.holderIdentity)throw Error('shared_execution_lease_mismatch');
  await execute(['delete','--raw',`/apis/coordination.k8s.io/v1/namespaces/${ns}/leases/${leaseName}`,'-f','-'],{apiVersion:'v1',kind:'DeleteOptions',preconditions:{uid:record.uid}});
 }
 function template(modelId,artifactLock){const job=modelRuntimeManifest().items.find(r=>r.kind==='Job'&&r.metadata.name===modelId);if(!job)throw Error('model_id_invalid');job.spec.template.spec.containers[0].image=artifactLock.image;job.spec.template.spec.containers[1].image=frontendImage;return job;}
 return {
  async create({modelId,runId,artifactLock}){
   const job=template(modelId,artifactLock);if(hash(job)!==isolationManifestHash)throw Error('measured_manifest_mismatch');
   const lease=await acquireLease(modelId,runId);job.metadata.name=`${modelId}-${runId}`;job.metadata.labels['evidscope.io/run']=runId;job.spec.template.metadata.labels['evidscope.io/run']=runId;job.metadata.annotations['evidscope.io/execution-lease-uid']=lease.uid;job.metadata.annotations['evidscope.io/execution-lease-holder']=lease.holderIdentity;job.metadata.annotations['evidscope.io/expires-at']=new Date(Date.now()+(modelId==='foundation-sec'?300:100)*1000).toISOString();job.spec.suspend=false;
   // Ambiguous create errors retain the exclusive lease. Never expire/take it over
   // while a model process may still exist; explicit orphan reconciliation is needed.
   let result;try{result=await execute(['create','-f','-','-o','json'],job);}catch{throw Error('workload_create_unconfirmed_lease_retained');}
   if(!result.metadata?.uid)throw Error('workload_create_unconfirmed_lease_retained');leases.set(result.metadata.uid,lease);return {name:result.metadata.name,uid:result.metadata.uid};
  },
  async observe({name,uid}){
   const jobs=await execute(['get','jobs','-l',label,'-o','json']);const job=jobs.items?.find(j=>j.metadata?.name===name);if(job&&job.metadata.uid!==uid)throw Error('workload_uid_mismatch');
   if(job&&!leases.has(uid)&&job.metadata.annotations?.['evidscope.io/execution-lease-uid'])leases.set(uid,{uid:job.metadata.annotations['evidscope.io/execution-lease-uid'],holderIdentity:job.metadata.annotations['evidscope.io/execution-lease-holder']});
   const pods=await execute(['get','pods','-l',`job-name=${name}`,'-o','json']);const own=(pods.items||[]).filter(p=>p.metadata.ownerReferences?.some(o=>o.uid===uid));const statuses=own.flatMap(p=>p.status?.containerStatuses||[]);const ready=!!job&&own.length===1&&statuses.length===2&&statuses.every(s=>s.ready&&s.state?.running)&&!job.metadata.deletionTimestamp;const allContainersTerminated=own.length>0&&statuses.length===own.length*2&&statuses.every(s=>s.state?.terminated);
   if((!job&&!own.length)||allContainersTerminated){const held=leases.get(uid);if(held){await releaseLease(held);leases.delete(uid);}if(!job&&!own.length)return {absent:true};}
   return {uid,phase:allContainersTerminated?(own.some(p=>p.status.phase==='Failed')?'Failed':'Succeeded'):ready?'Running':'Pending',ready,allContainersTerminated};
  },
  async delete({name,uid}){if(!/^[a-z0-9-]+$/.test(name)||typeof uid!=='string')throw Error('workload_identity_invalid');return execute(['delete','--raw',`/apis/batch/v1/namespaces/${ns}/jobs/${name}`,'-f','-'],{apiVersion:'v1',kind:'DeleteOptions',propagationPolicy:'Foreground',gracePeriodSeconds:5,preconditions:{uid}});},
  async list(){const result=await execute(['get','jobs','-l',label,'-o','json']);return (result.items||[]).map(j=>({modelId:j.metadata.labels?.['evidscope.io/model'],runId:j.metadata.labels?.['evidscope.io/run'],name:j.metadata.name,uid:j.metadata.uid,expiresAt:j.metadata.annotations?.['evidscope.io/expires-at']}));},
  manifestHash(modelId,lock){return hash(template(modelId,lock));},
  sharedLease:{namespace:ns,name:leaseName,automaticTakeover:false}
 };
}
