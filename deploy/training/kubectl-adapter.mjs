import {spawn} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {trainingManifest} from './render.mjs';

const namespace='evidscope-training',leaseNamespace='evidscope-models',leaseName='evidscope-model-execution';
const sha=value=>createHash('sha256').update(value).digest('hex');
const digest=value=>/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(value||'');
const dns=value=>typeof value==='string'&&value.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(value);

// No shell, downloads, context changes, or cluster bootstrap. Every call has
// both a Kubernetes request deadline and a local subprocess deadline.
export function createBoundedKubectl(context,{spawnProcess=spawn}={}){
 if(typeof context!=='string'||!context.trim()||context.length>200||/[\x00-\x1f]/.test(context))throw Error('training_context_required');
 return (args,input,{namespace:targetNamespace=namespace}={})=>new Promise((resolve,reject)=>{
  let settled=false,stdout='',size=0,timer;
  const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):resolve(value);};
  const child=spawnProcess('kubectl',['--context',context,'--namespace',targetNamespace,'--request-timeout=5s',...args],{windowsHide:true,stdio:['pipe','pipe','pipe'],shell:false});
  timer=setTimeout(()=>{child.kill();finish(Error('training_kubernetes_timeout'));},7000);
  child.stdout.on('data',chunk=>{size+=chunk.length;if(size>1048576){child.kill();finish(Error('training_kubernetes_response_limit'));}else stdout+=chunk;});
  child.stderr.resume();
  child.stdin.on('error',()=>{});
  child.on('error',()=>finish(Error('training_kubernetes_unavailable')));
  child.on('close',code=>{if(code!==0)return finish(Error('training_kubernetes_request_failed'));try{finish(null,stdout.trim()?JSON.parse(stdout):{});}catch{finish(Error('training_kubernetes_response_invalid'));}});
  child.stdin.end(input===undefined?undefined:JSON.stringify(input));
 });
}

export function boundTrainingTemplate(config){
 if(!digest(config?.image)||!dns(config.nodeName)||!config.artifactLock||!/^[a-f0-9]{64}$/.test(config.datasetSha256||''))throw Error('training_template_configuration_invalid');
 const job=trainingManifest().items.find(item=>item.kind==='Job');
 const pod=job.spec.template.spec,container=pod.containers[0];
 pod.nodeName=config.nodeName;container.image=config.image;
 const revisionIndex=container.args.indexOf('--base-revision');
 if(revisionIndex<0)throw Error('training_template_revision_argument_missing');
 container.args[revisionIndex+1]=config.baseRevision;
 container.env.push(...Object.entries({EVIDSCOPE_DATASET_SHA256:config.datasetSha256,EVIDSCOPE_BASE_REPOSITORY:config.baseRepository,EVIDSCOPE_BASE_REVISION:config.baseRevision,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:sha(JSON.stringify(config.artifactLock)),EVIDSCOPE_TRAINING_IMAGE:config.image}).map(([name,value])=>({name,value})));
 if(config.resumeCheckpoint){if(!/^\/checkpoints\/runs\/[a-f0-9]{32}\/checkpoint-[1-9][0-9]*$/.test(config.resumeCheckpoint))throw Error('training_resume_path_invalid');container.args.push('--resume-from-checkpoint',config.resumeCheckpoint);}
 job.metadata.labels={'evidscope.io/managed':'true','evidscope.io/component':'isolated-training'};
 job.spec.template.metadata.labels={...job.metadata.labels};
 return job;
}

export const trainingTemplateHash=config=>sha(JSON.stringify(boundTrainingTemplate(config)));

export function createKubectlTrainingAdapter(config,{execute=createBoundedKubectl(config.context),beforeCreate,newRunId=()=>randomUUID().replaceAll('-',''),wait=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
 if(typeof beforeCreate!=='function')throw Error('training_fresh_host_guard_required');
 const template=boundTrainingTemplate(config),templateHash=sha(JSON.stringify(template));
 if(templateHash!==config.measuredIsolationReceipt?.manifestHash)throw Error('training_isolation_manifest_mismatch');
 const owned=new Map();
 async function get(kind,name,ns=namespace){return execute(['get',kind,name,'--ignore-not-found=true','-o','json'],undefined,{namespace:ns});}
 function validateLease(lease,record){if(lease.metadata?.uid!==record.leaseUid||lease.spec?.holderIdentity!==record.holder)throw Error('training_lease_identity_mismatch');}
 function validateJob(job,record){
  if(job.metadata?.name!==record.name||job.metadata?.namespace!==namespace||job.metadata.labels?.['evidscope.io/run']!==record.runId||job.metadata.annotations?.['evidscope.io/execution-lease-uid']!==record.leaseUid||job.metadata.annotations?.['evidscope.io/execution-lease-holder']!==record.holder||!job.metadata.uid||(record.uid&&record.uid!==job.metadata.uid))throw Error('training_workload_identity_mismatch');
 }
 function identity(workload){const record=owned.get(workload?.uid);if(!record||record.name!==workload.name)throw Error('training_owned_workload_required');return record;}
 async function quarantine(record){
  record.quarantined=true;
  try{await execute(['patch','lease',leaseName,'--type=json','--patch-file=-','-o','json'],[{op:'test',path:'/metadata/uid',value:record.leaseUid},{op:'test',path:'/spec/holderIdentity',value:record.holder},{op:'add',path:'/metadata/annotations/evidscope.io~1execution-state',value:'quarantined'}],{namespace:leaseNamespace});}catch{}
 }
 async function release(record){
  if(record.quarantined)return;
  const current=await get('lease',leaseName,leaseNamespace);
  if(!current.metadata?.uid){if(record.releaseAttempted){record.released=true;return;}throw Error('training_lease_disappeared');}
  if(record.releaseAttempted&&current.metadata.uid!==record.leaseUid){record.released=true;return;}
  validateLease(current,record);record.releaseAttempted=true;
  await execute(['delete','--raw',`/apis/coordination.k8s.io/v1/namespaces/${leaseNamespace}/leases/${leaseName}`,'-f','-'],{apiVersion:'v1',kind:'DeleteOptions',preconditions:{uid:record.leaseUid}},{namespace:leaseNamespace});
  const after=await get('lease',leaseName,leaseNamespace);
  if(after.metadata?.uid===record.leaseUid)throw Error('training_lease_release_unconfirmed');
  record.released=true;
 }
 async function recoverCreate(record){
  await quarantine(record);
  const error=Error('training_create_ambiguous_lease_quarantined');
  error.leaseRetained=true;error.terminationConfirmed=false;error.recovery={context:config.context,namespace,name:record.name,runId:record.runId,leaseUid:record.leaseUid};
  try{const job=await get('job',record.name);if(job.metadata?.uid){validateJob(job,record);record.uid=job.metadata.uid;owned.set(record.uid,record);error.workload={name:record.name,uid:record.uid};}}catch{}
  // Even a successful immediate absence observation cannot prove a timed-out
  // create will never commit later. The exclusive lease is kept quarantined.
  throw error;
 }
 return {
  sharedLease:{namespace:leaseNamespace,name:leaseName,automaticTakeover:false},
  manifestHash:()=>templateHash,
  async start({signal}={}){
   if(signal?.aborted)throw Error('training_cancelled_before_start');
   const runId=newRunId();if(!/^[a-f0-9]{32}$/.test(runId))throw Error('training_run_identity_invalid');
   const name=`foundation-qlora-${runId}`,holder=`training:${runId}`,record={runId,name,holder,quarantined:false};
   const lease={apiVersion:'coordination.k8s.io/v1',kind:'Lease',metadata:{name:leaseName,namespace:leaseNamespace,labels:{'evidscope.io/managed':'true'},annotations:{'evidscope.io/execution-state':'reserved','evidscope.io/training-job':name,'evidscope.io/training-namespace':namespace}},spec:{holderIdentity:holder,acquireTime:new Date().toISOString()}};
   let acquired;
   try{acquired=await execute(['create','-f','-','-o','json'],lease,{namespace:leaseNamespace});}catch{
    const error=Error('training_shared_execution_lease_unavailable');
    try{const current=await get('lease',leaseName,leaseNamespace);if(current.spec?.holderIdentity===holder&&current.metadata?.uid){record.leaseUid=current.metadata.uid;await quarantine(record);error.leaseRetained=true;error.recovery={context:config.context,namespace,name,runId,leaseUid:record.leaseUid};}}catch{}
    throw error;
   }
   if(!acquired.metadata?.uid||acquired.spec?.holderIdentity!==holder)throw Error('training_shared_execution_lease_unconfirmed');
   record.leaseUid=acquired.metadata.uid;
   // Cancellation after the reservation but before create cannot leave a Job.
   try{if(signal?.aborted)throw Error('training_cancelled_before_create');await beforeCreate();if(signal?.aborted)throw Error('training_cancelled_before_create');}catch(error){await release(record);throw error;}
   const job=structuredClone(template);job.metadata.name=name;
   const container=job.spec.template.spec.containers[0];container.args[container.args.indexOf('--output')+1]=`/checkpoints/runs/${runId}`;
   job.metadata.labels['evidscope.io/run']=runId;job.spec.template.metadata.labels['evidscope.io/run']=runId;
   job.metadata.annotations={...job.metadata.annotations,'evidscope.io/execution-lease-uid':record.leaseUid,'evidscope.io/execution-lease-holder':holder};
   job.spec.suspend=false;
   let created;try{created=await execute(['create','-f','-','-o','json'],job);}catch{return recoverCreate(record);}
   try{validateJob(created,record);}catch{return recoverCreate(record);}
   record.uid=created.metadata.uid;owned.set(record.uid,record);return {name,uid:record.uid};
  },
  async observe(workload){
   const record=identity(workload),job=await get('job',record.name);
   if(job.metadata?.uid)validateJob(job,record);
   const pods=await execute(['get','pods','-l',`evidscope.io/run=${record.runId}`,'-o','json']);
   if(!Array.isArray(pods.items))throw Error('training_pod_observation_invalid');
   if(pods.items.some(p=>!p.metadata?.ownerReferences?.some(owner=>owner.kind==='Job'&&owner.uid===record.uid&&owner.name===record.name)))throw Error('training_pod_identity_mismatch');
   if(!job.metadata?.uid&&pods.items.length===0){if(!record.released)await release(record);return {state:'absent',terminationConfirmed:true,leaseRetained:record.quarantined};}
   const conditions=job.status?.conditions||[];
   return {state:conditions.some(c=>c.type==='Failed'&&c.status==='True')?'failed':conditions.some(c=>c.type==='Complete'&&c.status==='True')?'succeeded':'running',terminationConfirmed:false};
  },
  async verifyArtifacts(workload){
   const record=identity(workload),job=await get('job',record.name);validateJob(job,record);
   if(!job.status?.conditions?.some(c=>c.type==='Complete'&&c.status==='True'))throw Error('training_not_complete');
   const verifier=structuredClone(template),name=`${record.name}-verify`,label=`${record.runId}-verify`,pod=verifier.spec.template.spec,container=pod.containers[0];
   verifier.metadata={name,namespace,labels:{'evidscope.io/run':label,'evidscope.io/component':'artifact-verifier'}};verifier.spec.template.metadata={labels:{...verifier.metadata.labels}};
   verifier.spec.suspend=false;verifier.spec.activeDeadlineSeconds=120;verifier.spec.ttlSecondsAfterFinished=300;
   container.command=['python','/app/training_artifacts.py'];container.args=[`/checkpoints/runs/${record.runId}/candidate`];container.terminationMessagePath='/tmp/artifact-verification.json';
   container.resources={requests:{cpu:'1',memory:'256Mi'},limits:{cpu:'1',memory:'256Mi'}};
   container.volumeMounts=container.volumeMounts.filter(v=>['checkpoints','temporary','podinfo'].includes(v.name)).map(v=>v.name==='checkpoints'?{...v,readOnly:true}:v);
   pod.volumes=pod.volumes.filter(v=>['checkpoints','temporary','podinfo'].includes(v.name));
   let created,verified;
   try{
    try{created=await execute(['create','-f','-','-o','json'],verifier);}catch{await quarantine(record);throw Error('artifact_verifier_create_ambiguous');}
    if(!created.metadata?.uid)throw Error('artifact_verifier_identity_missing');
    for(let attempt=0;attempt<60;attempt++){
     const current=await get('job',name);if(current.metadata?.uid!==created.metadata.uid)throw Error('artifact_verifier_identity_changed');
     const pods=await execute(['get','pods','-l',`evidscope.io/run=${label}`,'-o','json']);
     if(!Array.isArray(pods.items)||pods.items.some(p=>!p.metadata?.ownerReferences?.some(o=>o.uid===created.metadata.uid)))throw Error('artifact_verifier_pod_identity_mismatch');
     if(current.status?.conditions?.some(c=>c.type==='Failed'&&c.status==='True'))throw Error('candidate_verification_failed');
     if(current.status?.conditions?.some(c=>c.type==='Complete'&&c.status==='True')){
      if(pods.items.length!==1)throw Error('artifact_verifier_pod_missing');
      const exit=pods.items[0].status?.containerStatuses?.find(c=>c.name==='training')?.state?.terminated;
      if(exit?.exitCode!==0)throw Error('candidate_verifier_exit_invalid');
      try{verified=JSON.parse(exit.message);}catch{throw Error('candidate_verification_receipt_invalid');}
      if(verified?.verified!==true||!Number.isSafeInteger(verified.globalStep)||verified.globalStep<1||!Number.isSafeInteger(verified.fileCount)||verified.fileCount<3||!/^[a-f0-9]{64}$/.test(verified.artifactSha256||'')||verified.identity?.datasetSha256!==config.datasetSha256||verified.identity?.baseRevision!==config.baseRevision||verified.identity?.baseArtifactLockSha256!==sha(JSON.stringify(config.artifactLock))||verified.identity?.baseRepository!==config.baseRepository||verified.identity?.image!==config.image)throw Error('candidate_verification_binding_mismatch');
      return verified;
     }
     await wait(1000);
    }
    throw Error('artifact_verifier_timeout');
   }finally{
    if(created?.metadata?.uid){
     try{
      await execute(['delete','--raw',`/apis/batch/v1/namespaces/${namespace}/jobs/${name}`,'-f','-'],{apiVersion:'v1',kind:'DeleteOptions',propagationPolicy:'Foreground',gracePeriodSeconds:5,preconditions:{uid:created.metadata.uid}});
      let absent=false;
      for(let attempt=0;attempt<40;attempt++){const [remaining,pods]=await Promise.all([get('job',name),execute(['get','pods','-l',`evidscope.io/run=${label}`,'-o','json'])]);if(!remaining.metadata?.uid&&Array.isArray(pods.items)&&pods.items.length===0){absent=true;break;}await wait(1000);}
      if(!absent)throw Error('artifact_verifier_stop_unconfirmed');
     }catch{await quarantine(record);throw Error('artifact_verifier_stop_unconfirmed');}
    }
   }
  },
  async stop(workload){
   const record=identity(workload),job=await get('job',record.name);
   if(!job.metadata?.uid)return;
   validateJob(job,record);
   await execute(['delete','--raw',`/apis/batch/v1/namespaces/${namespace}/jobs/${record.name}`,'-f','-'],{apiVersion:'v1',kind:'DeleteOptions',propagationPolicy:'Foreground',gracePeriodSeconds:5,preconditions:{uid:record.uid}});
  }
 };
}
