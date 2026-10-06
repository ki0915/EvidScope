import test from 'node:test';
import assert from 'node:assert/strict';
import {hostname,tmpdir} from 'node:os';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {createHash} from 'node:crypto';
import {createIdleTrainingGuard} from '../src/training-resource-guard.mjs';
import {validateTrainingRuntimeConfig,inspectTrainingDataset,inspectTrainingReadiness,createIsolatedTrainingSession} from '../src/isolated-training-session.mjs';
import {createBoundedKubectl,boundTrainingTemplate,trainingTemplateHash,createKubectlTrainingAdapter} from '../deploy/training/kubectl-adapter.mjs';
import {runTrainingCommand} from '../scripts/training-run.mjs';

const now=Date.parse('2026-09-19T08:00:00Z');
const receipt=(overrides={})=>({schemaVersion:1,source:'trusted_windows_host_probe',observedAt:new Date(now).toISOString(),idleSeconds:1200,cpuPercent:5,freeMemoryGiB:24,onAcPower:true,gpu:{memoryUsedMiB:500,memoryTotalMiB:12288,utilizationPercent:2,temperatureC:42,computeProcessCount:0},...overrides});
function config(){
 const value={schemaVersion:1,enabled:true,context:'explicit-local-context',nodeName:'approved-gpu-node',hostName:hostname(),image:`evidscope/qlora-training@sha256:${'a'.repeat(64)}`,baseRepository:'fdtn-ai/Foundation-Sec-8B-Reasoning',baseRevision:'63c930c82d7646226d33502bec5870019738400e',datasetSha256:'b'.repeat(64),sharedExecutionLease:{namespace:'evidscope-models',name:'evidscope-model-execution',automaticTakeover:false}};
 value.artifactLock={repository:value.baseRepository,revision:value.baseRevision,files:['config.json','tokenizer.json','tokenizer_config.json','model.safetensors.index.json','model-00001-of-00001.safetensors'].map(path=>({path,sha256:'c'.repeat(64)}))};
 value.measuredIsolationReceipt={source:'measured_cluster_probe',observedAt:new Date(now).toISOString(),context:value.context,nodeName:value.nodeName,hostName:value.hostName,namespace:'evidscope-training',manifestHash:trainingTemplateHash(value),checks:Object.fromEntries(['defaultDenyEgress','crossNamespaceDenied','serviceAccountUnavailable','hostFilesystemUnavailable','approvedVolumesOnly','processExitObserved','hostResourceProbeMatchesNode','gpuMemoryPilotPassed'].map(k=>[k,true]))};return value;
}
const admitted=()=>({datasetSha256:'b'.repeat(64),admission:{admitted:true,trainingRunAllowed:true,reasons:[]}});
function fakeCluster({ambiguousCreate=false,commitAmbiguous=true,keepPods=false,completed=false,onLease}={}){
 const state={lease:null,job:null,pods:[],verifier:null,verifierPods:[],calls:[]};
 const execute=async(args,input,options={})=>{
  state.calls.push({args,input:structuredClone(input),options});
  if(args[0]==='create'&&input.kind==='Lease'){if(state.lease)throw Error('already_exists');state.lease={...structuredClone(input),metadata:{...input.metadata,uid:'lease-uid'}};onLease?.();return structuredClone(state.lease);}
  if(args[0]==='create'&&input.kind==='Job'){
   if(input.metadata.name.endsWith('-verify')){const env=Object.fromEntries(input.spec.template.spec.containers[0].env.map(v=>[v.name,v.value]));state.verifier={...structuredClone(input),metadata:{...input.metadata,uid:'verify-uid'},status:{conditions:[{type:'Complete',status:'True'}]}};state.verifierPods=[{metadata:{ownerReferences:[{uid:'verify-uid'}]},status:{containerStatuses:[{name:'training',state:{terminated:{exitCode:0,message:JSON.stringify({schemaVersion:1,verified:true,artifactSha256:'f'.repeat(64),globalStep:19,fileCount:4,identity:{baseRepository:env.EVIDSCOPE_BASE_REPOSITORY,baseRevision:env.EVIDSCOPE_BASE_REVISION,baseArtifactLockSha256:env.EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256,datasetSha256:env.EVIDSCOPE_DATASET_SHA256,image:env.EVIDSCOPE_TRAINING_IMAGE}})}}}]}}];return structuredClone(state.verifier);}
   if(!ambiguousCreate||commitAmbiguous){state.job={...structuredClone(input),metadata:{...input.metadata,uid:'job-uid'},status:{conditions:completed?[{type:'Complete',status:'True'}]:[]}};state.pods=[{metadata:{name:'training-pod',ownerReferences:[{kind:'Job',uid:'job-uid',name:input.metadata.name}]}}];}
   if(ambiguousCreate)throw Error('request_timeout');return structuredClone(state.job);
  }
  if(args[0]==='get'&&args[1]==='job')return structuredClone((args[2].endsWith('-verify')?state.verifier:state.job)||{});
  if(args[0]==='get'&&args[1]==='lease')return structuredClone(state.lease||{});
  if(args[0]==='get'&&args[1]==='pods')return {items:structuredClone(args.some(a=>a.endsWith('-verify'))?state.verifierPods:state.pods)};
  if(args[0]==='delete'&&args[2].endsWith('-verify')){assert.equal(input.preconditions.uid,state.verifier?.metadata.uid);state.verifier=null;state.verifierPods=[];return {};}
  if(args[0]==='delete'&&args[2].includes('/jobs/')){assert.equal(input.preconditions.uid,state.job?.metadata.uid);state.job=null;if(!keepPods)state.pods=[];return {};}
  if(args[0]==='delete'&&args[2].includes('/leases/')){assert.equal(input.preconditions.uid,state.lease?.metadata.uid);state.lease=null;return {};}
  if(args[0]==='patch'){assert.equal(input[0].value,state.lease.metadata.uid);assert.equal(input[1].value,state.lease.spec.holderIdentity);state.lease.metadata.annotations['evidscope.io/execution-state']='quarantined';return structuredClone(state.lease);}
  throw Error('unexpected_fake_command');
 };
 return {state,execute};
}
const adapter=(value,cluster,extra={})=>createKubectlTrainingAdapter(value,{execute:cluster.execute,beforeCreate:async()=>{},newRunId:()=> 'd'.repeat(32),...extra});

test('training config binds model, pinned image, data, host, context and fresh measured template',()=>{
 const valid=config();assert.equal(validateTrainingRuntimeConfig(valid,{now}).baseRepository,valid.baseRepository);
 for(const mutate of [v=>v.context='',v=>v.baseRepository='other/model',v=>v.baseRevision='main',v=>v.image='training:latest',v=>v.datasetSha256='',v=>v.hostName='different-host',v=>v.sharedExecutionLease.automaticTakeover=true,v=>v.measuredIsolationReceipt.context='other-context',v=>v.measuredIsolationReceipt.checks.approvedVolumesOnly=false,v=>v.measuredIsolationReceipt.observedAt=new Date(now-300001).toISOString(),v=>v.artifactLock.files[0].path='../secret',v=>v.nodeName='changed-node']){const value=structuredClone(valid);mutate(value);assert.throws(()=>validateTrainingRuntimeConfig(value,{now}));}
 const job=boundTrainingTemplate(valid),env=Object.fromEntries(job.spec.template.spec.containers[0].env.map(v=>[v.name,v.value]));
 assert.equal(env.EVIDSCOPE_DATASET_SHA256,valid.datasetSha256);assert.equal(env.EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256,createHash('sha256').update(JSON.stringify(valid.artifactLock)).digest('hex'));assert.equal(job.spec.suspend,true);
});

test('dataset bytes must match config, and synthetic unreviewed data cannot pass admission',()=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-training-data-'));try{const file=join(dir,'records.jsonl');writeFileSync(file,JSON.stringify({id:'unreviewed',roleId:'evidence-organizer',split:'tune',prompt:'example',evidence:[],truth:{labels:['test'],requiredRefs:[]}})+'\n');const result=inspectTrainingDataset(file);assert.equal(result.admission.trainingRunAllowed,false);assert.throws(()=>inspectTrainingDataset(file,{expectedHash:'a'.repeat(64)}),/digest_mismatch/);}finally{rmSync(dir,{recursive:true,force:true});}
});

test('check-only collects independent failed gates and never builds an execution session',async()=>{
 const result=await inspectTrainingReadiness({},{readConfig:()=>{throw Error('training_runtime_configuration_required');},inspectDataset:()=>({admission:{trainingRunAllowed:false,reasons:['human_review_missing']}}),probe:async()=>receipt({idleSeconds:0}),clock:()=>now});
 assert.equal(result.allowed,false);assert.equal(result.gates.runtime.allowed,false);assert.equal(result.gates.data.allowed,false);assert.equal(result.gates.host.allowed,false);
 let created=0;const dependencies={inspect:async()=>({allowed:true,started:false}),createSession:()=>{created++;}};
 assert.equal((await runTrainingCommand([],dependencies)).mode,'check-only');assert.equal(created,0);
 assert.equal((await runTrainingCommand(['--execute-isolated-training'],{...dependencies,inspect:async()=>result})).mode,'execution-blocked');assert.equal(created,0);
 await assert.rejects(runTrainingCommand(['--execute-isolated-training','--check-only'],dependencies),/mode_conflict/);
});

test('existing inference lease prevents all training creation and is never taken over',async()=>{
 const cluster=fakeCluster();cluster.state.lease={metadata:{uid:'inference-lease'},spec:{holderIdentity:'foundation-sec:other'}};
 await assert.rejects(adapter(config(),cluster).start(),/lease_unavailable/);assert.equal(cluster.state.job,null);assert.equal(cluster.state.lease.metadata.uid,'inference-lease');assert.equal(cluster.state.calls.some(c=>['patch','delete'].includes(c.args[0])),false);
});

test('single exact training Job gets pinned inputs and cleanup waits for owned Pods too',async()=>{
 const value=config(),cluster=fakeCluster({keepPods:true}),client=adapter(value,cluster),workload=await client.start();
 const created=cluster.state.calls.find(c=>c.input?.kind==='Job').input;
 assert.equal(created.spec.suspend,false);assert.equal(created.spec.template.spec.nodeName,value.nodeName);assert.equal(created.spec.template.spec.containers[0].image,value.image);
 assert.equal(cluster.state.calls.filter(c=>c.args[0]==='create').length,2);
 await client.stop(workload);assert.equal((await client.observe(workload)).terminationConfirmed,false);assert.ok(cluster.state.lease);
 cluster.state.pods=[];const gone=await client.observe(workload);assert.equal(gone.terminationConfirmed,true);assert.equal(cluster.state.lease,null);
 const deleted=cluster.state.calls.find(c=>c.args[0]==='delete'&&c.args[2].includes('/jobs/'));assert.equal(deleted.input.preconditions.uid,workload.uid);assert.equal(deleted.input.propagationPolicy,'Foreground');
});

test('a different Job UID is never deleted even when the name matches',async()=>{
 const cluster=fakeCluster(),client=adapter(config(),cluster),workload=await client.start();cluster.state.job.metadata.uid='replacement-uid';
 await assert.rejects(client.stop(workload),/identity_mismatch/);assert.ok(cluster.state.lease);assert.equal(cluster.state.calls.some(c=>c.args[0]==='delete'),false);
});

test('cancelled or busy pre-create host releases reservation without creating Job',async()=>{
 const controller=new AbortController(),cluster=fakeCluster({onLease:()=>controller.abort()});
 await assert.rejects(adapter(config(),cluster).start({signal:controller.signal}),/cancelled_before_create/);assert.equal(cluster.state.job,null);assert.equal(cluster.state.lease,null);
 const busy=fakeCluster();await assert.rejects(adapter(config(),busy,{beforeCreate:async()=>{throw Error('host_activity');}}).start(),/host_activity/);assert.equal(busy.state.job,null);assert.equal(busy.state.lease,null);
});

test('ambiguous create recovers only its run, cleans it, and quarantines shared lease',async()=>{
 const cluster=fakeCluster({ambiguousCreate:true}),client=adapter(config(),cluster),guard=createIdleTrainingGuard({probe:async()=>receipt(),launcher:client,clock:()=>now,wait:async()=>{}});
 await assert.rejects(guard.run(),error=>{assert.equal(error.message,'training_create_ambiguous_lease_quarantined');assert.equal(error.terminationConfirmed,true);assert.equal(error.leaseRetained,true);return true;});
 assert.equal(cluster.state.job,null);assert.equal(cluster.state.pods.length,0);assert.equal(cluster.state.lease.metadata.annotations['evidscope.io/execution-state'],'quarantined');
});

test('ambiguous create with immediate absence retains quarantine because late commit remains possible',async()=>{
 const cluster=fakeCluster({ambiguousCreate:true,commitAmbiguous:false}),client=adapter(config(),cluster);
 await assert.rejects(client.start(),error=>{assert.equal(error.leaseRetained,true);assert.equal(error.terminationConfirmed,false);assert.equal(error.workload,undefined);assert.equal(error.recovery.name,`foundation-qlora-${'d'.repeat(32)}`);return true;});
 assert.ok(cluster.state.lease);assert.equal(cluster.state.calls.some(c=>c.args[0]==='delete'),false);
});

test('session runs admission again and cannot claim training completion before cleanup',async()=>{
 const value=config(),cluster=fakeCluster({completed:true});let admissions=0;
 const session=createIsolatedTrainingSession({runtimeConfigPath:'fixture',dataPath:'fixture'},{clock:()=>now,readConfig:()=>value,inspectDataset:()=>{admissions++;return admitted();},createAdapter:(cfg,options)=>createKubectlTrainingAdapter(cfg,{...options,execute:cluster.execute,newRunId:()=> 'e'.repeat(32)}),probe:async()=>receipt(),wait:async()=>{}});
 const result=await session.run();assert.equal(admissions,2);assert.equal(result.trainingRunCompleted,true);assert.equal(result.terminationConfirmed,true);assert.equal(result.promotionAllowed,false);assert.equal(cluster.state.job,null);assert.equal(cluster.state.lease,null);
 assert.equal(result.artifactVerification.globalStep,19);assert.equal(cluster.state.verifier,null);
 await assert.rejects(session.run(),/training_session_already_used/);
});

test('complete Job cannot claim success without verified candidate files',async()=>{
 const value=config(),cluster=fakeCluster({completed:true});
 const session=createIsolatedTrainingSession({},{clock:()=>now,readConfig:()=>value,inspectDataset:()=>admitted(),createAdapter:(cfg,options)=>({...createKubectlTrainingAdapter(cfg,{...options,execute:cluster.execute}),verifyArtifacts:async()=>{throw Error('candidate_artifact_changed');}}),probe:async()=>receipt(),wait:async()=>{}});
 await assert.rejects(session.run(),/candidate_artifact_changed/);assert.equal(cluster.state.job,null);assert.equal(cluster.state.lease,null);
});

test('session refuses dataset changes before acquiring lease',async()=>{
 const value=config(),cluster=fakeCluster();let reads=0;
 const session=createIsolatedTrainingSession({},{clock:()=>now,readConfig:()=>value,inspectDataset:()=>{if(++reads===2)throw Error('training_dataset_digest_mismatch');return admitted();},createAdapter:(cfg,options)=>createKubectlTrainingAdapter(cfg,{...options,execute:cluster.execute}),probe:async()=>receipt(),wait:async()=>{}});
 await assert.rejects(session.run(),/digest_mismatch/);assert.equal(cluster.state.calls.length,0);
});

test('kubectl subprocess pins explicit context and refuses oversized responses',async()=>{
 let captured,killed=false;
 const execute=createBoundedKubectl('test-context',{spawnProcess:(program,args,options)=>{captured={program,args,options};const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdin=new PassThrough();child.kill=()=>{killed=true;};queueMicrotask(()=>child.stdout.write(Buffer.alloc(1048577)));return child;}});
 await assert.rejects(execute(['get','job','one','-o','json']),/response_limit/);assert.equal(captured.program,'kubectl');assert.equal(captured.args[1],'test-context');assert.ok(captured.args.includes('--request-timeout=5s'));assert.equal(captured.options.shell,false);assert.equal(captured.options.windowsHide,true);assert.equal(killed,true);
});
