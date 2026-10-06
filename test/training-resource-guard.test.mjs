import test from 'node:test';
import assert from 'node:assert/strict';
import {createIdleTrainingGuard,trainingStartDecision,trainingContinueDecision,TRAINING_RESOURCE_POLICY} from '../src/training-resource-guard.mjs';
import {trainingManifest} from '../deploy/training/render.mjs';
import {probeWindowsHostResources} from '../scripts/training-host-check.mjs';

const now=Date.parse('2026-09-12T08:00:00Z');
const receipt=(changes={})=>({schemaVersion:1,source:'trusted_windows_host_probe',observedAt:new Date(now).toISOString(),idleSeconds:1200,cpuPercent:5,freeMemoryGiB:24,onAcPower:true,gpu:{memoryUsedMiB:500,memoryTotalMiB:12288,utilizationPercent:2,temperatureC:42,computeProcessCount:0},...changes});

test('training starts only with a fresh idle low-load host receipt',()=>{
 assert.equal(trainingStartDecision(receipt(),{now}).allowed,true);
 for(const sample of [receipt({idleSeconds:10}),receipt({cpuPercent:90}),receipt({freeMemoryGiB:10}),receipt({onAcPower:false}),receipt({gpu:{...receipt().gpu,memoryUsedMiB:2000}}),receipt({gpu:{...receipt().gpu,computeProcessCount:1}}),receipt({observedAt:new Date(now-6000).toISOString()})])assert.equal(trainingStartDecision(sample,{now}).allowed,false);
 assert.equal(trainingContinueDecision(receipt({idleSeconds:0}),{now}).reasons[0],'interactive_use_resumed');
});

test('blocked preflight creates no workload',async()=>{
 let started=false;const guard=createIdleTrainingGuard({probe:async()=>receipt({idleSeconds:0}),launcher:{start:async()=>{started=true;},observe:async()=>({}),stop:async()=>{}},clock:()=>now,wait:async()=>{}});
 const result=await guard.run();assert.equal(result.state,'blocked_host_busy');assert.equal(result.started,false);assert.equal(started,false);assert.equal(result.terminationConfirmed,true);
});

test('user activity stops the owned training workload and confirms absence',async()=>{
 let probes=0,stopped=false;const launcher={start:async()=>({name:'training-1',uid:'uid-1'}),observe:async()=>stopped?{state:'absent',terminationConfirmed:true}:{state:'running'},stop:async workload=>{assert.equal(workload.uid,'uid-1');stopped=true;}};
 const guard=createIdleTrainingGuard({probe:async()=>++probes===1?receipt():receipt({idleSeconds:0}),launcher,clock:()=>now,wait:async()=>{}}),result=await guard.run();
 assert.equal(result.state,'stopped_for_host_activity');assert.equal(result.terminationConfirmed,true);assert.ok(result.reasons.includes('interactive_use_resumed'));
});

test('completed work is still deleted and unknown cleanup cannot report success',async()=>{
 let stopped=false;const complete=createIdleTrainingGuard({probe:async()=>receipt(),launcher:{start:async()=>({name:'training-1',uid:'uid-1'}),observe:async()=>stopped?{state:'absent',terminationConfirmed:true}:{state:'succeeded'},stop:async()=>{stopped=true;}},clock:()=>now,wait:async()=>{}});
 const result=await complete.run();assert.equal(result.state,'stopped');assert.equal(result.reason,'completed');assert.equal(result.terminationConfirmed,true);
 const controller=new AbortController();
 const stuck=createIdleTrainingGuard({probe:async()=>receipt(),launcher:{start:async()=>({name:'training-2',uid:'uid-2'}),observe:async()=>({state:'running',terminationConfirmed:false}),stop:async()=>{}},clock:()=>now,wait:async()=>{controller.abort();}});
 await assert.rejects(stuck.run({signal:controller.signal}),/TRAINING_STOP_UNCONFIRMED/);
});

test('pre-aborted or probe-time cancellation never starts training',async()=>{
 let started=0,probed=0;const controller=new AbortController();
 const guard=createIdleTrainingGuard({probe:async()=>{probed++;controller.abort();return receipt();},launcher:{start:async()=>{started++;},observe:async()=>({}),stop:async()=>{}},clock:()=>now,wait:async()=>{}});
 assert.equal((await guard.run({signal:AbortSignal.abort()})).state,'cancelled');assert.equal(probed,0);
 assert.equal((await guard.run({signal:controller.signal})).state,'cancelled');assert.equal(probed,1);assert.equal(started,0);
});

test('cleanup retries an ambiguous delete and requires explicit disappearance confirmation',async()=>{
 let stops=0,observations=0;const controller=new AbortController();
 const guard=createIdleTrainingGuard({probe:async()=>receipt(),launcher:{start:async()=>({name:'training-1',uid:'uid-1'}),stop:async()=>{if(++stops===1)throw Error('request_timeout');},observe:async()=>++observations===1?{state:'absent'}:{state:'absent',terminationConfirmed:true}},clock:()=>now,wait:async()=>{controller.abort();}});
 const result=await guard.run({signal:controller.signal});assert.equal(result.terminationConfirmed,true);assert.equal(stops,2);
});

test('training template is background-only, bounded and initially suspended',()=>{
 const manifest=trainingManifest(),priority=manifest.items.find(v=>v.kind==='PriorityClass'),job=manifest.items.find(v=>v.kind==='Job'),container=job.spec.template.spec.containers[0];
 assert.equal(priority.value,-10);assert.equal(priority.preemptionPolicy,'Never');assert.equal(job.spec.suspend,true);assert.equal(job.spec.activeDeadlineSeconds,3600);assert.equal(job.spec.template.spec.priorityClassName,priority.metadata.name);
 assert.deepEqual(container.resources.limits,{cpu:'2',memory:'12Gi','nvidia.com/gpu':'1'});assert.ok(container.args.includes('0.65'));assert.ok(container.env.some(v=>v.name==='OMP_NUM_THREADS'&&v.value==='2'));assert.equal(TRAINING_RESOURCE_POLICY.minIdleSeconds,900);
});

test('Windows probe wrapper accepts only the bounded receipt schema',()=>{
 const execute=(program,args,options)=>{assert.equal(program,'powershell.exe');assert.ok(args.some(v=>v.endsWith('training-host-probe.ps1')));assert.equal(options.windowsHide,true);return JSON.stringify(receipt());};
 assert.equal(probeWindowsHostResources({execute,now}).idleSeconds,1200);
});
