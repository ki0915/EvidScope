import test from 'node:test';
import assert from 'node:assert/strict';
import {observePublicQaPod} from '../scripts/run-public-qa-job.mjs';
import {QA_NAMESPACE,QA_NODE,QA_IMAGE} from '../scripts/public-qa-workload.mjs';

const jobUid='job-original',containerID='containerd://original-training-container';
function running(){return {metadata:{name:'public-qa-resume-pod',uid:'pod-original',namespace:QA_NAMESPACE,ownerReferences:[{kind:'Job',uid:jobUid}]},spec:{nodeName:QA_NODE,automountServiceAccountToken:false,restartPolicy:'Never',runtimeClassName:'nvidia',securityContext:{runAsUser:10001},volumes:[{name:'base',persistentVolumeClaim:{claimName:'public-qa-base'}}],containers:[{name:'training',image:QA_IMAGE,resources:{limits:{cpu:'2',memory:'12Gi','nvidia.com/gpu':'1'}},securityContext:{readOnlyRootFilesystem:true,allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}},volumeMounts:[{name:'base',readOnly:true}]}]},status:{phase:'Running',containerStatuses:[{name:'training',containerID,restartCount:0,state:{running:{startedAt:'2026-09-28T01:00:00Z'}}}]}};}
function completed(pod,exitCode=0){const current=structuredClone(pod);current.status.phase=exitCode===0?'Succeeded':'Failed';current.status.containerStatuses[0].state={terminated:{exitCode,reason:exitCode===0?'Completed':'Error',containerID,startedAt:'2026-09-28T01:00:00Z',finishedAt:'2026-09-28T01:30:00Z'}};return current;}
const missingContainer=()=>Object.assign(Error('error: Internal error occurred: unable to upgrade connection: container not found ("training")'),{code:1});

for(const exitCode of [0,1,137])test(`Running → exec failure → same Pod exit ${exitCode} returns its actual termination`,async()=>{
 const pod=running(),ended=completed(pod,exitCode),error=missingContainer(),calls=[];
 const result=await observePublicQaPod({pod,jobUid,measure:async name=>{calls.push(['measure',name]);throw error;},readPod:async name=>{calls.push(['readPod',name]);return ended;}});
 assert.deepEqual(calls,[['measure',pod.metadata.name],['readPod',pod.metadata.name]]);assert.deepEqual(result.terminated,ended.status.containerStatuses[0].state.terminated);assert.equal(result.sample,undefined);assert.equal(result.terminalRecheck.podUid,pod.metadata.uid);assert.equal(result.terminalRecheck.sampleError,error.message);
 assert.equal(result.terminated.exitCode===0,exitCode===0,'nonzero termination must never become success');
});

test('successful telemetry does not query another Pod or change the sample',async()=>{
 const sample={windows:{commitFreeGiB:16},cgroup:{memoryCurrentGiB:8}},result=await observePublicQaPod({pod:running(),jobUid,measure:async()=>sample,readPod:async()=>{assert.fail('unnecessary status recheck');}});assert.equal(result.sample,sample);assert.equal(result.terminated,undefined);
});

test('a telemetry failure while the same container remains live is not suppressed',async()=>{
 const pod=running(),error=missingContainer();await assert.rejects(observePublicQaPod({pod,jobUid,measure:async()=>{throw error;},readPod:async()=>structuredClone(pod)}),e=>e===error);
});

test('Pod status lookup failure preserves the telemetry error rather than declaring completion',async()=>{
 const error=missingContainer();await assert.rejects(observePublicQaPod({pod:running(),jobUid,measure:async()=>{throw error;},readPod:async()=>{throw Error('API server timeout');}}),e=>e===error);
});

for(const change of ['uid','name','owner','namespace','container','containerID','restartCount','restartPolicy'])test(`terminal status with changed ${change} cannot explain the original sample failure`,async()=>{
 const pod=running(),fresh=completed(pod);
 if(change==='uid')fresh.metadata.uid='replacement-pod';if(change==='name')fresh.metadata.name='different-pod';if(change==='owner')fresh.metadata.ownerReferences[0].uid='other-job';if(change==='namespace')fresh.metadata.namespace='other-namespace';
 if(change==='container')fresh.status.containerStatuses[0].name='sidecar';if(change==='containerID')fresh.status.containerStatuses[0].containerID='containerd://replacement';if(change==='restartCount')fresh.status.containerStatuses[0].restartCount=1;if(change==='restartPolicy')fresh.spec.restartPolicy='Always';
 await assert.rejects(observePublicQaPod({pod,jobUid,measure:async()=>{throw missingContainer();},readPod:async()=>fresh}),/identity_changed|scope_invalid/);
});

test('Succeeded Pod phase without a training-container exit code is insufficient',async()=>{
 const pod=running(),fresh=completed(pod),error=missingContainer();delete fresh.status.containerStatuses[0].state.terminated.exitCode;
 await assert.rejects(observePublicQaPod({pod,jobUid,measure:async()=>{throw error;},readPod:async()=>fresh}),e=>e===error);
});

const missingTask=()=>Error('failed to create exec "late-sample": task original-training-container not found');
test('a missing runtime task waits briefly for the same container terminal status',async()=>{
 const pod=running(),error=missingTask(),pauses=[];let reads=0;
 const result=await observePublicQaPod({pod,jobUid,measure:async()=>{throw error;},pause:async ms=>pauses.push(ms),readPod:async()=>++reads<3?structuredClone(pod):completed(pod)});
 assert.equal(result.terminated.exitCode,0);assert.equal(reads,3);assert.deepEqual(pauses,[250,500]);assert.equal(result.terminalRecheck.statusReads,3);
});
test('a missing runtime task never substitutes a replacement Pod during delayed status',async()=>{
 const pod=running(),error=missingTask();let reads=0;const replacement=completed(pod);replacement.metadata.uid='replacement';
 await assert.rejects(observePublicQaPod({pod,jobUid,measure:async()=>{throw error;},pause:async()=>{},readPod:async()=>++reads===1?structuredClone(pod):replacement}),/identity_changed/);
 assert.equal(reads,2);
});
test('bounded late status polling does not infer an exit from a missing task alone',async()=>{
 const pod=running(),error=missingTask(),pauses=[];let reads=0;
 await assert.rejects(observePublicQaPod({pod,jobUid,measure:async()=>{throw error;},pause:async ms=>pauses.push(ms),readPod:async()=>{reads++;return structuredClone(pod);}}),e=>e===error);
 assert.equal(reads,4);assert.deepEqual(pauses,[250,500,1000]);
});
