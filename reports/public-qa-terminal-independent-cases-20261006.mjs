import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {observePublicQaPod} from '../scripts/run-public-qa-job.mjs';
import {QA_NAMESPACE,QA_NODE,QA_IMAGE} from '../scripts/public-qa-workload.mjs';

const jobUid='independent-job',containerID='containerd://independent-container';
const pod=()=>({metadata:{name:'independent-pod',uid:'independent-pod-uid',namespace:QA_NAMESPACE,ownerReferences:[{kind:'Job',uid:jobUid}]},spec:{nodeName:QA_NODE,automountServiceAccountToken:false,restartPolicy:'Never',runtimeClassName:'nvidia',securityContext:{runAsUser:10001},volumes:[{name:'base',persistentVolumeClaim:{claimName:'public-qa-base'}}],containers:[{name:'training',image:QA_IMAGE,resources:{limits:{cpu:'2',memory:'12Gi','nvidia.com/gpu':'1'}},securityContext:{readOnlyRootFilesystem:true,allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}},volumeMounts:[{name:'base',readOnly:true}]}]},status:{phase:'Running',containerStatuses:[{name:'training',containerID,restartCount:0,state:{running:{startedAt:'2026-10-06T00:00:00Z'}}}]}});
const error=()=>Error('failed to create exec "sample": task independent-container not found');
function ended(original,exitCode){const current=structuredClone(original);current.status.containerStatuses[0].state={terminated:{exitCode,containerID}};return current;}
const cases=[];
for(const exitCode of [0,1,137]){
 const original=pod(),pauses=[];let reads=0;
 const result=await observePublicQaPod({pod:original,jobUid,measure:async()=>{throw error();},readPod:async()=>++reads===3?ended(original,exitCode):structuredClone(original),pause:async ms=>pauses.push(ms)});
 assert.equal(result.terminated.exitCode,exitCode);assert.deepEqual(pauses,[250,500]);cases.push({case:'delayed exit '+exitCode,reads,exitCode:result.terminated.exitCode});
}
for(const message of ['failed to create exec "sample": task another-container not found','task independent-container not found','failed to create exec "sample": task independent-containerX not found']){
 let reads=0;const original=pod(),failure=Error(message);
 await assert.rejects(observePublicQaPod({pod:original,jobUid,measure:async()=>{throw failure;},readPod:async()=>{reads++;return structuredClone(original);},pause:async()=>assert.fail('unrelated error must not delay')}),e=>e===failure);
 assert.equal(reads,1);cases.push({case:'unrelated failure preserves identity and error',message,reads});
}
for(const [name,change] of [
 ['image',current=>current.spec.containers[0].image='other-image'],
 ['cpu',current=>current.spec.containers[0].resources.limits.cpu='3'],
 ['memory',current=>current.spec.containers[0].resources.limits.memory='16Gi'],
 ['gpu',current=>current.spec.containers[0].resources.limits['nvidia.com/gpu']='2'],
 ['writeable base',current=>current.spec.containers[0].volumeMounts[0].readOnly=false],
 ['terminated CID',current=>current.status.containerStatuses[0].state.terminated.containerID='containerd://other-container'],
 ]){
 const original=pod(),fresh=ended(original,0);change(fresh);let reads=0;
 await assert.rejects(observePublicQaPod({pod:original,jobUid,measure:async()=>{throw error();},readPod:async()=>++reads===2?fresh:structuredClone(original),pause:async()=>{}}),/scope_invalid|identity_changed/);
 assert.equal(reads,2);cases.push({case:'delayed changed '+name,reads,rejected:true});
}
const result={scope:'mocked controller reads, not Kubernetes or actual r3 exit proof',passed:cases.length,cases};writeFileSync(new URL('./public-qa-terminal-independent-cases-20261006.json',import.meta.url),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
