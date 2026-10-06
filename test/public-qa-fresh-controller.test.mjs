import test from 'node:test';
import assert from 'node:assert/strict';
import {publicQaControllerOptions,runPublicQa,observePublicQaPod} from '../scripts/run-public-qa-job.mjs';
import {podSpec,QA_NAMESPACE,QA_NODE} from '../scripts/public-qa-workload.mjs';

test('fresh paired evaluation requires its explicit mode and cannot train or resume',async()=>{
 const options=publicQaControllerOptions(['--execute-fresh-evaluation','public-qa-fresh-test','--allow-interactive-use']);
 assert.equal(options.freshEvaluation,true);assert.equal(options.executeTraining,true);
 assert.equal(options.grounding,false);assert.equal(options.diagnostic,false);
 assert.throws(()=>publicQaControllerOptions(['--execute-fresh-evaluation','public-qa-fresh-test','--allow-interactive-use','--resume-provenance','other.json']),/cannot_use_other_execution_modes/);
 for(const flag of ['grounding','groundingContinuation','groundingDiagnostic','diagnostic','diagnosticStageTwo','pilot'])
  await assert.rejects(runPublicQa({freshEvaluation:true,[flag]:true}),/fresh_evaluation_cannot_use_other_execution_modes/);
});

test('terminal resource-read recovery rechecks workload mounts before accepting exit zero',async()=>{
 const uid='owned-job',pod={metadata:{name:'owned-pod',uid:'owned-pod-uid',namespace:QA_NAMESPACE,ownerReferences:[{kind:'Job',uid}]},spec:podSpec({gpu:true}),status:{containerStatuses:[{name:'trainer',containerID:'containerd://owned-container',restartCount:0,state:{running:{}}}]}};
 pod.status.containerStatuses[0].name=pod.spec.containers[0].name;
 pod.spec.nodeName=QA_NODE;
 const current=structuredClone(pod);current.status.containerStatuses[0].state={terminated:{exitCode:0}};
 current.spec.volumes.find(v=>v.name==='data').persistentVolumeClaim.claimName='foreign';
 const error=Error('failed to create exec: task owned-container not found');
 await assert.rejects(observePublicQaPod({pod,jobUid:uid,measure:async()=>{throw error;},readPod:async()=>current,
  assertScope:value=>{if(value.spec.volumes.find(v=>v.name==='data').persistentVolumeClaim.claimName!==pod.spec.volumes.find(v=>v.name==='data').persistentVolumeClaim.claimName)throw Error('fresh_mount_changed');}}),/fresh_mount_changed/);
});
