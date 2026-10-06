import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {BALANCED_FRESH_RUN_ID,BALANCED_FRESH_SOURCE_RUN,FRESH_SOURCE_RUN,FRESH_SOURCE_PINS,balancedFreshBinding,freshEvaluationContract,freshEvaluationJob,assertFreshEvaluationMounts,assertBalancedFreshSource,publicQaFreshEvaluationInputs} from '../scripts/public-qa-fresh-workload.mjs';
import {QA_BASE_REVISION,QA_IMAGE} from '../scripts/public-qa-workload.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
// Unit-only records, never persisted as actual training evidence.
function unitInputs(){
 const pins={...FRESH_SOURCE_PINS,criInspectionSha256:null,sourceCompletionKind:'controller_normal_exit'},identity={stage:'public_qa_grounding_balanced_v1',maxSteps:20,baseRepository:'fdtn-ai/Foundation-Sec-8B-Reasoning',baseRevision:QA_BASE_REVISION,baseArtifactLockSha256:pins.artifactLockSha256,image:QA_IMAGE},binding=balancedFreshBinding(identity,pins);
 return {...binding,binding,bindingSha256:sha(JSON.stringify(binding,null,2)+'\n'),runtimeSha256:'b'.repeat(64),runtimeConfigMap:'public-qa-fresh-'+ 'b'.repeat(16)};
}
test('balanced blind uses fresh baseline and exact r2 read-only mounts without mandatory normal-exit CRI',()=>{
 const value=unitInputs(),contract=freshEvaluationContract(value.runId,value.binding),job=freshEvaluationJob(value.runId,value),spec=job.spec.template.spec,c=spec.containers[0];
 assert.equal(contract.history,100);assert.equal(contract.sourceHistory,80);assert.equal(value.sourceRunId,BALANCED_FRESH_SOURCE_RUN);assert.equal(value.baselineExecutedThisRun,true);assert.deepEqual(value.executionOrder,['baseline','candidate']);assert.equal(c.args.includes('--cri-inspection'),false);
 assert.equal(c.volumeMounts.find(m=>m.name==='adapters').subPath,'grounding-balanced-runs/'+BALANCED_FRESH_SOURCE_RUN+'/candidate');assert.equal(c.volumeMounts.find(m=>m.name==='data').subPath,'grounding-balanced/'+BALANCED_FRESH_SOURCE_RUN+'/blind-evaluation');assert.equal(spec.volumes.find(v=>v.name==='data').persistentVolumeClaim.readOnly,true);assert.doesNotThrow(()=>assertFreshEvaluationMounts({spec},value));
 for(const edit of [v=>v.sourceRunId=FRESH_SOURCE_RUN,v=>v.sourceOptimizerHistoryUpdates=80,v=>v.datasetSha256=FRESH_SOURCE_PINS.adapterSha256,v=>v.binding.executionOrder.reverse(),v=>v.binding.sourceCompletionKind='cri_exit_reconciled',v=>v.candidateIdentity.stage='public_qa_grounding_continuation_v1']){const changed=structuredClone(value);edit(changed);assert.throws(()=>freshEvaluationJob(changed.runId,changed));}
 for(const edit of [s=>s.containers[0].volumeMounts.find(m=>m.name==='adapters').subPath='grounding-continuation-runs/'+FRESH_SOURCE_RUN+'/candidate',s=>s.containers[0].volumeMounts.find(m=>m.name==='data').readOnly=false,s=>s.volumes.find(v=>v.name==='data').persistentVolumeClaim.readOnly=false]){const changed=structuredClone(spec);edit(changed);assert.throws(()=>assertFreshEvaluationMounts({spec:changed},value));}
});
test('balanced source must match full recomputed proof and twenty actual updates after source80',()=>{
 const v=unitInputs(),pins={...v.binding},identity=v.candidateIdentity,report={verified:true,verificationPassed:true,actualTrainingExecutionVerified:true,sourceTrainingExecutionVerified:true,trainingRunCompleted:true,terminationConfirmed:true,syntheticFixture:false,runId:BALANCED_FRESH_SOURCE_RUN,globalStep:20,actualOptimizerUpdates:20,optimizerUpdatesThisRun:20,sourceOptimizerUpdates:80,totalAdapterHistoryOptimizerUpdates:100,optimizerStateRestored:false,schedulerStateRestored:false,qualityClaimAllowed:false,promotionAllowed:false,controllerSha256:pins.sourceControllerSha256,runtimeConfigMapSha256:pins.sourceRuntimeConfigMapSha256,artifactSha256:pins.candidateMarkerSha256,adapterSha256:pins.adapterSha256,identity,jobUid:'unit-job',podUid:'unit-pod'},controller={runId:BALANCED_FRESH_SOURCE_RUN,terminationConfirmed:true,jobUid:'unit-job',podUid:'unit-pod',state:'process_completed',exit:{exitCode:0}},provenance={targetRunId:BALANCED_FRESH_SOURCE_RUN,targetIdentity:identity,sourceOptimizerHistoryUpdates:80,targetOptimizerSteps:20},args={report,recomputed:structuredClone(report),controller,marker:{globalStep:20,identity},provenance,pins};
 assert.doesNotThrow(()=>assertBalancedFreshSource(args));
 const timestamp=structuredClone(args);timestamp.report.verifiedAt='earlier';timestamp.recomputed.verifiedAt='later';assert.doesNotThrow(()=>assertBalancedFreshSource(timestamp));
 for(const edit of [a=>a.recomputed.adapterSha256='a'.repeat(64),a=>{a.report.actualOptimizerUpdates=19;a.recomputed.actualOptimizerUpdates=19;},a=>{a.report.totalAdapterHistoryOptimizerUpdates=80;a.recomputed.totalAdapterHistoryOptimizerUpdates=80;},a=>a.controller.exit.exitCode=2,a=>a.provenance.targetRunId='public-qa-balanced-20261006-r1',a=>a.controller.cleanupError='failed']){const changed=structuredClone(args);edit(changed);assert.throws(()=>assertBalancedFreshSource(changed));}
});
test('missing completed balanced source cannot create an evaluation binding',async t=>{
 const root=mkdtempSync(join(tmpdir(),'evidscope-balanced-fresh-'));t.after(()=>rmSync(root,{recursive:true,force:true}));await assert.rejects(publicQaFreshEvaluationInputs({runId:BALANCED_FRESH_RUN_ID,workspaceRoot:root}),/ENOENT|plain/);
});
