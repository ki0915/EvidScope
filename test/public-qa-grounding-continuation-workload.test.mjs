import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {selectGroundingRows} from '../scripts/prepare-public-qa-grounding.mjs';
import {CONTINUATION_STAGE,SAMPLER} from '../scripts/prepare-public-qa-grounding-continuation.mjs';
import {CONTINUATION_SOURCE_RUN,CONTINUATION_PINS,groundingJob,assertGroundingMounts} from '../scripts/public-qa-grounding-continuation-workload.mjs';
import {publicQaControllerOptions} from '../scripts/run-public-qa-job.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
function row(id,split,isImpossible=false){const context='사람이 작성한 원문 '+id,question='작성 주체는?',answers=isImpossible?[]:[{text:'사람',answer_start:0}];return {id,split,context,question,answers,isImpossible,contextSha256:sha(context),familyId:'family-'+id,upstreamSplit:'train',upstreamRevision:'3efd98708a40ff49251fddde35453f8fbb11f536',sourceLicense:'CC-BY-SA-4.0',upstreamAnnotation:{kind:'human_authored_question_answer_spans'},originalQa:{question,answers,is_impossible:isImpossible}};}
test('unequal label selection keeps human originals and excludes exposed families with unchanged symmetric behavior',()=>{
 const sources={train:[row('a','train'),row('b','train',true),row('c','train'),row('d','train',true),row('e','train')],validation:[row('f','validation'),row('g','validation',true)]};
 const excluded=[{id:'prior',familyId:'family-a',contextSha256:'prior'}],result=selectGroundingRows(sources,excluded,{trainPerLabel:{answerable:2,impossible:1},validationPerLabel:1});
 assert.deepEqual(result.rows.map(r=>r.id),['c','b','e','f','g']);assert.deepEqual(result.counts,{train:3,validation:2});assert.deepEqual(result.rows[0].answers,sources.train[2].answers);assert.equal(result.rows[1].question,sources.train[1].question);
 const old=selectGroundingRows(sources,excluded,{trainPerLabel:1,validationPerLabel:1});assert.deepEqual(old.rows.map(r=>r.id),['c','b','f','g']);
 assert.throws(()=>selectGroundingRows(sources,excluded,{trainPerLabel:{answerable:2,impossible:0},validationPerLabel:1}),/label_limits_invalid/);
 sources.validation[0].familyId='family-c';assert.throws(()=>selectGroundingRows(sources,excluded,{trainPerLabel:{answerable:2,impossible:1},validationPerLabel:1}),/split_leakage/);
});
function inputs(){const runId='public-qa-grounding-test-cont',targetIdentity={maxSteps:20,learningRate:0.00003,sampler:SAMPLER,datasetSha256:'a'.repeat(64),manifestSha256:'b'.repeat(64)};return {runId,stage:CONTINUATION_STAGE,mode:'explicit_public_human_qa_grounding_continuation',rows:704,sourceRunId:CONTINUATION_SOURCE_RUN,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:60,sourceTrainingExecutionVerified:true,targetIdentity,groundingProvenance:{sourcePins:CONTINUATION_PINS,targetRunId:runId,targetIdentity},candidateMarkerSha256:CONTINUATION_PINS.marker,adapterSha256:CONTINUATION_PINS.adapter,sourceControllerSha256:CONTINUATION_PINS.controller,sourceVerificationSha256:CONTINUATION_PINS.verification,runtimeConfigMap:'public-qa-gcont-'+ 'c'.repeat(16),runtimeSha256:'c'.repeat(64),datasetSha256:targetIdentity.datasetSha256,manifestSha256:targetIdentity.manifestSha256,provenanceSha256:'d'.repeat(64),artifactLockSha256:'e'.repeat(64),qualityClaimAllowed:false,promotionAllowed:false};}
test('continuation job binds the actual latest source and separate writable output with unchanged resource isolation',()=>{
 const value=inputs(),job=groundingJob(value.runId,value),pod=job.spec.template,c=pod.spec.containers[0];assert.equal(job.spec.backoffLimit,0);assert.equal(c.resources.limits.cpu,'2');assert.equal(c.resources.limits.memory,'12Gi');assert.equal(c.resources.limits['nvidia.com/gpu'],'1');assert.equal(pod.spec.automountServiceAccountToken,false);
 assert.equal(c.volumeMounts.find(m=>m.name==='warmstart').subPath,'grounding-runs/'+CONTINUATION_SOURCE_RUN+'/candidate');assert.equal(c.volumeMounts.find(m=>m.name==='warmstart').readOnly,true);assert.equal(c.volumeMounts.find(m=>m.name==='grounding-output').subPath,'grounding-continuation-runs');assert.doesNotThrow(()=>assertGroundingMounts(pod,value));
 for(const change of [v=>v.sourceGlobalStep=60,v=>v.adapterSha256='a'.repeat(64),v=>v.promotionAllowed=true,v=>v.targetIdentity.learningRate=0.0001,v=>v.groundingProvenance.targetRunId='foreign']){const changed=structuredClone(value);change(changed);assert.throws(()=>groundingJob(changed.runId,changed),/binding_invalid/);}
 c.volumeMounts.find(m=>m.name==='warmstart').readOnly=false;assert.throws(()=>assertGroundingMounts(pod,value),/mount_scope_invalid/);
 const token=groundingJob(value.runId,value,{tokenCheck:true});assert.equal(token.spec.template.spec.containers[0].resources.limits['nvidia.com/gpu'],undefined);assert.equal(token.spec.template.spec.containers[0].args.at(-1),'--token-check');
});
test('controller requires explicit bounded continuation and rejects conflicting modes',()=>{
 const options=publicQaControllerOptions(['--execute-grounding-continuation','public-qa-grounding-test-cont','--allow-interactive-use']);assert.equal(options.groundingContinuation,true);assert.equal(options.executeTraining,true);assert.equal(options.grounding,true);assert.equal(options.interactiveUseApproved,true);
 assert.throws(()=>publicQaControllerOptions(['--execute-grounding-continuation','public-qa-grounding-test-cont','--allow-interactive-use','--resume-provenance','foreign.json']),/cannot_use_other_execution_modes/);
});
test('live mount checks accept explicit false PVC defaults while rejecting scope changes',()=>{
 const value=inputs(),pod=groundingJob(value.runId,value).spec.template;
 for(const volume of pod.spec.volumes)if(volume.persistentVolumeClaim)volume.persistentVolumeClaim.readOnly??=false;
 assert.doesNotThrow(()=>assertGroundingMounts(pod,value));
 for(const change of [p=>p.spec.volumes.find(v=>v.name==='warmstart').persistentVolumeClaim.readOnly=false,p=>p.spec.volumes.find(v=>v.name==='grounding-output').persistentVolumeClaim.claimName='foreign',p=>p.spec.volumes.find(v=>v.name==='base').hostPath={path:'/etc'},p=>p.spec.volumes.find(v=>v.name==='runtime').secret={secretName:'foreign'},p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='data').subPathExpr='$(FOREIGN)']){const changed=structuredClone(pod);change(changed);assert.throws(()=>assertGroundingMounts(changed,value),/mount_scope_invalid/);}
});
