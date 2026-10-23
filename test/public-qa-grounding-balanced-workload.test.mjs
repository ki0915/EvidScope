import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,rmSync,existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {STAGE,SOURCE_RUN,RUN_ID,RETRY_RUN_ID,SAMPLER,SOURCE_TRAINING_PINS} from '../scripts/prepare-public-qa-grounding-balanced.mjs';
import {QA_IMAGE,QA_BASE_REVISION} from '../scripts/public-qa-workload.mjs';
import {BALANCED_PINS,BALANCED_DATA_PINS,balancedDataPins,groundingRuntimeConfigMap,publicQaGroundingInputs,groundingJob,assertGroundingMounts} from '../scripts/public-qa-grounding-balanced-workload.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
// These are construction fixtures, never training-execution verification.
function inputs(runId=RUN_ID){
 const code=groundingRuntimeConfigMap(),runtimeFiles=Object.fromEntries(Object.entries(code.data).map(([key,value])=>[key,sha(value)]));
 const targetIdentity={baseRepository:'fdtn-ai/Foundation-Sec-8B-Reasoning',baseRevision:QA_BASE_REVISION,baseArtifactLockSha256:SOURCE_TRAINING_PINS.artifactLock,...BALANCED_DATA_PINS,trainerSha256:runtimeFiles['train-public-qa.py'],artifactHelperSha256:runtimeFiles['training_artifacts.py'],bindingHelperSha256:runtimeFiles['train-foundation-lora.py'],image:QA_IMAGE,rank:8,sequenceLength:1024,gpuMemoryFraction:0.65,batchSize:1,gradientAccumulationSteps:16,seed:42,learningRate:0.00003,maxSteps:20,stage:STAGE,groundingHelperSha256:runtimeFiles['public_qa_grounding_balanced.py'],contextSelection:'full_original_context',precision:'bf16',modelDtype:'bfloat16',quantComputeDtype:'bfloat16',sampler:SAMPLER};
 const sourceIdentity={...targetIdentity,stage:'public_qa_grounding_continuation_v1'};
 const groundingProvenance={schemaVersion:1,kind:'adapter_only_warmstart_balanced_public_qa_continuation',sourceRunId:SOURCE_RUN,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:80,sourcePins:BALANCED_PINS,sourceIdentity,targetRunId:RUN_ID,targetIdentity,optimizerReset:true,schedulerReset:true,targetOptimizerSteps:20,sourceTrainingExecutionVerified:true,qualityClaimAllowed:false,promotionAllowed:false};
 const pins=balancedDataPins(runId);Object.assign(targetIdentity,pins);groundingProvenance.targetRunId=runId;
 return {runId,mode:'explicit_public_human_qa_grounding_balanced',stage:STAGE,rows:704,sourceRunId:SOURCE_RUN,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:80,sourceTrainingExecutionVerified:true,targetIdentity,groundingProvenance,
 candidateMarkerSha256:BALANCED_PINS.marker,adapterSha256:BALANCED_PINS.adapter,sourceControllerSha256:BALANCED_PINS.controller,sourceVerificationSha256:BALANCED_PINS.verification,sourceProvenanceSha256:BALANCED_PINS.provenance,sourceRuntimeConfigMapSha256:BALANCED_PINS.runtime,criInspectionSha256:SOURCE_TRAINING_PINS.criInspection,artifactLockSha256:SOURCE_TRAINING_PINS.artifactLock,
 ...pins,runtimeConfigMap:code.metadata.name,runtimeSha256:code.metadata.annotations['evidscope.io/code-sha256'],runtimeFiles,provenanceSha256:sha(JSON.stringify(groundingProvenance,null,2)+'\n'),pvcOutputRelativePath:'grounding-balanced-runs/'+runId,diagnosticOnly:false,qualityClaimAllowed:false,promotionAllowed:false};
}

test('balanced runtime adds one helper to the frozen continuation mechanics',()=>{
 const cm=groundingRuntimeConfigMap();assert.equal(cm.immutable,true);assert.equal(Object.keys(cm.data).length,13);
 assert.match(cm.metadata.name,/^public-qa-gbal-[a-f0-9]{16}$/);assert.equal(cm.metadata.annotations['evidscope.io/code-sha256'],sha(JSON.stringify(cm.data)));
 for(const name of ['public_qa_grounding.py','public_qa_grounding_kbit.py','public_qa_grounding_continuation.py','public_qa_grounding_balanced.py','training_artifacts.py'])assert.equal(typeof cm.data[name],'string');
 assert.match(cm.data['public_qa_grounding_continuation.py'],/answerablePerGroup': 11/);assert.match(cm.data['public_qa_grounding_balanced.py'],/answerablePerGroup': 8/);
});

test('balanced GPU job mounts source80 read-only and confines writes to the new history100 run',()=>{
 const value=inputs(),job=groundingJob(RUN_ID,value),pod=job.spec.template,c=pod.spec.containers[0];
 assert.equal(job.spec.backoffLimit,0);assert.equal(job.spec.activeDeadlineSeconds,3600);assert.equal(pod.spec.automountServiceAccountToken,false);assert.equal(pod.spec.restartPolicy,'Never');
 assert.equal(c.resources.limits.cpu,'2');assert.equal(c.resources.limits.memory,'12Gi');assert.equal(c.resources.limits['nvidia.com/gpu'],'1');assert.equal(c.securityContext.readOnlyRootFilesystem,true);
 assert.equal(c.volumeMounts.find(m=>m.name==='data').subPath,'grounding-balanced/'+RUN_ID);assert.equal(c.volumeMounts.find(m=>m.name==='data').readOnly,true);assert.equal(pod.spec.volumes.find(v=>v.name==='data').persistentVolumeClaim.readOnly,true);
 assert.equal(c.volumeMounts.find(m=>m.name==='warmstart').subPath,'grounding-continuation-runs/'+SOURCE_RUN+'/candidate');assert.equal(c.volumeMounts.find(m=>m.name==='warmstart').readOnly,true);
 assert.equal(c.volumeMounts.find(m=>m.name==='grounding-output').subPath,'grounding-balanced-runs');assert.equal(c.volumeMounts.find(m=>m.name==='grounding-output').readOnly,false);
 assert.deepEqual(c.command,['python','/runtime/train-public-qa.py']);assert.equal(c.args[c.args.indexOf('--output')+1],'/checkpoints/runs/'+RUN_ID);assert.equal(c.args[c.args.indexOf('--max-steps')+1],'20');
 assert.equal(c.args.includes('--resume-from-checkpoint'),false);assert.equal(c.args.includes('--resume-provenance'),false);
 assert.equal(c.env.find(e=>e.name==='EVIDSCOPE_GROUNDING_PROVENANCE_SHA256').value,value.provenanceSha256);assert.equal(c.env.find(e=>e.name==='EVIDSCOPE_MEMORY_HIGH_REQUIRED').value,'1');
 assert.doesNotThrow(()=>assertGroundingMounts(pod,value));
});

test('token admission uses the same offline data and source while requesting no GPU',()=>{
 const value=inputs(),gpu=groundingJob(RUN_ID,value),token=groundingJob(RUN_ID,value,{tokenCheck:true}),spec=token.spec.template.spec;
 assert.equal(spec.runtimeClassName,undefined);assert.equal(spec.containers[0].resources.limits['nvidia.com/gpu'],undefined);assert.equal(spec.containers[0].args.at(-1),'--token-check');
 assert.deepEqual(spec.containers[0].volumeMounts,gpu.spec.template.spec.containers[0].volumeMounts);assert.deepEqual(spec.volumes,gpu.spec.template.spec.volumes);assert.doesNotThrow(()=>assertGroundingMounts(token.spec.template,value));
});

test('run, source, dataset, runtime and training identity mutations fail before a Job is produced',()=>{
 const value=inputs(),changes=[v=>v.runId='public-qa-balanced-foreign',v=>v.sourceRunId='public-qa-grounding-20261005-r4',v=>v.sourceGlobalStep=80,v=>v.sourceOptimizerHistoryUpdates=60,v=>v.sourceTrainingExecutionVerified=false,v=>v.rows=320,v=>v.diagnosticOnly=true,v=>v.mode='explicit_public_human_qa_grounding_continuation',v=>v.stage='public_qa_grounding_continuation_v1',v=>v.qualityClaimAllowed=true,v=>v.promotionAllowed=true,v=>v.pvcOutputRelativePath='../foreign',
 ...['candidateMarkerSha256','adapterSha256','sourceControllerSha256','sourceVerificationSha256','sourceProvenanceSha256','sourceRuntimeConfigMapSha256','criInspectionSha256','artifactLockSha256','datasetSha256','manifestSha256','provenanceSha256','runtimeSha256'].map(key=>v=>v[key]='f'.repeat(64)),v=>v.runtimeConfigMap='public-qa-gbal-'+ 'f'.repeat(16),v=>v.runtimeFiles['public_qa_grounding_balanced.py']='f'.repeat(64),v=>delete v.runtimeFiles['public_qa_grounding_continuation.py'],
 ...Object.entries({baseRepository:'other/base',baseRevision:'f'.repeat(40),image:'other/image',rank:16,sequenceLength:2048,gpuMemoryFraction:0.8,batchSize:2,gradientAccumulationSteps:8,seed:7,learningRate:0.0001,maxSteps:40,contextSelection:'cropped',precision:'fp16',modelDtype:'float16',quantComputeDtype:'float16'}).map(([key,bad])=>v=>v.targetIdentity[key]=bad),v=>v.targetIdentity.sampler.impossiblePerGroup=5];
 for(const change of changes){const changed=structuredClone(value);change(changed);assert.throws(()=>groundingJob(changed.runId,changed),/balanced_job_binding_invalid/);}
 assert.throws(()=>groundingJob(SOURCE_RUN,value),/balanced_job_binding_invalid/);
});

test('warmstart provenance cannot change history, reset, source pins or quality flags even with a recalculated digest',()=>{
 const value=inputs();
 const changes=[v=>v.groundingProvenance.kind='other',v=>v.groundingProvenance.sourceRunId='other',v=>v.groundingProvenance.sourceGlobalStep=80,v=>v.groundingProvenance.sourceOptimizerHistoryUpdates=60,v=>v.groundingProvenance.targetRunId='other',v=>v.groundingProvenance.targetOptimizerSteps=40,v=>v.groundingProvenance.optimizerReset=false,v=>v.groundingProvenance.schedulerReset=false,v=>v.groundingProvenance.sourceTrainingExecutionVerified=false,v=>v.groundingProvenance.qualityClaimAllowed=true,v=>v.groundingProvenance.promotionAllowed=true,v=>v.groundingProvenance.sourcePins.runtime='f'.repeat(64),v=>v.groundingProvenance.sourceIdentity.stage='public_qa_grounding_v1',v=>v.groundingProvenance.sourceIdentity.baseArtifactLockSha256='f'.repeat(64),v=>v.groundingProvenance.extra=true];
 for(const change of changes){const changed=structuredClone(value);change(changed);changed.provenanceSha256=sha(JSON.stringify(changed.groundingProvenance,null,2)+'\n');assert.throws(()=>groundingJob(RUN_ID,changed),/balanced_job_binding_invalid/);}
});

test('live PVC defaults are accepted while foreign claims, write scopes, projections and sidecars are rejected',()=>{
 const value=inputs(),pod=groundingJob(RUN_ID,value).spec.template;
 for(const volume of pod.spec.volumes)if(volume.persistentVolumeClaim)volume.persistentVolumeClaim.readOnly??=false;
 pod.spec.volumes.find(v=>v.name==='runtime').configMap.defaultMode=420;
 pod.spec.volumes.find(v=>v.name==='podinfo').downwardAPI.defaultMode=420;
 pod.spec.volumes.find(v=>v.name==='podinfo').downwardAPI.items[0].fieldRef.apiVersion='v1';
 assert.doesNotThrow(()=>assertGroundingMounts(pod,value));
 const changes=[p=>p.spec.volumes.find(v=>v.name==='data').persistentVolumeClaim.readOnly=false,p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='data').readOnly=false,p=>p.spec.volumes.find(v=>v.name==='warmstart').persistentVolumeClaim.readOnly=false,p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='warmstart').subPath='grounding-runs/foreign/candidate',p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='grounding-output').subPath='grounding-continuation-runs',p=>p.spec.volumes.find(v=>v.name==='base').hostPath={path:'/etc'},p=>p.spec.volumes.find(v=>v.name==='runtime').configMap.items=[{key:'elsewhere',path:'train-public-qa.py'}],p=>p.spec.volumes.find(v=>v.name==='runtime').configMap.optional=true,p=>p.spec.volumes.find(v=>v.name==='grounding-output').persistentVolumeClaim.claimName='foreign',p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='data').subPathExpr='$(FOREIGN)',p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='base').mountPropagation='Bidirectional',p=>p.spec.volumes.find(v=>v.name==='tmp').hostPath={path:'/host'},p=>p.spec.volumes.find(v=>v.name==='podinfo').downwardAPI.items[0].fieldRef.fieldPath='metadata.name',p=>p.spec.containers[0].volumeMounts.push({...p.spec.containers[0].volumeMounts[0]}),p=>p.spec.volumes.push({name:'extra',hostPath:{path:'/host'}}),p=>p.spec.containers.push({...p.spec.containers[0],name:'extra'}),p=>p.spec.initContainers=[{name:'extra'}],p=>p.spec.ephemeralContainers=[{name:'extra'}]];
 for(const change of changes){const changed=structuredClone(pod);change(changed);assert.throws(()=>assertGroundingMounts(changed,value),/live_balanced_/);}
});

test('inputs reject other runs and missing prepared data without attempting dataset regeneration',async()=>{
 await assert.rejects(()=>publicQaGroundingInputs({runId:'public-qa-balanced-other'}),/balanced_run_id_invalid/);
 const root=mkdtempSync(join(tmpdir(),'balanced-workload-missing-')),directory=join(root,'unprepared');mkdirSync(directory);
 // Keep the missing-preparation gate distinct from the outside-workspace gate.
 // An isolated CWD avoids changing the parent test process's global directory.
 const moduleUrl=pathToFileURL(resolve('scripts/public-qa-grounding-balanced-workload.mjs')).href;
 try{
  execFileSync(process.execPath,['--input-type=module','-e',`import assert from 'node:assert/strict';import {publicQaGroundingInputs} from ${JSON.stringify(moduleUrl)};await assert.rejects(()=>publicQaGroundingInputs({directory:'unprepared'}),/balanced_prepared_dataset_required/);`],{cwd:root,windowsHide:true,timeout:15000,stdio:'pipe'});
  assert.equal(existsSync(join(directory,'data.jsonl')),false);assert.equal(existsSync(join(directory,'provenance.json')),false);
 }finally{rmSync(root,{recursive:true,force:true});}
});


test('historical mount checks bind the recorded ConfigMap without requiring today runtime hashes',()=>{
 const original=inputs(),pod=groundingJob(RUN_ID,original).spec.template,historical=structuredClone(original);
 historical.runtimeConfigMap='public-qa-gbal-'+ 'e'.repeat(16);historical.runtimeSha256='e'.repeat(64);
 historical.runtimeFiles['train-public-qa.py']='e'.repeat(64);historical.targetIdentity.trainerSha256='e'.repeat(64);
 pod.spec.volumes.find(volume=>volume.name==='runtime').configMap.name=historical.runtimeConfigMap;
 assert.throws(()=>groundingJob(RUN_ID,historical),/balanced_job_binding_invalid/);
 assert.doesNotThrow(()=>assertGroundingMounts(pod,historical));
 const wrong=structuredClone(pod);wrong.spec.volumes.find(volume=>volume.name==='runtime').configMap.name=original.runtimeConfigMap;
 assert.throws(()=>assertGroundingMounts(wrong,historical),/live_balanced_mount_scope_invalid/);
});

test('fresh r2 identity has independent manifest and output while historical r1 remains valid',()=>{
 const r1=inputs(),r2=inputs(RETRY_RUN_ID),job=groundingJob(RETRY_RUN_ID,r2);
 assert.deepEqual(balancedDataPins(RUN_ID),BALANCED_DATA_PINS);
 assert.equal(r1.datasetSha256,r2.datasetSha256);assert.notEqual(r1.manifestSha256,r2.manifestSha256);
 assert.notEqual(r1.provenanceSha256,r2.provenanceSha256);
 assert.equal(job.spec.template.spec.containers[0].volumeMounts.find(m=>m.name==='data').subPath,'grounding-balanced/'+RETRY_RUN_ID);
 assert.equal(job.spec.template.spec.containers[0].args.at(-3),'/checkpoints/runs/'+RETRY_RUN_ID);
 assert.doesNotThrow(()=>groundingJob(RUN_ID,r1));assert.doesNotThrow(()=>assertGroundingMounts(job.spec.template,r2));
 for(const change of [v=>v.manifestSha256=r1.manifestSha256,v=>v.targetIdentity.manifestSha256=r1.manifestSha256,
  v=>v.groundingProvenance.targetRunId=RUN_ID,v=>v.pvcOutputRelativePath='grounding-balanced-runs/'+RUN_ID]){
  const altered=structuredClone(r2);change(altered);altered.provenanceSha256=sha(JSON.stringify(altered.groundingProvenance,null,2)+'\n');
  assert.throws(()=>groundingJob(RETRY_RUN_ID,altered),/balanced_job_binding_invalid/);
 }
 const foreign=structuredClone(job.spec.template);foreign.spec.containers[0].volumeMounts.find(m=>m.name==='data').subPath='grounding-balanced/'+RUN_ID;
 assert.throws(()=>assertGroundingMounts(foreign,r2),/live_balanced_mount_scope_invalid/);
 assert.throws(()=>balancedDataPins('public-qa-balanced-20261006-r3'),/balanced_run_id_invalid/);
});
