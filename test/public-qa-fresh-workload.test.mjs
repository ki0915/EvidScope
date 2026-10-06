import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,rmSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {FRESH_SOURCE_RUN,FRESH_SOURCE_PINS,FRESH_DATA_PINS,FRESH_SCOPE,freshEvaluationJob,assertFreshEvaluationMounts,freshEvaluationRuntimeConfigMap,publicQaFreshEvaluationInputs,verifyFrozenFreshEvaluation} from '../scripts/public-qa-fresh-workload.mjs';
import {FRESH_EVALUATION_STAGE} from '../scripts/prepare-public-qa-fresh-evaluation.mjs';
import {QA_NAMESPACE,QA_IMAGE,QA_BASE_REVISION,QA_NODE} from '../scripts/public-qa-workload.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
function inputs(){
 const runId='public-qa-fresh-test-1',candidateIdentity={baseRepository:'fdtn-ai/Foundation-Sec-8B-Reasoning',baseRevision:QA_BASE_REVISION,baseArtifactLockSha256:FRESH_SOURCE_PINS.artifactLockSha256,image:QA_IMAGE,stage:'public_qa_grounding_continuation_v1',maxSteps:20},binding={schemaVersion:1,mode:'public_qa_fresh_paired_evaluation',stage:FRESH_EVALUATION_STAGE,diagnosticOnly:true,runId,sourceRunId:FRESH_SOURCE_RUN,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:80,sourceTrainingExecutionVerified:true,candidateIdentity,...FRESH_SOURCE_PINS,...FRESH_DATA_PINS,rows:128,baselineExecutedThisRun:true,executionOrder:['baseline','candidate'],baselineKind:'fixed_reasoning_base_without_adapter',evaluationScope:FRESH_SCOPE,qualityClaimAllowed:false,promotionAllowed:false,localHumanReviewPerformed:false};
 return {...binding,binding,bindingSha256:sha(JSON.stringify(binding,null,2)+'\n'),runtimeConfigMap:'public-qa-fresh-'+ 'b'.repeat(16),runtimeSha256:'b'.repeat(64)};
}
test('fresh paired job fixes source80, unseen128 and sequential same-base comparison with unchanged resource isolation',()=>{
 const value=inputs(),job=freshEvaluationJob(value.runId,value),s=job.spec.template.spec,c=s.containers[0];
 assert.equal(job.metadata.namespace,QA_NAMESPACE);assert.equal(job.spec.backoffLimit,0);assert.equal(job.spec.activeDeadlineSeconds,3600);assert.equal(s.nodeSelector['kubernetes.io/hostname'],QA_NODE);assert.equal(s.runtimeClassName,'nvidia');assert.equal(s.automountServiceAccountToken,false);assert.equal(s.securityContext.runAsNonRoot,true);assert.equal(c.image,QA_IMAGE);assert.deepEqual(c.command,['python','/runtime/evaluate-public-qa-fresh.py']);assert.equal(c.resources.limits.cpu,'2');assert.equal(c.resources.limits.memory,'12Gi');assert.equal(c.resources.limits['nvidia.com/gpu'],'1');assert.equal(c.securityContext.readOnlyRootFilesystem,true);assert.equal(c.securityContext.allowPrivilegeEscalation,false);assert.deepEqual(c.securityContext.capabilities.drop,['ALL']);
 const mounts=Object.fromEntries(c.volumeMounts.map(m=>[m.name,m]));assert.deepEqual(mounts.adapters,{name:'adapters',mountPath:'/adapters/candidate',subPath:'grounding-continuation-runs/'+FRESH_SOURCE_RUN+'/candidate',readOnly:true});assert.equal(mounts.data.subPath,'fresh-evaluation');assert.equal(mounts.binding.subPath,'fresh-evaluation-bindings/'+value.runId);assert.equal(mounts['fresh-output'].subPath,'fresh-evaluations');assert.equal(mounts['fresh-output'].readOnly,false);assert.equal(mounts.checkpoints,undefined);assert.doesNotThrow(()=>assertFreshEvaluationMounts({spec:s},value));
 const env=Object.fromEntries(c.env.map(item=>[item.name,item.value]));assert.equal(env.EVIDSCOPE_FRESH_EVALUATION_BINDING_SHA256,value.bindingSha256);for(const [name,key]of Object.entries({DATA:'datasetSha256',MANIFEST:'manifestSha256',CONTROLLER:'sourceControllerSha256',VERIFICATION:'sourceVerificationSha256',CANDIDATE:'candidateMarkerSha256',ADAPTER:'adapterSha256'}))assert.equal(env['EVIDSCOPE_DIAGNOSTIC_'+name+'_SHA256'],value[key]);assert.equal(env.EVIDSCOPE_ISOLATED,'1');assert.equal(env.EVIDSCOPE_MEMORY_HIGH_REQUIRED,'1');assert.equal(c.args[c.args.indexOf('--cri-inspection')+1],'/bindings/cri-inspect.json');
 const token=freshEvaluationJob(value.runId,value,{tokenCheck:true});assert.equal(token.spec.template.spec.containers[0].resources.limits['nvidia.com/gpu'],undefined);assert.equal(token.spec.template.spec.containers[0].args.at(-1),'--token-check');
});
test('fresh generation binding rejects altered source, data, comparison and self-consistent false claims',()=>{
 const edits=[v=>v.sourceRunId='public-qa-grounding-20261005-r4',v=>v.sourceOptimizerHistoryUpdates=60,v=>v.sourceGlobalStep=80,v=>v.rows=64,v=>v.baselineExecutedThisRun=false,v=>v.executionOrder.reverse(),v=>v.promotionAllowed=true,v=>v.mode='public_qa_grounding_diagnostic',v=>v.stage='public_qa_grounding_v1',v=>v.runtimeConfigMap='public-qa-fresh-'+'a'.repeat(16),v=>v.binding.sourceTrainingExecutionVerified=false,v=>v.binding.extraClaim=true,v=>{v.candidateIdentity.stage='public_qa_grounding_v1';v.bindingSha256=sha(JSON.stringify(v.binding,null,2)+'\n');}];
 for(const edit of edits){const value=inputs();edit(value);assert.throws(()=>freshEvaluationJob(value.runId,value),/fresh_evaluation_job_/);}
 for(const key of Object.keys({...FRESH_SOURCE_PINS,...FRESH_DATA_PINS})){const value=inputs();value[key]='e'.repeat(64);value.binding[key]=value[key];value.bindingSha256=sha(JSON.stringify(value.binding,null,2)+'\n');assert.throws(()=>freshEvaluationJob(value.runId,value),/job_pin_changed/);}
 const value=inputs();assert.throws(()=>freshEvaluationJob('public-qa-fresh-'+ 'a'.repeat(29),value),/job_binding_invalid/);
});
test('live mounts tolerate Kubernetes defaults while rejecting broader volumes and writable source evidence',()=>{
 const value=inputs(),pod=freshEvaluationJob(value.runId,value).spec.template;
 for(const volume of pod.spec.volumes){if(volume.persistentVolumeClaim)volume.persistentVolumeClaim.readOnly??=false;if(volume.configMap)volume.configMap.defaultMode=420;if(volume.downwardAPI){volume.downwardAPI.defaultMode=420;volume.downwardAPI.items[0].fieldRef.apiVersion='v1';}}
 for(const mount of pod.spec.containers[0].volumeMounts)if(mount.readOnly)mount.recursiveReadOnly='Disabled';
 assert.doesNotThrow(()=>assertFreshEvaluationMounts(pod,value));
 for(const edit of [p=>p.spec.volumes.find(v=>v.name==='runtime').configMap.optional='false',p=>p.spec.volumes.find(v=>v.name==='podinfo').downwardAPI.items[0].resourceFieldRef={resource:'limits.memory'},p=>p.spec.volumes.find(v=>v.name==='podinfo').downwardAPI.items[0].fieldRef.apiVersion='v2',p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='adapters').readOnly=false,p=>p.spec.volumes.find(v=>v.name==='adapters').persistentVolumeClaim.readOnly=false,p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='binding').subPath='fresh-evaluation-bindings/foreign',p=>p.spec.volumes.find(v=>v.name==='data').hostPath={path:'/etc'},p=>p.spec.volumes.find(v=>v.name==='runtime').configMap.items=[{key:'other',path:'evaluate-public-qa-fresh.py'}],p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='data').subPathExpr='$(OTHER)',p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='data').readOnly='true',p=>p.spec.containers[0].volumeMounts.find(m=>m.name==='data').mountPropagation='Bidirectional',p=>p.spec.containers.push(structuredClone(p.spec.containers[0])),p=>p.spec.volumes.push({name:'extra',persistentVolumeClaim:{claimName:'public-qa-checkpoints'}})]){const changed=structuredClone(pod);edit(changed);assert.throws(()=>assertFreshEvaluationMounts(changed,value),/fresh_evaluation_live_/);}
});
test('missing private source artifacts fail closed without fabricated public evaluation admission',async t=>{
 const root=mkdtempSync(join(tmpdir(),'evidscope-fresh-missing-'));t.after(()=>rmSync(root,{recursive:true,force:true}));assert.throws(()=>verifyFrozenFreshEvaluation({workspaceRoot:root}));await assert.rejects(publicQaFreshEvaluationInputs({runId:'public-qa-fresh-test-1',workspaceRoot:root}));
});
test('fresh runtime is immutable and binds all six shipped helper bytes without GPU calls',()=>{
 const code=freshEvaluationRuntimeConfigMap();assert.equal(code.immutable,true);assert.equal(code.metadata.namespace,QA_NAMESPACE);assert.deepEqual(Object.keys(code.data).sort(),['evaluate-public-qa-fresh.py','evaluate-public-qa-diagnostic.py','training_artifacts.py','public_qa_cuda_runtime.py','public_qa_memory_gate.py','public_qa_thermal.py'].sort());const digest=sha(JSON.stringify(code.data));assert.equal(code.metadata.name,'public-qa-fresh-'+digest.slice(0,16));assert.equal(code.metadata.annotations['evidscope.io/code-sha256'],digest);assert.ok(code.data['evaluate-public-qa-fresh.py'].includes('def '));
});
test('a replaced runtime helper cannot redefine the frozen fresh experiment',t=>{
 const root=mkdtempSync(join(tmpdir(),'evidscope-fresh-code-')),previous=process.cwd();t.after(()=>rmSync(root,{recursive:true,force:true}));mkdirSync(join(root,'scripts'));
 for(const name of ['evaluate-public-qa-fresh.py','evaluate-public-qa-diagnostic.py','training_artifacts.py','public-qa-cuda-runtime.py','public-qa-memory-gate.py','public-qa-thermal.py'])writeFileSync(join(root,'scripts',name),readFileSync(join(previous,'scripts',name)));
 writeFileSync(join(root,'scripts','evaluate-public-qa-fresh.py'),'# replacement runtime\n');
 try{process.chdir(root);assert.throws(()=>freshEvaluationRuntimeConfigMap(),/fixed_runtime_changed/);}finally{process.chdir(previous);}
});

