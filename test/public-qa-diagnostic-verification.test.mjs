import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync,unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {verifyPublicQaDiagnostic,verifyPublicQaDiagnosticFixture} from '../scripts/verify-public-qa-diagnostic.mjs';
import {DIAGNOSTIC_PINS,DIAGNOSTIC_SOURCE_RUN,STAGE2_DIAGNOSTIC_PINS,STAGE2_DIAGNOSTIC_SOURCE_RUN,diagnosticJob} from '../scripts/public-qa-diagnostic-workload.mjs';
import {QA_IMAGE,QA_BASE_REVISION,QA_NAMESPACE,QA_NODE} from '../scripts/public-qa-workload.mjs';

const sha=v=>createHash('sha256').update(v).digest('hex');
// Deliberately synthetic; the fixture entry point never returns actual-execution success.
function fixture(t,{excluded=1,stageTwo=false}={}){
 const root=mkdtempSync(resolve(tmpdir(),'evidscope-diagnostic-verifier-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const runId='public-qa-synthetic-verifier',runDirectory=resolve(root,'output'),controllerReceipt=resolve(root,'controller/controller-receipt.json');
 const put=(name,value,bom=false)=>{const path=resolve(root,name);mkdirSync(dirname(path),{recursive:true});writeFileSync(path,(bom?'\uFEFF':'')+(typeof value==='string'?value:JSON.stringify(value)));return readFileSync(path);};
 const get=name=>JSON.parse(readFileSync(resolve(root,name),'utf8').replace(/^\uFEFF/,''));
 const edit=(name,fn)=>{const value=get(name);fn(value);put(name,value);};
 const data=Array.from({length:64},(_,i)=>({id:`row-${i}`,context:`context ${i}`,contextSha256:sha(`context ${i}`)}));
 const sourceRunId=stageTwo?STAGE2_DIAGNOSTIC_SOURCE_RUN:DIAGNOSTIC_SOURCE_RUN;
 const pins={};pins.datasetSha256=sha(put('source/data.jsonl',data.map(JSON.stringify).join('\n')));
 pins.manifestSha256=sha(put('source/manifest.json',{mode:'public_qa_diagnostic',diagnosticOnly:true,rowIds:data.map(r=>r.id),datasetSha256:pins.datasetSha256}));
 pins.artifactLockSha256=sha(put('source/lock.json',{revision:QA_BASE_REVISION}));
 pins.sourceControllerSha256=sha(put('source/failed-controller.json',stageTwo?{runId:sourceRunId,mode:'explicit_public_human_qa_stage2',state:'process_completed',exit:{exitCode:0},terminationConfirmed:true,trainingRunCompleted:false}:{state:'error',trainingRunCompleted:false}));
 pins.sourceVerificationSha256=sha(put('source/failed-verification.json',{verified:false,trainingRunCompleted:false,promotionAllowed:false}));
 const adapter=put('candidate/adapter_model.safetensors','synthetic adapter bytes');
 const candidate={globalStep:stageTwo?40:20,identity:{baseRevision:QA_BASE_REVISION,baseArtifactLockSha256:pins.artifactLockSha256,...(stageTwo?{stage:'public_qa_stage2',maxSteps:40}:{})},files:[{path:'adapter_model.safetensors',bytes:adapter.length,sha256:sha(adapter)}]};
 pins.candidateMarkerSha256=sha(put('candidate/candidate-complete.json',candidate));
 if(stageTwo){pins.adapterSha256=sha(adapter);pins.sourceRuntimeConfigMapSha256=sha(put('source/runtime-configmap.json',{data:{fixture:'source training runtime'}}));pins.sourceVerificationSha256=sha(put('source/failed-verification.json',{runId:sourceRunId,verified:true,trainingRunCompleted:true,terminationConfirmed:true,globalStep:40,actualOptimizerUpdates:40,skippedOptimizerUpdates:0,artifactSha256:pins.candidateMarkerSha256,controllerSha256:pins.sourceControllerSha256,runtimeConfigMapSha256:pins.sourceRuntimeConfigMapSha256,qualityClaimAllowed:false,promotionAllowed:false,identity:candidate.identity}));}
 const runtimeData=Object.fromEntries(['evaluate-public-qa-diagnostic.py','training_artifacts.py','public_qa_cuda_runtime.py','public_qa_memory_gate.py','public_qa_thermal.py'].map(n=>[n,`# synthetic exported ${n}\n`])),runtimeSha256=sha(JSON.stringify(runtimeData)),runtimeConfigMap='public-qa-diagnostic-'+runtimeSha256.slice(0,16);
 put('controller/runtime-configmap.json',{immutable:true,metadata:{namespace:QA_NAMESPACE,name:runtimeConfigMap,annotations:{'evidscope.io/code-sha256':runtimeSha256}},data:runtimeData},true);
 const inputs={...pins,mode:'public_qa_diagnostic',diagnosticOnly:true,sourceRunId,rows:64,trainingProvenanceVerified:stageTwo,qualityClaimAllowed:false,promotionAllowed:false,runtimeConfigMap,runtimeSha256,runtimeFiles:Object.fromEntries(Object.entries(runtimeData).map(([k,v])=>[k,sha(v)])),data:'source/data.jsonl',manifest:'source/manifest.json',lock:'source/lock.json',sourceController:'source/failed-controller.json',sourceVerification:'source/failed-verification.json',candidateMarker:'candidate/candidate-complete.json',...(stageTwo?{adapter:'candidate/adapter_model.safetensors',sourceRuntime:'source/runtime-configmap.json'}:{})};
 const job=diagnosticJob(runId,{...inputs,...(stageTwo?STAGE2_DIAGNOSTIC_PINS:DIAGNOSTIC_PINS)});
 const env=job.spec.template.spec.containers[0].env;for(const [name,key] of Object.entries({EVIDSCOPE_DIAGNOSTIC_DATA_SHA256:'datasetSha256',EVIDSCOPE_DIAGNOSTIC_MANIFEST_SHA256:'manifestSha256',EVIDSCOPE_DIAGNOSTIC_CONTROLLER_SHA256:'sourceControllerSha256',EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:'artifactLockSha256',...(stageTwo?{EVIDSCOPE_DIAGNOSTIC_VERIFICATION_SHA256:'sourceVerificationSha256',EVIDSCOPE_DIAGNOSTIC_CANDIDATE_SHA256:'candidateMarkerSha256',EVIDSCOPE_DIAGNOSTIC_ADAPTER_SHA256:'adapterSha256'}:{})}))env.find(e=>e.name===name).value=inputs[key];
 const liveSpec={...structuredClone(job.spec.template.spec),nodeName:QA_NODE},podUid='synthetic-pod-uid',jobUid='synthetic-job-uid',podName=runId+'-pod';
 put('controller/live-job.json',{metadata:{name:runId,namespace:QA_NAMESPACE,uid:jobUid},spec:{template:{spec:job.spec.template.spec}}},true);
 put('controller/live-pod.json',{metadata:{name:podName,namespace:QA_NAMESPACE,uid:podUid,ownerReferences:[{kind:'Job',name:runId,uid:jobUid}]},spec:liveSpec},true);
 const controller={runId,jobUid,podUid,podName,mode:'explicit_public_qa_diagnostic',diagnosticOnly:true,state:'process_completed',exit:{exitCode:0},terminationConfirmed:true,admission:{allowed:true},trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false,automaticGovernanceGateClaimed:false,inputs,manifest:job,manifestSha256:sha(JSON.stringify(job)),livePodSpec:liveSpec,memoryHigh:{podUid,markerReleased:true,containerLeafOnly:true,memoryHigh:'2147483648',memoryMax:'12884901888'}};
 put('controller/controller-receipt.json',controller,true);
 const admission={datasetSha256:pins.datasetSha256,manifestSha256:pins.manifestSha256,beforeAnyModelCall:true,answerBasedCropping:false,admitted:64-excluded,excluded,rows:data.map((row,i)=>({id:row.id,inputTokens:i>=64-excluded?900:50,outputTokenBudget:128,contextTokens:1024,contextSha256:row.contextSha256,fullContextPreserved:true,admitted:i<64-excluded,exclusionReason:i>=64-excluded?'full_context_token_budget_exceeded':null}))};
 const responses={mode:'public_qa_diagnostic',datasetSha256:pins.datasetSha256,maxOutputTokens:128,requestTimeoutSeconds:120,baseline:{},candidate:{}},logs=[];
 for(const side of ['baseline','candidate'])for(const a of admission.rows){const r={content:a.admitted?'synthetic answer':'',seconds:a.admitted?1.25:0,inputTokens:a.inputTokens,outputTokens:a.admitted?5:0,timedOut:false,tokenLimitReached:false,...(!a.admitted?{error:'full_context_token_budget_exceeded'}:{})};responses[side][a.id]=r;if(a.admitted){put(`output/rows/${side}-${a.id}.json`,{id:a.id,side,...r});logs.push({side,id:a.id,modelCalls:logs.length+1,seconds:r.seconds,outputTokens:r.outputTokens,timedOut:r.timedOut,tokenLimitReached:r.tokenLimitReached});}}
 const receipt={diagnosticOnly:true,source:'isolated_public_qa_generation',state:'generation_completed',podUid,image:QA_IMAGE,deviceId:'synthetic-device',sourceTrainingExecutionVerified:stageTwo,...(stageTwo?{sourceTrainingVerificationSha256:pins.sourceVerificationSha256}:{}),controllerExecutionVerified:false,sourceTrainingControllerFileReadInPod:false,qualityClaimAllowed:false,promotionAllowed:false,localHumanReviewPerformed:false,datasetSha256:pins.datasetSha256,manifestSha256:pins.manifestSha256,candidateMarkerSha256:pins.candidateMarkerSha256,adapterSha256:sha(adapter),baseArtifactLockSha256:pins.artifactLockSha256,sourceTrainingControllerSha256:pins.sourceControllerSha256,candidateIdentity:candidate.identity,preparedRows:64,admittedRows:63,excludedRows:1,modelCalls:126,cudaPeakAllocatedBytes:100,cudaPeakReservedBytes:200,resources:{cpuLimit:2,memoryLimitGiB:12,gpuAllocatorFraction:.65,contextTokens:1024,maxOutputTokens:128,requestTimeoutSeconds:120,seed:42,doSample:false,quantization:'NF4',samePromptsAndResources:true}};
 receipt.admittedRows=admission.admitted;receipt.excludedRows=admission.excluded;receipt.modelCalls=2*admission.admitted;
 put('output/progress.json',receipt);receipt.responsesSha256=sha(put('output/responses.json',responses));receipt.preadmissionSha256=sha(put('output/preadmission.json',admission));put('output/diagnostic-receipt.json',receipt);
 put('controller/training.log','Library startup\n'+logs.map(JSON.stringify).join('\n')+'\n');
 const options={runDirectory,controllerReceipt,workspaceRoot:root};
 const seal=()=>{const r=get('output/diagnostic-receipt.json');r.responsesSha256=sha(readFileSync(resolve(root,'output/responses.json')));r.preadmissionSha256=sha(readFileSync(resolve(root,'output/preadmission.json')));put('output/diagnostic-receipt.json',r);const {responsesSha256,preadmissionSha256,...progress}=r;put('output/progress.json',progress);};
 return {root,put,get,edit,pins,options,seal,verify:()=>verifyPublicQaDiagnosticFixture(options,pins)};
}

test('complete persisted synthetic evidence with BOM verifies consistency without claiming actual execution or quality',t=>{
 const f=fixture(t),result=f.verify();assert.equal(result.verificationPassed,true);assert.equal(result.evaluationExecutionVerified,false);assert.equal(result.syntheticFixture,true);assert.equal(result.modelCalls,126);assert.equal(result.excludedRows,1);for(const key of ['sourceTrainingExecutionVerified','trainingRunCompleted','qualityClaimAllowed','promotionAllowed'])assert.equal(result[key],false);
 assert.throws(()=>verifyPublicQaDiagnostic(f.options),/diagnostic_input_pin_changed/);
});
test('stage2 binds a verified forty-step source and same-base paired generation without synthetic quality claims',t=>{
 const f=fixture(t,{stageTwo:true}),result=f.verify();assert.equal(result.verificationPassed,true);assert.equal(result.syntheticFixture,true);
 assert.equal(result.evaluationExecutionVerified,false);assert.equal(result.qualityClaimAllowed,false);assert.equal(result.promotionAllowed,false);
 assert.ok(!result.limitations.some(value=>value.includes('failure remains')));assert.throws(()=>verifyPublicQaDiagnostic(f.options),/diagnostic_input_pin_changed/);
});
test('stage2 rejects source verification mismatch even after repinning fixture bytes',t=>{
 for(const [field,value]of [['verified',false],['actualOptimizerUpdates',39],['terminationConfirmed',false],['qualityClaimAllowed',true],['artifactSha256','f'.repeat(64)]]){
  const f=fixture(t,{stageTwo:true});f.edit('source/failed-verification.json',v=>{v[field]=value;});
  f.pins.sourceVerificationSha256=sha(readFileSync(resolve(f.root,'source/failed-verification.json')));
  f.edit('controller/controller-receipt.json',c=>{c.inputs.sourceVerificationSha256=f.pins.sourceVerificationSha256;});
  assert.throws(f.verify,/source_stage2_training_not_verified/);
 }
});
test('stage2 refuses lost verified-source claim, changed candidate or source runtime, and writable adapter',t=>{
 for(const [file,change,error]of [
  ['output/diagnostic-receipt.json',r=>{r.sourceTrainingExecutionVerified=false;},/diagnostic_source_training_claim_changed/],
  ['output/diagnostic-receipt.json',r=>{r.sourceTrainingVerificationSha256='f'.repeat(64);},/diagnostic_source_verification_changed/],
  ['source/runtime-configmap.json',r=>{r.data.fixture='changed';},/diagnostic_source_changed:sourceRuntime/],
  ['controller/live-pod.json',p=>{p.spec.containers[0].volumeMounts.find(v=>v.name==='adapters').readOnly=false;},/live_diagnostic_mount_scope_invalid/],
 ]){const f=fixture(t,{stageTwo:true});f.edit(file,change);assert.throws(f.verify,error);}
 const f=fixture(t,{stageTwo:true});f.put('candidate/adapter_model.safetensors','changed stage2 adapter');assert.throws(f.verify,/diagnostic_source_changed:adapter/);
});
test('stage2 cannot substitute stage1 command, candidate mount or verification environment in the live Pod',t=>{
 for(const change of [p=>{p.spec.containers[0].args.splice(-2);},p=>{p.spec.containers[0].volumeMounts.find(v=>v.name==='adapters').subPath=`runs/${DIAGNOSTIC_SOURCE_RUN}/candidate`;},p=>{p.spec.containers[0].env.find(v=>v.name==='EVIDSCOPE_DIAGNOSTIC_VERIFICATION_SHA256').value='f'.repeat(64);}]){
  const f=fixture(t,{stageTwo:true});f.edit('controller/live-pod.json',change);assert.throws(f.verify,/diagnostic_command_changed|live_diagnostic_mount_scope_invalid|diagnostic_environment_changed/);
 }
});
test('all 64 admitted rows require 128 paired calls and raw partials',t=>{
 const f=fixture(t,{excluded:0}),result=f.verify();assert.equal(result.modelCalls,128);assert.equal(result.admittedRows,64);assert.equal(result.excludedRows,0);assert.equal(result.evaluationExecutionVerified,false);
});
test('production CLI rejects fixture pins and writes a failure receipt without overwriting controller evidence',t=>{
 const f=fixture(t),before=readFileSync(f.options.controllerReceipt),output=resolve(f.root,'verification.json');
 const run=spawnSync(process.execPath,[resolve('scripts/verify-public-qa-diagnostic.mjs'),f.options.runDirectory,f.options.controllerReceipt,output],{encoding:'utf8'});
 assert.equal(run.status,2,run.stderr);const report=JSON.parse(readFileSync(output));assert.equal(report.evaluationExecutionVerified,false);assert.equal(report.verificationPassed,false);assert.match(report.error,/diagnostic_input_pin_changed/);assert.deepEqual(readFileSync(f.options.controllerReceipt),before);
});
for(const [name,mutate,reason]of [
 ['exit zero without successful controller',f=>f.edit('controller/controller-receipt.json',r=>r.state='error'),/controller_execution/],
 ['missing termination confirmation',f=>f.edit('controller/controller-receipt.json',r=>r.terminationConfirmed=false),/controller_execution/],
 ['nonzero process exit',f=>f.edit('controller/controller-receipt.json',r=>r.exit.exitCode=1),/controller_execution/],
 ['admission denied',f=>f.edit('controller/controller-receipt.json',r=>r.admission.allowed=false),/controller_execution/],
 ['training mode passed as diagnostic',f=>f.edit('controller/controller-receipt.json',r=>r.mode='explicit_public_qa_training'),/controller_execution/],
 ['controller cannot mask generation error',f=>f.edit('output/diagnostic-receipt.json',r=>r.state='error'),/generation_unverified/],
 ['different Pod UID',f=>f.edit('controller/live-pod.json',r=>r.metadata.uid='foreign-pod'),/live_job_pod_binding/],
 ['different Job owner UID',f=>f.edit('controller/live-pod.json',r=>r.metadata.ownerReferences[0].uid='foreign-job'),/live_job_pod_binding/],
 ['different generation Pod UID',f=>f.edit('output/diagnostic-receipt.json',r=>r.podUid='foreign-pod'),/generation_unverified/],
 ['missing response file',f=>unlinkSync(resolve(f.root,'output/responses.json')),/ENOENT/],
 ['response bytes changed',f=>f.edit('output/responses.json',r=>r.baseline['row-0'].content='forged'),/receipt_binding/],
 ['raw row differs despite recomputed response hash',f=>{f.edit('output/responses.json',r=>r.baseline['row-0'].content='forged');f.seal();},/row_partial_changed/],
 ['missing response ID despite recomputed hash',f=>{f.edit('output/responses.json',r=>delete r.baseline['row-0']);f.seal();},/response_ids_changed/],
 ['invalid raw elapsed time',f=>{f.edit('output/responses.json',r=>r.baseline['row-0'].seconds=null);f.seal();},/measurement_invalid/],
 ['negative token measurement',f=>{f.edit('output/responses.json',r=>r.baseline['row-0'].outputTokens=-1);f.seal();},/measurement_invalid/],
 ['excluded sample lacks error flag',f=>{f.edit('output/responses.json',r=>delete r.candidate['row-63'].error);f.seal();},/exclusion_changed/],
 ['admission crops full context',f=>{f.edit('output/preadmission.json',r=>r.rows[0].fullContextPreserved=false);f.seal();},/preadmission_row/],
 ['model call total inconsistent',f=>{f.edit('output/diagnostic-receipt.json',r=>r.modelCalls=128);f.seal();},/counts_invalid/],
 ['stdout call omitted',f=>f.put('controller/training.log','{}\n'),/generation_log_mismatch/],
 ['runtime code changed',f=>f.edit('controller/runtime-configmap.json',r=>r.data['training_artifacts.py']+='\n# change'),/runtime_changed/],
 ['source failed controller overwritten',f=>f.edit('source/failed-controller.json',r=>r.state='process_completed'),/source_changed/],
 ['candidate adapter changed',f=>f.put('candidate/adapter_model.safetensors','forged bytes'),/candidate_file_changed/],
 ['unexpected candidate file',f=>f.put('candidate/extra.py','extra'),/candidate_inventory_changed/],
 ['writable candidate live mount',f=>f.edit('controller/live-pod.json',r=>r.spec.containers[0].volumeMounts.find(m=>m.name==='adapters').readOnly=false),/mount_scope/],
 ['writable outputs escape diagnostic subtree',f=>f.edit('controller/live-pod.json',r=>r.spec.containers[0].volumeMounts.find(m=>m.name==='diagnostic-output').subPath='runs'),/mount_scope/],
 ['manifest mismatch',f=>f.edit('controller/controller-receipt.json',r=>r.manifest.metadata.name='public-qa-other'),/job_manifest_changed/],
 ['source path escape',f=>f.edit('controller/controller-receipt.json',r=>r.inputs.data='../outside.jsonl'),/path_escape/],
 ['missing raw row',f=>unlinkSync(resolve(f.root,'output/rows/baseline-row-0.json')),/ENOENT/],
 ['extra raw row',f=>f.put('output/rows/extra.json',{}),/row_inventory/],
])test(`rejects ${name}`,t=>{const f=fixture(t);mutate(f);assert.throws(f.verify,reason);});
