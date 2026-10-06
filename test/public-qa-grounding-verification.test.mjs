import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,readdirSync,statSync,rmSync,unlinkSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,dirname,join} from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {verifyPublicQaGrounding,verifyPublicQaGroundingFixture} from '../scripts/verify-public-qa-grounding.mjs';
import {QA_BASE_REVISION,QA_IMAGE,QA_NAMESPACE,QA_NODE,podSpec} from '../scripts/public-qa-workload.mjs';
import {STAGE2_DIAGNOSTIC_SOURCE_RUN} from '../scripts/public-qa-diagnostic-workload.mjs';
import {GROUNDING_STAGE} from '../scripts/prepare-public-qa-grounding.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
function adapterBytes(value=.5){
 const header={__metadata__:{format:'pt'}},chunks=[];let offset=0;
 for(let layer=0;layer<32;layer++)for(const projection of ['q_proj','k_proj','v_proj','o_proj'])for(const side of ['A','B']){const chunk=Buffer.alloc(32);for(let index=0;index<8;index++)chunk.writeFloatLE(value,index*4);header[`base_model.model.model.layers.${layer}.self_attn.${projection}.lora_${side}.weight`]={dtype:'F32',shape:side==='A'?[8,1]:[1,8],data_offsets:[offset,offset+32]};offset+=32;chunks.push(chunk);}
 const headerBytes=Buffer.from(JSON.stringify(header)),prefix=Buffer.alloc(8);prefix.writeBigUInt64LE(BigInt(headerBytes.length));return Buffer.concat([prefix,headerBytes,...chunks]);
}
function fixture(t){
 const root=mkdtempSync(join(tmpdir(),'evidscope-grounding-verifier-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const runId='public-qa-grounding-test',runDirectory=resolve(root,'output'),controllerReceipt=resolve(root,'controller/controller-receipt.json');
 const put=(name,value,bom=false)=>{const path=resolve(root,name);mkdirSync(dirname(path),{recursive:true});writeFileSync(path,Buffer.isBuffer(value)?value:(bom?'\uFEFF':'')+(typeof value==='string'?value:JSON.stringify(value)));return readFileSync(path);};
 const get=name=>JSON.parse(readFileSync(resolve(root,name),'utf8').replace(/^\uFEFF/,''));
 const edit=(name,change)=>{const value=get(name);change(value);put(name,value);};
 const inventory=directory=>readdirSync(resolve(root,directory)).filter(name=>!name.endsWith('-complete.json')).sort().map(path=>({path,bytes:statSync(resolve(root,directory,path)).size,sha256:sha(readFileSync(resolve(root,directory,path)))}));
 const trainingPins={},datasetPins={},runtimeData=Object.fromEntries(['train-public-qa.py','train-foundation-lora.py','training_artifacts.py','resource-pilot.py','public_qa_cuda_runtime.py','public_qa_memory_gate.py','public_qa_kbit.py','public_qa_thermal.py','public_qa_resume.py','public_qa_grounding.py'].map(name=>[name,`# synthetic ${name}\n`])),runtimeSha256=sha(JSON.stringify(runtimeData)),runtimeConfigMap='public-qa-grounding-'+runtimeSha256.slice(0,16),runtimeFiles=Object.fromEntries(Object.entries(runtimeData).map(([name,value])=>[name,sha(value)]));
 trainingPins.artifactLockSha256=sha(put('source/lock.json',{revision:QA_BASE_REVISION}));
 const sourceIdentity={baseRepository:'fdtn-ai/Foundation-Sec-8B-Reasoning',baseRevision:QA_BASE_REVISION,baseArtifactLockSha256:trainingPins.artifactLockSha256,rank:8,sequenceLength:1024,batchSize:1,gradientAccumulationSteps:16,maxSteps:40,stage:'public_qa_stage2'};
 put('source/candidate/adapter_config.json',{r:8});put('source/candidate/adapter_model.safetensors','synthetic source adapter');put('source/candidate/training-receipt.json',{identity:sourceIdentity,globalStep:40});
 trainingPins.candidateMarkerSha256=sha(put('source/candidate/candidate-complete.json',{schemaVersion:1,identity:sourceIdentity,globalStep:40,files:inventory('source/candidate')}));
 trainingPins.adapterSha256=sha(readFileSync(resolve(root,'source/candidate/adapter_model.safetensors')));
 trainingPins.sourceControllerSha256=sha(put('source/controller.json',{runId:STAGE2_DIAGNOSTIC_SOURCE_RUN,mode:'explicit_public_human_qa_stage2',state:'process_completed',exit:{exitCode:0},terminationConfirmed:true}));
 trainingPins.sourceRuntimeConfigMapSha256=sha(put('source/runtime.json',{data:{fixture:'historic source trainer differs from current workspace'}}));
 trainingPins.sourceVerificationSha256=sha(put('source/verification.json',{verified:true,runId:STAGE2_DIAGNOSTIC_SOURCE_RUN,trainingRunCompleted:true,terminationConfirmed:true,globalStep:40,actualOptimizerUpdates:40,skippedOptimizerUpdates:0,qualityClaimAllowed:false,promotionAllowed:false,artifactSha256:trainingPins.candidateMarkerSha256,controllerSha256:trainingPins.sourceControllerSha256,runtimeConfigMapSha256:trainingPins.sourceRuntimeConfigMapSha256,identity:sourceIdentity}));
 const sourceRows=Array.from({length:704},(_,index)=>{const isImpossible=index%2===1,context=`정답 ${index}`,question=`질문 ${index}`,answers=isImpossible?[]:[{text:'정답',answer_start:0}];return {id:`row-${index}`,familyId:`family-${index}`,contextSha256:sha(context),context,question,answers,isImpossible,split:index<640?'train':'validation',originalQa:{question,answers,is_impossible:isImpossible}};});
 const lineRows=rows=>rows.map(JSON.stringify).join('\n')+'\n';
 const sourceFiles={sourceManifest:'source-manifest.json',sourceTrain:'source-train.jsonl',sourceValidation:'source-validation.jsonl',oldTraining:'old-training.jsonl',diagnostic:'diagnostic.jsonl'};
 datasetPins.sourceManifest=sha(put('data/source-manifest.json',{revision:'3efd98708a40ff49251fddde35453f8fbb11f536',license:'CC-BY-SA-4.0'}));
 datasetPins.sourceTrain=sha(put('data/source-train.jsonl',lineRows(sourceRows.slice(0,640))));datasetPins.sourceValidation=sha(put('data/source-validation.jsonl',lineRows(sourceRows.slice(640))));
 const excluded={id:'excluded',familyId:'excluded-family',contextSha256:sha('excluded')};datasetPins.oldTraining=sha(put('data/old-training.jsonl',lineRows([excluded])));datasetPins.diagnostic=sha(put('data/diagnostic.jsonl',lineRows([excluded])));
 const dataset=sourceRows.map(row=>({...row,stage:GROUNDING_STAGE,contextSelection:'full_original_context',localHumanReviewPerformed:false,privacyScreen:{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false}})),datasetSha256=sha(put('data/data.jsonl',lineRows(dataset)));
 const manifest={schemaVersion:1,stage:GROUNDING_STAGE,task:'korean_extractive_qa',datasetSha256,upstreamRevision:'3efd98708a40ff49251fddde35453f8fbb11f536',license:'CC-BY-SA-4.0',sourcePins:datasetPins,sourceFiles,counts:{train:640,validation:64},labelCounts:{train:{answerable:320,impossible:320},validation:{answerable:32,impossible:32}},heldoutUsed:false,localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false,selection:{maxContextCodepoints:650,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true},previousExposureOverlap:{id:0,family:0,context:0},rowIds:dataset.map(row=>row.id)},manifestSha256=sha(put('data/manifest.json',manifest));
 const identity={baseRepository:'fdtn-ai/Foundation-Sec-8B-Reasoning',baseRevision:QA_BASE_REVISION,baseArtifactLockSha256:trainingPins.artifactLockSha256,datasetSha256,manifestSha256,trainerSha256:runtimeFiles['train-public-qa.py'],artifactHelperSha256:runtimeFiles['training_artifacts.py'],bindingHelperSha256:runtimeFiles['train-foundation-lora.py'],groundingHelperSha256:runtimeFiles['public_qa_grounding.py'],image:QA_IMAGE,stage:GROUNDING_STAGE,contextSelection:'full_original_context',precision:'bf16',modelDtype:'bfloat16',quantComputeDtype:'bfloat16',rank:8,sequenceLength:1024,batchSize:1,gradientAccumulationSteps:16,seed:42,learningRate:.0001,maxSteps:20,gpuMemoryFraction:.65};
 const provenance={schemaVersion:1,kind:'adapter_only_warmstart_new_balanced_public_qa',sourceRunId:STAGE2_DIAGNOSTIC_SOURCE_RUN,sourceGlobalStep:40,sourcePins:{marker:trainingPins.candidateMarkerSha256,adapter:trainingPins.adapterSha256,controller:trainingPins.sourceControllerSha256,verification:trainingPins.sourceVerificationSha256},sourceIdentity,targetRunId:runId,targetIdentity:identity,optimizerReset:true,schedulerReset:true,targetOptimizerSteps:20,sourceTrainingExecutionVerified:true,qualityClaimAllowed:false,promotionAllowed:false},provenanceSha256=sha(put('data/provenance.json',provenance));
 const inputs={...trainingPins,sourceRunId:STAGE2_DIAGNOSTIC_SOURCE_RUN,sourceController:'source/controller.json',sourceVerification:'source/verification.json',sourceRuntime:'source/runtime.json',candidateMarker:'source/candidate/candidate-complete.json',adapter:'source/candidate/adapter_model.safetensors',lock:'source/lock.json',data:'data/data.jsonl',manifest:'data/manifest.json',datasetSha256,manifestSha256,mode:'explicit_public_human_qa_grounding',stage:GROUNDING_STAGE,diagnosticOnly:false,rows:704,runId,qualityClaimAllowed:false,promotionAllowed:false,runtimeConfigMap,runtimeSha256,runtimeFiles,targetIdentity:identity,provenancePath:'data/provenance.json',provenanceSha256,groundingProvenance:provenance};
 put('controller/runtime-configmap.json',{apiVersion:'v1',kind:'ConfigMap',immutable:true,metadata:{name:runtimeConfigMap,namespace:QA_NAMESPACE,annotations:{'evidscope.io/code-sha256':runtimeSha256}},data:runtimeData},true);
 const spec=podSpec({gpu:true}),container=spec.containers[0];
 spec.volumes=spec.volumes.filter(volume=>volume.name!=='checkpoints');container.volumeMounts=container.volumeMounts.filter(mount=>mount.name!=='checkpoints');Object.assign(container.volumeMounts.find(mount=>mount.name==='data'),{mountPath:'/data/grounding',subPath:`grounding/${runId}`});
 spec.volumes.push({name:'warmstart',persistentVolumeClaim:{claimName:'public-qa-checkpoints',readOnly:true}},{name:'grounding-output',persistentVolumeClaim:{claimName:'public-qa-checkpoints'}},{name:'runtime',configMap:{name:runtimeConfigMap}});container.volumeMounts.push({name:'warmstart',mountPath:'/warmstart/candidate',subPath:`runs/${STAGE2_DIAGNOSTIC_SOURCE_RUN}/candidate`,readOnly:true},{name:'grounding-output',mountPath:'/checkpoints/runs',subPath:'grounding-runs',readOnly:false},{name:'runtime',mountPath:'/runtime',readOnly:true});
 container.command=['python','/runtime/train-public-qa.py'];container.args=['--data','/data/grounding/data.jsonl','--manifest','/data/grounding/manifest.json','--grounding-provenance','/data/grounding/provenance.json','--warmstart-adapter','/warmstart/candidate','--model-dir','/models/foundation-base','--base-revision',QA_BASE_REVISION,'--output',`/checkpoints/runs/${runId}`,'--max-steps','20'];
 container.env=Object.entries({PYTHONPATH:'/runtime',EVIDSCOPE_ISOLATED:'1',EVIDSCOPE_MEMORY_HIGH_REQUIRED:'1',EVIDSCOPE_GROUNDING_PROVENANCE_SHA256:provenanceSha256,EVIDSCOPE_DATASET_SHA256:datasetSha256,EVIDSCOPE_BASE_REPOSITORY:'fdtn-ai/Foundation-Sec-8B-Reasoning',EVIDSCOPE_BASE_REVISION:QA_BASE_REVISION,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:trainingPins.artifactLockSha256,EVIDSCOPE_TRAINING_IMAGE:QA_IMAGE}).map(([name,value])=>({name,value}));
 const job={metadata:{name:runId,namespace:QA_NAMESPACE,annotations:{'evidscope.io/run-kind':'explicit-public-human-qa-grounding','evidscope.io/dataset-sha256':datasetSha256,'evidscope.io/manifest-sha256':manifestSha256,'evidscope.io/provenance-sha256':provenanceSha256}},spec:{template:{spec}}},liveSpec={...structuredClone(spec),nodeName:QA_NODE},jobUid='synthetic-job-uid',podUid='synthetic-pod-uid',podName=runId+'-pod';
 const controller={schemaVersion:1,runId,jobUid,podUid,podName,mode:'explicit_public_human_qa_grounding_v1',state:'process_completed',exit:{exitCode:0},terminationConfirmed:true,admission:{allowed:true},trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false,automaticGovernanceGateClaimed:false,inputs,manifest:job,manifestSha256:sha(JSON.stringify(job)),livePodSpec:liveSpec,memoryHigh:{podUid,markerReleased:true,containerLeafOnly:true,memoryHigh:'2147483648',memoryMax:'12884901888'}};
 put('controller/controller-receipt.json',controller,true);put('controller/live-job.json',{metadata:{name:runId,namespace:QA_NAMESPACE,uid:jobUid},spec:{template:{spec}}});put('controller/live-pod.json',{metadata:{name:podName,namespace:QA_NAMESPACE,uid:podUid,ownerReferences:[{name:runId,uid:jobUid,kind:'Job'}]},spec:liveSpec});
 const lineage={...provenance,provenanceSha256,sourceOptimizerUpdates:40,optimizerUpdatesThisExperiment:20,sourceStateLoaded:'adapter_only',optimizerStateLoaded:false,schedulerStateLoaded:false},metrics={train_loss:.4,eval_loss:.5,base_eval_loss:1.2};
 const receipt={schemaVersion:2,status:'trained_'+GROUNDING_STAGE,globalStep:20,identity,trainingMetrics:metrics,trainingRunCompleted:true,qualityClaimAllowed:false,promotionAllowed:false,heldOutTestUsedForTraining:false,localHumanReviewPerformed:false,sourceLicense:'CC-BY-SA-4.0',targetFormat:'exact_human_answer_json_without_generated_reasoning',groundingLineage:lineage,cudaPeakAllocatedBytes:100,cudaPeakReservedBytes:200,adapterFiniteCheck:{passed:true,tensorCount:256,nonFiniteTensorCount:0,dtypes:['torch.float32'],beforeCandidateSealing:true}};
 put('output/candidate/adapter_config.json',{r:8});put('output/candidate/adapter_model.safetensors',adapterBytes());put('output/candidate/training-receipt.json',receipt);
 const sealCandidate=()=>put('output/candidate/candidate-complete.json',{schemaVersion:1,globalStep:20,identity,metrics,files:inventory('output/candidate')});sealCandidate();
 for(const step of [10,20]){const directory='output/checkpoint-'+step;for(const name of ['adapter_config.json','optimizer.pt','scheduler.pt','rng_state.pth','training_args.bin'])put(directory+'/'+name,`synthetic ${step} ${name}`);put(directory+'/adapter_model.safetensors',adapterBytes(step===20?.5:.25));put(directory+'/trainer_state.json',{global_step:step});put(directory+'/checkpoint-complete.json',{schemaVersion:1,globalStep:step,identity,files:inventory(directory)});}
 put('output/encoding-receipt.json',{datasetSha256,rows:dataset.map(row=>({id:row.id,contextStart:0,contextEnd:Array.from(row.context).length,tokens:100,answerPreserved:true,originalContextSha256:row.contextSha256,selectedContextSha256:row.contextSha256}))});
 const records=Array.from({length:20},(_,index)=>({optimizerStep:index+1,actualOptimizerUpdates:index+1,skippedOptimizerUpdates:0,learningRate:.0001*(19-index)/20,cudaPeakAllocatedBytes:100,cudaPeakReservedBytes:200}));
 const writeLog=(steps=records)=>put('controller/training.log',JSON.stringify({groundingWarmstart:{...lineage,optimizerUpdatesThisExperiment:0}})+'\n'+JSON.stringify({groundingAdapterLoaded:true,sourceGlobalStep:40,newGlobalStep:0,optimizerStateLoaded:false,schedulerStateLoaded:false})+'\n'+steps.map(value=>'progress bar '+JSON.stringify(value)).join('\n')+'\n'+JSON.stringify({adapterFiniteCheck:receipt.adapterFiniteCheck})+'\n'+JSON.stringify(receipt)+'\n');writeLog();
 const options={runDirectory,controllerReceipt,workspaceRoot:root},pins={training:trainingPins,dataset:datasetPins};
 return {root,put,get,edit,options,pins,receipt,identity,lineage,records,writeLog,sealCandidate,verify:()=>verifyPublicQaGroundingFixture(options,pins)};
}

test('sealed balanced warmstart verifies local bindings while synthetic fixtures cannot claim training execution',async t=>{
 const f=fixture(t),result=await f.verify();assert.equal(result.verificationPassed,true);assert.equal(result.syntheticFixture,true);assert.equal(result.verified,false);assert.equal(result.actualTrainingExecutionVerified,false);assert.equal(result.trainingRunCompleted,false);assert.equal(result.qualityClaimAllowed,false);assert.equal(result.promotionAllowed,false);assert.equal(result.globalStep,20);assert.equal(result.sourceOptimizerUpdates,40);assert.equal(result.optimizerUpdatesThisRun,20);assert.equal(result.totalAdapterHistoryOptimizerUpdates,60);assert.equal(result.optimizerStateRestored,false);assert.deepEqual(result.checkpoints.map(value=>value.globalStep),[10,20]);assert.equal(result.adapterTensorVerification.allFinite,true);assert.equal(result.adapterTensorVerification.tensorCount,256);assert.equal(result.identity.precision,'bf16');
 await assert.rejects(verifyPublicQaGrounding(f.options),/grounding_source_pin_changed/);
});
test('production CLI rejects fixture pins and preserves existing report/evidence files',async t=>{
 const f=fixture(t),output=resolve(f.root,'verification.json'),before=readFileSync(f.options.controllerReceipt),run=spawnSync(process.execPath,['scripts/verify-public-qa-grounding.mjs',f.options.runDirectory,f.options.controllerReceipt,output],{encoding:'utf8'});
 assert.equal(run.status,2,run.stderr);const report=JSON.parse(readFileSync(output));assert.equal(report.actualTrainingExecutionVerified,false);assert.equal(report.trainingRunCompleted,false);assert.equal(report.promotionAllowed,false);assert.match(report.error,/grounding_source_pin_changed/);assert.deepEqual(readFileSync(f.options.controllerReceipt),before);
 const second=spawnSync(process.execPath,['scripts/verify-public-qa-grounding.mjs',f.options.runDirectory,f.options.controllerReceipt,output],{encoding:'utf8'});assert.notEqual(second.status,0);assert.deepEqual(JSON.parse(readFileSync(output)),report);
});
test('Kubernetes ConfigMap defaults preserve the measured mount contract',async t=>{
 const f=fixture(t);for(const path of ['controller/live-job.json','controller/live-pod.json'])f.edit(path,value=>{const spec=path.includes('live-job')?value.spec.template.spec:value.spec;spec.volumes.find(volume=>volume.name==='runtime').configMap.defaultMode=420;});
 assert.equal((await f.verify()).verificationPassed,true);
});
test('archived runtime accepts the additional grounding-only kbit helper but rejects unrelated runtime members',async t=>{
 const f=fixture(t),runtime=f.get('controller/runtime-configmap.json');
 runtime.data['public_qa_grounding_kbit.py']='# synthetic grounding-only kbit helper\n';
 const runtimeSha256=sha(JSON.stringify(runtime.data)),runtimeConfigMap='public-qa-grounding-'+runtimeSha256.slice(0,16);
 runtime.metadata.name=runtimeConfigMap;runtime.metadata.annotations['evidscope.io/code-sha256']=runtimeSha256;f.put('controller/runtime-configmap.json',runtime);
 const updateSpec=spec=>{spec.volumes.find(volume=>volume.name==='runtime').configMap.name=runtimeConfigMap;};
 f.edit('controller/controller-receipt.json',controller=>{Object.assign(controller.inputs,{runtimeConfigMap,runtimeSha256,runtimeFiles:Object.fromEntries(Object.entries(runtime.data).map(([name,value])=>[name,sha(value)]))});updateSpec(controller.manifest.spec.template.spec);updateSpec(controller.livePodSpec);controller.manifestSha256=sha(JSON.stringify(controller.manifest));});
 f.edit('controller/live-job.json',value=>updateSpec(value.spec.template.spec));f.edit('controller/live-pod.json',value=>updateSpec(value.spec));
 assert.equal((await f.verify()).verificationPassed,true);
 runtime.data['unrelated_helper.py']='# unrelated helper\n';f.put('controller/runtime-configmap.json',runtime);await assert.rejects(f.verify(),/runtime_changed/);
});
for(const [name,path,mutate,reason]of [
 ['nonzero exit','controller/controller-receipt.json',value=>value.exit.exitCode=1,/controller_execution/],
 ['unconfirmed reclamation','controller/controller-receipt.json',value=>value.terminationConfirmed=false,/controller_execution/],
 ['controller error','controller/controller-receipt.json',value=>value.error='failure',/controller_execution/],
 ['denied admission','controller/controller-receipt.json',value=>value.admission.allowed=false,/controller_execution/],
 ['changed source run','controller/controller-receipt.json',value=>value.inputs.sourceRunId='public-qa-other',/source_run/],
 ['diagnostic-only training label','controller/controller-receipt.json',value=>value.inputs.diagnosticOnly=true,/input_scope/],
 ['controller quality claim','controller/controller-receipt.json',value=>value.qualityClaimAllowed=true,/controller_claim/],
 ['changed runtime bytes','controller/runtime-configmap.json',value=>value.data['train-public-qa.py']+='change',/runtime_changed/],
 ['changed Job UID','controller/live-job.json',value=>value.metadata.uid='foreign-job',/job_pod_binding/],
 ['foreign owner Job','controller/live-pod.json',value=>value.metadata.ownerReferences[0].uid='foreign-job',/job_pod_binding/],
 ['wrong GPU node','controller/live-pod.json',value=>value.spec.nodeName='other-node',/node_or_user/],
 ['writable source adapter','controller/live-pod.json',value=>value.spec.containers[0].volumeMounts.find(mount=>mount.name==='warmstart').readOnly=false,/mounts_changed/],
 ['broad checkpoint mount','controller/live-pod.json',value=>delete value.spec.containers[0].volumeMounts.find(mount=>mount.name==='warmstart').subPath,/mounts_changed/],
 ['wrong runtime env','controller/live-pod.json',value=>value.spec.containers[0].env.find(item=>item.name==='EVIDSCOPE_DATASET_SHA256').value='f'.repeat(64),/environment_changed/],
 ['wrong optimizer count','controller/live-pod.json',value=>value.spec.containers[0].args[value.spec.containers[0].args.indexOf('--max-steps')+1]='60',/command_changed/],
 ['wrong memory cgroup','controller/controller-receipt.json',value=>value.memoryHigh.podUid='other-pod',/memory_control/],
 ['context crop receipt','output/encoding-receipt.json',value=>value.rows[0].contextStart=1,/full_context_encoding/],
 ['token overflow receipt','output/encoding-receipt.json',value=>value.rows[0].tokens=1025,/full_context_encoding/],
])test('grounding rejects '+name,async t=>{const f=fixture(t);f.edit(path,mutate);await assert.rejects(f.verify(),reason);});

test('new checkpoint and source adapter bytes remain bound to their complete markers',async t=>{
 const f=fixture(t);f.put('output/checkpoint-10/optimizer.pt','altered optimizer');await assert.rejects(f.verify(),/checkpoint_artifact_changed/);
 const g=fixture(t);g.put('source/candidate/adapter_model.safetensors','changed source adapter');await assert.rejects(g.verify(),/source_file_changed:adapter/);
 const h=fixture(t);h.put('output/candidate/extra.txt','unlisted');await assert.rejects(h.verify(),/candidate_artifact_changed/);
});
test('self-consistent final checkpoint cannot substitute a different adapter',async t=>{
 const f=fixture(t);f.put('output/checkpoint-20/adapter_model.safetensors','different sealed adapter');f.edit('output/checkpoint-20/checkpoint-complete.json',marker=>{const entry=marker.files.find(file=>file.path==='adapter_model.safetensors'),raw=readFileSync(resolve(f.root,'output/checkpoint-20/adapter_model.safetensors'));entry.bytes=raw.length;entry.sha256=sha(raw);});await assert.rejects(f.verify(),/final_checkpoint_adapter/);
});
test('source verification cannot conceal failed training after repinning synthetic fixture bytes',async t=>{
 const f=fixture(t);f.edit('source/verification.json',value=>value.actualOptimizerUpdates=39);f.pins.training.sourceVerificationSha256=sha(readFileSync(resolve(f.root,'source/verification.json')));f.edit('controller/controller-receipt.json',value=>value.inputs.sourceVerificationSha256=f.pins.training.sourceVerificationSha256);await assert.rejects(f.verify(),/source_training_unverified/);
});
test('exactly twenty ordered non-skipped new updates are required',async t=>{
 const f=fixture(t);for(const records of [f.records.slice(1),[...f.records,f.records.at(-1)],[...f.records].reverse(),f.records.map(value=>({...value,optimizerStep:value.optimizerStep+40})),f.records.map(value=>({...value,skippedOptimizerUpdates:1}))]){f.writeLog(records);await assert.rejects(f.verify(),/actual_optimizer_updates/);}
 f.writeLog(f.records.map((value,index)=>index===0?{...value,learningRate:0}:value));await assert.rejects(f.verify(),/update_measurement/);
});
test('warmstart must reset optimizer/scheduler and cannot be represented as checkpoint resume',async t=>{
 const f=fixture(t);f.put('controller/training.log',readFileSync(resolve(f.root,'controller/training.log'),'utf8').replace('"newGlobalStep":0','"newGlobalStep":40'));await assert.rejects(f.verify(),/adapter_only_warmstart/);
 f.writeLog();f.receipt.groundingLineage.optimizerStateLoaded=true;f.put('output/candidate/training-receipt.json',f.receipt);f.sealCandidate();await assert.rejects(f.verify(),/candidate_receipt/);
});
test('altered original annotations and reused old contexts cannot be hidden by resealing fixture hashes',async t=>{
 const f=fixture(t);f.edit('data/manifest.json',manifest=>manifest.selection.answerBasedCropping=true);const hash=sha(readFileSync(resolve(f.root,'data/manifest.json')));f.edit('controller/controller-receipt.json',controller=>controller.inputs.manifestSha256=hash);await assert.rejects(f.verify(),/dataset_context_policy/);
 const g=fixture(t);g.put('data/old-training.jsonl',JSON.stringify({id:'old',familyId:'old-family',contextSha256:sha('정답 0')})+'\n');g.pins.dataset.oldTraining=sha(readFileSync(resolve(g.root,'data/old-training.jsonl')));g.edit('data/manifest.json',manifest=>manifest.sourcePins.oldTraining=g.pins.dataset.oldTraining);const newHash=sha(readFileSync(resolve(g.root,'data/manifest.json')));g.edit('controller/controller-receipt.json',controller=>controller.inputs.manifestSha256=newHash);await assert.rejects(g.verify(),/previous_exposure_leakage/);
 const h=fixture(t),rows=readFileSync(resolve(h.root,'data/data.jsonl'),'utf8').trim().split('\n').map(JSON.parse);rows[0].question='generated question';const dataHash=sha(h.put('data/data.jsonl',rows.map(JSON.stringify).join('\n')+'\n'));h.edit('data/manifest.json',manifest=>manifest.datasetSha256=dataHash);const changedManifestHash=sha(readFileSync(resolve(h.root,'data/manifest.json')));h.edit('controller/controller-receipt.json',controller=>{controller.inputs.datasetSha256=dataHash;controller.inputs.manifestSha256=changedManifestHash;});await assert.rejects(h.verify(),/original_row_changed/);
});
test('missing and linked checkpoint members fail before execution success can be claimed',async t=>{
 const f=fixture(t);unlinkSync(resolve(f.root,'output/checkpoint-20/optimizer.pt'));await assert.rejects(f.verify(),/checkpoint_artifact_changed/);
 const g=fixture(t);symlinkSync(resolve(g.root,'source/candidate'),resolve(g.root,'output/candidate/linked'),process.platform==='win32'?'junction':'dir');await assert.rejects(g.verify(),/grounding_symlink/);
});
test('resealed NaN and infinity tensors cannot pass finite candidate inspection',async t=>{
 for(const value of [NaN,Infinity,-Infinity]){const f=fixture(t),raw=adapterBytes(value);f.put('output/candidate/adapter_model.safetensors',raw);f.sealCandidate();f.put('output/checkpoint-20/adapter_model.safetensors',raw);f.edit('output/checkpoint-20/checkpoint-complete.json',marker=>{const item=marker.files.find(file=>file.path==='adapter_model.safetensors');item.bytes=raw.length;item.sha256=sha(raw);});await assert.rejects(f.verify(),/adapter_nonfinite_tensor/);}
});
test('the new experiment cannot conceal an FP16 identity after candidate resealing',async t=>{
 const f=fixture(t);f.identity.precision='fp16';f.sealCandidate();await assert.rejects(f.verify(),/candidate_identity_changed/);
});
test('a finite GPU check is required before sealing and must match its standalone callback record',async t=>{
 const f=fixture(t);f.receipt.adapterFiniteCheck.nonFiniteTensorCount=1;f.put('output/candidate/training-receipt.json',f.receipt);f.sealCandidate();await assert.rejects(f.verify(),/gpu_finite_check/);
 const g=fixture(t),log=readFileSync(resolve(g.root,'controller/training.log'),'utf8');g.put('controller/training.log',log.split('\n').filter(line=>!line.startsWith('{"adapterFiniteCheck":')).join('\n'));await assert.rejects(g.verify(),/gpu_finite_check/);
});
