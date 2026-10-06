import {createHash} from 'node:crypto';
import {createReadStream,lstatSync,readFileSync,readdirSync,mkdirSync,writeFileSync} from 'node:fs';
import {resolve,dirname,join,relative,isAbsolute,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {QA_BASE_REVISION,QA_IMAGE,QA_NAMESPACE,QA_NODE} from './public-qa-workload.mjs';
import {STAGE2_DIAGNOSTIC_PINS,STAGE2_DIAGNOSTIC_SOURCE_RUN} from './public-qa-diagnostic-workload.mjs';
import {GROUNDING_STAGE,GROUNDING_SOURCE_PINS} from './prepare-public-qa-grounding.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const requireValue=(value,reason)=>{if(!value)throw Error(reason);};
const same=isDeepStrictEqual;
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const parseJson=bytes=>JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/,''));
function checkedPath(root,name){
 root=resolve(root);const path=resolve(root,name),part=relative(root,path);
 requireValue(part&&!isAbsolute(part)&&part!=='..'&&!part.startsWith('..'+sep),'grounding_path_escape');
 for(let current=path;;current=dirname(current)){requireValue(!lstatSync(current).isSymbolicLink(),'grounding_symlink');if(dirname(current)===current)break;}
 requireValue(lstatSync(path).isFile(),'grounding_file_invalid');return path;
}
function bytes(root,name,limit=64*1024*1024){const path=checkedPath(root,name);requireValue(lstatSync(path).size<=limit,'grounding_file_too_large');return readFileSync(path);}
const json=(root,name)=>parseJson(bytes(root,name));
async function fileHash(path){const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);return hash.digest('hex');}
function tree(root){
 root=resolve(root);const files=[];
 function visit(path){const stat=lstatSync(path);requireValue(!stat.isSymbolicLink(),'grounding_symlink');requireValue(!path.endsWith('.partial'),'grounding_partial_artifact');if(stat.isDirectory())for(const name of readdirSync(path).sort())visit(join(path,name));else{requireValue(stat.isFile(),'grounding_special_artifact');files.push(path);}}
 visit(root);return files;
}
async function sealed(root,kind,identity,step,expectedMarkerHash){
 const markerName=kind+'-complete.json',markerPath=checkedPath(root,markerName),marker=json(root,markerName);
 requireValue(marker.schemaVersion===1&&marker.globalStep===step&&same(marker.identity,identity)&&(!expectedMarkerHash||await fileHash(markerPath)===expectedMarkerHash),'grounding_'+kind+'_identity_changed');
 const inventory=[];for(const file of tree(root).filter(path=>path!==markerPath))inventory.push({path:relative(root,file).replaceAll('\\','/'),bytes:lstatSync(file).size,sha256:await fileHash(file)});
 inventory.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 requireValue(same(inventory,marker.files),'grounding_'+kind+'_artifact_changed');
 const required=kind==='checkpoint'?['adapter_config.json','adapter_model.safetensors','trainer_state.json','optimizer.pt','scheduler.pt','rng_state.pth','training_args.bin']:['adapter_config.json','adapter_model.safetensors','training-receipt.json'];
 requireValue(required.every(name=>inventory.some(file=>file.path===name&&file.bytes>0)),'grounding_'+kind+'_incomplete');
 if(kind==='checkpoint')requireValue(json(root,'trainer_state.json').global_step===step,'grounding_checkpoint_step_changed');
 return {marker,files:inventory,markerSha256:await fileHash(markerPath),globalStep:step};
}
function finiteAdapter(root){
 const raw=bytes(root,'adapter_model.safetensors');requireValue(raw.length>=10,'grounding_adapter_tensor_format_invalid');
 const headerLengthBig=raw.readBigUInt64LE(0);requireValue(headerLengthBig>1n&&headerLengthBig<=1048576n&&headerLengthBig<=BigInt(raw.length-8),'grounding_adapter_tensor_format_invalid');
 const headerLength=Number(headerLengthBig),header=parseJson(raw.subarray(8,8+headerLength)),data=raw.subarray(8+headerLength),entries=Object.entries(header).filter(([name])=>name!=='__metadata__'),ranges=[];
 requireValue(entries.length===256,'grounding_adapter_tensor_count_invalid');
 let elements=0;
 for(const [name,tensor]of entries){
  const match=/^base_model\.model\.model\.layers\.(\d+)\.self_attn\.(q_proj|k_proj|v_proj|o_proj)\.lora_([AB])\.weight$/.exec(name);
  requireValue(match&&String(Number(match[1]))===match[1]&&Number(match[1])<32&&tensor.dtype==='F32'&&Array.isArray(tensor.shape)&&tensor.shape.length===2&&tensor.shape.every(size=>Number.isSafeInteger(size)&&size>0)&&tensor.shape[match[3]==='A'?0:1]===8&&Array.isArray(tensor.data_offsets)&&tensor.data_offsets.length===2,'grounding_adapter_tensor_schema_invalid');
  const [start,end]=tensor.data_offsets,count=tensor.shape[0]*tensor.shape[1];requireValue(Number.isSafeInteger(count)&&Number.isSafeInteger(start)&&Number.isSafeInteger(end)&&start>=0&&end<=data.length&&end-start===count*4,'grounding_adapter_tensor_bounds_invalid');
  for(let offset=start;offset<end;offset+=4)requireValue(Number.isFinite(data.readFloatLE(offset)),'grounding_adapter_nonfinite_tensor');
  elements+=count;ranges.push([start,end]);
 }
 ranges.sort((a,b)=>a[0]-b[0]);requireValue(ranges.every(([start],index)=>start===(index?ranges[index-1][1]:0))&&ranges.at(-1)[1]===data.length,'grounding_adapter_tensor_ranges_invalid');
 return {verified:true,device:'cpu',format:'safetensors',dtype:'F32',tensorCount:entries.length,elementCount:elements,allFinite:true,sha256:sha(raw)};
}
async function sourceBindings(workspace,inputs,pins){
 const fields={sourceController:'sourceControllerSha256',sourceVerification:'sourceVerificationSha256',candidateMarker:'candidateMarkerSha256',adapter:'adapterSha256',sourceRuntime:'sourceRuntimeConfigMapSha256',lock:'artifactLockSha256'},source={};
 requireValue(inputs.sourceRunId===STAGE2_DIAGNOSTIC_SOURCE_RUN,'grounding_source_run_changed');
 for(const [field,pin]of Object.entries(fields)){requireValue(inputs[pin]===pins[pin]&&digest(pins[pin]),'grounding_source_pin_changed:'+pin);source[field]=bytes(workspace,inputs[field]);requireValue(sha(source[field])===pins[pin],'grounding_source_file_changed:'+field);}
 const controller=parseJson(source.sourceController),verification=parseJson(source.sourceVerification),candidate=parseJson(source.candidateMarker),identity=candidate.identity;
 requireValue(controller.runId===inputs.sourceRunId&&controller.mode==='explicit_public_human_qa_stage2'&&controller.state==='process_completed'&&controller.exit?.exitCode===0&&controller.terminationConfirmed===true&&!controller.error&&!controller.cleanupError,'grounding_source_controller_unverified');
 requireValue(verification.verified===true&&verification.runId===inputs.sourceRunId&&verification.trainingRunCompleted===true&&verification.terminationConfirmed===true&&verification.globalStep===40&&verification.actualOptimizerUpdates===40&&verification.skippedOptimizerUpdates===0&&verification.qualityClaimAllowed===false&&verification.promotionAllowed===false&&verification.artifactSha256===pins.candidateMarkerSha256&&verification.controllerSha256===pins.sourceControllerSha256&&verification.runtimeConfigMapSha256===pins.sourceRuntimeConfigMapSha256&&same(verification.identity,identity),'grounding_source_training_unverified');
 requireValue(identity?.stage==='public_qa_stage2'&&identity.maxSteps===40&&identity.baseRevision===QA_BASE_REVISION&&identity.baseArtifactLockSha256===pins.artifactLockSha256&&parseJson(source.lock).revision===QA_BASE_REVISION,'grounding_source_base_changed');
 const verified=await sealed(dirname(resolve(workspace,inputs.candidateMarker)),'candidate',identity,40,pins.candidateMarkerSha256);
 requireValue(verified.files.find(file=>file.path==='adapter_model.safetensors')?.sha256===pins.adapterSha256,'grounding_source_adapter_changed');
 return {identity,pins};
}

function datasetBindings(workspace,inputs,manifest,dataBytes,dataPins){
 const sourceFiles={sourceManifest:'source-manifest.json',sourceTrain:'source-train.jsonl',sourceValidation:'source-validation.jsonl',oldTraining:'old-training.jsonl',diagnostic:'diagnostic.jsonl'};
 requireValue(manifest.schemaVersion===1&&manifest.stage===GROUNDING_STAGE&&manifest.task==='korean_extractive_qa'&&manifest.upstreamRevision==='3efd98708a40ff49251fddde35453f8fbb11f536'&&manifest.license==='CC-BY-SA-4.0'&&same(manifest.sourcePins,dataPins)&&same(manifest.sourceFiles,sourceFiles),'grounding_dataset_identity_changed');
 requireValue(same(manifest.counts,{train:640,validation:64})&&same(manifest.labelCounts,{train:{answerable:320,impossible:320},validation:{answerable:32,impossible:32}})&&manifest.heldoutUsed===false&&manifest.localHumanReviewPerformed===false&&manifest.qualityClaimAllowed===false&&manifest.promotionAllowed===false,'grounding_dataset_scope_changed');
 requireValue(same(manifest.selection,{maxContextCodepoints:650,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true})&&same(manifest.previousExposureOverlap,{id:0,family:0,context:0}),'grounding_dataset_context_policy_changed');
 const root=dirname(resolve(workspace,inputs.manifest)),sources={};
 for(const [key,name]of Object.entries(sourceFiles)){const raw=bytes(root,name);requireValue(digest(dataPins[key])&&sha(raw)===dataPins[key],'grounding_dataset_source_changed:'+key);sources[key]=raw;}
 const upstream=parseJson(sources.sourceManifest);requireValue(upstream.revision===manifest.upstreamRevision&&upstream.license===manifest.license,'grounding_upstream_identity_changed');
 const rows=raw=>raw.toString('utf8').split(/\r?\n/).filter(line=>line.trim()).map(JSON.parse);
 const original=new Map([...rows(sources.sourceTrain),...rows(sources.sourceValidation)].map(row=>[row.id,row])),excluded=[...rows(sources.oldTraining),...rows(sources.diagnostic)],forbidden=Object.fromEntries(['id','familyId','contextSha256'].map(key=>[key,new Set(excluded.map(row=>row[key]))]));
 const dataset=rows(dataBytes),ids=new Set(),families=new Map(),contexts=new Map(),counts={train:{answerable:0,impossible:0},validation:{answerable:0,impossible:0}};
 requireValue(dataset.length===704&&same(manifest.rowIds,dataset.map(row=>row.id)),'grounding_dataset_rows_changed');
 for(const row of dataset){
  const {stage,contextSelection,localHumanReviewPerformed,privacyScreen,...sourceRow}=row;
  requireValue(typeof row.id==='string'&&!ids.has(row.id)&&same(sourceRow,original.get(row.id)),'grounding_original_row_changed');
  requireValue(stage===GROUNDING_STAGE&&contextSelection==='full_original_context'&&localHumanReviewPerformed===false&&same(privacyScreen,{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false})&&['train','validation'].includes(row.split)&&typeof row.isImpossible==='boolean','grounding_row_policy_changed');
  requireValue(typeof row.context==='string'&&typeof row.question==='string'&&Array.from(row.context).length<=650&&Array.from(row.question).length<=240&&sha(row.context)===row.contextSha256&&Array.isArray(row.answers)&&row.question===row.originalQa?.question&&row.isImpossible===row.originalQa?.is_impossible&&same(row.answers,row.originalQa?.answers),'grounding_row_annotation_changed');
  requireValue(row.isImpossible?row.answers.length===0:row.answers.length>0&&row.answers.every(answer=>Number.isSafeInteger(answer.answer_start)&&answer.answer_start>=0&&typeof answer.text==='string'&&answer.text&&Array.from(row.context).slice(answer.answer_start,answer.answer_start+Array.from(answer.text).length).join('')===answer.text),'grounding_answer_span_changed');
  for(const key of Object.keys(forbidden))requireValue(typeof row[key]==='string'&&row[key]&&!forbidden[key].has(row[key]),'grounding_previous_exposure_leakage');
  for(const [key,map]of [['familyId',families],['contextSha256',contexts]]){requireValue(!map.has(row[key])||map.get(row[key])===row.split,'grounding_split_leakage');map.set(row[key],row.split);}
  counts[row.split][row.isImpossible?'impossible':'answerable']++;ids.add(row.id);
 }
 requireValue(same(counts,manifest.labelCounts),'grounding_dataset_balance_changed');
 return dataset;
}

function validateSpec(spec,runId,inputs,{live=false}={}){
 requireValue(spec?.containers?.length===1&&!spec.initContainers?.length&&!spec.ephemeralContainers?.length&&spec.automountServiceAccountToken===false&&spec.restartPolicy==='Never'&&spec.runtimeClassName==='nvidia'&&!spec.hostNetwork&&!spec.hostPID&&!spec.hostIPC,'grounding_pod_scope_changed');
 requireValue(spec.nodeSelector?.['kubernetes.io/hostname']===QA_NODE&&(!live||spec.nodeName===QA_NODE)&&spec.securityContext?.runAsUser===10001&&spec.securityContext?.runAsNonRoot===true&&spec.securityContext?.seccompProfile?.type==='RuntimeDefault','grounding_node_or_user_changed');
 const container=spec.containers[0];requireValue(container.name==='training'&&container.image===QA_IMAGE&&container.securityContext?.readOnlyRootFilesystem===true&&container.securityContext?.allowPrivilegeEscalation===false&&container.securityContext?.capabilities?.drop?.includes('ALL'),'grounding_container_scope_changed');
 requireValue(container.resources?.limits?.cpu==='2'&&container.resources.limits.memory==='12Gi'&&String(container.resources.limits['nvidia.com/gpu'])==='1','grounding_resources_changed');
 requireValue(same(container.command,['python','/runtime/train-public-qa.py'])&&same(container.args,['--data','/data/grounding/data.jsonl','--manifest','/data/grounding/manifest.json','--grounding-provenance','/data/grounding/provenance.json','--warmstart-adapter','/warmstart/candidate','--model-dir','/models/foundation-base','--base-revision',QA_BASE_REVISION,'--output',`/checkpoints/runs/${runId}`,'--max-steps','20']),'grounding_command_changed');
 const env=Object.fromEntries((container.env||[]).map(item=>[item.name,item.value]));requireValue(Object.keys(env).length===(container.env||[]).length,'grounding_duplicate_env');
 for(const [name,value]of Object.entries({PYTHONPATH:'/runtime',EVIDSCOPE_MEMORY_HIGH_REQUIRED:'1',EVIDSCOPE_ISOLATED:'1',EVIDSCOPE_GROUNDING_PROVENANCE_SHA256:inputs.provenanceSha256,EVIDSCOPE_DATASET_SHA256:inputs.datasetSha256,EVIDSCOPE_BASE_REPOSITORY:'fdtn-ai/Foundation-Sec-8B-Reasoning',EVIDSCOPE_BASE_REVISION:QA_BASE_REVISION,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:inputs.artifactLockSha256,EVIDSCOPE_TRAINING_IMAGE:QA_IMAGE}))requireValue(env[name]===value,'grounding_environment_changed:'+name);
 const mounts={base:{path:'/models/foundation-base',claim:'public-qa-base',readOnly:true},data:{path:'/data/grounding',claim:'public-qa-data',readOnly:true,subPath:`grounding/${runId}`},warmstart:{path:'/warmstart/candidate',claim:'public-qa-checkpoints',readOnly:true,volumeReadOnly:true,subPath:`runs/${STAGE2_DIAGNOSTIC_SOURCE_RUN}/candidate`},'grounding-output':{path:'/checkpoints/runs',claim:'public-qa-checkpoints',readOnly:false,subPath:'grounding-runs'},runtime:{path:'/runtime',readOnly:true,configMap:inputs.runtimeConfigMap}};
 requireValue(Array.isArray(spec.volumes)&&Array.isArray(container.volumeMounts)&&!spec.volumes.some(volume=>volume.hostPath||volume.secret),'grounding_mounts_changed');
 for(const [name,want]of Object.entries(mounts)){
  const found=container.volumeMounts.filter(mount=>mount.name===name),volumes=spec.volumes.filter(volume=>volume.name===name);
  requireValue(found.length===1&&volumes.length===1&&found[0].mountPath===want.path&&Boolean(found[0].readOnly)===want.readOnly&&found[0].subPath===want.subPath&&!found[0].subPathExpr&&(want.claim?volumes[0].persistentVolumeClaim?.claimName===want.claim&&Boolean(volumes[0].persistentVolumeClaim?.readOnly)===Boolean(want.volumeReadOnly):volumes[0].configMap?.name===want.configMap),'grounding_mounts_changed:'+name);
 }
 requireValue(container.volumeMounts.every(mount=>[...Object.keys(mounts),'tmp','podinfo'].includes(mount.name))&&spec.volumes.every(volume=>[...Object.keys(mounts),'tmp','podinfo'].includes(volume.name)),'grounding_extra_mount');
}

function runtimeBindings(controllerRoot,inputs,identity){
 const runtime=json(controllerRoot,'runtime-configmap.json'),hash=sha(JSON.stringify(runtime.data)),baseNames=['train-public-qa.py','train-foundation-lora.py','training_artifacts.py','resource-pilot.py','public_qa_cuda_runtime.py','public_qa_memory_gate.py','public_qa_kbit.py','public_qa_thermal.py','public_qa_resume.py','public_qa_grounding.py'].sort(),names=Object.keys(runtime.data||{}).sort();
 requireValue(runtime.apiVersion==='v1'&&runtime.kind==='ConfigMap'&&runtime.immutable===true&&runtime.metadata?.namespace===QA_NAMESPACE&&runtime.metadata.name===inputs.runtimeConfigMap&&runtime.metadata.name==='public-qa-grounding-'+hash.slice(0,16)&&runtime.metadata.annotations?.['evidscope.io/code-sha256']===hash&&inputs.runtimeSha256===hash&&(same(names,baseNames)||same(names,[...baseNames,'public_qa_grounding_kbit.py'].sort()))&&same(Object.keys(inputs.runtimeFiles||{}).sort(),names),'grounding_runtime_changed');
 for(const [name,code]of Object.entries(runtime.data))requireValue(typeof code==='string'&&sha(code)===inputs.runtimeFiles[name],'grounding_runtime_file_changed');
 for(const [field,name]of [['trainerSha256','train-public-qa.py'],['artifactHelperSha256','training_artifacts.py'],['bindingHelperSha256','train-foundation-lora.py'],['groundingHelperSha256','public_qa_grounding.py']])requireValue(identity[field]===inputs.runtimeFiles[name],'grounding_runtime_identity_changed');
 return runtime;
}

function provenanceBindings(workspace,inputs,identity,sourceIdentity,runId,pins){
 const raw=bytes(workspace,inputs.provenancePath),provenance=parseJson(raw);
 requireValue(digest(inputs.provenanceSha256)&&sha(raw)===inputs.provenanceSha256&&same(provenance,inputs.groundingProvenance),'grounding_provenance_changed');
 const expected={schemaVersion:1,kind:'adapter_only_warmstart_new_balanced_public_qa',sourceRunId:STAGE2_DIAGNOSTIC_SOURCE_RUN,sourceGlobalStep:40,sourcePins:{marker:pins.candidateMarkerSha256,adapter:pins.adapterSha256,controller:pins.sourceControllerSha256,verification:pins.sourceVerificationSha256},sourceIdentity,targetRunId:runId,targetIdentity:identity,optimizerReset:true,schedulerReset:true,targetOptimizerSteps:20,sourceTrainingExecutionVerified:true,qualityClaimAllowed:false,promotionAllowed:false};
 requireValue(same(provenance,expected),'grounding_provenance_scope_changed');
 for(const field of ['baseRepository','baseRevision','baseArtifactLockSha256','rank','sequenceLength','batchSize','gradientAccumulationSteps'])requireValue(identity[field]===sourceIdentity[field],'grounding_warmstart_incompatible');
 return {...provenance,provenanceSha256:inputs.provenanceSha256,sourceOptimizerUpdates:40,optimizerUpdatesThisExperiment:20,sourceStateLoaded:'adapter_only',optimizerStateLoaded:false,schedulerStateLoaded:false};
}

function trainingLogBindings(controllerRoot,lineage,identity,finiteCheck){
 const log=bytes(controllerRoot,'training.log',16*1024*1024),records={optimizerStep:[],groundingWarmstart:[],groundingAdapterLoaded:[],resumedGlobalStep:[],resumeRngStateLoaded:[]};
 for(const line of log.toString('utf8').split(/\r?\n|\r/))for(const key of Object.keys(records))if(line.includes('"'+key+'"')){
  const at=line.indexOf('{"'+key+'":');requireValue(at>=0,'grounding_training_log_invalid');let value;try{value=JSON.parse(line.slice(at));}catch{throw Error('grounding_training_log_invalid');}records[key].push(value);
 }
 requireValue(records.groundingWarmstart.length===1&&same(records.groundingWarmstart[0],{groundingWarmstart:{...lineage,optimizerUpdatesThisExperiment:0}})&&records.groundingAdapterLoaded.length===1&&same(records.groundingAdapterLoaded[0],{groundingAdapterLoaded:true,sourceGlobalStep:40,newGlobalStep:0,optimizerStateLoaded:false,schedulerStateLoaded:false})&&!records.resumedGlobalStep.length&&!records.resumeRngStateLoaded.length,'grounding_adapter_only_warmstart_unverified');
 requireValue(records.optimizerStep.length===20&&records.optimizerStep.every((record,index)=>record.optimizerStep===index+1&&record.actualOptimizerUpdates===index+1&&record.skippedOptimizerUpdates===0),'grounding_actual_optimizer_updates_unverified');
 requireValue(records.optimizerStep.every(record=>Number.isFinite(record.learningRate)&&record.learningRate>=0&&record.learningRate<=identity.learningRate&&(record.optimizerStep===20||record.learningRate>0)&&Number.isFinite(record.cudaPeakAllocatedBytes)&&record.cudaPeakAllocatedBytes>0&&Number.isFinite(record.cudaPeakReservedBytes)&&record.cudaPeakReservedBytes>=record.cudaPeakAllocatedBytes),'grounding_update_measurement_invalid');
 const finiteRecords=[];for(const line of log.toString('utf8').split(/\r?\n|\r/)){const at=line.indexOf('{"adapterFiniteCheck":');if(at>=0){try{finiteRecords.push(JSON.parse(line.slice(at)));}catch{throw Error('grounding_training_log_invalid');}}}
 requireValue(finiteRecords.length===1&&same(finiteRecords[0],{adapterFiniteCheck:finiteCheck}),'grounding_gpu_finite_check_unverified');
 return log;
}

// Receipts bind local execution records and exported bytes. They are not
// independent hardware attestations or an admission of answer/legal quality.
async function verifyCore(options,pins,syntheticFixture){
 const {runDirectory,controllerReceipt,workspaceRoot=process.cwd()}=options;
 tree(resolve(runDirectory));
 const controllerPath=resolve(controllerReceipt),controllerRoot=dirname(controllerPath),controllerBytes=bytes(controllerRoot,relative(controllerRoot,controllerPath)),controller=parseJson(controllerBytes),inputs=controller.inputs;
 requireValue(controller.schemaVersion===1&&controller.mode==='explicit_public_human_qa_grounding_v1'&&controller.state==='process_completed'&&controller.exit?.exitCode===0&&controller.terminationConfirmed===true&&controller.admission?.allowed===true&&!controller.error&&!controller.cleanupError&&!controller.creationUncertain,'grounding_controller_execution_unverified');
 requireValue(controller.trainingRunCompleted===false&&controller.qualityClaimAllowed===false&&controller.promotionAllowed===false&&controller.automaticGovernanceGateClaimed===false,'grounding_controller_claim_changed');
 requireValue(/^public-qa-[a-z0-9-]{1,35}$/.test(controller.runId||'')&&typeof controller.jobUid==='string'&&controller.jobUid&&typeof controller.podUid==='string'&&controller.podUid,'grounding_execution_identity_missing');
 requireValue(inputs&&inputs.qualityClaimAllowed===false&&inputs.promotionAllowed===false,'grounding_input_scope_changed');
 requireValue(inputs.mode==='explicit_public_human_qa_grounding'&&inputs.stage===GROUNDING_STAGE&&inputs.diagnosticOnly===false&&inputs.rows===704&&inputs.runId===controller.runId&&/^public-qa-grounding-[a-z0-9-]{1,28}$/.test(controller.runId),'grounding_input_scope_changed');
 const source=await sourceBindings(workspaceRoot,inputs,pins.training);
 const dataBytes=bytes(workspaceRoot,inputs.data),manifestBytes=bytes(workspaceRoot,inputs.manifest),manifest=parseJson(manifestBytes);
 requireValue(digest(inputs.datasetSha256)&&sha(dataBytes)===inputs.datasetSha256&&digest(inputs.manifestSha256)&&sha(manifestBytes)===inputs.manifestSha256&&manifest.datasetSha256===inputs.datasetSha256,'grounding_dataset_binding_changed');
 const dataset=datasetBindings(workspaceRoot,inputs,manifest,dataBytes,pins.dataset);
 const candidate=await sealed(join(resolve(runDirectory),'candidate'),'candidate',json(join(resolve(runDirectory),'candidate'),'candidate-complete.json').identity,20),identity=candidate.marker.identity,receipt=json(join(resolve(runDirectory),'candidate'),'training-receipt.json');
 requireValue(identity?.baseRepository==='fdtn-ai/Foundation-Sec-8B-Reasoning'&&identity.baseRevision===QA_BASE_REVISION&&identity.image===QA_IMAGE&&identity.stage===GROUNDING_STAGE&&identity.contextSelection==='full_original_context'&&identity.precision==='bf16'&&identity.modelDtype==='bfloat16'&&identity.quantComputeDtype==='bfloat16'&&identity.rank===8&&identity.sequenceLength===1024&&identity.batchSize===1&&identity.gradientAccumulationSteps===16&&identity.seed===42&&identity.learningRate===0.0001&&identity.maxSteps===20&&identity.gpuMemoryFraction>0&&identity.gpuMemoryFraction<=0.65&&identity.datasetSha256===inputs.datasetSha256&&identity.manifestSha256===inputs.manifestSha256&&identity.baseArtifactLockSha256===pins.training.artifactLockSha256&&same(identity,inputs.targetIdentity),'grounding_candidate_identity_changed');
 runtimeBindings(controllerRoot,inputs,identity);
 const lineage=provenanceBindings(workspaceRoot,inputs,identity,source.identity,controller.runId,pins.training);
 requireValue(receipt.schemaVersion===2&&receipt.status==='trained_'+GROUNDING_STAGE&&receipt.globalStep===20&&receipt.trainingRunCompleted===true&&receipt.qualityClaimAllowed===false&&receipt.promotionAllowed===false&&receipt.heldOutTestUsedForTraining===false&&receipt.localHumanReviewPerformed===false&&receipt.sourceLicense==='CC-BY-SA-4.0'&&receipt.targetFormat==='exact_human_answer_json_without_generated_reasoning'&&!receipt.resumeLineage&&same(receipt.identity,identity)&&same(receipt.trainingMetrics,candidate.marker.metrics)&&same(receipt.groundingLineage,lineage),'grounding_candidate_receipt_changed');
 requireValue(['train_loss','eval_loss','base_eval_loss'].every(key=>Number.isFinite(receipt.trainingMetrics?.[key]))&&Number.isFinite(receipt.cudaPeakAllocatedBytes)&&receipt.cudaPeakAllocatedBytes>0&&Number.isFinite(receipt.cudaPeakReservedBytes)&&receipt.cudaPeakReservedBytes>=receipt.cudaPeakAllocatedBytes,'grounding_candidate_measurement_invalid');
 requireValue(same(receipt.adapterFiniteCheck,{passed:true,tensorCount:256,nonFiniteTensorCount:0,dtypes:['torch.float32'],beforeCandidateSealing:true}),'grounding_gpu_finite_check_unverified');
 const trainingLog=trainingLogBindings(controllerRoot,lineage,identity,receipt.adapterFiniteCheck);
 const checkpoints=[];for(const step of [10,20])checkpoints.push(await sealed(join(resolve(runDirectory),'checkpoint-'+step),'checkpoint',identity,step));
 const adapter=candidate.files.find(file=>file.path==='adapter_model.safetensors');requireValue(checkpoints.at(-1).files.find(file=>file.path==='adapter_model.safetensors')?.sha256===adapter.sha256,'grounding_final_checkpoint_adapter_changed');
 const adapterTensorVerification=finiteAdapter(join(resolve(runDirectory),'candidate'));
 for(const step of [10,20])finiteAdapter(join(resolve(runDirectory),'checkpoint-'+step));
 const encodingBytes=bytes(runDirectory,'encoding-receipt.json'),encoding=parseJson(encodingBytes);
 requireValue(encoding.datasetSha256===inputs.datasetSha256&&encoding.rows?.length===704&&encoding.rows.every((row,index)=>row.id===dataset[index].id&&row.contextStart===0&&row.contextEnd===Array.from(dataset[index].context).length&&row.originalContextSha256===dataset[index].contextSha256&&row.selectedContextSha256===row.originalContextSha256&&row.answerPreserved===true&&Number.isSafeInteger(row.tokens)&&row.tokens>0&&row.tokens<=1024),'grounding_full_context_encoding_unverified');
 const job=controller.manifest;requireValue(sha(JSON.stringify(job))===controller.manifestSha256&&job.metadata?.name===controller.runId&&job.metadata.namespace===QA_NAMESPACE&&job.metadata.annotations?.['evidscope.io/run-kind']==='explicit-public-human-qa-grounding'&&job.metadata.annotations['evidscope.io/dataset-sha256']===inputs.datasetSha256&&job.metadata.annotations['evidscope.io/manifest-sha256']===inputs.manifestSha256&&job.metadata.annotations['evidscope.io/provenance-sha256']===inputs.provenanceSha256,'grounding_job_manifest_changed');
 validateSpec(job.spec?.template?.spec,controller.runId,inputs);validateSpec(controller.livePodSpec,controller.runId,inputs,{live:true});
 const liveJob=json(controllerRoot,'live-job.json'),livePod=json(controllerRoot,'live-pod.json');
 requireValue(liveJob.metadata?.uid===controller.jobUid&&liveJob.metadata.name===controller.runId&&liveJob.metadata.namespace===QA_NAMESPACE&&livePod.metadata?.uid===controller.podUid&&livePod.metadata.name===controller.podName&&livePod.metadata.namespace===QA_NAMESPACE&&livePod.metadata.ownerReferences?.some(owner=>owner.kind==='Job'&&owner.uid===controller.jobUid&&owner.name===controller.runId),'grounding_job_pod_binding_changed');
 validateSpec(liveJob.spec?.template?.spec,controller.runId,inputs);validateSpec(livePod.spec,controller.runId,inputs,{live:true});
 requireValue(controller.memoryHigh?.podUid===controller.podUid&&controller.memoryHigh.markerReleased===true&&controller.memoryHigh.containerLeafOnly===true&&controller.memoryHigh.memoryHigh==='2147483648'&&controller.memoryHigh.memoryMax==='12884901888','grounding_memory_control_unverified');
 return {schemaVersion:1,verificationPassed:true,verified:!syntheticFixture,syntheticFixture,actualTrainingExecutionVerified:!syntheticFixture,sourceTrainingExecutionVerified:!syntheticFixture,verifiedAt:new Date().toISOString(),runId:controller.runId,jobUid:controller.jobUid,podUid:controller.podUid,artifactSha256:candidate.markerSha256,adapterSha256:adapter.sha256,adapterTensorVerification,controllerSha256:sha(controllerBytes),runtimeConfigMapSha256:sha(bytes(controllerRoot,'runtime-configmap.json')),trainingLogSha256:sha(trainingLog),encodingReceiptSha256:sha(encodingBytes),datasetSha256:inputs.datasetSha256,manifestSha256:inputs.manifestSha256,identity,globalStep:20,actualOptimizerUpdates:20,optimizerUpdatesThisRun:20,sourceOptimizerUpdates:40,totalAdapterHistoryOptimizerUpdates:60,skippedOptimizerUpdates:0,optimizerStateRestored:false,schedulerStateRestored:false,groundingLineage:lineage,checkpoints:checkpoints.map(({markerSha256,globalStep})=>({markerSha256,globalStep})),trainingRunCompleted:!syntheticFixture,terminationConfirmed:true,qualityClaimAllowed:false,promotionAllowed:false,trainingMetrics:receipt.trainingMetrics,limitations:['Local persisted execution records and exported hashes; not independent hardware attestation.','The source has forty optimizer updates; this experiment resets optimizer/scheduler and performs twenty new updates. It is not a resumed optimizer at step sixty.','Public human annotation does not imply local human review or legal/financial task quality.']};
}

// Read-only artifact checks shared by subsequent, separately pinned verifiers.
export const groundingArtifactChecks=Object.freeze({sealed,finiteAdapter,bytes,json,fileHash,tree});
export const verifyPublicQaGrounding=options=>verifyCore(options,{training:STAGE2_DIAGNOSTIC_PINS,dataset:GROUNDING_SOURCE_PINS},false);
// Deliberately synthetic test inputs cannot make actual training success claims.
export const verifyPublicQaGroundingFixture=(options,testOnlyPins)=>verifyCore(options,testOnlyPins,true);
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [runDirectory,controllerReceipt,output,...extra]=process.argv.slice(2);
 requireValue(runDirectory&&controllerReceipt&&output&&!extra.length,'usage: node scripts/verify-public-qa-grounding.mjs RUN_DIRECTORY CONTROLLER_RECEIPT NEW_REPORT_JSON');
 let result;try{result=await verifyPublicQaGrounding({runDirectory,controllerReceipt});}catch(error){result={schemaVersion:1,verified:false,verificationPassed:false,actualTrainingExecutionVerified:false,sourceTrainingExecutionVerified:false,trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false,error:error.message};process.exitCode=2;}
 mkdirSync(dirname(resolve(output)),{recursive:true});writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));
}
