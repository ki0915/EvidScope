import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve,dirname,join,relative} from 'node:path';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual as same} from 'node:util';
import {QA_BASE_REVISION,QA_IMAGE,QA_NAMESPACE,QA_NODE} from './public-qa-workload.mjs';
import {groundingArtifactChecks,verifyPublicQaGrounding} from './verify-public-qa-grounding.mjs';
import {CONTINUATION_STAGE,CONTINUATION_SOURCE_PINS,CONTINUATION_SOURCE_FILES,SAMPLER} from './prepare-public-qa-grounding-continuation.mjs';

const {sealed,finiteAdapter,bytes,json,fileHash,tree}=groundingArtifactChecks;
const sha=value=>createHash('sha256').update(value).digest('hex');
const requireValue=(value,reason)=>{if(!value)throw Error('continuation_'+reason);};
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const parseJson=raw=>JSON.parse(raw.toString('utf8').replace(/^\uFEFF/,''));
const readRows=raw=>raw.toString('utf8').split(/\r?\n/).filter(line=>line.trim()).map(JSON.parse);
export const CONTINUATION_VERIFICATION_PINS=Object.freeze({candidateMarkerSha256:'aa6b6fc1c7fa32f56507a4e31920acef3b46257ca90bf597c2a6e9e480fd1e60',adapterSha256:'c3b836df159917cd9ababd61ed9f574ac5b77252b8ec058a66269b045c78d9f6',sourceControllerSha256:'a376708b9932a6b1831568347b0ca2f1719c7707b8750b0f2e0025ffaca86617',sourceVerificationSha256:'c33c946a0c80b6bdba4bc8e738fd98d6e04cfbfa10887b2f39a8b28e613ec517',sourceProvenanceSha256:'b165e9f1b4d1fac016efa18825649cf21e13e86ff523105d2cb17ced900c5459'});
const SOURCE_RUN='public-qa-grounding-20261005-r4';
const canonical=value=>JSON.stringify(value,(_key,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);

// This independently reconstructs the trainer's deterministic stratification.
export function continuationPlan(dataset){
 const rows=dataset.filter(row=>row.split==='train');
 requireValue(rows.length===640&&new Set(rows.map(row=>row.id)).size===640,'sampler_rows_changed');
 const pools=[false,true].map(label=>rows.map((row,index)=>({row,index})).filter(({row})=>row.isImpossible===label).sort((a,b)=>sha(`42|class|${Number(label)}|${a.row.id}`).localeCompare(sha(`42|class|${Number(label)}|${b.row.id}`))||a.row.id.localeCompare(b.row.id)));
 requireValue(pools[0].length===440&&pools[1].length===200,'sampler_balance_changed');
 const plan=[];
 for(let group=0;group<40;group++)for(const {row,index}of [...pools[0].slice(group*11,(group+1)*11),...pools[1].slice(group*5,(group+1)*5)].sort((a,b)=>sha(`42|group|${group}|${a.row.id}`).localeCompare(sha(`42|group|${group}|${b.row.id}`))||a.row.id.localeCompare(b.row.id)))plan.push({datasetIndex:index,rowId:row.id,isImpossible:row.isImpossible});
 return plan;
}

export function verifyContinuationExposure(exposure,dataset,encoding,step){
 const plan=continuationPlan(dataset),train=dataset.filter(row=>row.split==='train'),expectedRows=step*16;
 requireValue([10,20].includes(step)&&exposure.schemaVersion===1&&exposure.stage===CONTINUATION_STAGE&&exposure.datasetSha256===encoding.datasetSha256&&same(exposure.sampler,SAMPLER)&&exposure.plannedOrderSha256===sha(canonical(plan)),'exposure_identity_changed');
 requireValue(exposure.sourceOptimizerHistoryUpdates===60&&exposure.optimizerUpdatesThisExperiment===step&&exposure.totalAdapterHistoryOptimizerUpdates===60+step&&exposure.processedMicrobatches===expectedRows&&exposure.completedOptimizerGroups===step&&exposure.qualityClaimAllowed===false&&exposure.promotionAllowed===false,'exposure_steps_changed');
 requireValue(same(exposure.counts,{answerable:11*step,impossible:5*step})&&Array.isArray(exposure.rows)&&exposure.rows.length===expectedRows&&same(exposure.groups,Array.from({length:step},(_,index)=>({optimizerGroup:index+1,microbatches:16,answerable:11,impossible:5}))),'exposure_balance_changed');
 const encoded=new Map(encoding.rows.map(row=>[row.id,row]));
 exposure.rows.forEach((record,index)=>{
  const selected=plan[index],row=train[selected.datasetIndex],original=encoded.get(row.id);
  requireValue(same(Object.keys(record).sort(),['microbatch','optimizerGroup','positionInGroup','datasetIndex','rowId','isImpossible','inputSha256','tokenCount','forwardBackwardCompleted'].sort())&&record.microbatch===index+1&&record.optimizerGroup===Math.floor(index/16)+1&&record.positionInGroup===index%16+1&&record.datasetIndex===selected.datasetIndex&&record.rowId===selected.rowId&&record.isImpossible===selected.isImpossible&&record.forwardBackwardCompleted===true,'exposure_consumed_row_changed');
  requireValue(digest(record.inputSha256)&&record.inputSha256===original?.inputSha256&&record.tokenCount===original.tokens&&Number.isSafeInteger(record.tokenCount)&&record.tokenCount>0&&record.tokenCount<=1024,'exposure_tensor_binding_changed');
 });
 return {processedMicrobatches:expectedRows,completedOptimizerGroups:step,counts:exposure.counts,plannedOrderSha256:exposure.plannedOrderSha256,actualTensorBindingChecked:true};
}

async function sourceBindings(workspace,inputs,pins,syntheticFixture){
 requireValue(inputs.sourceRunId===SOURCE_RUN,'source_run_changed');
 const source={};
 for(const [field,pin]of Object.entries({sourceController:'sourceControllerSha256',sourceVerification:'sourceVerificationSha256',candidateMarker:'candidateMarkerSha256',adapter:'adapterSha256',sourceProvenance:'sourceProvenanceSha256'})){
  const recorded=field==='sourceProvenance'?(inputs[pin]??inputs.groundingProvenance?.sourcePins?.provenance):inputs[pin];requireValue(recorded===pins[pin]&&digest(pins[pin]),'source_pin_changed:'+pin);source[field]=bytes(workspace,inputs[field]);requireValue(sha(source[field])===pins[pin],'source_file_changed:'+field);
 }
 const report=parseJson(source.sourceVerification),controller=parseJson(source.sourceController),marker=parseJson(source.candidateMarker),identity=marker.identity;
 requireValue(controller.mode==='explicit_public_human_qa_grounding_v1'&&controller.runId===SOURCE_RUN&&controller.state==='process_completed'&&controller.exit?.exitCode===0&&controller.terminationConfirmed===true&&!controller.error&&!controller.cleanupError,'source_controller_unverified');
 requireValue(report.verificationPassed===true&&report.verified===true&&report.syntheticFixture===false&&report.actualTrainingExecutionVerified===true&&report.sourceTrainingExecutionVerified===true&&report.trainingRunCompleted===true&&report.terminationConfirmed===true&&report.runId===SOURCE_RUN&&report.globalStep===20&&report.actualOptimizerUpdates===20&&report.sourceOptimizerUpdates===40&&report.totalAdapterHistoryOptimizerUpdates===60&&report.skippedOptimizerUpdates===0&&report.qualityClaimAllowed===false&&report.promotionAllowed===false&&report.artifactSha256===pins.candidateMarkerSha256&&report.adapterSha256===pins.adapterSha256&&report.controllerSha256===pins.sourceControllerSha256&&same(report.identity,identity),'source_training_unverified');
 requireValue(inputs.sourceRuntimeConfigMapSha256===report.runtimeConfigMapSha256&&sha(bytes(workspace,inputs.sourceRuntime))===report.runtimeConfigMapSha256&&inputs.artifactLockSha256===identity.baseArtifactLockSha256&&sha(bytes(workspace,inputs.lock))===inputs.artifactLockSha256&&json(workspace,inputs.lock).revision===QA_BASE_REVISION,'source_runtime_or_base_changed');
 const sourceRoot=dirname(resolve(workspace,inputs.candidateMarker));
 await sealed(sourceRoot,'candidate',identity,20,pins.candidateMarkerSha256);
 requireValue(identity.stage==='public_qa_grounding_v1'&&identity.maxSteps===20,'source_identity_changed');
 if(!syntheticFixture){
  const verified=await verifyPublicQaGrounding({runDirectory:dirname(sourceRoot),controllerReceipt:resolve(workspace,inputs.sourceController),workspaceRoot:workspace});
  for(const key of ['verified','actualTrainingExecutionVerified','sourceTrainingExecutionVerified','trainingRunCompleted','terminationConfirmed','runId','artifactSha256','adapterSha256','controllerSha256','runtimeConfigMapSha256','trainingLogSha256','encodingReceiptSha256','datasetSha256','manifestSha256','identity','globalStep','actualOptimizerUpdates','sourceOptimizerUpdates','totalAdapterHistoryOptimizerUpdates','groundingLineage','checkpoints'])requireValue(same(verified[key],report[key]),'source_recomputed_verification_changed:'+key);
 }
 return {identity,report};
}

function datasetBindings(workspace,inputs,manifest,dataBytes,dataPins){
 requireValue(manifest.schemaVersion===1&&manifest.stage===CONTINUATION_STAGE&&manifest.task==='korean_extractive_qa'&&manifest.upstreamRevision==='3efd98708a40ff49251fddde35453f8fbb11f536'&&manifest.license==='CC-BY-SA-4.0'&&same(manifest.sourcePins,dataPins)&&same(manifest.sourceFiles,CONTINUATION_SOURCE_FILES),'dataset_identity_changed');
 requireValue(same(manifest.counts,{train:640,validation:64})&&same(manifest.labelCounts,{train:{answerable:440,impossible:200},validation:{answerable:32,impossible:32}})&&same(manifest.sampler,SAMPLER)&&manifest.heldoutUsed===false&&manifest.localHumanReviewPerformed===false&&manifest.qualityClaimAllowed===false&&manifest.promotionAllowed===false,'dataset_scope_changed');
 requireValue(same(manifest.selection,{maxContextCodepoints:650,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true})&&same(manifest.previousExposureOverlap,{id:0,family:0,context:0}),'dataset_context_policy_changed');
 const sourceRoot=dirname(resolve(workspace,inputs.manifest)),sources={};
 for(const [key,name]of Object.entries(CONTINUATION_SOURCE_FILES)){const raw=bytes(sourceRoot,name);requireValue(digest(dataPins[key])&&sha(raw)===dataPins[key],'dataset_source_changed:'+key);sources[key]=raw;}
 const upstream=parseJson(sources.sourceManifest);requireValue(upstream.revision===manifest.upstreamRevision&&upstream.license===manifest.license,'upstream_identity_changed');
 const originals=[...readRows(sources.sourceTrain),...readRows(sources.sourceValidation)],original=new Map(originals.map(row=>[row.id,row]));requireValue(original.size===originals.length,'source_duplicate_row');
 const excluded=[...readRows(sources.oldTraining),...readRows(sources.diagnostic),...readRows(sources.previousGrounding)],forbidden=Object.fromEntries(['id','familyId','contextSha256'].map(key=>[key,new Set(excluded.map(row=>row[key]))]));
 const dataset=readRows(dataBytes),ids=new Set(),families=new Map(),contexts=new Map(),counts={train:{answerable:0,impossible:0},validation:{answerable:0,impossible:0}};
 requireValue(dataset.length===704&&same(manifest.rowIds,dataset.map(row=>row.id)),'dataset_rows_changed');
 for(const row of dataset){
  const {stage,contextSelection,localHumanReviewPerformed,privacyScreen,...sourceRow}=row;
  requireValue(typeof row.id==='string'&&!ids.has(row.id)&&same(sourceRow,original.get(row.id)),'original_row_changed');
  requireValue(stage===CONTINUATION_STAGE&&contextSelection==='full_original_context'&&localHumanReviewPerformed===false&&same(privacyScreen,{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false})&&['train','validation'].includes(row.split)&&typeof row.isImpossible==='boolean','row_policy_changed');
  requireValue(typeof row.context==='string'&&row.context&&typeof row.question==='string'&&row.question&&Array.from(row.context).length<=650&&Array.from(row.question).length<=240&&sha(row.context)===row.contextSha256&&Array.isArray(row.answers)&&row.question===row.originalQa?.question&&row.isImpossible===row.originalQa?.is_impossible&&same(row.answers,row.originalQa?.answers),'row_annotation_changed');
  requireValue(row.isImpossible?row.answers.length===0:row.answers.length>0&&Array.from(row.answers[0].text).length<=160&&row.answers.every(answer=>Number.isSafeInteger(answer.answer_start)&&answer.answer_start>=0&&typeof answer.text==='string'&&answer.text&&Array.from(row.context).slice(answer.answer_start,answer.answer_start+Array.from(answer.text).length).join('')===answer.text),'answer_span_changed');
  for(const key of Object.keys(forbidden))requireValue(typeof row[key]==='string'&&row[key]&&!forbidden[key].has(row[key]),'previous_exposure_leakage');
  for(const [key,map]of [['familyId',families],['contextSha256',contexts]]){requireValue(!map.has(row[key])||map.get(row[key])===row.split,'split_leakage');map.set(row[key],row.split);}
  counts[row.split][row.isImpossible?'impossible':'answerable']++;ids.add(row.id);
 }
 requireValue(same(counts,manifest.labelCounts),'dataset_balance_changed');return dataset;
}

function provenanceBindings(workspace,inputs,identity,sourceIdentity,runId,pins){
 const raw=bytes(workspace,inputs.provenancePath),provenance=parseJson(raw);
 requireValue(digest(inputs.provenanceSha256)&&sha(raw)===inputs.provenanceSha256&&same(provenance,inputs.groundingProvenance),'provenance_changed');
 const expected={schemaVersion:1,kind:'adapter_only_warmstart_stratified_public_qa_continuation',sourceRunId:SOURCE_RUN,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:60,sourcePins:{marker:pins.candidateMarkerSha256,adapter:pins.adapterSha256,controller:pins.sourceControllerSha256,verification:pins.sourceVerificationSha256,provenance:pins.sourceProvenanceSha256},sourceIdentity,targetRunId:runId,targetIdentity:identity,optimizerReset:true,schedulerReset:true,targetOptimizerSteps:20,sourceTrainingExecutionVerified:true,qualityClaimAllowed:false,promotionAllowed:false};
 requireValue(same(provenance,expected),'provenance_scope_changed');
 for(const field of ['baseRepository','baseRevision','baseArtifactLockSha256','rank','sequenceLength','batchSize','gradientAccumulationSteps','image'])requireValue(identity[field]===sourceIdentity[field],'warmstart_incompatible');
 return {...provenance,provenanceSha256:inputs.provenanceSha256,sourceOptimizerUpdates:60,optimizerUpdatesThisExperiment:20,sourceStateLoaded:'adapter_only',optimizerStateLoaded:false,schedulerStateLoaded:false};
}

function runtimeBindings(root,inputs,identity){
 const runtime=json(root,'runtime-configmap.json'),hash=sha(JSON.stringify(runtime.data)),names=['train-public-qa.py','train-foundation-lora.py','training_artifacts.py','resource-pilot.py','public_qa_cuda_runtime.py','public_qa_memory_gate.py','public_qa_kbit.py','public_qa_thermal.py','public_qa_resume.py','public_qa_grounding.py','public_qa_grounding_kbit.py','public_qa_grounding_continuation.py'].sort();
 requireValue(runtime.apiVersion==='v1'&&runtime.kind==='ConfigMap'&&runtime.immutable===true&&runtime.metadata?.namespace===QA_NAMESPACE&&runtime.metadata.name===inputs.runtimeConfigMap&&runtime.metadata.name==='public-qa-gcont-'+hash.slice(0,16)&&runtime.metadata.annotations?.['evidscope.io/code-sha256']===hash&&inputs.runtimeSha256===hash&&same(Object.keys(runtime.data||{}).sort(),names)&&same(Object.keys(inputs.runtimeFiles||{}).sort(),names),'runtime_changed');
 for(const [name,code]of Object.entries(runtime.data))requireValue(typeof code==='string'&&sha(code)===inputs.runtimeFiles[name],'runtime_file_changed');
 for(const [field,name]of [['trainerSha256','train-public-qa.py'],['artifactHelperSha256','training_artifacts.py'],['bindingHelperSha256','train-foundation-lora.py'],['groundingHelperSha256','public_qa_grounding_continuation.py']])requireValue(identity[field]===inputs.runtimeFiles[name],'runtime_identity_changed');
}

function validateSpec(spec,runId,inputs,{live=false}={}){
 requireValue(spec?.containers?.length===1&&!spec.initContainers?.length&&!spec.ephemeralContainers?.length&&spec.automountServiceAccountToken===false&&spec.restartPolicy==='Never'&&spec.runtimeClassName==='nvidia'&&!spec.hostNetwork&&!spec.hostPID&&!spec.hostIPC,'pod_scope_changed');
 requireValue(spec.nodeSelector?.['kubernetes.io/hostname']===QA_NODE&&(!live||spec.nodeName===QA_NODE)&&spec.securityContext?.runAsUser===10001&&spec.securityContext?.runAsNonRoot===true&&spec.securityContext?.seccompProfile?.type==='RuntimeDefault','node_or_user_changed');
 const container=spec.containers[0];requireValue(container.name==='training'&&container.image===QA_IMAGE&&container.securityContext?.readOnlyRootFilesystem===true&&container.securityContext?.allowPrivilegeEscalation===false&&same(container.securityContext?.capabilities?.drop,['ALL'])&&!container.securityContext?.privileged&&!container.securityContext?.capabilities?.add,'container_scope_changed');
 requireValue(container.resources?.limits?.cpu==='2'&&container.resources.limits.memory==='12Gi'&&String(container.resources.limits['nvidia.com/gpu'])==='1','resources_changed');
 requireValue(same(container.command,['python','/runtime/train-public-qa.py'])&&same(container.args,['--data','/data/grounding/data.jsonl','--manifest','/data/grounding/manifest.json','--grounding-provenance','/data/grounding/provenance.json','--warmstart-adapter','/warmstart/candidate','--model-dir','/models/foundation-base','--base-revision',QA_BASE_REVISION,'--output',`/checkpoints/runs/${runId}`,'--max-steps','20']),'command_changed');
 const env=Object.fromEntries((container.env||[]).map(item=>[item.name,item.value]));requireValue(Object.keys(env).length===(container.env||[]).length&&!container.envFrom,'duplicate_or_extra_env');
 for(const [name,value]of Object.entries({PYTHONPATH:'/runtime',EVIDSCOPE_MEMORY_HIGH_REQUIRED:'1',EVIDSCOPE_ISOLATED:'1',EVIDSCOPE_GROUNDING_PROVENANCE_SHA256:inputs.provenanceSha256,EVIDSCOPE_DATASET_SHA256:inputs.datasetSha256,EVIDSCOPE_BASE_REPOSITORY:'fdtn-ai/Foundation-Sec-8B-Reasoning',EVIDSCOPE_BASE_REVISION:QA_BASE_REVISION,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:inputs.artifactLockSha256,EVIDSCOPE_TRAINING_IMAGE:QA_IMAGE}))requireValue(env[name]===value,'environment_changed:'+name);
 const mounts={base:{path:'/models/foundation-base',claim:'public-qa-base',readOnly:true},data:{path:'/data/grounding',claim:'public-qa-data',readOnly:true,subPath:`grounding-continuation/${runId}`},warmstart:{path:'/warmstart/candidate',claim:'public-qa-checkpoints',readOnly:true,volumeReadOnly:true,subPath:`grounding-runs/${SOURCE_RUN}/candidate`},'grounding-output':{path:'/checkpoints/runs',claim:'public-qa-checkpoints',readOnly:false,subPath:'grounding-continuation-runs'},runtime:{path:'/runtime',readOnly:true,configMap:inputs.runtimeConfigMap}};
 requireValue(Array.isArray(spec.volumes)&&Array.isArray(container.volumeMounts)&&!spec.volumes.some(volume=>volume.hostPath||volume.secret),'mounts_changed');
 for(const [name,want]of Object.entries(mounts)){
  const found=container.volumeMounts.filter(mount=>mount.name===name),volumes=spec.volumes.filter(volume=>volume.name===name),volume=volumes[0];
  requireValue(found.length===1&&volumes.length===1&&found[0].mountPath===want.path&&Boolean(found[0].readOnly)===want.readOnly&&found[0].subPath===want.subPath&&!found[0].subPathExpr&&(want.claim?volume.persistentVolumeClaim?.claimName===want.claim&&Boolean(volume.persistentVolumeClaim?.readOnly)===Boolean(want.volumeReadOnly):volume.configMap?.name===want.configMap&&!volume.configMap?.optional&&(volume.configMap?.defaultMode===undefined||volume.configMap.defaultMode===420)),'mounts_changed:'+name);
 }
 requireValue(container.volumeMounts.every(mount=>[...Object.keys(mounts),'tmp','podinfo'].includes(mount.name))&&spec.volumes.every(volume=>[...Object.keys(mounts),'tmp','podinfo'].includes(volume.name)),'extra_mount');
}

function trainingLogBindings(root,lineage,identity,finiteCheck){
 const log=bytes(root,'training.log',16*1024*1024),sequence=[],records={optimizerStep:[],groundingWarmstart:[],groundingAdapterLoaded:[],resumedGlobalStep:[],resumeRngStateLoaded:[],adapterFiniteCheck:[],continuationTrainingSample:[],continuationOptimizerGroup:[]};
 for(const line of log.toString('utf8').split(/\r?\n|\r/))for(const key of Object.keys(records)){const at=line.indexOf('{"'+key+'":');if(at>=0)try{const record=JSON.parse(line.slice(at));records[key].push(record);if(['optimizerStep','continuationTrainingSample','continuationOptimizerGroup'].includes(key))sequence.push(record);}catch{throw Error('continuation_training_log_invalid');}}
 requireValue(records.groundingWarmstart.length===1&&same(records.groundingWarmstart[0],{groundingWarmstart:{...lineage,optimizerUpdatesThisExperiment:0}})&&records.groundingAdapterLoaded.length===1&&same(records.groundingAdapterLoaded[0],{groundingAdapterLoaded:true,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:60,newGlobalStep:0,optimizerStateLoaded:false,schedulerStateLoaded:false})&&!records.resumedGlobalStep.length&&!records.resumeRngStateLoaded.length,'adapter_only_warmstart_unverified');
 requireValue(records.optimizerStep.length===20&&records.optimizerStep.every((record,index)=>record.optimizerStep===index+1&&record.actualOptimizerUpdates===index+1&&record.skippedOptimizerUpdates===0),'actual_optimizer_updates_unverified');
 requireValue(records.optimizerStep.every(record=>Number.isFinite(record.learningRate)&&record.learningRate>=0&&record.learningRate<=identity.learningRate&&(record.optimizerStep===20||record.learningRate>0)&&Number.isFinite(record.cudaPeakAllocatedBytes)&&record.cudaPeakAllocatedBytes>0&&Number.isFinite(record.cudaPeakReservedBytes)&&record.cudaPeakReservedBytes>=record.cudaPeakAllocatedBytes),'update_measurement_invalid');
 requireValue(records.adapterFiniteCheck.length===1&&same(records.adapterFiniteCheck[0],{adapterFiniteCheck:finiteCheck}),'gpu_finite_check_unverified');return {log,records,sequence};
}

const cgroupReadCommand="import json,pathlib; p=pathlib.Path('/sys/fs/cgroup'); e=dict(l.split() for l in (p/'memory.events').read_text().splitlines()); print(json.dumps({'memoryCurrentGiB':int((p/'memory.current').read_text())/1073741824,'memoryLimitGiB':int((p/'memory.max').read_text())/1073741824,'oomCount':int(e.get('oom',0)),'oomKillCount':int(e.get('oom_kill',0)),'cpuMax':(p/'cpu.max').read_text().strip(),'memoryStat':dict((k,int(v)) for k,v in (line.split() for line in (p/'memory.stat').read_text().splitlines()) if k in ('anon','file','file_mapped','file_dirty','inactive_file','active_file'))}))";
const regexEscape=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
function exitTimestamp(value){
 const match=typeof value==='string'&&/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d{1,9})?Z$/.exec(value);
 if(!match)return NaN;
 const [,year,month,day,hour,minute,second]=match.map(Number),days=new Date(Date.UTC(year+400,month,0)).getUTCDate();
 return month>=1&&month<=12&&day>=1&&day<=days&&hour<24&&minute<60&&second<60?Date.parse(value):NaN;
}

// A raw local CRI record can reconcile only this specific post-exit cgroup
// observation race. It cannot turn any other controller failure into success.
export function verifyRuntimeExitReconciliation({controller,controllerSha256,criInspectionPath,controllerRoot}){
 requireValue(digest(controllerSha256)&&typeof criInspectionPath==='string'&&criInspectionPath,'cri_exit_receipt_missing');
 requireValue(controller.state==='error'&&(controller.exit===undefined||controller.exit===null)&&controller.terminationConfirmed===true&&!controller.cleanupError&&!controller.creationUncertain&&(controller.stopReasons===undefined||same(controller.stopReasons,[])),'cri_controller_state_unreconcilable');
 const cid=controller.memoryHigh?.containerID;
 requireValue(digest(cid)&&typeof controller.podName==='string'&&controller.podName&&typeof controller.podUid==='string'&&controller.podUid&&controller.memoryHigh.podUid===controller.podUid,'cri_controller_identity_missing');
 const prefix=`Command failed: kubectl --kubeconfig .test-runs/evidscope-training/kubeconfig.yaml --request-timeout=10s -n ${QA_NAMESPACE} exec ${controller.podName} -- python -c ${cgroupReadCommand}\n`;
 const suffix='error: Internal error occurred: Internal error occurred: error executing command in container: failed to exec in container: failed to create exec "';
 requireValue(typeof controller.error==='string'&&new RegExp('^'+regexEscape(prefix+suffix)+'[a-f0-9]{64}'+regexEscape(`": task ${cid} not found\n`)+'$').test(controller.error),'cri_controller_error_not_exit_race');
 const root=dirname(resolve(criInspectionPath)),raw=bytes(root,relative(root,resolve(criInspectionPath))),inspection=parseJson(raw),status=inspection?.status,info=inspection?.info;
 requireValue(inspection&&typeof inspection==='object'&&!Array.isArray(inspection)&&status&&typeof status==='object'&&!Array.isArray(status)&&info&&typeof info==='object'&&!Array.isArray(info),'cri_receipt_header_invalid');
 requireValue(status.state==='CONTAINER_EXITED'&&status.exitCode===0&&Number.isSafeInteger(status.exitCode)&&status.reason==='Completed'&&status.message===''&&info.pid===0&&info.removing===false,'cri_exit_not_completed');
 requireValue(status.id===cid&&status.metadata?.name==='training'&&status.metadata.attempt===0&&Number.isSafeInteger(status.metadata.attempt)&&status.annotations?.['io.kubernetes.container.restartCount']==='0'&&info.config?.metadata?.name==='training'&&info.config.annotations?.['io.kubernetes.container.restartCount']==='0','cri_container_identity_changed');
 const expectedLabels={'io.kubernetes.container.name':'training','io.kubernetes.pod.name':controller.podName,'io.kubernetes.pod.namespace':QA_NAMESPACE,'io.kubernetes.pod.uid':controller.podUid};
 for(const [key,value]of Object.entries(expectedLabels))requireValue(status.labels?.[key]===value&&info.config.labels?.[key]===value,'cri_pod_identity_changed');
 const annotations=info.runtimeSpec?.annotations;
 requireValue(annotations?.['io.kubernetes.cri.container-name']==='training'&&annotations['io.kubernetes.cri.container-type']==='container'&&annotations['io.kubernetes.cri.sandbox-name']===controller.podName&&annotations['io.kubernetes.cri.sandbox-namespace']===QA_NAMESPACE&&annotations['io.kubernetes.cri.sandbox-uid']===controller.podUid&&info.runtimeSpec?.linux?.cgroupsPath===`/kubepods/burstable/pod${controller.podUid}/${cid}`,'cri_runtime_identity_changed');
 requireValue(status.imageRef===QA_IMAGE&&info.config.image?.user_specified_image===QA_IMAGE&&annotations['io.kubernetes.cri.image-name']===QA_IMAGE,'cri_image_reference_changed');
 const livePod=json(controllerRoot,'live-pod.json'),liveJob=json(controllerRoot,'live-job.json'),containers=livePod.status?.containerStatuses;
 requireValue(Array.isArray(containers)&&containers.length===1&&containers[0].name==='training'&&containers[0].containerID==='containerd://'+cid&&containers[0].imageID===QA_IMAGE&&containers[0].restartCount===0&&Number.isSafeInteger(containers[0].restartCount)&&same(containers[0].lastState,{})&&livePod.metadata?.uid===controller.podUid&&livePod.metadata.name===controller.podName&&livePod.metadata.namespace===QA_NAMESPACE,'cri_live_container_binding_changed');
 const attempt=controller.controllerAttemptId;
 requireValue(typeof attempt==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(attempt)&&controller.manifest?.metadata?.annotations?.['evidscope.io/controller-attempt']===attempt&&liveJob.metadata?.annotations?.['evidscope.io/controller-attempt']===attempt,'cri_controller_attempt_changed');
 const start=exitTimestamp(controller.startedAt),end=exitTimestamp(controller.finishedAt),created=exitTimestamp(status.createdAt),started=exitTimestamp(status.startedAt),finished=exitTimestamp(status.finishedAt),released=exitTimestamp(controller.memoryHigh.observedAt),podStarted=exitTimestamp(containers[0].state?.running?.startedAt);
 requireValue([start,end,created,started,finished,released,podStarted].every(Number.isFinite)&&start<=created&&created<=started&&started<=released&&released<finished&&finished<=end&&end-finished<=30000&&started>=podStarted&&started-podStarted<1000&&end-start<=3600000,'cri_finish_timing_invalid');
 return {schemaVersion:1,kind:'exact_container_cri_exit_after_cgroup_exec_race_v1',reconciliationPassed:true,criInspectionPath:resolve(criInspectionPath),criInspectionSha256:sha(raw),originalControllerSha256:controllerSha256,originalControllerState:controller.state,originalControllerError:controller.error,controllerAttemptId:attempt,jobUid:controller.jobUid,podUid:controller.podUid,podName:controller.podName,namespace:QA_NAMESPACE,containerId:cid,imageRef:status.imageRef,containerAttempt:0,restartCount:0,state:status.state,exitCode:0,reason:status.reason,createdAt:status.createdAt,startedAt:status.startedAt,finishedAt:status.finishedAt,terminationConfirmed:true,limitations:['Raw persisted local CRI report reconciles an observation race; it is not independent hardware attestation or a rewritten controller success record.']};
}

async function verifyCore({runDirectory,controllerReceipt,workspaceRoot=process.cwd(),criInspectionPath},pins,syntheticFixture){
 tree(resolve(runDirectory));const controllerPath=resolve(controllerReceipt),controllerRoot=dirname(controllerPath),controllerBytes=bytes(controllerRoot,relative(controllerRoot,controllerPath)),controller=parseJson(controllerBytes),inputs=controller.inputs;
 requireValue(controller.schemaVersion===1&&controller.mode==='explicit_public_human_qa_grounding_continuation_v1'&&controller.terminationConfirmed===true&&controller.admission?.allowed===true&&!controller.cleanupError&&!controller.creationUncertain,'controller_execution_unverified');
 let runtimeExitReconciliation;
 if(criInspectionPath!==undefined)runtimeExitReconciliation=verifyRuntimeExitReconciliation({controller,controllerSha256:sha(controllerBytes),criInspectionPath,controllerRoot});
 else requireValue(controller.state==='process_completed'&&controller.exit?.exitCode===0&&!controller.error,'controller_execution_unverified');
 requireValue(controller.trainingRunCompleted===false&&controller.qualityClaimAllowed===false&&controller.promotionAllowed===false&&controller.automaticGovernanceGateClaimed===false,'controller_claim_changed');
 requireValue(typeof controller.jobUid==='string'&&controller.jobUid&&typeof controller.podUid==='string'&&controller.podUid&&inputs?.qualityClaimAllowed===false&&inputs.promotionAllowed===false&&inputs.mode==='explicit_public_human_qa_grounding_continuation'&&inputs.stage===CONTINUATION_STAGE&&inputs.diagnosticOnly===false&&inputs.rows===704&&inputs.runId===controller.runId&&controller.runId!==SOURCE_RUN&&/^public-qa-grounding-[a-z0-9-]{1,28}$/.test(controller.runId),'input_scope_changed');
 const source=await sourceBindings(workspaceRoot,inputs,pins.training,syntheticFixture),dataBytes=bytes(workspaceRoot,inputs.data),manifestBytes=bytes(workspaceRoot,inputs.manifest),manifest=parseJson(manifestBytes);
 requireValue(digest(inputs.datasetSha256)&&sha(dataBytes)===inputs.datasetSha256&&digest(inputs.manifestSha256)&&sha(manifestBytes)===inputs.manifestSha256&&manifest.datasetSha256===inputs.datasetSha256,'dataset_binding_changed');
 const dataset=datasetBindings(workspaceRoot,inputs,manifest,dataBytes,pins.dataset),candidateRoot=join(resolve(runDirectory),'candidate'),candidate=await sealed(candidateRoot,'candidate',json(candidateRoot,'candidate-complete.json').identity,20),identity=candidate.marker.identity,receipt=json(candidateRoot,'training-receipt.json');
 requireValue(identity?.baseRepository==='fdtn-ai/Foundation-Sec-8B-Reasoning'&&identity.baseRevision===QA_BASE_REVISION&&identity.image===QA_IMAGE&&identity.stage===CONTINUATION_STAGE&&identity.contextSelection==='full_original_context'&&identity.precision==='bf16'&&identity.modelDtype==='bfloat16'&&identity.quantComputeDtype==='bfloat16'&&identity.rank===8&&identity.sequenceLength===1024&&identity.batchSize===1&&identity.gradientAccumulationSteps===16&&identity.seed===42&&identity.learningRate===.00003&&identity.maxSteps===20&&identity.gpuMemoryFraction===.65&&same(identity.sampler,SAMPLER)&&identity.datasetSha256===inputs.datasetSha256&&identity.manifestSha256===inputs.manifestSha256&&identity.baseArtifactLockSha256===inputs.artifactLockSha256&&same(identity,inputs.targetIdentity),'candidate_identity_changed');
 runtimeBindings(controllerRoot,inputs,identity);const lineage=provenanceBindings(workspaceRoot,inputs,identity,source.identity,controller.runId,pins.training);
 requireValue(receipt.schemaVersion===2&&receipt.status==='trained_'+CONTINUATION_STAGE&&receipt.globalStep===20&&receipt.trainingRunCompleted===true&&receipt.qualityClaimAllowed===false&&receipt.promotionAllowed===false&&receipt.heldOutTestUsedForTraining===false&&receipt.localHumanReviewPerformed===false&&receipt.sourceLicense==='CC-BY-SA-4.0'&&receipt.targetFormat==='exact_human_answer_json_without_generated_reasoning'&&!receipt.resumeLineage&&same(receipt.identity,identity)&&same(receipt.trainingMetrics,candidate.marker.metrics)&&same(receipt.groundingLineage,lineage),'candidate_receipt_changed');
 requireValue(['train_loss','eval_loss','base_eval_loss'].every(key=>Number.isFinite(receipt.trainingMetrics?.[key]))&&Number.isFinite(receipt.cudaPeakAllocatedBytes)&&receipt.cudaPeakAllocatedBytes>0&&Number.isFinite(receipt.cudaPeakReservedBytes)&&receipt.cudaPeakReservedBytes>=receipt.cudaPeakAllocatedBytes,'candidate_measurement_invalid');
 requireValue(same(receipt.adapterFiniteCheck,{passed:true,tensorCount:256,nonFiniteTensorCount:0,dtypes:['torch.float32'],beforeCandidateSealing:true}),'gpu_finite_check_unverified');
 const {log,records,sequence}=trainingLogBindings(controllerRoot,lineage,identity,receipt.adapterFiniteCheck),checkpoints=[];for(const step of [10,20])checkpoints.push(await sealed(join(resolve(runDirectory),'checkpoint-'+step),'checkpoint',identity,step));
 const adapter=candidate.files.find(file=>file.path==='adapter_model.safetensors');requireValue(checkpoints.at(-1).files.find(file=>file.path==='adapter_model.safetensors')?.sha256===adapter.sha256&&adapter.sha256!==pins.training.adapterSha256,'final_checkpoint_adapter_changed');
 const finite=finiteAdapter(candidateRoot);for(const step of [10,20])finiteAdapter(join(resolve(runDirectory),'checkpoint-'+step));
 const encodingBytes=bytes(runDirectory,'encoding-receipt.json'),encoding=parseJson(encodingBytes);
 requireValue(encoding.datasetSha256===inputs.datasetSha256&&encoding.rows?.length===704&&encoding.rows.every((row,index)=>row.id===dataset[index].id&&row.contextStart===0&&row.contextEnd===Array.from(dataset[index].context).length&&row.originalContextSha256===dataset[index].contextSha256&&row.selectedContextSha256===row.originalContextSha256&&row.answerPreserved===true&&Number.isSafeInteger(row.tokens)&&row.tokens>0&&row.tokens<=1024&&digest(row.inputSha256)),'full_context_encoding_unverified');
 const exposureBytes=bytes(runDirectory,'training-exposure.json'),exposure=parseJson(exposureBytes),exposureVerification=verifyContinuationExposure(exposure,dataset,encoding,20);
 requireValue(same(records.continuationTrainingSample,exposure.rows.map(record=>({continuationTrainingSample:record})))&&same(records.continuationOptimizerGroup,exposure.groups.map(group=>({continuationOptimizerGroup:group,processedMicrobatches:group.optimizerGroup*16,totalAdapterHistoryOptimizerUpdates:60+group.optimizerGroup}))),'exposure_log_changed');
 requireValue(same(sequence,exposure.groups.flatMap((group,index)=>[...records.continuationTrainingSample.slice(index*16,(index+1)*16),records.optimizerStep[index],records.continuationOptimizerGroup[index]])),'exposure_optimizer_order_changed');
 requireValue(same(json(candidateRoot,'training-exposure.json'),exposure)&&same(json(join(runDirectory,'checkpoint-20'),'training-exposure.json'),exposure),'exposure_snapshot_changed');
 const firstExposure=json(join(runDirectory,'checkpoint-10'),'training-exposure.json');verifyContinuationExposure(firstExposure,dataset,encoding,10);requireValue(same(firstExposure.rows,exposure.rows.slice(0,160)),'exposure_checkpoint_prefix_changed');
 const exposureSummary={path:'training-exposure.json',sha256:sha(exposureBytes),processedMicrobatches:320,completedOptimizerGroups:20,counts:{answerable:220,impossible:100},sourceOptimizerHistoryUpdates:60,optimizerUpdatesThisExperiment:20,totalAdapterHistoryOptimizerUpdates:80,actualTensorBindingChecked:true};
 requireValue(same(receipt.trainingExposure,exposureSummary),'candidate_exposure_receipt_changed');
 requireValue(receipt.sourceOptimizerHistoryUpdates===60&&receipt.optimizerUpdatesThisExperiment===20&&receipt.totalAdapterHistoryOptimizerUpdates===80,'candidate_exposure_history_changed');
 const job=controller.manifest;requireValue(sha(JSON.stringify(job))===controller.manifestSha256&&job.metadata?.name===controller.runId&&job.metadata.namespace===QA_NAMESPACE&&job.metadata.annotations?.['evidscope.io/run-kind']==='explicit-public-human-qa-grounding-continuation'&&job.metadata.annotations['evidscope.io/dataset-sha256']===inputs.datasetSha256&&job.metadata.annotations['evidscope.io/manifest-sha256']===inputs.manifestSha256&&job.metadata.annotations['evidscope.io/provenance-sha256']===inputs.provenanceSha256&&job.spec?.backoffLimit===0&&job.spec.activeDeadlineSeconds===3600,'job_manifest_changed');
 validateSpec(job.spec.template.spec,controller.runId,inputs);validateSpec(controller.livePodSpec,controller.runId,inputs,{live:true});
 const liveJob=json(controllerRoot,'live-job.json'),livePod=json(controllerRoot,'live-pod.json');
 requireValue(liveJob.metadata?.uid===controller.jobUid&&liveJob.metadata.name===controller.runId&&liveJob.metadata.namespace===QA_NAMESPACE&&livePod.metadata?.uid===controller.podUid&&livePod.metadata.name===controller.podName&&livePod.metadata.namespace===QA_NAMESPACE&&livePod.metadata.ownerReferences?.some(owner=>owner.kind==='Job'&&owner.uid===controller.jobUid&&owner.name===controller.runId),'job_pod_binding_changed');
 validateSpec(liveJob.spec?.template?.spec,controller.runId,inputs);validateSpec(livePod.spec,controller.runId,inputs,{live:true});
 requireValue(controller.memoryHigh?.podUid===controller.podUid&&controller.memoryHigh.markerReleased===true&&controller.memoryHigh.containerLeafOnly===true&&controller.memoryHigh.memoryHigh==='2147483648'&&controller.memoryHigh.memoryMax==='12884901888','memory_control_unverified');
 return {schemaVersion:1,verificationPassed:true,verified:!syntheticFixture,syntheticFixture,actualTrainingExecutionVerified:!syntheticFixture,sourceTrainingExecutionVerified:!syntheticFixture,verifiedAt:new Date().toISOString(),runId:controller.runId,jobUid:controller.jobUid,podUid:controller.podUid,artifactSha256:candidate.markerSha256,adapterSha256:adapter.sha256,adapterTensorVerification:finite,controllerSha256:sha(controllerBytes),...(runtimeExitReconciliation?{originalControllerState:controller.state,originalControllerError:controller.error,runtimeExitReconciliation}:{}),runtimeConfigMapSha256:sha(bytes(controllerRoot,'runtime-configmap.json')),trainingLogSha256:sha(log),encodingReceiptSha256:sha(encodingBytes),exposureReceiptSha256:sha(exposureBytes),trainingExposure:exposureVerification,datasetSha256:inputs.datasetSha256,manifestSha256:inputs.manifestSha256,identity,globalStep:20,actualOptimizerUpdates:20,optimizerUpdatesThisRun:20,sourceOptimizerUpdates:60,sourceGlobalStep:20,totalAdapterHistoryOptimizerUpdates:80,skippedOptimizerUpdates:0,optimizerStateRestored:false,schedulerStateRestored:false,groundingLineage:lineage,checkpoints:checkpoints.map(({markerSha256,globalStep})=>({markerSha256,globalStep})),trainingRunCompleted:!syntheticFixture,terminationConfirmed:true,qualityClaimAllowed:false,promotionAllowed:false,trainingMetrics:receipt.trainingMetrics,limitations:['Local persisted records and exported hashes; not independent hardware attestation.','Twenty fresh optimizer updates after adapter-only warmstart; source step twenty and adapter history sixty are distinct.','Recorded completed forward/backward consumption: 220 answerable and 100 impossible microbatches.','Public human annotation is not local human review or evidence of legal/financial model quality.']};
}

export const verifyPublicQaGroundingContinuation=options=>verifyCore(options,{training:CONTINUATION_VERIFICATION_PINS,dataset:CONTINUATION_SOURCE_PINS},false);
// Test-only synthetic inputs never produce actual execution or completion claims.
export const verifyPublicQaGroundingContinuationFixture=(options,testOnlyPins)=>verifyCore(options,testOnlyPins,true);
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [runDirectory,controllerReceipt,output,...extra]=process.argv.slice(2);requireValue(runDirectory&&controllerReceipt&&output&&(extra.length===0||extra.length===2&&extra[0]==='--cri-exit-receipt'&&extra[1]),'usage: RUN_DIRECTORY CONTROLLER_RECEIPT NEW_REPORT_JSON [--cri-exit-receipt RAW_CRI_INSPECTION_JSON]');
 let result;try{result=await verifyPublicQaGroundingContinuation({runDirectory,controllerReceipt,criInspectionPath:extra[1]});}catch(error){result={schemaVersion:1,verified:false,verificationPassed:false,actualTrainingExecutionVerified:false,sourceTrainingExecutionVerified:false,trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false,error:error.message};process.exitCode=2;}
 mkdirSync(dirname(resolve(output)),{recursive:true});writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));
}
