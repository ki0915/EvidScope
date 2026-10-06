import {readFileSync,writeFileSync,lstatSync,readdirSync} from 'node:fs';
import {resolve,dirname,relative,sep,isAbsolute,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {canonical} from '../src/crypto.mjs';
import {DIAGNOSTIC_PINS,DIAGNOSTIC_SOURCE_RUN,diagnosticProfile,assertDiagnosticMounts} from './public-qa-diagnostic-workload.mjs';
import {QA_IMAGE,QA_BASE_REVISION,QA_NAMESPACE,QA_NODE} from './public-qa-workload.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const requireValue=(value,reason)=>{if(!value)throw Error(reason);};
const same=(a,b)=>canonical(a)===canonical(b);
const runtimeNames=['evaluate-public-qa-diagnostic.py','training_artifacts.py','public_qa_cuda_runtime.py','public_qa_memory_gate.py','public_qa_thermal.py'].sort();
const sorted=value=>[...value].sort();
function file(root,name,limit=64*1024*1024){
 root=resolve(root);const path=resolve(root,name),part=relative(root,path);requireValue(part&&!isAbsolute(part)&&!part.startsWith('..'+sep)&&part!=='..','verification_path_escape');
 for(let current=path;;current=dirname(current)){requireValue(!lstatSync(current).isSymbolicLink(),'verification_symlink');if(current===root)break;}
 const stat=lstatSync(path);requireValue(stat.isFile()&&stat.size<=limit,'verification_file_invalid');return readFileSync(path);
}
const parseJson=bytes=>JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/,''));
const readJson=(root,name)=>parseJson(file(root,name));
function validateSpec(spec,runId,inputs,{live=false}={}){
 requireValue(spec?.containers?.length===1&&!spec.initContainers?.length&&!spec.ephemeralContainers?.length&&spec.automountServiceAccountToken===false&&spec.restartPolicy==='Never'&&spec.runtimeClassName==='nvidia'&&!spec.hostNetwork&&!spec.hostPID&&!spec.hostIPC,'diagnostic_pod_scope_invalid');
 if(live)requireValue(spec.nodeName===QA_NODE,'diagnostic_node_changed');
 requireValue(spec.nodeSelector?.['kubernetes.io/hostname']===QA_NODE&&spec.securityContext?.runAsUser===10001,'diagnostic_node_or_user_changed');
 const {stageTwo}=diagnosticProfile(inputs.sourceRunId);
 const c=spec.containers[0];requireValue(c.name==='training'&&c.image===QA_IMAGE&&c.securityContext?.readOnlyRootFilesystem===true&&c.securityContext?.allowPrivilegeEscalation===false&&c.securityContext?.capabilities?.drop?.includes('ALL'),'diagnostic_container_scope_invalid');
 requireValue(c.resources?.limits?.cpu==='2'&&c.resources.limits.memory==='12Gi'&&String(c.resources.limits['nvidia.com/gpu'])==='1','diagnostic_resources_changed');
 requireValue(same(c.command,['python','/runtime/evaluate-public-qa-diagnostic.py'])&&same(c.args,['--data','/data/diagnostic/data.jsonl','--manifest','/data/diagnostic/manifest.json','--model-dir','/models/foundation-base','--adapter-dir','/adapters/candidate','--output',`/checkpoints/diagnostics/${runId}`,...(stageTwo?['--source-stage','stage2']:[])]),'diagnostic_command_changed');
 const env=Object.fromEntries((c.env||[]).map(x=>[x.name,x.value]));requireValue(Object.keys(env).length===(c.env||[]).length,'diagnostic_duplicate_env');
 for(const [name,value]of Object.entries({EVIDSCOPE_ISOLATED:'1',EVIDSCOPE_MEMORY_HIGH_REQUIRED:'1',EVIDSCOPE_DIAGNOSTIC_DATA_SHA256:inputs.datasetSha256,EVIDSCOPE_DIAGNOSTIC_MANIFEST_SHA256:inputs.manifestSha256,EVIDSCOPE_DIAGNOSTIC_CONTROLLER_SHA256:inputs.sourceControllerSha256,EVIDSCOPE_BASE_REVISION:QA_BASE_REVISION,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:inputs.artifactLockSha256,EVIDSCOPE_TRAINING_IMAGE:QA_IMAGE}))requireValue(env[name]===value,'diagnostic_environment_changed:'+name);
 if(stageTwo)for(const [name,value]of Object.entries({EVIDSCOPE_DIAGNOSTIC_VERIFICATION_SHA256:inputs.sourceVerificationSha256,EVIDSCOPE_DIAGNOSTIC_CANDIDATE_SHA256:inputs.candidateMarkerSha256,EVIDSCOPE_DIAGNOSTIC_ADAPTER_SHA256:inputs.adapterSha256}))requireValue(env[name]===value,'diagnostic_environment_changed:'+name);
 assertDiagnosticMounts({spec},inputs.sourceRunId);
 requireValue(!spec.volumes.some(v=>v.hostPath||v.secret)&&spec.volumes.filter(v=>v.name==='runtime'&&v.configMap?.name===inputs.runtimeConfigMap).length===1&&c.volumeMounts.filter(m=>m.name==='runtime'&&m.mountPath==='/runtime'&&m.readOnly===true).length===1,'diagnostic_runtime_mount_changed');
}
function verifyCore({runDirectory,controllerReceipt,workspaceRoot=process.cwd()},pins,syntheticFixture){
 const controllerPath=resolve(controllerReceipt),controllerRoot=dirname(controllerPath),controllerBytes=file(controllerRoot,relative(controllerRoot,controllerPath)),controller=parseJson(controllerBytes),inputs=controller.inputs;
 const profile=diagnosticProfile(inputs?.sourceRunId),stageTwo=profile.stageTwo;pins??=profile.pins;
 requireValue(controller.mode==='explicit_public_qa_diagnostic'&&controller.diagnosticOnly===true&&controller.state==='process_completed'&&controller.exit?.exitCode===0&&controller.terminationConfirmed===true&&controller.admission?.allowed===true&&!controller.error&&!controller.cleanupError,'diagnostic_controller_execution_unverified');
 requireValue(controller.trainingRunCompleted===false&&controller.qualityClaimAllowed===false&&controller.promotionAllowed===false&&controller.automaticGovernanceGateClaimed===false,'diagnostic_controller_claim_changed');
 requireValue(/^public-qa-[a-z0-9-]{1,35}$/.test(controller.runId||'')&&typeof controller.jobUid==='string'&&controller.jobUid&&typeof controller.podUid==='string'&&controller.podUid,'diagnostic_execution_identity_missing');
 requireValue(inputs?.mode==='public_qa_diagnostic'&&inputs.diagnosticOnly===true&&inputs.sourceRunId===profile.sourceRunId&&inputs.rows===64&&inputs.trainingProvenanceVerified===stageTwo&&inputs.promotionAllowed===false&&inputs.qualityClaimAllowed===false,'diagnostic_input_scope_changed');
 for(const [key,value]of Object.entries(pins))requireValue(inputs[key]===value,'diagnostic_input_pin_changed:'+key);
 const sourceFiles={data:'datasetSha256',manifest:'manifestSha256',lock:'artifactLockSha256',sourceController:'sourceControllerSha256',sourceVerification:'sourceVerificationSha256',candidateMarker:'candidateMarkerSha256',...(stageTwo?{adapter:'adapterSha256',sourceRuntime:'sourceRuntimeConfigMapSha256'}:{})},source={};
 for(const [key,pin]of Object.entries(sourceFiles)){requireValue(typeof inputs[key]==='string','diagnostic_source_path_missing:'+key);source[key]=file(workspaceRoot,inputs[key]);requireValue(sha(source[key])===pins[pin],'diagnostic_source_changed:'+key);}
 const dataset=source.data.toString('utf8').trim().split(/\r?\n/).map(JSON.parse),manifest=parseJson(source.manifest),candidate=parseJson(source.candidateMarker),failedController=parseJson(source.sourceController),failedVerification=parseJson(source.sourceVerification),lock=parseJson(source.lock);
 const ids=dataset.map(row=>row.id);requireValue(ids.length===64&&new Set(ids).size===64&&ids.every(id=>/^[a-zA-Z0-9_-]{1,160}$/.test(id))&&same(manifest.rowIds,ids)&&manifest.datasetSha256===pins.datasetSha256&&manifest.mode==='public_qa_diagnostic'&&manifest.diagnosticOnly===true,'diagnostic_dataset_identity_invalid');
 if(stageTwo){requireValue(failedController.runId===profile.sourceRunId&&failedController.mode==='explicit_public_human_qa_stage2'&&failedController.state==='process_completed'&&failedController.exit?.exitCode===0&&failedController.terminationConfirmed===true&&!failedController.error&&!failedController.cleanupError&&failedVerification.verified===true&&failedVerification.runId===profile.sourceRunId&&failedVerification.trainingRunCompleted===true&&failedVerification.terminationConfirmed===true&&failedVerification.globalStep===40&&failedVerification.actualOptimizerUpdates===40&&failedVerification.skippedOptimizerUpdates===0&&failedVerification.runtimeConfigMapSha256===pins.sourceRuntimeConfigMapSha256&&failedVerification.artifactSha256===pins.candidateMarkerSha256&&failedVerification.controllerSha256===pins.sourceControllerSha256&&failedVerification.qualityClaimAllowed===false&&failedVerification.promotionAllowed===false&&same(failedVerification.identity,candidate.identity),'source_stage2_training_not_verified');}
 else requireValue(failedController.state==='error'&&failedController.trainingRunCompleted===false&&failedVerification.verified===false&&failedVerification.trainingRunCompleted===false&&failedVerification.promotionAllowed===false,'source_training_failure_not_preserved');
 requireValue(lock.revision===QA_BASE_REVISION&&candidate.globalStep===(stageTwo?40:20)&&candidate.identity?.baseRevision===QA_BASE_REVISION&&candidate.identity.baseArtifactLockSha256===pins.artifactLockSha256,'diagnostic_candidate_base_changed');
 const candidateRoot=dirname(resolve(workspaceRoot,inputs.candidateMarker));requireValue(Array.isArray(candidate.files)&&candidate.files.length>0,'candidate_inventory_missing');
 for(const item of candidate.files){const bytes=file(candidateRoot,item.path);requireValue(bytes.length===item.bytes&&sha(bytes)===item.sha256,'diagnostic_candidate_file_changed');}
 requireValue(same(readdirSync(candidateRoot).sort(),[...candidate.files.map(f=>f.path),basename(inputs.candidateMarker)].sort()),'diagnostic_candidate_inventory_changed');
 const adapter=candidate.files.find(f=>f.path==='adapter_model.safetensors');requireValue(adapter&&(!stageTwo||adapter.sha256===pins.adapterSha256&&candidate.identity.stage==='public_qa_stage2'&&candidate.identity.maxSteps===40),'diagnostic_adapter_missing');
 const job=controller.manifest;requireValue(sha(JSON.stringify(job))===controller.manifestSha256&&job.metadata?.name===controller.runId&&job.metadata.namespace===QA_NAMESPACE,'diagnostic_job_manifest_changed');
 validateSpec(job.spec.template.spec,controller.runId,inputs);validateSpec(controller.livePodSpec,controller.runId,inputs,{live:true});
 const liveJob=readJson(controllerRoot,'live-job.json'),livePod=readJson(controllerRoot,'live-pod.json');
 requireValue(liveJob.metadata?.uid===controller.jobUid&&liveJob.metadata.name===controller.runId&&liveJob.metadata.namespace===QA_NAMESPACE&&livePod.metadata?.uid===controller.podUid&&livePod.metadata.name===controller.podName&&livePod.metadata.namespace===QA_NAMESPACE&&livePod.metadata.ownerReferences?.some(o=>o.kind==='Job'&&o.uid===controller.jobUid&&o.name===controller.runId),'diagnostic_live_job_pod_binding_changed');
 validateSpec(liveJob.spec.template.spec,controller.runId,inputs);validateSpec(livePod.spec,controller.runId,inputs,{live:true});
 requireValue(controller.memoryHigh?.podUid===controller.podUid&&controller.memoryHigh.markerReleased===true&&controller.memoryHigh.containerLeafOnly===true&&controller.memoryHigh.memoryHigh==='2147483648'&&controller.memoryHigh.memoryMax==='12884901888','diagnostic_memory_control_unverified');
 const runtime=readJson(controllerRoot,'runtime-configmap.json'),runtimeHash=sha(JSON.stringify(runtime.data));
 requireValue(runtime.immutable===true&&runtime.metadata?.namespace===QA_NAMESPACE&&runtime.metadata.name===inputs.runtimeConfigMap&&runtime.metadata.name==='public-qa-diagnostic-'+runtimeHash.slice(0,16)&&runtime.metadata.annotations?.['evidscope.io/code-sha256']===runtimeHash&&inputs.runtimeSha256===runtimeHash&&same(Object.keys(runtime.data).sort(),runtimeNames)&&same(Object.keys(inputs.runtimeFiles||{}).sort(),runtimeNames),'diagnostic_runtime_changed');
 for(const [name,code]of Object.entries(runtime.data))requireValue(typeof code==='string'&&sha(code)===inputs.runtimeFiles[name],'diagnostic_runtime_file_changed');
 const receipt=readJson(runDirectory,'diagnostic-receipt.json'),responseBytes=file(runDirectory,'responses.json'),admissionBytes=file(runDirectory,'preadmission.json'),responses=parseJson(responseBytes),admission=parseJson(admissionBytes),progress=readJson(runDirectory,'progress.json');
 requireValue(receipt.state==='generation_completed'&&receipt.diagnosticOnly===true&&receipt.source==='isolated_public_qa_generation'&&receipt.podUid===controller.podUid&&receipt.image===QA_IMAGE&&typeof receipt.deviceId==='string'&&receipt.deviceId,'diagnostic_generation_unverified');
 for(const key of ['controllerExecutionVerified','sourceTrainingControllerFileReadInPod','qualityClaimAllowed','promotionAllowed','localHumanReviewPerformed'])requireValue(receipt[key]===false,'diagnostic_generation_claim_changed:'+key);
 requireValue(receipt.sourceTrainingExecutionVerified===stageTwo,'diagnostic_source_training_claim_changed');
 if(stageTwo)requireValue(receipt.sourceTrainingVerificationSha256===pins.sourceVerificationSha256,'diagnostic_source_verification_changed');
 for(const [key,value]of Object.entries({datasetSha256:pins.datasetSha256,manifestSha256:pins.manifestSha256,candidateMarkerSha256:pins.candidateMarkerSha256,adapterSha256:adapter.sha256,baseArtifactLockSha256:pins.artifactLockSha256,sourceTrainingControllerSha256:pins.sourceControllerSha256,responsesSha256:sha(responseBytes),preadmissionSha256:sha(admissionBytes)}))requireValue(receipt[key]===value,'diagnostic_receipt_binding_changed:'+key);
 requireValue(same(receipt.candidateIdentity,candidate.identity),'diagnostic_candidate_identity_changed');
 const {responsesSha256,preadmissionSha256,...withoutHashes}=receipt;requireValue(same(progress,withoutHashes),'diagnostic_progress_incomplete');
 requireValue(same(receipt.resources,{cpuLimit:2,memoryLimitGiB:12,gpuAllocatorFraction:.65,contextTokens:1024,maxOutputTokens:128,requestTimeoutSeconds:120,seed:42,doSample:false,quantization:'NF4',samePromptsAndResources:true}),'diagnostic_generation_resources_changed');
 requireValue(Number.isFinite(receipt.cudaPeakAllocatedBytes)&&receipt.cudaPeakAllocatedBytes>0&&Number.isFinite(receipt.cudaPeakReservedBytes)&&receipt.cudaPeakReservedBytes>=receipt.cudaPeakAllocatedBytes,'diagnostic_cuda_measurement_invalid');
 requireValue(admission.datasetSha256===pins.datasetSha256&&admission.manifestSha256===pins.manifestSha256&&admission.beforeAnyModelCall===true&&admission.answerBasedCropping===false&&same(admission.rows?.map(r=>r.id),ids),'diagnostic_preadmission_changed');
 const admitted=[];for(let i=0;i<ids.length;i++){const a=admission.rows[i],row=dataset[i],accept=a.inputTokens+128<=1024;requireValue(Number.isSafeInteger(a.inputTokens)&&a.inputTokens>0&&a.outputTokenBudget===128&&a.contextTokens===1024&&a.contextSha256===row.contextSha256&&a.fullContextPreserved===true&&a.admitted===accept&&a.exclusionReason===(accept?null:'full_context_token_budget_exceeded'),'diagnostic_preadmission_row_invalid');if(accept)admitted.push(row.id);}
 requireValue(admitted.length>0&&admission.admitted===admitted.length&&admission.excluded===64-admitted.length&&receipt.preparedRows===64&&receipt.admittedRows===admitted.length&&receipt.excludedRows===64-admitted.length&&receipt.modelCalls===2*admitted.length,'diagnostic_generation_counts_invalid');
 requireValue(responses.mode==='public_qa_diagnostic'&&responses.datasetSha256===pins.datasetSha256&&responses.maxOutputTokens===128&&responses.requestTimeoutSeconds===120,'diagnostic_response_scope_changed');
 const expectedPartials=[],expectedLogs=[];let call=0;
 for(const side of ['baseline','candidate']){
  requireValue(same(Object.keys(responses[side]||{}).sort(),sorted(ids)),'diagnostic_response_ids_changed');
  for(let i=0;i<ids.length;i++){
   const id=ids[i],r=responses[side][id],a=admission.rows[i];requireValue(typeof r.content==='string'&&Number.isFinite(r.seconds)&&r.seconds>=0&&r.inputTokens===a.inputTokens&&Number.isSafeInteger(r.outputTokens)&&r.outputTokens>=0&&r.outputTokens<=128&&r.timedOut===(r.seconds>=120)&&r.tokenLimitReached===(r.outputTokens>=128),'diagnostic_response_measurement_invalid');
   if(!a.admitted){requireValue(r.content===''&&r.seconds===0&&r.outputTokens===0&&r.error==='full_context_token_budget_exceeded','diagnostic_exclusion_changed');continue;}
   requireValue(r.error===undefined,'diagnostic_admitted_response_error');const name=`${side}-${id}.json`;expectedPartials.push(name);requireValue(same(readJson(runDirectory,'rows/'+name),{id,side,...r}),'diagnostic_row_partial_changed');
   expectedLogs.push({side,id,modelCalls:++call,seconds:r.seconds,outputTokens:r.outputTokens,timedOut:r.timedOut,tokenLimitReached:r.tokenLimitReached});
  }
 }
 requireValue(same(readdirSync(resolve(runDirectory,'rows')).sort(),expectedPartials.sort()),'diagnostic_row_inventory_changed');
 const generationLogs=[];for(const line of file(controllerRoot,'training.log',16*1024*1024).toString('utf8').split(/[\r\n]+/)){const at=line.indexOf('{');if(at<0)continue;let value;try{value=JSON.parse(line.slice(at));}catch{continue;}if(Object.hasOwn(value,'side')&&Object.hasOwn(value,'modelCalls'))generationLogs.push(value);}
 requireValue(same(generationLogs,expectedLogs),'diagnostic_generation_log_mismatch');
 return {schemaVersion:1,verificationPassed:true,evaluationExecutionVerified:!syntheticFixture,syntheticFixture,runId:controller.runId,jobUid:controller.jobUid,podUid:controller.podUid,controllerReceiptSha256:sha(controllerBytes),responsesSha256,preAdmissionSha256:preadmissionSha256,datasetSha256:pins.datasetSha256,modelCalls:receipt.modelCalls,admittedRows:admitted.length,excludedRows:64-admitted.length,sourceTrainingExecutionVerified:stageTwo&&!syntheticFixture,trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false,limitations:['Local persisted execution evidence and hashes; not independent hardware attestation.','Output quality scoring and human semantic review remain separate.',...(stageTwo?[]:['Source training controller failure remains unresolved.'])]};
}
export const verifyPublicQaDiagnostic=options=>verifyCore(options,null,false);
// Synthetic unit fixtures cannot produce an actual-execution verification claim.
export const verifyPublicQaDiagnosticFixture=(options,testOnlyPins)=>verifyCore(options,testOnlyPins,true);
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const [runDirectory,controllerReceipt,output,...extra]=process.argv.slice(2);if(!runDirectory||!controllerReceipt||!output||extra.length)throw Error('usage: verify-public-qa-diagnostic RUN_DIRECTORY CONTROLLER_RECEIPT OUTPUT_JSON');
 let result;try{result=verifyPublicQaDiagnostic({runDirectory,controllerReceipt});}catch(error){result={schemaVersion:1,verificationPassed:false,evaluationExecutionVerified:false,sourceTrainingExecutionVerified:false,trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false,error:error.message};process.exitCode=2;}
 requireValue(![controllerReceipt,...['responses.json','preadmission.json','diagnostic-receipt.json','progress.json'].map(name=>resolve(runDirectory,name))].some(path=>resolve(path)===resolve(output)),'verification_output_overwrites_evidence');
 writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
