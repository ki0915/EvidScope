import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {QA_NAMESPACE,QA_IMAGE,QA_BASE_REVISION,podSpec} from './public-qa-workload.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export const DIAGNOSTIC_PINS=Object.freeze({datasetSha256:'50561634095f758781c4695fcc30e2d7bd7cf7d9b937d8c10174a3e927c837f9',manifestSha256:'98224737c904da0c5c6abecf50c7238d8469c29877e76ffe92c10c003b9644d2',sourceControllerSha256:'a855afe3b260a20a0563dcff2ef01f066c4f4c4340552c66dda8fa27a229b36c',sourceVerificationSha256:'9c04141bd6d8cce1504c5ea5060a146d09e1a68786d4f485729f9d70b40ae0ca',candidateMarkerSha256:'3b0905e517c7daf21bc4359fad5bde302d88e763633832d157aeec268ea228c1',artifactLockSha256:'c067d1fe680e8f6dc14c592ade49a1d791ea6cb15ecbefeda52a609d5d922949'});
export const DIAGNOSTIC_SOURCE_RUN='public-qa-resume-20260928-r1';
export const STAGE2_DIAGNOSTIC_SOURCE_RUN='public-qa-stage2-lowmem-20261005-r4';
export const STAGE2_DIAGNOSTIC_PINS=Object.freeze({...DIAGNOSTIC_PINS,sourceControllerSha256:'10a6f18485608964af7674bc3ac51b97cb5f07258e99fbef767c4337774a06f6',sourceVerificationSha256:'5a69fa9345c234f57f29787285a7cec8aec852392226cbbf7fc6d076447db3e9',candidateMarkerSha256:'a6f152d43c2ae481277650b094a8c416f9c99bbe74ea962fd6ed2bf485b899ea',adapterSha256:'d7ab9fe25bed50ef85d8038f3493edfff3c1e492aa26f16945842935298f0c19',sourceRuntimeConfigMapSha256:'2e185f70a7de6a4a727831abcab434cba2ea2721f793465878ee3d76318d8b55'});
export function diagnosticProfile(sourceRunId=DIAGNOSTIC_SOURCE_RUN){
 if(sourceRunId===DIAGNOSTIC_SOURCE_RUN)return {pins:DIAGNOSTIC_PINS,sourceRunId,stageTwo:false};
 if(sourceRunId===STAGE2_DIAGNOSTIC_SOURCE_RUN)return {pins:STAGE2_DIAGNOSTIC_PINS,sourceRunId,stageTwo:true};
 throw Error('diagnostic_source_run_binding_invalid');
}
const runtimeFiles=Object.freeze({'evaluate-public-qa-diagnostic.py':'evaluate-public-qa-diagnostic.py','training_artifacts.py':'training_artifacts.py','public_qa_cuda_runtime.py':'public-qa-cuda-runtime.py','public_qa_memory_gate.py':'public-qa-memory-gate.py','public_qa_thermal.py':'public-qa-thermal.py'});
export function diagnosticRuntimeConfigMap(){
 const data=Object.fromEntries(Object.entries(runtimeFiles).map(([target,source])=>[target,readFileSync(`scripts/${source}`,'utf8')])),digest=sha(JSON.stringify(data));
 return {apiVersion:'v1',kind:'ConfigMap',metadata:{name:`public-qa-diagnostic-${digest.slice(0,16)}`,namespace:QA_NAMESPACE,annotations:{'evidscope.io/code-sha256':digest}},immutable:true,data};
}
export function publicQaDiagnosticInputs({stageTwo=false}={}){
 const {pins,sourceRunId}=diagnosticProfile(stageTwo?STAGE2_DIAGNOSTIC_SOURCE_RUN:DIAGNOSTIC_SOURCE_RUN);
 const paths={data:'.local/public-training/diagnostic/20260928/data.jsonl',manifest:'.local/public-training/diagnostic/20260928/manifest.json',lock:`.local/training/base/${QA_BASE_REVISION}/artifact-lock.json`,sourceController:`.local/training/public-qa-run/${sourceRunId}/controller-receipt.json`,sourceVerification:stageTwo?'reports/public-qa-stage2-artifact-verification-20261005.json':'reports/public-qa-artifact-verification-20260928.json',candidateMarker:`.local/training/runs/${sourceRunId}/candidate/candidate-complete.json`};
 const bindings={data:'datasetSha256',manifest:'manifestSha256',lock:'artifactLockSha256',sourceController:'sourceControllerSha256',sourceVerification:'sourceVerificationSha256',candidateMarker:'candidateMarkerSha256'},bytes=Object.fromEntries(Object.entries(paths).map(([key,path])=>[key,readFileSync(path)]));
 for(const [key,pin]of Object.entries(bindings))if(sha(bytes[key])!==pins[pin])throw Error('public_qa_diagnostic_input_binding_invalid:'+key);
 const manifest=JSON.parse(bytes.manifest),sourceVerification=JSON.parse(bytes.sourceVerification),candidate=JSON.parse(bytes.candidateMarker);
 if(manifest.mode!=='public_qa_diagnostic'||manifest.diagnosticOnly!==true||manifest.counts.total!==64||manifest.counts.answerable!==32||manifest.counts.unanswerable!==32||sourceVerification.verified!==stageTwo||sourceVerification.promotionAllowed!==false||candidate.globalStep!==(stageTwo?40:20)||candidate.identity.baseRevision!==QA_BASE_REVISION)throw Error('public_qa_diagnostic_scope_invalid');
 if(stageTwo){
  paths.sourceRuntime=`.local/training/public-qa-run/${sourceRunId}/runtime-configmap.json`;
  if(sha(readFileSync(paths.sourceRuntime))!==pins.sourceRuntimeConfigMapSha256||sourceVerification.runtimeConfigMapSha256!==pins.sourceRuntimeConfigMapSha256)throw Error('stage2_diagnostic_source_runtime_changed');
  paths.adapter=paths.candidateMarker.replace('candidate-complete.json','adapter_model.safetensors');
  const controller=JSON.parse(bytes.sourceController),adapter=candidate.files.find(item=>item.path==='adapter_model.safetensors');
  if(sha(readFileSync(paths.adapter))!==pins.adapterSha256||adapter?.sha256!==pins.adapterSha256||candidate.identity.stage!=='public_qa_stage2'||candidate.identity.maxSteps!==40||controller.runId!==sourceRunId||controller.mode!=='explicit_public_human_qa_stage2'||controller.state!=='process_completed'||controller.exit?.exitCode!==0||controller.terminationConfirmed!==true||controller.error||controller.cleanupError||sourceVerification.runId!==sourceRunId||sourceVerification.trainingRunCompleted!==true||sourceVerification.terminationConfirmed!==true||sourceVerification.globalStep!==40||sourceVerification.actualOptimizerUpdates!==40||sourceVerification.skippedOptimizerUpdates!==0||sourceVerification.artifactSha256!==pins.candidateMarkerSha256||sourceVerification.controllerSha256!==pins.sourceControllerSha256||sourceVerification.qualityClaimAllowed!==false||!isDeepStrictEqual(sourceVerification.identity,candidate.identity))throw Error('stage2_diagnostic_training_verification_invalid');
 }
 const code=diagnosticRuntimeConfigMap();
 return {...paths,...pins,mode:'public_qa_diagnostic',diagnosticOnly:true,sourceRunId,sourceVerificationReceipt:sourceVerification,trainingProvenanceVerified:stageTwo,promotionAllowed:false,qualityClaimAllowed:false,rows:64,runtimeConfigMap:code.metadata.name,runtimeSha256:code.metadata.annotations['evidscope.io/code-sha256'],runtimeFiles:Object.fromEntries(Object.entries(code.data).map(([name,value])=>[name,sha(value)]))};
}
export function diagnosticJob(runId,inputs=publicQaDiagnosticInputs()){
 if(!/^public-qa-[a-z0-9-]{1,35}$/.test(runId))throw Error('invalid_run_id');
 const {pins,sourceRunId,stageTwo}=diagnosticProfile(inputs.sourceRunId);
 if(Object.entries(pins).some(([key,value])=>inputs[key]!==value)||inputs.mode!=='public_qa_diagnostic'||inputs.diagnosticOnly!==true||inputs.sourceRunId!==sourceRunId||inputs.rows!==64||inputs.trainingProvenanceVerified!==stageTwo||inputs.promotionAllowed!==false||inputs.qualityClaimAllowed!==false||!/^public-qa-diagnostic-[a-f0-9]{16}$/.test(inputs.runtimeConfigMap))throw Error('public_qa_diagnostic_job_binding_invalid');
 const spec=podSpec({gpu:true}),container=spec.containers[0];
 spec.volumes=spec.volumes.filter(v=>v.name!=='checkpoints');container.volumeMounts=container.volumeMounts.filter(v=>v.name!=='checkpoints');
 spec.volumes.push({name:'adapters',persistentVolumeClaim:{claimName:'public-qa-checkpoints',readOnly:true}},{name:'diagnostic-output',persistentVolumeClaim:{claimName:'public-qa-checkpoints'}},{name:'runtime',configMap:{name:inputs.runtimeConfigMap}});
 container.volumeMounts.push({name:'adapters',mountPath:'/adapters/candidate',subPath:`runs/${sourceRunId}/candidate`,readOnly:true},{name:'diagnostic-output',mountPath:'/checkpoints/diagnostics',subPath:'diagnostics',readOnly:false},{name:'runtime',mountPath:'/runtime',readOnly:true});
 container.command=['python','/runtime/evaluate-public-qa-diagnostic.py'];
 container.args=['--data','/data/diagnostic/data.jsonl','--manifest','/data/diagnostic/manifest.json','--model-dir','/models/foundation-base','--adapter-dir','/adapters/candidate','--output',`/checkpoints/diagnostics/${runId}`];
 container.env=Object.entries({PYTHONPATH:'/runtime',PYTORCH_CUDA_ALLOC_CONF:'garbage_collection_threshold:0.5,max_split_size_mb:128',EVIDSCOPE_MEMORY_HIGH_REQUIRED:'1',EVIDSCOPE_ISOLATED:'1',EVIDSCOPE_DIAGNOSTIC_DATA_SHA256:inputs.datasetSha256,EVIDSCOPE_DIAGNOSTIC_MANIFEST_SHA256:inputs.manifestSha256,EVIDSCOPE_DIAGNOSTIC_CONTROLLER_SHA256:inputs.sourceControllerSha256,EVIDSCOPE_BASE_REPOSITORY:'fdtn-ai/Foundation-Sec-8B-Reasoning',EVIDSCOPE_BASE_REVISION:QA_BASE_REVISION,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:inputs.artifactLockSha256,EVIDSCOPE_TRAINING_IMAGE:QA_IMAGE}).map(([name,value])=>({name,value}));
 if(stageTwo){container.args.push('--source-stage','stage2');container.env.push(...Object.entries({EVIDSCOPE_DIAGNOSTIC_VERIFICATION_SHA256:inputs.sourceVerificationSha256,EVIDSCOPE_DIAGNOSTIC_CANDIDATE_SHA256:inputs.candidateMarkerSha256,EVIDSCOPE_DIAGNOSTIC_ADAPTER_SHA256:inputs.adapterSha256}).map(([name,value])=>({name,value})));}
 return {apiVersion:'batch/v1',kind:'Job',metadata:{name:runId,namespace:QA_NAMESPACE,annotations:{'evidscope.io/run-kind':'explicit-public-qa-diagnostic','evidscope.io/dataset-sha256':inputs.datasetSha256,'evidscope.io/manifest-sha256':inputs.manifestSha256,'evidscope.io/source-controller-sha256':inputs.sourceControllerSha256,'evidscope.io/source-verification-sha256':inputs.sourceVerificationSha256,'evidscope.io/diagnostic-only':'true'}},spec:{backoffLimit:0,activeDeadlineSeconds:3600,template:{metadata:{labels:{app:'public-qa-diagnostic'}},spec}}};
}
export function assertDiagnosticMounts(pod,sourceRunId=DIAGNOSTIC_SOURCE_RUN){
 const {pins,stageTwo}=diagnosticProfile(sourceRunId);
 const expected=diagnosticJob('public-qa-mount-check',{...pins,mode:'public_qa_diagnostic',diagnosticOnly:true,sourceRunId,rows:64,trainingProvenanceVerified:stageTwo,promotionAllowed:false,qualityClaimAllowed:false,runtimeConfigMap:'public-qa-diagnostic-'+'0'.repeat(16)}).spec.template.spec;
 const mounts=pod.spec.containers[0].volumeMounts;
 for(const name of ['base','data','adapters','diagnostic-output']){
  const actual=mounts.filter(m=>m.name===name),want=expected.containers[0].volumeMounts.find(m=>m.name===name),volumes=pod.spec.volumes.filter(v=>v.name===name),volume=expected.volumes.find(v=>v.name===name);
  if(actual.length!==1||volumes.length!==1||actual[0].mountPath!==want.mountPath||Boolean(actual[0].readOnly)!==Boolean(want.readOnly)||actual[0].subPath!==want.subPath||actual[0].subPathExpr||volumes[0].persistentVolumeClaim?.claimName!==volume.persistentVolumeClaim.claimName||Boolean(volumes[0].persistentVolumeClaim?.readOnly)!==Boolean(volume.persistentVolumeClaim.readOnly))throw Error('live_diagnostic_mount_scope_invalid');
 }
 if(mounts.some(m=>!['base','data','adapters','diagnostic-output','tmp','podinfo','runtime'].includes(m.name))||pod.spec.volumes.some(v=>v.persistentVolumeClaim&&!['base','data','adapters','diagnostic-output'].includes(v.name)))throw Error('live_diagnostic_extra_mount_invalid');
}
