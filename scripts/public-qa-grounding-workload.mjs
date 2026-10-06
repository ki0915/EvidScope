import {readFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {QA_NAMESPACE,QA_IMAGE,QA_BASE_REVISION,podSpec,runtimeConfigMap} from './public-qa-workload.mjs';
import {STAGE2_DIAGNOSTIC_SOURCE_RUN,STAGE2_DIAGNOSTIC_PINS,publicQaDiagnosticInputs} from './public-qa-diagnostic-workload.mjs';
import {GROUNDING_STAGE,GROUNDING_DIRECTORY,GROUNDING_SOURCE_PINS,immutableGroundingWrite,preparePublicQaGrounding} from './prepare-public-qa-grounding.mjs';

export const GROUNDING_SOURCE_RUN=STAGE2_DIAGNOSTIC_SOURCE_RUN;
export const GROUNDING_PINS=Object.freeze(Object.fromEntries(['sourceControllerSha256','sourceVerificationSha256','candidateMarkerSha256','adapterSha256','sourceRuntimeConfigMapSha256','artifactLockSha256'].map(key=>[key,STAGE2_DIAGNOSTIC_PINS[key]])));
export const GROUNDING_RUN_ID='public-qa-grounding-20261005-r4';
const sha=value=>createHash('sha256').update(value).digest('hex');
export function groundingRuntimeConfigMap(){
 const previous=runtimeConfigMap(),data={...previous.data,'public_qa_grounding.py':readFileSync('scripts/public-qa-grounding.py','utf8'),'public_qa_grounding_kbit.py':readFileSync('scripts/public-qa-grounding-kbit.py','utf8')},digest=sha(JSON.stringify(data));
 return {...previous,metadata:{name:`public-qa-grounding-${digest.slice(0,16)}`,namespace:QA_NAMESPACE,annotations:{'evidscope.io/code-sha256':digest}},data};
}
export function publicQaGroundingInputs({directory,runId=GROUNDING_RUN_ID}={}){
 if(!/^public-qa-grounding-[a-z0-9-]{1,28}$/.test(runId))throw Error('grounding_run_id_invalid');
 directory??=join(GROUNDING_DIRECTORY,runId);
 if(!existsSync(join(directory,'data.jsonl')))preparePublicQaGrounding({output:directory});
 const source=publicQaDiagnosticInputs({stageTwo:true}),data=join(directory,'data.jsonl'),manifest=join(directory,'manifest.json'),bytes=readFileSync(data),metadata=JSON.parse(readFileSync(manifest));
 if(metadata.stage!==GROUNDING_STAGE||metadata.datasetSha256!==sha(bytes)||metadata.counts?.train!==640||metadata.counts?.validation!==64||metadata.selection?.fullContextPreserved!==true||metadata.selection?.answerBasedCropping!==false||metadata.qualityClaimAllowed!==false||metadata.promotionAllowed!==false||!isDeepStrictEqual(metadata.sourcePins,GROUNDING_SOURCE_PINS))throw Error('grounding_input_binding_invalid');
 for(const [key,name]of Object.entries(metadata.sourceFiles))if(sha(readFileSync(join(directory,name)))!==GROUNDING_SOURCE_PINS[key])throw Error('grounding_source_file_changed:'+key);
 const code=groundingRuntimeConfigMap(),files=Object.fromEntries(Object.entries(code.data).map(([name,value])=>[name,sha(value)])),candidate=JSON.parse(readFileSync(source.candidateMarker));
 const identity={baseRepository:'fdtn-ai/Foundation-Sec-8B-Reasoning',baseRevision:QA_BASE_REVISION,baseArtifactLockSha256:source.artifactLockSha256,datasetSha256:sha(bytes),manifestSha256:sha(readFileSync(manifest)),trainerSha256:files['train-public-qa.py'],artifactHelperSha256:files['training_artifacts.py'],bindingHelperSha256:files['train-foundation-lora.py'],image:QA_IMAGE,rank:8,sequenceLength:1024,gpuMemoryFraction:0.65,batchSize:1,gradientAccumulationSteps:16,seed:42,learningRate:0.0001,maxSteps:20,stage:GROUNDING_STAGE,groundingHelperSha256:files['public_qa_grounding.py'],contextSelection:'full_original_context',precision:'bf16',modelDtype:'bfloat16',quantComputeDtype:'bfloat16'};
 const groundingProvenance={schemaVersion:1,kind:'adapter_only_warmstart_new_balanced_public_qa',sourceRunId:GROUNDING_SOURCE_RUN,sourceGlobalStep:40,sourcePins:{marker:source.candidateMarkerSha256,adapter:source.adapterSha256,controller:source.sourceControllerSha256,verification:source.sourceVerificationSha256},sourceIdentity:candidate.identity,targetRunId:runId,targetIdentity:identity,optimizerReset:true,schedulerReset:true,targetOptimizerSteps:20,sourceTrainingExecutionVerified:true,qualityClaimAllowed:false,promotionAllowed:false};
 const provenancePath=join(directory,'provenance.json');immutableGroundingWrite(provenancePath,JSON.stringify(groundingProvenance,null,2)+'\n');
 return {...source,data,manifest,mode:'explicit_public_human_qa_grounding',diagnosticOnly:false,stage:GROUNDING_STAGE,rows:704,runId,directory,datasetSha256:sha(bytes),manifestSha256:sha(readFileSync(manifest)),provenance:provenancePath,provenancePath,provenanceSha256:sha(readFileSync(provenancePath)),groundingProvenance,targetIdentity:identity,runtimeConfigMap:code.metadata.name,runtimeSha256:code.metadata.annotations['evidscope.io/code-sha256'],runtimeFiles:files,pvcOutputRelativePath:`grounding-runs/${runId}`};
}
export function groundingJob(runId,inputs=publicQaGroundingInputs({runId}),{tokenCheck=false}={}){
 if(!/^public-qa-grounding-[a-z0-9-]{1,28}$/.test(runId)||inputs.runId!==runId||inputs.mode!=='explicit_public_human_qa_grounding'||inputs.sourceRunId!==GROUNDING_SOURCE_RUN||inputs.rows!==704||inputs.stage!==GROUNDING_STAGE||inputs.targetIdentity?.maxSteps!==20||inputs.groundingProvenance?.targetRunId!==runId||inputs.promotionAllowed!==false||inputs.qualityClaimAllowed!==false||!/^public-qa-grounding-[a-f0-9]{16}$/.test(inputs.runtimeConfigMap)||Object.entries(GROUNDING_PINS).some(([key,value])=>inputs[key]!==value))throw Error('grounding_job_binding_invalid');
 const spec=podSpec({gpu:!tokenCheck}),container=spec.containers[0];
 spec.volumes=spec.volumes.filter(v=>v.name!=='checkpoints');container.volumeMounts=container.volumeMounts.filter(v=>v.name!=='checkpoints');
 container.volumeMounts.find(m=>m.name==='data').subPath=`grounding/${runId}`;
 container.volumeMounts.find(m=>m.name==='data').mountPath='/data/grounding';
 spec.volumes.push({name:'warmstart',persistentVolumeClaim:{claimName:'public-qa-checkpoints',readOnly:true}},{name:'grounding-output',persistentVolumeClaim:{claimName:'public-qa-checkpoints'}},{name:'runtime',configMap:{name:inputs.runtimeConfigMap}});
 container.volumeMounts.push({name:'warmstart',mountPath:'/warmstart/candidate',subPath:`runs/${GROUNDING_SOURCE_RUN}/candidate`,readOnly:true},{name:'grounding-output',mountPath:'/checkpoints/runs',subPath:'grounding-runs',readOnly:false},{name:'runtime',mountPath:'/runtime',readOnly:true});
 container.command=['python','/runtime/train-public-qa.py'];
 container.args=['--data','/data/grounding/data.jsonl','--manifest','/data/grounding/manifest.json','--grounding-provenance','/data/grounding/provenance.json','--warmstart-adapter','/warmstart/candidate','--model-dir','/models/foundation-base','--base-revision',QA_BASE_REVISION,'--output',`/checkpoints/runs/${runId}`,'--max-steps','20'];
 if(tokenCheck)container.args.push('--token-check');
 container.env=Object.entries({PYTHONPATH:'/runtime',PYTORCH_CUDA_ALLOC_CONF:'garbage_collection_threshold:0.5,max_split_size_mb:128',EVIDSCOPE_MEMORY_HIGH_REQUIRED:'1',EVIDSCOPE_ISOLATED:'1',EVIDSCOPE_GROUNDING_PROVENANCE_SHA256:inputs.provenanceSha256,EVIDSCOPE_DATASET_SHA256:inputs.datasetSha256,EVIDSCOPE_BASE_REPOSITORY:'fdtn-ai/Foundation-Sec-8B-Reasoning',EVIDSCOPE_BASE_REVISION:QA_BASE_REVISION,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:inputs.artifactLockSha256,EVIDSCOPE_TRAINING_IMAGE:QA_IMAGE}).map(([name,value])=>({name,value}));
 return {apiVersion:'batch/v1',kind:'Job',metadata:{name:runId,namespace:QA_NAMESPACE,annotations:{'evidscope.io/run-kind':tokenCheck?'explicit-public-qa-grounding-token-check':'explicit-public-human-qa-grounding','evidscope.io/dataset-sha256':inputs.datasetSha256,'evidscope.io/manifest-sha256':inputs.manifestSha256,'evidscope.io/provenance-sha256':inputs.provenanceSha256}},spec:{backoffLimit:0,activeDeadlineSeconds:3600,template:{metadata:{labels:{app:'public-qa-grounding'}},spec}}};
}
export function assertGroundingMounts(pod,inputs){
 const expected=groundingJob(inputs.runId,inputs).spec.template.spec;
 for(const name of ['base','data','warmstart','grounding-output','runtime']){
  const mounts=pod.spec.containers[0].volumeMounts.filter(m=>m.name===name),want=expected.containers[0].volumeMounts.find(m=>m.name===name),volumes=pod.spec.volumes.filter(v=>v.name===name),volume=expected.volumes.find(v=>v.name===name);
  const pvc=volumes[0]?.persistentVolumeClaim,wantPvc=volume?.persistentVolumeClaim,cm=volumes[0]?.configMap,wantCm=volume?.configMap;
  if(mounts.length!==1||volumes.length!==1||mounts[0].mountPath!==want.mountPath||Boolean(mounts[0].readOnly)!==Boolean(want.readOnly)||mounts[0].subPath!==want.subPath||mounts[0].subPathExpr||pvc?.claimName!==wantPvc?.claimName||Boolean(pvc?.readOnly)!==Boolean(wantPvc?.readOnly)||cm?.name!==wantCm?.name||Boolean(cm?.optional)!==Boolean(wantCm?.optional)||(cm?.defaultMode!==undefined&&cm.defaultMode!==420))throw Error('live_grounding_mount_scope_invalid');
 }
 if(pod.spec.containers[0].volumeMounts.some(m=>!['base','data','warmstart','grounding-output','runtime','tmp','podinfo'].includes(m.name))||pod.spec.volumes.some(v=>v.persistentVolumeClaim&&!['base','data','warmstart','grounding-output'].includes(v.name)))throw Error('live_grounding_extra_mount_invalid');
}
