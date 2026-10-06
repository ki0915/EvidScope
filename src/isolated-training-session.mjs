import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {hostname} from 'node:os';
import {trainingAdmission} from '../scripts/model-training-data.mjs';
import {probeWindowsHostResources} from '../scripts/training-host-check.mjs';
import {createIdleTrainingGuard,trainingStartDecision} from './training-resource-guard.mjs';
import {createKubectlTrainingAdapter,trainingTemplateHash} from '../deploy/training/kubectl-adapter.mjs';

export const TRAINING_BASE_REPOSITORY='fdtn-ai/Foundation-Sec-8B-Reasoning';
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const sha256=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const requiredIsolationChecks=['defaultDenyEgress','crossNamespaceDenied','serviceAccountUnavailable','hostFilesystemUnavailable','approvedVolumesOnly','processExitObserved','hostResourceProbeMatchesNode','gpuMemoryPilotPassed'];

export function validateTrainingRuntimeConfig(config,{now=Date.now(),hostName=hostname()}={}){
 const keys=['schemaVersion','enabled','context','nodeName','hostName','image','baseRepository','baseRevision','datasetSha256','artifactLock','measuredIsolationReceipt','sharedExecutionLease','resumeCheckpoint'];
 if(!config||config.schemaVersion!==1||config.enabled!==true||Object.keys(config).some(k=>!keys.includes(k)))throw Error('training_runtime_configuration_required');
 if(typeof config.context!=='string'||!config.context.trim()||config.context.length>200||/[\x00-\x1f]/.test(config.context))throw Error('training_context_required');
 if(typeof config.hostName!=='string'||config.hostName.toLowerCase()!==hostName.toLowerCase())throw Error('training_host_binding_required');
 if(config.baseRepository!==TRAINING_BASE_REPOSITORY||!/^[a-f0-9]{40}$/.test(config.baseRevision||''))throw Error('training_base_revision_required');
 if(!/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(config.image||''))throw Error('training_image_digest_required');
 if(!sha256(config.datasetSha256))throw Error('training_dataset_digest_required');
 const lock=config.artifactLock;
 if(!lock||lock.repository!==config.baseRepository||lock.revision!==config.baseRevision||!Array.isArray(lock.files)||!lock.files.length||lock.files.length>200)throw Error('training_artifact_lock_required');
 const paths=new Set();
 for(const item of lock.files){if(!item||typeof item.path!=='string'||item.path.length>200||!item.path.split('/').every(part=>/^[a-zA-Z0-9_.-]+$/.test(part)&&!['.','..'].includes(part))||paths.has(item.path)||!sha256(item.sha256))throw Error('training_artifact_lock_invalid');paths.add(item.path);}
 if(!['config.json','tokenizer.json','tokenizer_config.json','model.safetensors.index.json'].every(path=>paths.has(path))||![...paths].some(path=>path.endsWith('.safetensors')))throw Error('training_artifact_files_missing');
 if(config.sharedExecutionLease?.namespace!=='evidscope-models'||config.sharedExecutionLease?.name!=='evidscope-model-execution'||config.sharedExecutionLease?.automaticTakeover!==false)throw Error('training_shared_execution_lease_required');
 const receipt=config.measuredIsolationReceipt,observed=Date.parse(receipt?.observedAt);
 if(receipt?.source!=='measured_cluster_probe'||!Number.isFinite(observed)||observed>now||now-observed>300000||receipt.context!==config.context||receipt.nodeName!==config.nodeName||receipt.hostName?.toLowerCase()!==config.hostName.toLowerCase()||receipt.namespace!=='evidscope-training'||!sha256(receipt.manifestHash)||requiredIsolationChecks.some(key=>receipt.checks?.[key]!==true))throw Error('training_measured_isolation_required');
 if(trainingTemplateHash(config)!==receipt.manifestHash)throw Error('training_isolation_manifest_mismatch');
 return structuredClone(config);
}

export function readTrainingRuntimeConfig(path,options={}){
 if(!path)throw Error('training_runtime_configuration_required');
 try{const raw=readFileSync(path,'utf8');if(Buffer.byteLength(raw)>65536)throw Error('training_runtime_configuration_too_large');return validateTrainingRuntimeConfig(JSON.parse(raw),options);}
 catch(error){if(error.message.startsWith('training_'))throw error;throw Error('training_runtime_configuration_unavailable');}
}

export function inspectTrainingDataset(path,{expectedHash}={}){
 if(!path)throw Error('training_dataset_required');
 let raw;try{raw=readFileSync(path);if(!raw.length||raw.length>67108864)throw Error();}catch{throw Error('training_dataset_unavailable');}
 const datasetSha256=hash(raw);if(expectedHash&&datasetSha256!==expectedHash)throw Error('training_dataset_digest_mismatch');
 let rows;try{rows=raw.toString('utf8').trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);}catch{throw Error('training_dataset_invalid');}
 return {datasetSha256,admission:trainingAdmission(rows,{roleId:'evidence-organizer'})};
}

// This preflight is read-only and deliberately checks independent gates even
// when another gate fails. It never calls kubectl or loads model libraries.
export async function inspectTrainingReadiness({runtimeConfigPath,dataPath}={},dependencies={}){
 const clock=dependencies.clock||Date.now,result={schemaVersion:1,mode:'check-only',started:false,trainingRunCompleted:false,gates:{},reasons:[]};
 let config;
 try{config=(dependencies.readConfig||readTrainingRuntimeConfig)(runtimeConfigPath,{now:clock()});result.gates.runtime={allowed:true,context:config.context,baseRepository:config.baseRepository,baseRevision:config.baseRevision,manifestHash:config.measuredIsolationReceipt.manifestHash};}
 catch(error){result.gates.runtime={allowed:false,reasons:[error.message]};result.reasons.push(error.message);}
 try{const checked=(dependencies.inspectDataset||inspectTrainingDataset)(dataPath,{expectedHash:config?.datasetSha256});result.gates.data={allowed:checked.admission.trainingRunAllowed===true,...checked};if(!result.gates.data.allowed)result.reasons.push('training_data_admission_failed');}
 catch(error){result.gates.data={allowed:false,reasons:[error.message]};result.reasons.push(error.message);}
 try{const receipt=await(dependencies.probe||probeWindowsHostResources)(),decision=trainingStartDecision(receipt,{now:clock()});result.gates.host={...decision,receipt};if(!decision.allowed)result.reasons.push(...decision.reasons);}
 catch{result.gates.host={allowed:false,reasons:['host_resource_probe_unavailable']};result.reasons.push('host_resource_probe_unavailable');}
 result.allowed=Object.values(result.gates).every(gate=>gate.allowed===true);return result;
}

export function createIsolatedTrainingSession({runtimeConfigPath,dataPath}={},dependencies={}){
 const clock=dependencies.clock||Date.now,readConfig=dependencies.readConfig||readTrainingRuntimeConfig,inspectDataset=dependencies.inspectDataset||inspectTrainingDataset;
 const config=readConfig(runtimeConfigPath,{now:clock()});
 const checkData=()=>{const checked=inspectDataset(dataPath,{expectedHash:config.datasetSha256});if(checked.admission.trainingRunAllowed!==true)throw Error('training_data_admission_failed');return checked;};
 checkData();
 const probe=dependencies.probe||probeWindowsHostResources;
 const beforeCreate=async()=>{validateTrainingRuntimeConfig(config,{now:clock(),hostName:dependencies.hostName||hostname()});const decision=trainingStartDecision(await probe(),{now:clock()});if(!decision.allowed)throw Error('training_host_changed_before_create');};
 const adapter=(dependencies.createAdapter||createKubectlTrainingAdapter)(config,{beforeCreate});
 if(adapter.sharedLease?.namespace!=='evidscope-models'||adapter.sharedLease?.name!=='evidscope-model-execution'||adapter.sharedLease?.automaticTakeover!==false||adapter.manifestHash()!==config.measuredIsolationReceipt.manifestHash)throw Error('training_adapter_binding_invalid');
 let artifactVerification,used=false;
 const launcher={start:async options=>{validateTrainingRuntimeConfig(config,{now:clock(),hostName:dependencies.hostName||hostname()});checkData();return adapter.start(options);},observe:async workload=>{const result=await adapter.observe(workload);if(result.state==='succeeded'&&!artifactVerification){if(typeof adapter.verifyArtifacts!=='function')throw Error('training_artifact_verifier_required');artifactVerification=await adapter.verifyArtifacts(workload);if(artifactVerification?.verified!==true||!Number.isSafeInteger(artifactVerification.globalStep)||artifactVerification.globalStep<1)throw Error('training_artifacts_unverified');}return result;},stop:workload=>adapter.stop(workload)};
 const guard=createIdleTrainingGuard({probe,launcher,clock,...(dependencies.wait?{wait:dependencies.wait}:{})});
 return {run:async({signal}={})=>{
  if(used)throw Error('training_session_already_used');used=true;
  const result=await guard.run({signal});
  return {...result,artifactVerification:artifactVerification||null,trainingRunCompleted:result.reason==='completed'&&result.terminationConfirmed===true&&artifactVerification?.verified===true,qualityClaimAllowed:false,promotionAllowed:false};
 }};
}
