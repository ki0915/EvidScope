import {readFileSync} from 'node:fs';
import {createModelRuntime,validateArtifactLock,withModelSession} from './model-runtime.mjs';
import {createKubectlModelAdapter} from '../deploy/model-runtime/kubectl-adapter.mjs';
import {loadModelTlsConfig} from './isolated-inference-client.mjs';
import {runAssistance} from './assistance-runner.mjs';

const image=value=>/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(value||'');
const requiredChecks=['defaultDenyEgress','crossNamespaceDenied','serviceAccountUnavailable','hostFilesystemUnavailable','tlsPeerVerified','processExitObserved'];
export function validateIsolatedRuntimeConfig(config,{modelId='foundation-sec',now=Date.now()}={}){
 if(!config||config.schemaVersion!==1||config.enabled!==true||Object.keys(config).some(k=>!['schemaVersion','enabled','modelId','artifactLock','measuredIsolationReceipt','frontendImage','sharedExecutionLease'].includes(k)))throw Error('isolated_runtime_configuration_required');
 if(config.modelId!==modelId||config.artifactLock?.modelId!==modelId||!validateArtifactLock(config.artifactLock).valid||!image(config.frontendImage))throw Error('isolated_runtime_artifact_lock_invalid');
 const receipt=config.measuredIsolationReceipt,time=Date.parse(receipt?.observedAt);if(receipt?.source!=='measured_cluster_probe'||!Number.isFinite(time)||time>now||now-time>300000||!/^[a-f0-9]{64}$/.test(receipt.manifestHash||'')||requiredChecks.some(k=>receipt.checks?.[k]!==true))throw Error('isolated_runtime_measured_isolation_required');
 if(config.sharedExecutionLease?.namespace!=='evidscope-models'||config.sharedExecutionLease?.name!=='evidscope-model-execution'||config.sharedExecutionLease?.automaticTakeover!==false)throw Error('shared_execution_lease_required');
 return structuredClone(config);
}
export function readIsolatedRuntimeConfig(file,options){try{const raw=readFileSync(file,'utf8');if(Buffer.byteLength(raw)>65536)throw Error();return validateIsolatedRuntimeConfig(JSON.parse(raw),options);}catch(error){if(/^isolated_runtime_|^shared_execution_lease_/.test(error.message))throw error;throw Error('isolated_runtime_configuration_required');}}

// Construction performs only local validation. No Pod, model or fixture is started.
export function createIsolatedModelSession({tlsConfigPath,runtimeConfigPath,modelId='foundation-sec'}={},dependencies={}){
 if(!tlsConfigPath||!runtimeConfigPath)throw Error('isolated_tls_and_runtime_configuration_required');
 const config=(dependencies.readRuntimeConfig||readIsolatedRuntimeConfig)(runtimeConfigPath,{modelId});
 const tls=(dependencies.loadTls||loadModelTlsConfig)(tlsConfigPath);
 const adapter=(dependencies.createAdapter||createKubectlModelAdapter)({frontendImage:config.frontendImage,isolationManifestHash:config.measuredIsolationReceipt.manifestHash});
 if(adapter.sharedLease?.name!=='evidscope-model-execution'||adapter.sharedLease?.automaticTakeover!==false)throw Error('shared_execution_lease_required');
 if(adapter.manifestHash(modelId,config.artifactLock)!==config.measuredIsolationReceipt.manifestHash)throw Error('isolation_manifest_mismatch');
 const runtime=(dependencies.createRuntime||createModelRuntime)({adapter});
 return {modelId,tls,run:({runId,signal,onReceipt}={},work)=>withModelSession(runtime,{modelId,runId,artifactLock:config.artifactLock,isolationReceipt:config.measuredIsolationReceipt},({signal:sessionSignal})=>work({tls,signal:sessionSignal}),{signal,onReceipt})};
}
export async function runIsolatedAssistance({credential,baseUrl,tlsConfigPath,runtimeConfigPath,signal,onReceipt}={},dependencies={}){
 const session=createIsolatedModelSession({tlsConfigPath,runtimeConfigPath,modelId:'foundation-sec'},dependencies);
 return session.run({runId:credential?.runId,signal,onReceipt},({tls,signal:sessionSignal})=>(dependencies.runAssistance||runAssistance)({credential,baseUrl,tls,signal:sessionSignal}));
}
