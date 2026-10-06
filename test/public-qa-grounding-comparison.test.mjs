import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {verifySharedComparisonRuntime} from '../scripts/compare-public-qa-grounding.mjs';
import {GROUNDING_DIAGNOSTIC_REFERENCE_RUN,GROUNDING_DIAGNOSTIC_REFERENCE_PINS,groundingDiagnosticRuntimeConfigMap} from '../scripts/public-qa-grounding-diagnostic-workload.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=value=>Buffer.from(JSON.stringify(value));
function fixture(){
 const priorRoot=`.local/training/public-qa-run/${GROUNDING_DIAGNOSTIC_REFERENCE_RUN}`,priorControllerBytes=readFileSync(priorRoot+'/controller-receipt.json'),priorRuntimeBytes=readFileSync(priorRoot+'/runtime-configmap.json'),currentRuntime=groundingDiagnosticRuntimeConfigMap();
 const currentController={fixtureOnly:true,inputs:{runtimeConfigMap:currentRuntime.metadata.name,runtimeSha256:currentRuntime.metadata.annotations['evidscope.io/code-sha256'],runtimeFiles:Object.fromEntries(Object.entries(currentRuntime.data).map(([name,code])=>[name,sha(code)]))}},currentControllerBytes=json(currentController);
 return {priorControllerBytes,priorRuntimeBytes,currentRuntimeBytes:json(currentRuntime),currentControllerBytes,expectedPriorControllerSha256:GROUNDING_DIAGNOSTIC_REFERENCE_PINS.controllerSha256,expectedCurrentControllerSha256:sha(currentControllerBytes)};
}
test('shared generation guard accepts actual historical code and current inference helper without claiming execution',()=>{
 const result=verifySharedComparisonRuntime(fixture());assert.equal(result.sharedGenerationFile,'evaluate-public-qa-diagnostic.py');assert.equal(result.sharedGenerationSha256,'91ca7734c0eb11ffcfe643d3e134a3d8569d72dbdbcc53164fc5e7ac6a515a26');assert.equal(result.evaluationExecutionVerified,undefined);
});
test('fully rebound changed generation code is rejected even if controller and ConfigMap hashes remain consistent',()=>{
 const f=fixture(),runtime=JSON.parse(f.currentRuntimeBytes),controller=JSON.parse(f.currentControllerBytes),name='evaluate-public-qa-diagnostic.py';
 runtime.data[name]+='\n# changed generation implementation\n';const digest=sha(JSON.stringify(runtime.data));runtime.metadata.name='public-qa-gdiag-'+digest.slice(0,16);runtime.metadata.annotations['evidscope.io/code-sha256']=digest;controller.inputs.runtimeConfigMap=runtime.metadata.name;controller.inputs.runtimeSha256=digest;controller.inputs.runtimeFiles[name]=sha(runtime.data[name]);f.currentControllerBytes=json(controller);f.currentRuntimeBytes=json(runtime);f.expectedCurrentControllerSha256=sha(f.currentControllerBytes);
 assert.throws(()=>verifySharedComparisonRuntime(f),/shared_generation_code_changed/);
});
test('controller substitution and a changed unbound runtime file both fail closed',()=>{
 const f=fixture();f.currentControllerBytes=Buffer.from(f.currentControllerBytes.toString()+' ');assert.throws(()=>verifySharedComparisonRuntime(f),/controller_changed/);
 const changed=fixture(),runtime=JSON.parse(changed.currentRuntimeBytes);runtime.data['evaluate-public-qa-grounding.py']+='\n# mutation\n';changed.currentRuntimeBytes=json(runtime);assert.throws(()=>verifySharedComparisonRuntime(changed),/runtime_binding_changed/);
});
