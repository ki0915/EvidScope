import test from 'node:test';
import assert from 'node:assert/strict';
import {DIAGNOSTIC_PINS} from '../scripts/public-qa-diagnostic-workload.mjs';
import {GROUNDING_DIAGNOSTIC_REFERENCE_PINS,groundingDiagnosticJob,groundingDiagnosticRuntimeConfigMap,assertGroundingDiagnosticMounts} from '../scripts/public-qa-grounding-diagnostic-workload.mjs';

const fixture=()=>({...DIAGNOSTIC_PINS,mode:'public_qa_grounding_diagnostic',diagnosticOnly:true,sourceRunId:'public-qa-grounding-20261005-r2',rows:64,sourceTrainingExecutionVerified:true,qualityClaimAllowed:false,promotionAllowed:false,baselineExecutedThisRun:false,evaluationScope:'retrospective_regression_diagnosis_on_previously_observed_64_rows',priorResponsesSha256:GROUNDING_DIAGNOSTIC_REFERENCE_PINS.responsesSha256,priorVerificationSha256:GROUNDING_DIAGNOSTIC_REFERENCE_PINS.verificationSha256,bindingSha256:'1'.repeat(64),adapterSha256:'2'.repeat(64),runtimeConfigMap:'public-qa-gdiag-'+'a'.repeat(16)});
test('generation-only fixture job scopes candidate and binding read-only and accepts admitted default modes',()=>{
 const inputs=fixture(),job=groundingDiagnosticJob('public-qa-gdiag-fixture',inputs),pod=job.spec.template,c=pod.spec.containers[0];
 assert.deepEqual(c.command,['python','/runtime/evaluate-public-qa-grounding.py']);assert.equal(c.args.includes('--max-steps'),false);assert.equal(c.args.includes('--resume-from-checkpoint'),false);
 assert.equal(c.volumeMounts.find(m=>m.name==='adapters').subPath,'grounding-runs/public-qa-grounding-20261005-r2/candidate');assert.equal(c.volumeMounts.find(m=>m.name==='adapters').readOnly,true);assert.equal(c.volumeMounts.find(m=>m.name==='binding').subPath,'grounding-diagnostic/public-qa-grounding-20261005-r2');
 pod.spec.volumes.find(v=>v.name==='runtime').configMap.defaultMode=420;assert.doesNotThrow(()=>assertGroundingDiagnosticMounts(pod,inputs));
 c.volumeMounts.find(m=>m.name==='binding').readOnly=false;assert.throws(()=>assertGroundingDiagnosticMounts(pod,inputs),/mount_scope_invalid/);
});
test('generation job rejects changed observed64 data, prior output lineage and invented new baseline execution',()=>{
 for(const patch of [{datasetSha256:'0'.repeat(64)},{priorResponsesSha256:'0'.repeat(64)},{baselineExecutedThisRun:true},{sourceRunId:'untrusted-model'},{promotionAllowed:true}])assert.throws(()=>groundingDiagnosticJob('public-qa-gdiag-fixture',{...fixture(),...patch}),/fixed_data_changed|job_binding_invalid/);
});
test('generation runtime contains inference and integrity helpers without trainer execution',()=>{
 const cm=groundingDiagnosticRuntimeConfigMap();assert.equal(cm.immutable,true);assert.equal(cm.data['train-public-qa.py'],undefined);assert.ok(cm.data['evaluate-public-qa-grounding.py']);assert.ok(cm.data['evaluate-public-qa-diagnostic.py']);assert.ok(cm.data['public_qa_grounding.py']);assert.match(cm.metadata.name,/^public-qa-gdiag-[a-f0-9]{16}$/);
});
