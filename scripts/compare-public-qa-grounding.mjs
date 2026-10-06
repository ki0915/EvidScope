import {readFileSync,writeFileSync} from 'node:fs';
import {join,resolve,dirname} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {scoreDiagnostic} from './score-public-qa-diagnostic.mjs';
import {verifyPublicQaGroundingDiagnostic} from './verify-public-qa-grounding-diagnostic.mjs';
import {GROUNDING_DIAGNOSTIC_REFERENCE_RUN,GROUNDING_DIAGNOSTIC_REFERENCE_PINS} from './public-qa-grounding-diagnostic-workload.mjs';
import {QA_NAMESPACE} from './public-qa-workload.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const sharedRunner='evaluate-public-qa-diagnostic.py';
// This helper proves code identity only. Execution remains the verifier's job.
export function verifySharedComparisonRuntime({priorControllerBytes,currentControllerBytes,priorRuntimeBytes,currentRuntimeBytes,expectedPriorControllerSha256,expectedCurrentControllerSha256}){
 const controllers=[priorControllerBytes,currentControllerBytes],runtimes=[priorRuntimeBytes,currentRuntimeBytes],expected=[expectedPriorControllerSha256,expectedCurrentControllerSha256],codes=[];
 for(let index=0;index<2;index++){
  if(!/^[a-f0-9]{64}$/.test(expected[index]||'')||sha(controllers[index])!==expected[index])throw Error('comparison_controller_changed');
  const controller=JSON.parse(controllers[index]),runtime=JSON.parse(runtimes[index]),inputs=controller.inputs,data=runtime.data;
  if(!inputs||runtime.apiVersion!=='v1'||runtime.kind!=='ConfigMap'||runtime.immutable!==true||runtime.metadata?.namespace!==QA_NAMESPACE||runtime.metadata.name!==inputs.runtimeConfigMap||typeof data!=='object'||data===null||Array.isArray(data)||sha(JSON.stringify(data))!==inputs.runtimeSha256||runtime.metadata.annotations?.['evidscope.io/code-sha256']!==inputs.runtimeSha256)throw Error('comparison_runtime_binding_changed');
  const names=Object.keys(data).sort(),boundNames=Object.keys(inputs.runtimeFiles||{}).sort();
  if(JSON.stringify(names)!==JSON.stringify(boundNames)||names.some(name=>typeof data[name]!=='string'||sha(data[name])!==inputs.runtimeFiles[name])||typeof data[sharedRunner]!=='string'||!data[sharedRunner])throw Error('comparison_runtime_file_changed');
  codes.push(data[sharedRunner]);
 }
 if(codes[0]!==codes[1]||sha(codes[0])!==sha(codes[1]))throw Error('comparison_shared_generation_code_changed');
 return {sharedGenerationFile:sharedRunner,sharedGenerationSha256:sha(codes[0]),priorRuntimeConfigMapSha256:sha(priorRuntimeBytes),candidateRuntimeConfigMapSha256:sha(currentRuntimeBytes)};
}
export async function comparePublicQaGrounding(runDirectory,controllerReceipt){
 const proof=await verifyPublicQaGroundingDiagnostic({runDirectory,controllerReceipt});
 if(!proof.evaluationExecutionVerified||proof.modelCalls!==64||proof.baselineExecutedThisRun!==false)throw Error('grounding_generation_not_verified');
 const priorControllerRoot=`.local/training/public-qa-run/${GROUNDING_DIAGNOSTIC_REFERENCE_RUN}`,currentControllerRoot=dirname(resolve(controllerReceipt));
 const sharedRuntime=verifySharedComparisonRuntime({priorControllerBytes:readFileSync(join(priorControllerRoot,'controller-receipt.json')),currentControllerBytes:readFileSync(controllerReceipt),priorRuntimeBytes:readFileSync(join(priorControllerRoot,'runtime-configmap.json')),currentRuntimeBytes:readFileSync(join(currentControllerRoot,'runtime-configmap.json')),expectedPriorControllerSha256:GROUNDING_DIAGNOSTIC_REFERENCE_PINS.controllerSha256,expectedCurrentControllerSha256:proof.controllerReceiptSha256});
 const previousBytes=readFileSync(`.local/training/diagnostics/${GROUNDING_DIAGNOSTIC_REFERENCE_RUN}/responses.json`);
 if(sha(previousBytes)!==GROUNDING_DIAGNOSTIC_REFERENCE_PINS.responsesSha256)throw Error('prior_generation_changed');
 const previous=JSON.parse(previousBytes),currentBytes=readFileSync(join(runDirectory,'responses.json')),current=JSON.parse(currentBytes);
 if(sha(currentBytes)!==proof.responsesSha256||current.maxOutputTokens!==previous.maxOutputTokens||current.requestTimeoutSeconds!==previous.requestTimeoutSeconds||current.datasetSha256!==previous.datasetSha256)throw Error('comparison_settings_changed');
 const score=scoreDiagnostic({dataBytes:readFileSync('.local/public-training/diagnostic/20260928/data.jsonl'),manifest:JSON.parse(readFileSync('.local/public-training/diagnostic/20260928/manifest.json')),responses:{...previous,baseline:previous.candidate,candidate:current.candidate}});
 const gained=[],regressed=[];
 score.rows.candidate.forEach((row,index)=>{const old=score.rows.baseline[index];if(row.id!==old.id)throw Error('comparison_row_order_changed');if(row.passed&&!old.passed)gained.push(row.id);if(old.passed&&!row.passed)regressed.push(row.id);});
 return {...score,comparison:{referenceRunId:GROUNDING_DIAGNOSTIC_REFERENCE_RUN,candidateRunId:proof.runId,sourceTrainingRunId:proof.sourceRunId,referenceResponsesSha256:sha(previousBytes),candidateResponsesSha256:sha(currentBytes),...sharedRuntime,newModelCalls:64,referenceExecutedThisRun:false,evaluationScope:proof.evaluationScope,gained,regressed},executionVerification:proof};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [runDirectory,controllerReceipt,output,...extra]=process.argv.slice(2);
 if(!runDirectory||!controllerReceipt||!output||extra.length)throw Error('usage: compare-public-qa-grounding RUN_DIRECTORY CONTROLLER_RECEIPT NEW_REPORT_JSON');
 const report=await comparePublicQaGrounding(runDirectory,controllerReceipt);
 writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({baseline:report.baseline.passed,candidate:report.candidate.passed,answerable:report.byAnswerability.answerable.candidate.passed,unanswerable:report.byAnswerability.unanswerable.candidate.passed,gained:report.comparison.gained.length,regressed:report.comparison.regressed.length,newModelCalls:64,promotionAllowed:false}));
}
