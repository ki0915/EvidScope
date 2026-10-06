import {readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {verifyPublicQaFresh} from './verify-public-qa-fresh.mjs';
import {scoreFreshEvaluation} from './score-public-qa-fresh.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

export async function comparePublicQaFresh({runDirectory,controllerReceipt}){
 const proof=await verifyPublicQaFresh({runDirectory,controllerReceipt});
 if(proof.verified!==true||proof.evaluationExecutionVerified!==true||proof.sourceTrainingExecutionVerified!==true||proof.modelCalls!==256||proof.admittedRows!==128||proof.excludedRows!==0||proof.baselineExecutedThisRun!==true||proof.qualityClaimAllowed!==false||proof.promotionAllowed!==false)throw Error('fresh_comparison_execution_unverified');
 const controllerBytes=readFileSync(controllerReceipt),controller=JSON.parse(controllerBytes),dataBytes=readFileSync(controller.inputs.data),manifestBytes=readFileSync(controller.inputs.manifest),responsesBytes=readFileSync(join(runDirectory,'responses.json'));
 if(sha(controllerBytes)!==proof.controllerSha256||sha(dataBytes)!==proof.datasetSha256||sha(manifestBytes)!==proof.manifestSha256||sha(responsesBytes)!==proof.responsesSha256)throw Error('fresh_comparison_inputs_changed_after_verification');
 const result=scoreFreshEvaluation({dataBytes,manifest:JSON.parse(manifestBytes),responses:JSON.parse(responsesBytes)});
 return {...result,actualModelExecutionVerified:true,comparison:{baselineExecutedThisRun:true,sourceRunId:proof.sourceRunId,candidateRunId:proof.runId,newModelCalls:256,rows:128,evaluationScope:proof.evaluationScope,sameReasoningBase:true,executionOrder:['baseline','candidate'],sourceOptimizerHistoryUpdates:80},executionVerification:proof,qualityClaimAllowed:false,promotionAllowed:false};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [runDirectory,controllerReceipt,output,...extra]=process.argv.slice(2);
 if(!runDirectory||!controllerReceipt||!output||extra.length)throw Error('usage: compare-public-qa-fresh RUN_DIRECTORY CONTROLLER_RECEIPT NEW_REPORT_JSON');
 const report=await comparePublicQaFresh({runDirectory,controllerReceipt});writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({modelCalls:256,rows:128,baselinePassed:report.baseline.passed.count,candidatePassed:report.candidate.passed.count,gained:report.gained.length,regressed:report.regressed.length,qualityClaimAllowed:false,promotionAllowed:false}));
}
