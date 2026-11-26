import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {verifyPublicQaGroundingBalanced as verifyExecution} from './verify-public-qa-grounding-continuation.mjs';
import {balancedDataPins} from './public-qa-grounding-balanced-workload.mjs';
export {balancedPlan,verifyBalancedExposure} from './verify-public-qa-grounding-continuation.mjs';
export async function verifyPublicQaGroundingBalanced(options){
 const controller=JSON.parse(readFileSync(options.controllerReceipt,'utf8').replace(/^\uFEFF/,''));
 let pins;try{pins=balancedDataPins(controller.runId??controller.inputs?.runId);}catch{throw Error('continuation_balanced_frozen_data_pin_changed');}
 if(controller.inputs?.datasetSha256!==pins.datasetSha256||controller.inputs?.manifestSha256!==pins.manifestSha256)throw Error('continuation_balanced_frozen_data_pin_changed');
 return verifyExecution(options);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [runDirectory,controllerReceipt,output,...extra]=process.argv.slice(2);
 if(!runDirectory||!controllerReceipt||!output||!(extra.length===0||extra.length===2&&extra[0]==='--cri-exit-receipt'&&extra[1]))throw Error('Usage: RUN_DIRECTORY CONTROLLER_RECEIPT NEW_REPORT_JSON [--cri-exit-receipt RAW_CRI_INSPECTION_JSON]');
 let result;
 try{result=await verifyPublicQaGroundingBalanced({runDirectory,controllerReceipt,criInspectionPath:extra[1]});}
 catch(error){result={schemaVersion:1,verified:false,verificationPassed:false,actualTrainingExecutionVerified:false,sourceTrainingExecutionVerified:false,trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false,error:error.message};process.exitCode=2;}
 mkdirSync(dirname(resolve(output)),{recursive:true});writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));
}
