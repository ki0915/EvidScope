import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {balancedPlan,verifyBalancedExposure,verifyPublicQaGroundingBalanced} from '../scripts/verify-public-qa-grounding-balanced.mjs';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {BALANCED_DATA_PINS,balancedDataPins} from '../scripts/public-qa-grounding-balanced-workload.mjs';
import {STAGE,SAMPLER,RUN_ID,RETRY_RUN_ID} from '../scripts/prepare-public-qa-grounding-balanced.mjs';
import {publicQaControllerOptions,runPublicQa} from '../scripts/run-public-qa-job.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const canonical=value=>JSON.stringify(value,(_key,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);
function fixture(step=20){
 const dataset=Array.from({length:640},(_,index)=>({id:'synthetic-'+index,familyId:'family-'+index,contextSha256:sha('context-'+index),split:'train',isImpossible:index>=320}));
 const encoding={datasetSha256:sha('synthetic-dataset'),rows:dataset.map(row=>({id:row.id,inputSha256:sha('encoded-tensors-'+row.id),tokens:128}))};
 const plan=balancedPlan(dataset);
 const exposure={schemaVersion:1,stage:STAGE,datasetSha256:encoding.datasetSha256,sampler:SAMPLER,plannedOrderSha256:sha(canonical(plan)),sourceOptimizerHistoryUpdates:80,optimizerUpdatesThisExperiment:step,totalAdapterHistoryOptimizerUpdates:80+step,processedMicrobatches:step*16,completedOptimizerGroups:step,qualityClaimAllowed:false,promotionAllowed:false,counts:{answerable:8*step,impossible:8*step},groups:Array.from({length:step},(_,index)=>({optimizerGroup:index+1,microbatches:16,answerable:8,impossible:8})),rows:plan.slice(0,step*16).map((selected,index)=>{
  const row=dataset[selected.datasetIndex],encoded=encoding.rows[selected.datasetIndex];
  return {...selected,microbatch:index+1,optimizerGroup:Math.floor(index/16)+1,positionInGroup:index%16+1,inputSha256:encoded.inputSha256,tokenCount:encoded.tokens,forwardBackwardCompleted:true,rowIdentitySha256:sha(canonical({id:row.id,familyId:row.familyId,contextSha256:row.contextSha256,isImpossible:row.isImpossible}))};
 })};
 return {dataset,encoding,exposure};
}
test('balanced plan consumes distinct rows in eight-to-eight optimizer groups',()=>{
 const {dataset}=fixture(),plan=balancedPlan(dataset);
 assert.equal(new Set(plan.map(row=>row.rowId)).size,640);
 for(let offset=0;offset<640;offset+=16)assert.equal(plan.slice(offset,offset+16).filter(row=>row.isImpossible).length,8);
 assert.deepEqual(balancedPlan(dataset),plan);
});
test('checkpoint consumption distinguishes source history eighty from new updates',()=>{
 for(const step of [10,20]){
  const {dataset,encoding,exposure}=fixture(step),result=verifyBalancedExposure(exposure,dataset,encoding,step);
  assert.deepEqual(result.counts,{answerable:step*8,impossible:step*8});assert.equal(result.processedMicrobatches,step*16);
  assert.equal(result.actualTensorBindingChecked,true);
 }
});
test('balanced evidence rejects reused, relabeled, unfinished or unbound consumption',()=>{
 const mutations=[e=>e.rows[0].rowId=e.rows[1].rowId,e=>e.rows[0].isImpossible=!e.rows[0].isImpossible,e=>e.rows[0].forwardBackwardCompleted=false,e=>e.rows[0].inputSha256=sha('other tensor labels'),e=>e.rows[0].rowIdentitySha256=sha('other event family'),e=>delete e.rows[0].rowIdentitySha256,e=>e.rows[0].tokenCount=1025,e=>e.rows[0].datasetIndex=e.rows[1].datasetIndex,e=>e.sourceOptimizerHistoryUpdates=60,e=>e.totalAdapterHistoryOptimizerUpdates=80,e=>e.groups[0].answerable=11,e=>e.groups[0].impossible=5,e=>e.rows.reverse(),e=>e.stage='public_qa_grounding_continuation_v1',e=>e.qualityClaimAllowed=true];
 for(const mutate of mutations){const f=fixture();mutate(f.exposure);assert.throws(()=>verifyBalancedExposure(f.exposure,f.dataset,f.encoding,20));}
 const f=fixture();f.dataset[f.exposure.rows[0].datasetIndex].familyId='other-source-family';assert.throws(()=>verifyBalancedExposure(f.exposure,f.dataset,f.encoding,20),/row_identity/);
});
test('new manual balanced mode preserves interactive resource gates and rejects mixed modes',async()=>{
 const options=publicQaControllerOptions(['--execute-grounding-balanced','public-qa-balanced-test','--allow-interactive-use']);
 assert.equal(options.groundingBalanced,true);assert.equal(options.grounding,true);assert.equal(options.executeTraining,true);assert.equal(options.interactiveUseApproved,true);
 assert.throws(()=>publicQaControllerOptions(['--execute-grounding-balanced','public-qa-balanced-test','--allow-interactive-use','--resume-provenance','other.json']),/grounding_cannot/);
 for(const forbidden of ['groundingContinuation','freshEvaluation','groundingDiagnostic','diagnostic','diagnosticStageTwo','pilot'])await assert.rejects(runPublicQa({groundingBalanced:true,[forbidden]:true}),/balanced_cannot/);
});
test('post-run verifier rejects resealed replacements of the approved freeze manifest',async t=>{
 const root=mkdtempSync(join(tmpdir(),'balanced-freeze-pin-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const controllerReceipt=join(root,'controller.json');
 for(const key of ['datasetSha256','manifestSha256']){
  writeFileSync(controllerReceipt,JSON.stringify({inputs:{...BALANCED_DATA_PINS,[key]:sha('replacement with altered frozenAt')}}));
  await assert.rejects(verifyPublicQaGroundingBalanced({controllerReceipt,runDirectory:root}),/balanced_frozen_data_pin_changed/);
 }
});

test('post-run verifier selects r2 pins while rejecting cross-run r1 manifest substitution',async t=>{
 const root=mkdtempSync(join(tmpdir(),'balanced-retry-verifier-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const controllerReceipt=join(root,'controller.json'),r2=balancedDataPins(RETRY_RUN_ID);
 for(const runId of [RUN_ID,RETRY_RUN_ID]){
  const other=runId===RUN_ID?RETRY_RUN_ID:RUN_ID;
  writeFileSync(controllerReceipt,JSON.stringify({runId,inputs:{runId,...balancedDataPins(other)}}));
  await assert.rejects(verifyPublicQaGroundingBalanced({controllerReceipt,runDirectory:root}),/balanced_frozen_data_pin_changed/);
 }
 // Correct pins pass the identity gate but cannot manufacture live execution evidence.
 writeFileSync(controllerReceipt,JSON.stringify({runId:RETRY_RUN_ID,inputs:{runId:RETRY_RUN_ID,...r2}}));
 await assert.rejects(verifyPublicQaGroundingBalanced({controllerReceipt,runDirectory:root}),error=>error.code==='ENOENT'&&error.path===join(root,'live-job.json'));
});
