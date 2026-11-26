import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {join,resolve,sep} from 'node:path';
import {revision} from '../scripts/prepare-public-qa-run.mjs';
import {STAGE,BLIND_STAGE,RUN_ID,RETRY_RUN_ID,RETRY_DIRECTORY,balancedRunBinding,balancedRetryDocuments,SOURCE_PINS,SOURCE_FILES,SAMPLER,SELECTION,selectBalancedRows,selectBalancedBlind,verifiedBalancedFile} from '../scripts/prepare-public-qa-grounding-balanced.mjs';
import {selectGroundingRows,immutableGroundingWrite} from '../scripts/prepare-public-qa-grounding.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
function row(id,split,impossible=false,length=20){
 const context='원문 '+id+' '+ '가'.repeat(Math.max(0,length-Array.from('원문 '+id+' ').length)),answers=impossible?[]:[{text:'원문',answer_start:0}],question='무엇인가요?';
 return {id,split,familyId:'family-'+id,context,contextSha256:sha(context),question,answers,isImpossible:impossible,language:'ko',
  upstreamSplit:split==='heldout'?'dev':'train',upstreamRevision:revision,sourceLicense:'CC-BY-SA-4.0',
  upstreamAnnotation:{kind:'human_authored_question_answer_spans'},originalQa:{question,answers,is_impossible:impossible}};
}
const minimal=()=>({train:[row('a','train'),row('b','train',true)],validation:[row('c','validation'),row('d','validation',true)]});
const tiny={trainPerLabel:1,validationPerLabel:1};
test('balanced contract retains source pins, authentic labels and narrow resource-safe policy',()=>{
 assert.deepEqual(SAMPLER,{kind:'balanced_optimizer_groups_v1',groupSize:16,answerablePerGroup:8,impossiblePerGroup:8,seed:42});
 assert.equal(SELECTION.maxContextCodepoints,700);assert.equal(SELECTION.answerBasedCropping,false);assert.equal(SELECTION.actualTokenizerPreadmissionRequired,true);
 assert.deepEqual(Object.keys(SOURCE_PINS).sort(),Object.keys(SOURCE_FILES).sort());assert.equal(Object.keys(SOURCE_FILES).length,9);
 const source=minimal(),result=selectBalancedRows(source,[],tiny);
 assert.deepEqual(result.counts,{train:2,validation:2});assert.deepEqual(result.labelCounts,{train:{answerable:1,impossible:1},validation:{answerable:1,impossible:1}});
 for(const selected of result.rows){const original=source[selected.split].find(item=>item.id===selected.id);assert.equal(selected.context,original.context);assert.deepEqual(selected.answers,original.answers);assert.deepEqual(selected.originalQa,original.originalQa);assert.equal(selected.stage,STAGE);assert.equal(selected.localHumanReviewPerformed,false);}
});
test('all three prior exposure identities including official dev prevent training reuse',()=>{
 const source={train:[row('a','train'),row('b','train'),row('c','train'),row('d','train'),row('i','train',true)],validation:[row('v','validation'),row('w','validation',true)]};
 const excluded=[{id:'a',familyId:'other1',contextSha256:'other1'},{id:'other2',familyId:'family-b',contextSha256:'other2'},
  {id:'other3',familyId:'other3',contextSha256:source.train[2].contextSha256}];
 const result=selectBalancedRows(source,excluded,tiny);assert.deepEqual(result.rows.map(item=>item.id),['d','i','v','w']);assert.equal(result.exclusions.previousExposure,3);
 source.train[3].upstreamSplit='dev';assert.throws(()=>selectBalancedRows(source,excluded,tiny),/source_identity_invalid/);
});
test('changed original human questions, labels, answers and context are rejected',()=>{
 for(const mutate of [r=>r.question='변경',r=>r.isImpossible=true,r=>r.answers=[{text:'가',answer_start:8}],r=>r.context+='변경']){
  const source=minimal();mutate(source.train[0]);assert.throws(()=>selectBalancedRows(source,[],tiny),/original_changed/);
 }
 const source=minimal();source.train[1].answers=[{text:'원문',answer_start:0}];source.train[1].originalQa.answers=source.train[1].answers;
 assert.throws(()=>selectBalancedRows(source,[],tiny),/answer_span_invalid/);
});
test('invalid original answer offsets are never converted into generated targets',()=>{
 for(const start of [-1,0.5,99]){const source=minimal();source.train[0].answers=[{text:'원문',answer_start:start}];source.train[0].originalQa.answers=source.train[0].answers;assert.throws(()=>selectBalancedRows(source,[],tiny),/answer_span_invalid/);}
});
test('700 preserves full originals while the historical default remains 650',()=>{
 const source=minimal();source.train[0]=row('a','train',false,700);
 const result=selectBalancedRows(source,[],tiny);assert.equal(Array.from(result.rows[0].context).length,700);assert.equal(result.rows[0].context,source.train[0].context);
 assert.throws(()=>selectGroundingRows(source,[],tiny),/grounding_insufficient_train/);
 source.train[0]=row('a','train',false,701);assert.throws(()=>selectBalancedRows(source,[],tiny),/rows_insufficient_train/);
});
test('duplicate IDs and family or context overlap across splits fail closed',()=>{
 const duplicate=minimal();duplicate.train.push(structuredClone(duplicate.train[0]));assert.throws(()=>selectBalancedRows(duplicate,[],tiny),/duplicate_source_id/);
 const family=minimal();family.validation[0].familyId=family.train[0].familyId;assert.throws(()=>selectBalancedRows(family,[],tiny),/split_leakage/);
 const context=minimal();context.validation[0].context=context.train[0].context;context.validation[0].contextSha256=context.train[0].contextSha256;assert.throws(()=>selectBalancedRows(context,[],tiny),/split_leakage/);
});
test('privacy screening and insufficient original label pools never pad or repeat examples',()=>{
 const source=minimal();source.train[0].context+=' test@example.com';source.train[0].contextSha256=sha(source.train[0].context);
 assert.throws(()=>selectBalancedRows(source,[],tiny),/rows_insufficient_train/);assert.throws(()=>selectBalancedRows(minimal(),[],{trainPerLabel:2,validationPerLabel:1}),/rows_insufficient_train/);
 for(const limit of [0,-1,0.5,NaN])assert.throws(()=>selectBalancedRows(minimal(),[],{trainPerLabel:limit,validationPerLabel:1}),/label_count_invalid/);
});
test('new blind128 is deterministic and excludes observed IDs, families and full training contexts',()=>{
 const source=Array.from({length:150},(_,index)=>row('held-'+String(index).padStart(3,'0'),'heldout',index%2===1)),exposed=[
  {id:source[0].id,familyId:'other',contextSha256:'other'},
  {id:'other1',familyId:source[1].familyId,contextSha256:'other1'},
  {id:'other2',familyId:'other2',contextSha256:source[2].contextSha256}];
 const a=selectBalancedBlind(source,exposed),b=selectBalancedBlind(source.slice().reverse(),exposed);
 assert.deepEqual(a.rows,b.rows);assert.deepEqual(a.counts,{answerable:64,impossible:64});assert.equal(a.uniqueSelectedFamilies,128);assert.equal(a.uniqueSelectedContexts,128);
 assert.equal(a.excluded.previousExposure,3);for(const selected of a.rows){assert.equal(selected.stage,BLIND_STAGE);assert.equal(selected.localHumanReviewPerformed,false);assert(!source.slice(0,3).some(prior=>prior.id===selected.id));}
});
test('blind rejects altered labels and scarcity instead of weakening separation',()=>{
 const source=Array.from({length:128},(_,index)=>row('blind-'+index,'heldout',index%2===1));source[0].question='교체';assert.throws(()=>selectBalancedBlind(source,[]),/original_changed/);
 assert.throws(()=>selectBalancedBlind([row('a','heldout'),row('b','heldout',true)],[]),/blind_rows_insufficient/);
});
test('pinned input and immutable output digest checks preserve originals on attempted replacement',t=>{
 const parent=resolve('.test-runs');mkdirSync(parent,{recursive:true});const directory=mkdtempSync(join(parent,'balanced-data-'));assert(directory.startsWith(parent+sep));t.after(()=>rmSync(directory,{recursive:true,force:true}));
 const file=join(directory,'original.json');writeFileSync(file,'original');assert.equal(verifiedBalancedFile(file,sha('original')).toString(),'original');
 assert.throws(()=>verifiedBalancedFile(file,sha('changed')),/source_changed/);assert.throws(()=>verifiedBalancedFile(directory,sha('original')),/source_not_plain_file/);
 immutableGroundingWrite(file,'original');assert.throws(()=>immutableGroundingWrite(file,'changed'),/output_exists_changed/);assert.equal(readFileSync(file,'utf8'),'original');
});

test('retry documents change only execution and blind bindings without modifying source freezes',()=>{
 const frozenAt='2026-10-06T07:00:00.000Z',blind={stage:BLIND_STAGE,plannedTrainingRunId:RUN_ID,frozenAt,trainingUsed:false,rowIds:['independent-heldout']},
  manifest={stage:STAGE,runId:RUN_ID,frozenAt,rows:['same-reviewed-public-row'],sampler:SAMPLER,
   blindEvaluation:{directory:'original/blind-evaluation',datasetSha256:sha('unchanged-blind'),manifestSha256:sha('original-manifest'),trainingUsed:false}},
  before=structuredClone({manifest,blind}),next=balancedRetryDocuments(manifest,blind);
 assert.deepEqual({manifest,blind},before);assert.equal(next.manifest.runId,RETRY_RUN_ID);
 assert.equal(next.blindManifest.plannedTrainingRunId,RETRY_RUN_ID);assert.equal(next.manifest.blindEvaluation.directory,RETRY_DIRECTORY+'/blind-evaluation');
 assert.equal(next.manifest.blindEvaluation.manifestSha256,sha(JSON.stringify(next.blindManifest,null,2)+'\n'));
 const restored=structuredClone(next);restored.manifest.runId=RUN_ID;restored.manifest.blindEvaluation=manifest.blindEvaluation;restored.blindManifest.plannedTrainingRunId=RUN_ID;
 assert.deepEqual(restored,{manifest,blindManifest:blind});
 assert.equal(balancedRunBinding(RUN_ID).pins.datasetSha256,balancedRunBinding(RETRY_RUN_ID).pins.datasetSha256);
 assert.notEqual(balancedRunBinding(RUN_ID).pins.manifestSha256,balancedRunBinding(RETRY_RUN_ID).pins.manifestSha256);
 assert.notEqual(balancedRunBinding(RUN_ID).directory,balancedRunBinding(RETRY_RUN_ID).directory);
 assert.throws(()=>balancedRetryDocuments({...manifest,runId:RETRY_RUN_ID},blind),/retry_source_identity_invalid/);
 assert.throws(()=>balancedRetryDocuments(manifest,{...blind,plannedTrainingRunId:RETRY_RUN_ID}),/retry_source_identity_invalid/);
});
