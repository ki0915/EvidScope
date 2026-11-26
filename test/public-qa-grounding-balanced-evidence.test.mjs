import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {resolve,join,relative,sep} from 'node:path';
import {revision} from '../scripts/prepare-public-qa-run.mjs';
import {STAGE,BLIND_STAGE,SOURCE_RUN,SOURCE_FILES,SOURCE_TRAINING_PINS,SAMPLER,SELECTION,selectBalancedRows,selectBalancedBlind} from '../scripts/prepare-public-qa-grounding-balanced.mjs';
import {verifyBalancedDatasetBindings,verifyBalancedDatasetBindingsFixture} from '../scripts/public-qa-grounding-balanced-evidence.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const json=value=>JSON.stringify(value,null,2)+'\n';
const jsonl=value=>value.map(row=>JSON.stringify(row)).join('\n')+'\n';
function original(id,split,impossible){
 const context='원문 '+id+' '+ '가'.repeat(12),question='원문의 대상은 무엇인가요?',answers=impossible?[]:[{text:'원문',answer_start:0}];
 return {id,split,language:'ko',familyId:'family-'+id,context,contextSha256:sha(context),question,answers,isImpossible:impossible,
  upstreamSplit:split==='heldout'?'dev':'train',upstreamRevision:revision,sourceLicense:'CC-BY-SA-4.0',
  upstreamAnnotation:{kind:'human_authored_question_answer_spans'},originalQa:{question,answers,is_impossible:impossible}};
}
function fixture(t){
 const parent=resolve('.test-runs');mkdirSync(parent,{recursive:true});const root=mkdtempSync(join(parent,'balanced-evidence-'));assert(root.startsWith(parent+sep));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const directory=join(root,'public-qa-balanced-fixture'),blindDirectory=join(root,'blind-evaluation');mkdirSync(directory);mkdirSync(blindDirectory);
 const source={sourceManifest:{revision,license:'CC-BY-SA-4.0',licenseUrl:'https://creativecommons.org/licenses/by-sa/4.0/',attribution:'Synthetic fixture; no real execution.',humanConstructionEvidence:{description:'Synthetic test only.'}},
  sourceTrain:Array.from({length:660},(_,index)=>original('train-'+String(index).padStart(3,'0'),'train',index%2===1)),
  sourceValidation:Array.from({length:70},(_,index)=>original('validation-'+String(index).padStart(3,'0'),'validation',index%2===1)),
  heldout:Array.from({length:150},(_,index)=>original('heldout-'+String(index).padStart(3,'0'),'heldout',index%2===1))};
 const exposures=['oldTraining','diagnostic','previousGrounding','continuation','observedFresh'];
 exposures.forEach((key,index)=>{source[key]=[source.sourceTrain[index]];});
 const sourcePins={},sourceInputs=[];
 for(const [key,name]of Object.entries(SOURCE_FILES)){
  const raw=key==='sourceManifest'?json(source[key]):jsonl(source[key]),path=join(directory,name);writeFileSync(path,raw);sourcePins[key]=sha(raw);
  sourceInputs.push({name:key,path:relative(process.cwd(),path),sha256:sourcePins[key],rows:key==='sourceManifest'?null:source[key].length});
 }
 const exposed=exposures.flatMap(key=>source[key]),selected=selectBalancedRows({train:source.sourceTrain,validation:source.sourceValidation},[...exposed,...source.heldout]),
  blind=selectBalancedBlind(source.heldout,[...exposed,...source.sourceTrain,...source.sourceValidation,...selected.rows]),runId='public-qa-balanced-fixture',frozenAt='2026-10-06T07:00:00.000Z';
 const common={schemaVersion:1,task:'korean_extractive_qa',upstreamRevision:revision,license:source.sourceManifest.license,licenseUrl:source.sourceManifest.licenseUrl,
  attribution:source.sourceManifest.attribution,humanConstructionEvidence:source.sourceManifest.humanConstructionEvidence,sourcePins,sourceFiles:{...SOURCE_FILES},sourceInputs,
  originalHumanLabelsPreserved:true,automaticallyGeneratedLabels:false,localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false};
 const blindManifest={...common,stage:BLIND_STAGE,datasetSha256:sha(jsonl(blind.rows)),frozenAt,frozenBeforeBalancedTraining:true,plannedTrainingRunId:runId,
  sourceRevision:revision,sourceHeldoutSha256:sourcePins.heldout,counts:{total:128,answerable:64,impossible:64},
  exposedInputRows:exposed.length+source.sourceTrain.length+source.sourceValidation.length+selected.rows.length,
  excluded:blind.excluded,availableCounts:blind.availableCounts,previousExposureOverlap:blind.overlap,uniqueSelectedFamilies:128,uniqueSelectedContexts:128,
  selection:{maxContextCodepoints:650,maxQuestionCodepoints:240,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true,
   algorithm:'sha256_42_fresh_evaluation_id_interleaved_labels_unique_family_context',duplicateFamiliesWithinSelection:false},
  trainingUsed:false,heldoutUsedForTraining:false,rowIds:blind.rows.map(row=>row.id)};
 const manifest={...common,stage:STAGE,runId,datasetSha256:sha(jsonl(selected.rows)),frozenAt,counts:selected.counts,labelCounts:selected.labelCounts,
  selection:SELECTION,sampler:SAMPLER,exclusions:selected.exclusions,availableCounts:selected.availableCounts,previousExposureOverlap:selected.previousExposureOverlap,
  wholeOfficialDevExcludedFromTraining:true,officialDevExclusionRows:source.heldout.length,exposedInputRows:exposed.length,heldoutUsed:false,heldoutUsedForTraining:false,
  sourceTraining:{sourceRunId:SOURCE_RUN,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:80,sourceTrainingExecutionVerified:true,sourcePins:SOURCE_TRAINING_PINS},
  blindEvaluation:{directory:relative(process.cwd(),blindDirectory),datasetSha256:blindManifest.datasetSha256,manifestSha256:sha(json(blindManifest)),stage:BLIND_STAGE,frozenAt,rows:128,trainingUsed:false},
  rowIds:selected.rows.map(row=>row.id),experiment:{plannedOptimizerSteps:20,plannedMicrobatches:320,plannedExposure:{answerable:160,impossible:160},learningRate:0.00003,
   sourceOptimizerHistoryUpdates:80,plannedTotalAdapterHistoryOptimizerUpdates:100,lengthDistributionExpansion:true,previousMaxContextCodepoints:650,maxContextCodepoints:700,
   balanceOnlyCausalComparison:false,qualityImprovementClaimed:false}};
 const value={root,directory,blindDirectory,source,sourcePins,manifest,blindManifest,data:selected.rows,blindData:blind.rows,
  inputs:{runId,data:relative(process.cwd(),join(directory,'data.jsonl')),manifest:relative(process.cwd(),join(directory,'manifest.json'))},startedAt:'2026-10-06T08:00:00.000Z'};
 persist(value);return value;
}
function persist(f){
 const data=jsonl(f.data),blindData=jsonl(f.blindData);f.manifest.datasetSha256=sha(data);f.blindManifest.datasetSha256=sha(blindData);
 f.manifest.blindEvaluation.datasetSha256=f.blindManifest.datasetSha256;f.manifest.blindEvaluation.manifestSha256=sha(json(f.blindManifest));
 writeFileSync(join(f.blindDirectory,'data.jsonl'),blindData);writeFileSync(join(f.blindDirectory,'manifest.json'),json(f.blindManifest));
 writeFileSync(join(f.directory,'data.jsonl'),data);writeFileSync(join(f.directory,'manifest.json'),json(f.manifest));
 f.inputs.datasetSha256=sha(data);f.inputs.manifestSha256=sha(json(f.manifest));
}
const options=f=>({workspaceRoot:process.cwd(),inputs:f.inputs,manifest:f.manifest,dataBytes:readFileSync(join(f.directory,'data.jsonl')),startedAt:f.startedAt});
const verify=f=>verifyBalancedDatasetBindingsFixture(options(f),{sourcePins:f.sourcePins});
test('synthetic data evidence reconstructs704 and blind128 without actual execution claims',t=>{
 const f=fixture(t),result=verify(f);assert.equal(result.rows.length,704);assert.deepEqual(result.rows,f.data);
 for(const key of ['actualTrainingExecutionVerified','sourceTrainingExecutionVerified','trainingRunCompleted','qualityClaimAllowed','promotionAllowed'])assert.equal(result[key],false);
 assert.equal(result.syntheticFixture,true);assert.throws(()=>verifyBalancedDatasetBindings(options(f)),/source_file_changed/);
});
test('changing pinned source bytes cannot be hidden behind fresh dataset and manifest hashes',t=>{
 const f=fixture(t);writeFileSync(join(f.directory,SOURCE_FILES.observedFresh),'[]\n');assert.throws(()=>verify(f),/source_file_changed:observedFresh/);
});
test('forged source input provenance and inventories are rejected',t=>{
 for(const mutate of [f=>f.manifest.sourceInputs[0].sha256='0'.repeat(64),f=>f.manifest.sourceInputs[1].rows++,f=>f.manifest.sourceInputs.pop(),
  f=>f.manifest.sourceInputs[0].path='../outside.json',f=>f.manifest.sourceFiles.heldout='other.json']){
  const f=fixture(t);mutate(f);persist(f);assert.throws(()=>verify(f),/source_input|source_inputs|source_identity|path_escape/);
 }
});
test('changed original rows, old-family reuse and label changes reject even after resealing hashes',t=>{
 for(const mutate of [f=>f.data[0].question='수정',f=>f.data[0].context=f.data[0].context.slice(0,5),f=>f.data[0].isImpossible=!f.data[0].isImpossible,
  f=>f.data[0]={...f.source.oldTraining[0],stage:STAGE,contextSelection:'full_original_context',localHumanReviewPerformed:false,privacyScreen:f.data[0].privacyScreen}]){
  const f=fixture(t);mutate(f);persist(f);assert.throws(()=>verify(f),/original_selection_changed/);
 }
});
test('selection statistics, entire dev exclusion and experimental causal boundaries are verified',t=>{
 for(const mutate of [f=>f.manifest.exclusions.previousExposure++,f=>f.manifest.availableCounts.train.impossible++,f=>f.manifest.previousExposureOverlap.family=1,
  f=>f.manifest.officialDevExclusionRows--,f=>f.manifest.wholeOfficialDevExcludedFromTraining=false,f=>f.manifest.selection={...SELECTION,maxContextCodepoints:650},
  f=>f.manifest.experiment.balanceOnlyCausalComparison=true,f=>f.manifest.experiment.plannedExposure={answerable:220,impossible:100},
  f=>f.manifest.sourceTraining.sourceOptimizerHistoryUpdates=60]){
  const f=fixture(t);mutate(f);persist(f);assert.throws(()=>verify(f),/selection_statistics|dataset_policy|experiment_boundary|source80_metadata/);
 }
});
test('local human review and promotion claims cannot be forged in either manifest',t=>{
 for(const target of ['manifest','blindManifest'])for(const key of ['localHumanReviewPerformed','qualityClaimAllowed','promotionAllowed']){
  const f=fixture(t);f[target][key]=true;persist(f);assert.throws(()=>verify(f),/claim_boundary_changed/);
 }
});
test('blind originals, same-source attribution, frozen bindings and sibling placement are enforced',t=>{
 for(const mutate of [f=>f.blindData[0].question='변조',f=>f.blindData[0].answers=[],f=>f.blindManifest.excluded.previousExposure++,
  f=>f.blindManifest.attribution='invented',f=>f.blindManifest.trainingUsed=true,f=>f.blindManifest.frozenBeforeBalancedTraining=false,
  f=>f.blindManifest.uniqueSelectedFamilies=127,f=>f.manifest.blindEvaluation.directory=relative(process.cwd(),f.directory),
  f=>f.manifest.blindEvaluation.stage=STAGE]){
  const f=fixture(t);mutate(f);persist(f);assert.throws(()=>verify(f),/blind_|source_identity/);
 }
});
test('training must start strictly after the valid identical freeze timestamps',t=>{
 for(const startedAt of ['2026-10-06T07:00:00.000Z','2026-10-06T06:59:59.999Z','2026-02-30T08:00:00.000Z','invalid',null]){
  const f=fixture(t);f.startedAt=startedAt;assert.throws(()=>verify(f),/freeze_not_before_training|timestamp_invalid/);
 }
 const f=fixture(t);f.blindManifest.frozenAt='2026-10-06T07:00:00.001Z';persist(f);assert.throws(()=>verify(f),/blind_scope_changed/);
});
test('caller-supplied bytes or manifest objects must equal the actual frozen files',t=>{
 const f=fixture(t),o=options(f);o.dataBytes=Buffer.from('changed');assert.throws(()=>verifyBalancedDatasetBindingsFixture(o,{sourcePins:f.sourcePins}),/dataset_binding_changed/);
 const p=options(f);p.manifest=structuredClone(f.manifest);p.manifest.heldoutUsed=true;assert.throws(()=>verifyBalancedDatasetBindingsFixture(p,{sourcePins:f.sourcePins}),/dataset_binding_changed/);
 assert.throws(()=>verifyBalancedDatasetBindingsFixture(options(f),{sourcePins:{}}),/fixture_pins_invalid/);
});
