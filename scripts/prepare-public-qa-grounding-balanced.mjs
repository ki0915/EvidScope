// A new experiment, never a rewrite of the sealed source60/source80 datasets.
import {readFileSync,mkdirSync,lstatSync,existsSync} from 'node:fs';
import {join,resolve,relative,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual as same} from 'node:util';
import {pathToFileURL} from 'node:url';
import {basicPrivacyMatch,revision} from './prepare-public-qa-run.mjs';
import {GROUNDING_SOURCE_PINS,immutableGroundingWrite} from './prepare-public-qa-grounding.mjs';
import {selectFreshEvaluation,writeFrozenEvaluation} from './prepare-public-qa-fresh-evaluation.mjs';

export const STAGE='public_qa_grounding_balanced_v1';
export const DIRECTORY='.local/public-training/grounding-balanced/20261006';
export const SOURCE_RUN='public-qa-grounding-20261006-r3';
export const RUN_ID='public-qa-balanced-20261006-r1';
export const RETRY_RUN_ID='public-qa-balanced-20261006-r2';
export const RETRY_DIRECTORY=DIRECTORY+'/attempt-r2';
const DATASET_SHA256='074ba6367f2be2ad833ad3b07e4ef66d4972facdf241a001fae13309f7dbcbc1';
const BLIND_DATASET_SHA256='8eb5a4ab3bca89eaa086635793bb352e65955bee079c1b6a4e1bf42005005062';
const RUN_BINDINGS=Object.freeze({
 [RUN_ID]:Object.freeze({directory:DIRECTORY,pins:Object.freeze({datasetSha256:DATASET_SHA256,manifestSha256:'4192f558003601a03b98a9dd6d327b33e8ed923c2ea5bb9b5f27d2703e4ea073'}),blindDatasetSha256:BLIND_DATASET_SHA256,blindManifestSha256:'ed0338bc99f5df14416b95b7e5a101b9fa90865dcf50053287192faa592ca1a3'}),
 [RETRY_RUN_ID]:Object.freeze({directory:RETRY_DIRECTORY,pins:Object.freeze({datasetSha256:DATASET_SHA256,manifestSha256:'830a6ff6431d5d93ea96140442314c75afb586948f6b27803127bf782884c21a'}),blindDatasetSha256:BLIND_DATASET_SHA256,blindManifestSha256:'7b681710da7cc0ca3544618858d9fde7dd597706617d858b2db1c791b205154d'})
});
export function balancedRunBinding(runId){requireValue(Object.hasOwn(RUN_BINDINGS,runId),'run_id_invalid');return RUN_BINDINGS[runId];}
export const BLIND_STAGE='public_qa_grounding_balanced_blind_evaluation_v1';
export const SAMPLER=Object.freeze({kind:'balanced_optimizer_groups_v1',groupSize:16,answerablePerGroup:8,impossiblePerGroup:8,seed:42});
export const SELECTION=Object.freeze({maxContextCodepoints:700,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true});
export const SOURCE_PINS=Object.freeze({...GROUNDING_SOURCE_PINS,
 heldout:'681ceb8154dd4131c01679fcf8199e24d27c8d44e2abfe786588b2874bcb16e6',
 previousGrounding:'a080f3ff03ce813d5f4e242512a6442ff148e2341613e227f8c03e2e29a8d4ea',
 continuation:'258ea70365b16ab31357467f3b32c66edca38b3ea0c6db46a11009ab79ed372b',
 observedFresh:'dc8a7bb0c9eb9de9abbc6f3cea39851453db8c60cc91602223f3a9aaeb628142'});
export const SOURCE_FILES=Object.freeze({sourceManifest:'source-manifest.json',sourceTrain:'source-train.jsonl',sourceValidation:'source-validation.jsonl',
 heldout:'source-heldout.jsonl',oldTraining:'old-training.jsonl',diagnostic:'diagnostic.jsonl',previousGrounding:'previous-grounding.jsonl',continuation:'continuation.jsonl',observedFresh:'observed-fresh.jsonl'});
export const SOURCE_TRAINING_PINS=Object.freeze({
 candidateMarker:'4f25923e903e4f604401920035ac8d32fc6736874d57509f8be897340407d3eb',
 adapter:'3de58b12eb5d6b46d4ad7a4ea53c008e5f070adcfe53a73826c0002e7495374e',
 sourceController:'bbb6504733765876abf85ff557f9726b762cbe565422672ee07ce4880c54409d',
 sourceVerification:'2ee71ff2cc856ad62cbd03e4e892c76728624e622f0548167bf6c34be8732ca9',
 provenance:'75e890ffb1b3381bdd59ffff454c4bdb253b854f2d83643511e90404c943d53a',
 sourceRuntime:'fd16f98282d570af43310e9920f017867509af910f14dc7dc8360878c283e934',
 criInspection:'9751ae20dfea9f656d4643a70c1c2863acd4224913228a5d4117ff41e0e8b6b1',
 artifactLock:'c067d1fe680e8f6dc14c592ade49a1d791ea6cb15ecbefeda52a609d5d922949'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const rows=bytes=>bytes.toString('utf8').trim().split(/\r?\n/u).map(JSON.parse);
const requireValue=(value,message)=>{if(!value)throw Error('balanced_'+message);};
const keys=['id','familyId','contextSha256'];
export function verifiedBalancedFile(path,digest){
 const stat=lstatSync(path);requireValue(stat.isFile()&&!stat.isSymbolicLink(),'source_not_plain_file');
 const bytes=readFileSync(path);requireValue(sha(bytes)===digest,'source_changed:'+path);return bytes;
}

export function selectBalancedRows(sources,excluded,{trainPerLabel=320,validationPerLabel=32}={}){
 for(const value of [trainPerLabel,validationPerLabel])requireValue(Number.isSafeInteger(value)&&value>0,'label_count_invalid');
 const forbidden=Object.fromEntries(keys.map(key=>[key,new Set(excluded.map(row=>row[key]))]));
 const selected=[],seen=new Set(),families=new Map(),contexts=new Map(),counts={},availableCounts={},labelCounts={},
  exclusions={previousExposure:0,privacyPattern:0,fullContextTooLong:0};
 for(const [split,limit]of [['train',trainPerLabel],['validation',validationPerLabel]]){
  const pool=sources[split].slice().sort((a,b)=>a.id.localeCompare(b.id,'en')),sourceIds=new Set(),labels=new Map([[false,[]],[true,[]]]);
  for(const row of pool){
   requireValue(!sourceIds.has(row.id),'duplicate_source_id');sourceIds.add(row.id);
   requireValue(row.split===split&&row.upstreamSplit==='train'&&row.upstreamRevision===revision&&row.sourceLicense==='CC-BY-SA-4.0'
    &&row.upstreamAnnotation?.kind==='human_authored_question_answer_spans'&&typeof row.isImpossible==='boolean'
    &&typeof row.context==='string'&&row.context&&typeof row.question==='string'&&row.question&&typeof row.familyId==='string'&&row.familyId,'source_identity_invalid');
   requireValue(sha(row.context)===row.contextSha256&&row.question===row.originalQa?.question&&row.isImpossible===row.originalQa?.is_impossible
    &&same(row.answers,row.originalQa?.answers),'original_changed');
   const points=Array.from(row.context);
   requireValue(Array.isArray(row.answers)&&(row.isImpossible?row.answers.length===0:row.answers.length>0&&row.answers.every(answer=>
    typeof answer.text==='string'&&answer.text&&Number.isSafeInteger(answer.answer_start)&&answer.answer_start>=0
    &&points.slice(answer.answer_start,answer.answer_start+Array.from(answer.text).length).join('')===answer.text)),'answer_span_invalid');
   if(keys.some(key=>forbidden[key].has(row[key]))){exclusions.previousExposure++;continue;}
   if(points.length>SELECTION.maxContextCodepoints||Array.from(row.question).length>240||(!row.isImpossible&&Array.from(row.answers[0].text).length>160)){exclusions.fullContextTooLong++;continue;}
   if(basicPrivacyMatch(row.question+'\n'+row.context)){exclusions.privacyPattern++;continue;}
   labels.get(row.isImpossible).push(row);
  }
  availableCounts[split]={answerable:labels.get(false).length,impossible:labels.get(true).length};
  requireValue([...labels.values()].every(items=>items.length>=limit),'rows_insufficient_'+split);
  for(let index=0;index<limit;index++)for(const label of [false,true]){
   const row=labels.get(label)[index];
   requireValue(!seen.has(row.id)&&(!families.has(row.familyId)||families.get(row.familyId)===split)
    &&(!contexts.has(row.contextSha256)||contexts.get(row.contextSha256)===split),'split_leakage');
   seen.add(row.id);families.set(row.familyId,split);contexts.set(row.contextSha256,split);
   selected.push({...row,stage:STAGE,contextSelection:'full_original_context',localHumanReviewPerformed:false,
    privacyScreen:{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false}});
  }
  counts[split]=limit*2;labelCounts[split]={answerable:limit,impossible:limit};
 }
 return {rows:selected,counts,labelCounts,availableCounts,exclusions,previousExposureOverlap:{id:0,family:0,context:0}};
}

export function selectBalancedBlind(source,exposed){
 const selection=selectFreshEvaluation(source,exposed);
 requireValue(selection.sufficient===true,'blind_rows_insufficient');
 return {...selection,rows:selection.rows.map(row=>({...row,stage:BLIND_STAGE}))};
}

function sourceTrainingPaths(){return {
 candidateMarker:`.local/training/runs/${SOURCE_RUN}/candidate/candidate-complete.json`,
 adapter:`.local/training/runs/${SOURCE_RUN}/candidate/adapter_model.safetensors`,
 sourceController:`.local/training/public-qa-run/${SOURCE_RUN}/controller-receipt.json`,
 sourceVerification:'reports/public-qa-grounding-continuation-verification-20261006.json',
 provenance:`.local/public-training/grounding-continuation/20261006/${SOURCE_RUN}/provenance.json`,
 sourceRuntime:`.local/training/public-qa-run/${SOURCE_RUN}/runtime-configmap.json`,
 criInspection:'.local/training/public-qa-run/continuation-preparation-20261006-r3/cri-inspect.json',
 artifactLock:'.local/training/base/63c930c82d7646226d33502bec5870019738400e/artifact-lock.json'};}
function verifySource80(){
 const paths=sourceTrainingPaths(),bytes=Object.fromEntries(Object.entries(paths).map(([key,path])=>[key,verifiedBalancedFile(path,SOURCE_TRAINING_PINS[key])])),
  report=JSON.parse(bytes.sourceVerification),marker=JSON.parse(bytes.candidateMarker),controller=JSON.parse(bytes.sourceController);
 for(const flag of ['verified','verificationPassed','actualTrainingExecutionVerified','sourceTrainingExecutionVerified','trainingRunCompleted','terminationConfirmed'])requireValue(report[flag]===true,'source_execution_unverified:'+flag);
 requireValue(report.syntheticFixture===false&&report.runId===SOURCE_RUN&&report.globalStep===20&&report.totalAdapterHistoryOptimizerUpdates===80
  &&report.optimizerUpdatesThisRun===20&&report.qualityClaimAllowed===false&&report.promotionAllowed===false
  &&report.datasetSha256===SOURCE_PINS.continuation&&marker.globalStep===20&&same(marker.identity,report.identity)
  &&marker.identity.stage==='public_qa_grounding_continuation_v1'&&controller.runId===SOURCE_RUN&&controller.jobUid===report.jobUid
  &&controller.podUid===report.podUid&&controller.terminationConfirmed===true&&report.artifactSha256===SOURCE_TRAINING_PINS.candidateMarker
  &&report.adapterSha256===SOURCE_TRAINING_PINS.adapter&&report.controllerSha256===SOURCE_TRAINING_PINS.sourceController
  &&report.runtimeConfigMapSha256===SOURCE_TRAINING_PINS.sourceRuntime,'source80_scope_changed');
 return {sourceRunId:SOURCE_RUN,sourceGlobalStep:20,sourceOptimizerHistoryUpdates:80,sourceTrainingExecutionVerified:true,
  verificationScope:'recomputed_pinned_original_files_and_previously_verified_receipt_identity_workload_must_reverify_execution',
  sourcePins:SOURCE_TRAINING_PINS,sourceInputs:Object.entries(paths).map(([name,path])=>({name,path,sha256:sha(bytes[name])})),
  originalControllerState:controller.state,runtimeExitReconciliation:report.runtimeExitReconciliation};
}

export function preparePublicQaGroundingBalanced({source=`.local/public-training/klue-mrc/${revision}`,output=DIRECTORY,runId=RUN_ID}={}){
 if(runId===RETRY_RUN_ID){requireValue(output===DIRECTORY||output===RETRY_DIRECTORY,'retry_output_scope_invalid');return preparePublicQaGroundingBalancedRetry();}
 requireValue(/^public-qa-balanced-[a-z0-9-]{1,28}$/.test(runId),'run_id_invalid');
 const directory=join(output,runId),blindDirectory=join(output,'blind-evaluation');
 // Existing freeze is never replaced, even if only its timestamp would change.
 requireValue(!existsSync(directory)&&!existsSync(blindDirectory),'output_already_exists');
 const paths={sourceManifest:join(source,'manifest.json'),sourceTrain:join(source,'train.jsonl'),sourceValidation:join(source,'validation.jsonl'),heldout:join(source,'heldout.jsonl'),
  oldTraining:'.local/public-training/stage1/public-qa-stage1.jsonl',diagnostic:'.local/public-training/diagnostic/20260928/data.jsonl',
  previousGrounding:'.local/public-training/grounding/20261005/public-qa-grounding-20261005-r4/data.jsonl',
  continuation:`.local/public-training/grounding-continuation/20261006/${SOURCE_RUN}/data.jsonl`,
  observedFresh:'.local/public-training/grounding-continuation/20261006/fresh-evaluation/data.jsonl'};
 const bytes=Object.fromEntries(Object.entries(paths).map(([key,path])=>[key,verifiedBalancedFile(path,SOURCE_PINS[key])])),upstream=JSON.parse(bytes.sourceManifest);
 requireValue(upstream.revision===revision&&upstream.license==='CC-BY-SA-4.0','upstream_identity_invalid');
 for(const item of [...upstream.raw,...upstream.outputs]){const path=resolve(source,item.path),part=relative(resolve(source),path);requireValue(part&&!part.startsWith('..')&&!isAbsolute(part),'source_path_escape');verifiedBalancedFile(path,item.sha256);}
 const source80=verifySource80(),parsed=Object.fromEntries(Object.entries(bytes).filter(([key])=>key!=='sourceManifest').map(([key,raw])=>[key,rows(raw)])),
  exposureKeys=['oldTraining','diagnostic','previousGrounding','continuation','observedFresh'],exposed=exposureKeys.flatMap(key=>parsed[key]);
 const result=selectBalancedRows({train:parsed.sourceTrain,validation:parsed.sourceValidation},[...exposed,...parsed.heldout]),
  blind=selectBalancedBlind(parsed.heldout,[...exposed,...parsed.sourceTrain,...parsed.sourceValidation,...result.rows]);
 const frozenAt=new Date().toISOString(),data=Buffer.from(result.rows.map(row=>JSON.stringify(row)).join('\n')+'\n'),
  blindData=Buffer.from(blind.rows.map(row=>JSON.stringify(row)).join('\n')+'\n'),sourceInputs=Object.entries(paths).map(([name,path])=>({name,path,sha256:sha(bytes[name]),rows:name==='sourceManifest'?null:parsed[name].length}));
 const common={schemaVersion:1,task:'korean_extractive_qa',upstreamRevision:revision,license:upstream.license,licenseUrl:upstream.licenseUrl,
  attribution:upstream.attribution,humanConstructionEvidence:upstream.humanConstructionEvidence,sourcePins:SOURCE_PINS,sourceFiles:SOURCE_FILES,sourceInputs,
  originalHumanLabelsPreserved:true,automaticallyGeneratedLabels:false,localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false};
 const blindManifest={...common,stage:BLIND_STAGE,datasetSha256:sha(blindData),frozenAt,frozenBeforeBalancedTraining:true,plannedTrainingRunId:runId,
  sourceRevision:revision,sourceHeldoutSha256:SOURCE_PINS.heldout,counts:{total:128,answerable:64,impossible:64},
  exposedInputRows:exposed.length+parsed.sourceTrain.length+parsed.sourceValidation.length+result.rows.length,
  excluded:blind.excluded,availableCounts:blind.availableCounts,previousExposureOverlap:blind.overlap,
  uniqueSelectedFamilies:blind.uniqueSelectedFamilies,uniqueSelectedContexts:blind.uniqueSelectedContexts,
  selection:{maxContextCodepoints:650,maxQuestionCodepoints:240,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true,
   algorithm:'sha256_42_fresh_evaluation_id_interleaved_labels_unique_family_context',duplicateFamiliesWithinSelection:false},
  trainingUsed:false,heldoutUsedForTraining:false,rowIds:blind.rows.map(row=>row.id),
  limitations:['Isolated from all recorded prior observed evaluations and complete official training families/contexts.','Pretraining corpus overlap is unknown.','Actual tokenizer admission and model generation remain required.','No local human semantic review or comprehensive privacy review.']};
 const manifest={...common,stage:STAGE,runId,datasetSha256:sha(data),frozenAt,counts:result.counts,labelCounts:result.labelCounts,
  selection:SELECTION,sampler:SAMPLER,exclusions:result.exclusions,availableCounts:result.availableCounts,
  previousExposureOverlap:result.previousExposureOverlap,wholeOfficialDevExcludedFromTraining:true,officialDevExclusionRows:parsed.heldout.length,
  exposedInputRows:exposed.length,heldoutUsed:false,heldoutUsedForTraining:false,sourceTraining:source80,
  blindEvaluation:{directory:blindDirectory,datasetSha256:sha(blindData),manifestSha256:sha(JSON.stringify(blindManifest,null,2)+'\n'),stage:BLIND_STAGE,frozenAt,rows:128,trainingUsed:false},
  rowIds:result.rows.map(row=>row.id),experiment:{hypothesis:'Higher impossible-label exposure may reduce unsupported answers; improvement is unproven.',
   plannedOptimizerSteps:20,plannedMicrobatches:320,plannedExposure:{answerable:160,impossible:160},learningRate:0.00003,
   sourceOptimizerHistoryUpdates:80,plannedTotalAdapterHistoryOptimizerUpdates:100,lengthDistributionExpansion:true,
   previousMaxContextCodepoints:650,maxContextCodepoints:700,reason:'At 650 codepoints only 128 impossible train and 11 impossible validation rows remain after all exposure exclusions; 700 preserves originals and supplies independent balanced rows.',
   balanceOnlyCausalComparison:false,qualityImprovementClaimed:false},
  limitations:['Original public human annotations; no local human semantic review.','Basic privacy regex is not a comprehensive privacy review.','No answer-based crop, teacher labels or governance legal targets.','All 704 full contexts must pass the fixed 1024-token actual tokenizer admission before training.']};
 // No writes occur until source identity, availability and both split boundaries pass.
 const frozenBlind=writeFrozenEvaluation(blindDirectory,blind.rows,blindManifest);
 mkdirSync(directory,{recursive:true});immutableGroundingWrite(join(directory,'data.jsonl'),data);immutableGroundingWrite(join(directory,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
 for(const [key,name]of Object.entries(SOURCE_FILES))immutableGroundingWrite(join(directory,name),bytes[key]);
 return {prepared:true,directory,data:join(directory,'data.jsonl'),manifest:join(directory,'manifest.json'),datasetSha256:sha(data),
  manifestSha256:sha(readFileSync(join(directory,'manifest.json'))),counts:result.counts,labelCounts:result.labelCounts,availableCounts:result.availableCounts,
  exclusions:result.exclusions,sourceTraining:source80,blindEvaluation:{...frozenBlind,counts:blindManifest.counts,excluded:blind.excluded,availableCounts:blind.availableCounts},
  actualTokenizerPreadmissionRequired:true,trainingRunStarted:false,qualityClaimAllowed:false,promotionAllowed:false};
}
// Derivation is limited to new execution identity; rows, labels and freeze time stay unchanged.
export function balancedRetryDocuments(manifest,blindManifest){
 requireValue(manifest?.runId===RUN_ID&&manifest.stage===STAGE&&blindManifest?.plannedTrainingRunId===RUN_ID
  &&blindManifest.stage===BLIND_STAGE&&manifest.frozenAt===blindManifest.frozenAt,'retry_source_identity_invalid');
 const blind=structuredClone(blindManifest);blind.plannedTrainingRunId=RETRY_RUN_ID;
 const next=structuredClone(manifest);next.runId=RETRY_RUN_ID;
 next.blindEvaluation.directory=RETRY_DIRECTORY+'/blind-evaluation';
 next.blindEvaluation.manifestSha256=sha(JSON.stringify(blind,null,2)+'\n');
 return {manifest:next,blindManifest:blind};
}
export function preparePublicQaGroundingBalancedRetry(){
 const old=balancedRunBinding(RUN_ID),binding=balancedRunBinding(RETRY_RUN_ID),source=join(old.directory,RUN_ID),
  directory=join(binding.directory,RETRY_RUN_ID),blindDirectory=join(binding.directory,'blind-evaluation');
 requireValue(!existsSync(binding.directory),'retry_output_already_exists');
 const data=verifiedBalancedFile(join(source,'data.jsonl'),old.pins.datasetSha256),
  manifest=JSON.parse(verifiedBalancedFile(join(source,'manifest.json'),old.pins.manifestSha256)),
  blindData=verifiedBalancedFile(join(old.directory,'blind-evaluation/data.jsonl'),old.blindDatasetSha256),
  blindManifest=JSON.parse(verifiedBalancedFile(join(old.directory,'blind-evaluation/manifest.json'),old.blindManifestSha256));
 const sources=Object.fromEntries(Object.entries(SOURCE_FILES).map(([key,name])=>[name,verifiedBalancedFile(join(source,name),SOURCE_PINS[key])]));
 verifySource80();
 const next=balancedRetryDocuments(manifest,blindManifest),manifestBytes=JSON.stringify(next.manifest,null,2)+'\n',blindManifestBytes=JSON.stringify(next.blindManifest,null,2)+'\n';
 requireValue(sha(manifestBytes)===binding.pins.manifestSha256&&sha(blindManifestBytes)===binding.blindManifestSha256,'retry_derivation_changed');
 // Fresh output only. A partial failed preparation is preserved and cannot be overwritten.
 mkdirSync(binding.directory,{recursive:false});
 const frozenBlind=writeFrozenEvaluation(blindDirectory,rows(blindData),next.blindManifest);
 mkdirSync(directory,{recursive:false});immutableGroundingWrite(join(directory,'data.jsonl'),data);immutableGroundingWrite(join(directory,'manifest.json'),manifestBytes);
 for(const [name,bytes]of Object.entries(sources))immutableGroundingWrite(join(directory,name),bytes);
 return {prepared:true,runId:RETRY_RUN_ID,directory,data:join(directory,'data.jsonl'),manifest:join(directory,'manifest.json'),...binding.pins,
  counts:manifest.counts,labelCounts:manifest.labelCounts,blindEvaluation:frozenBlind,reusedFrozenDataFromRunId:RUN_ID,
  previousRunOutputsUsed:false,sourceRunId:SOURCE_RUN,sourceOptimizerHistoryUpdates:80,actualTokenizerPreadmissionRequired:true,
  trainingRunStarted:false,qualityClaimAllowed:false,promotionAllowed:false};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args=process.argv.slice(2);requireValue(args.length===0||args.length===2&&args[0]==='--retry'&&args[1]===RETRY_RUN_ID,'usage_invalid');
 console.log(JSON.stringify(args.length?preparePublicQaGroundingBalancedRetry():preparePublicQaGroundingBalanced(),null,2));
}
