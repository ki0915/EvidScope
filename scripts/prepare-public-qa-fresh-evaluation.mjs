// Freeze previously unobserved, authentic heldout QA before the next training run.
// This script never calls a model, creates labels, or changes training artifacts.
import {readFileSync,writeFileSync,mkdirSync,existsSync,lstatSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {pathToFileURL} from 'node:url';
import {basicPrivacyMatch,revision} from './prepare-public-qa-run.mjs';

export const FRESH_EVALUATION_STAGE='public_qa_grounding_continuation_fresh_evaluation_v1';
export const FRESH_EVALUATION_OUTPUT='.local/public-training/grounding-continuation/20261006/fresh-evaluation';
export const FRESH_EVALUATION_PINS=Object.freeze({
 sourceManifest:'c412bc1f048a33351be60ce8a4395bcf9d5a160d58047decc380a8c2197db14c',
 heldout:'681ceb8154dd4131c01679fcf8199e24d27c8d44e2abfe786588b2874bcb16e6',
 stage1:'21b4b91ad0f755de666fe2ebe9077f301477da6420ffa0195cb53b5189d2822f',
 previousGrounding:'a080f3ff03ce813d5f4e242512a6442ff148e2341613e227f8c03e2e29a8d4ea',
 observedDiagnostic:'50561634095f758781c4695fcc30e2d7bd7cf7d9b937d8c10174a3e927c837f9',
 continuation:'258ea70365b16ab31357467f3b32c66edca38b3ea0c6db46a11009ab79ed372b',
});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const parse=bytes=>bytes.toString('utf8').trim().split(/\r?\n/u).map(JSON.parse);
const require=(value,message)=>{if(!value)throw Error(message);};

export function selectFreshEvaluation(source,exposed,{perLabel=64}={}){
 require(Number.isSafeInteger(perLabel)&&perLabel>0&&perLabel<=64,'fresh_evaluation_label_count_invalid');
 const forbidden=Object.fromEntries(['id','familyId','contextSha256'].map(key=>[key,new Set(exposed.map(row=>row[key]))]));
 const seen=new Set(),available=[],excluded={previousExposure:0,privacyPattern:0,contextTooLong:0,questionTooLong:0};
 for(const row of source){
  require(!seen.has(row.id),'fresh_evaluation_duplicate_source_id');seen.add(row.id);
  require(row.split==='heldout'&&row.upstreamSplit==='dev'&&row.upstreamRevision===revision&&row.language==='ko'
   &&row.sourceLicense==='CC-BY-SA-4.0'&&row.upstreamAnnotation?.kind==='human_authored_question_answer_spans'
   &&typeof row.isImpossible==='boolean'&&typeof row.context==='string'&&row.context&&typeof row.question==='string'&&row.question
   &&typeof row.familyId==='string'&&row.familyId,'fresh_evaluation_original_provenance_invalid');
  require(sha(row.context)===row.contextSha256&&row.question===row.originalQa?.question
   &&row.isImpossible===row.originalQa?.is_impossible&&isDeepStrictEqual(row.answers,row.originalQa?.answers),
   'fresh_evaluation_original_changed');
  const context=Array.from(row.context);
  require(Array.isArray(row.answers)&&(row.isImpossible?row.answers.length===0:row.answers.length>0&&row.answers.every(answer=>
   typeof answer.text==='string'&&answer.text&&Number.isSafeInteger(answer.answer_start)&&answer.answer_start>=0
   &&context.slice(answer.answer_start,answer.answer_start+Array.from(answer.text).length).join('')===answer.text)),
   'fresh_evaluation_answer_span_invalid');
  if(Object.keys(forbidden).some(key=>forbidden[key].has(row[key]))){excluded.previousExposure++;continue;}
  if(context.length>650){excluded.contextTooLong++;continue;}
  if(Array.from(row.question).length>240){excluded.questionTooLong++;continue;}
  if(basicPrivacyMatch(row.question+'\n'+row.context)){excluded.privacyPattern++;continue;}
  available.push(row);
 }
 // A hash permutation prevents the old first-ID selection window recurring.
 const pools=new Map([false,true].map(label=>[label,available.filter(row=>row.isImpossible===label).sort((a,b)=>{
  const x=sha(`42|fresh-evaluation|${a.id}`),y=sha(`42|fresh-evaluation|${b.id}`);return x<y?-1:x>y?1:a.id.localeCompare(b.id,'en');
 })]));
 const rows=[],families=new Set(),contexts=new Set(),selected={answerable:0,impossible:0};
 for(let index=0;index<perLabel;index++)for(const label of [false,true]){
  const row=pools.get(label).find(item=>!families.has(item.familyId)&&!contexts.has(item.contextSha256));
  if(!row)return {sufficient:false,rows:[],excluded,availableCounts:{answerable:pools.get(false).length,impossible:pools.get(true).length},selectedBeforeInsufficient:selected};
  families.add(row.familyId);contexts.add(row.contextSha256);selected[label?'impossible':'answerable']++;
  rows.push({...row,stage:FRESH_EVALUATION_STAGE,contextSelection:'full_original_context_no_answer_based_crop',
   localHumanReviewPerformed:false,privacyScreen:{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false}});
 }
 require(rows.every(row=>Object.keys(forbidden).every(key=>!forbidden[key].has(row[key]))),'fresh_evaluation_exposure_leakage');
 return {sufficient:true,rows,excluded,availableCounts:{answerable:pools.get(false).length,impossible:pools.get(true).length},counts:selected,
  overlap:{id:0,family:0,context:0},uniqueSelectedFamilies:families.size,uniqueSelectedContexts:contexts.size};
}

export function writeFrozenEvaluation(output,rows,manifest){
 require(!existsSync(output),'fresh_evaluation_output_already_exists');
 const data=Buffer.from(rows.map(row=>JSON.stringify(row)).join('\n')+'\n');
 require(manifest.datasetSha256===sha(data),'fresh_evaluation_output_digest_mismatch');
 mkdirSync(output,{recursive:true});
 writeFileSync(join(output,'data.jsonl'),data,{flag:'wx'});
 writeFileSync(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});
 return {directory:output,data:join(output,'data.jsonl'),manifest:join(output,'manifest.json'),datasetSha256:sha(data),manifestSha256:sha(readFileSync(join(output,'manifest.json')))};
}

export function prepareFreshEvaluation({output=FRESH_EVALUATION_OUTPUT}={}){
 const paths={sourceManifest:`.local/public-training/klue-mrc/${revision}/manifest.json`,heldout:`.local/public-training/klue-mrc/${revision}/heldout.jsonl`,
  stage1:'.local/public-training/stage1/public-qa-stage1.jsonl',previousGrounding:'.local/public-training/grounding/20261005/public-qa-grounding-20261005-r4/data.jsonl',
  observedDiagnostic:'.local/public-training/diagnostic/20260928/data.jsonl',continuation:'.local/public-training/grounding-continuation/20261006/public-qa-grounding-20261006-r1/data.jsonl'};
 const bytes=Object.fromEntries(Object.entries(paths).map(([key,path])=>{require(lstatSync(path).isFile()&&!lstatSync(path).isSymbolicLink(),'fresh_evaluation_source_path_invalid');return [key,readFileSync(path)];}));
 for(const [key,value]of Object.entries(bytes))require(sha(value)===FRESH_EVALUATION_PINS[key],'fresh_evaluation_source_digest_changed:'+key);
 const upstream=JSON.parse(bytes.sourceManifest);
 require(upstream.revision===revision&&upstream.license==='CC-BY-SA-4.0','fresh_evaluation_source_identity_invalid');
 const source=parse(bytes.heldout),exposures=Object.fromEntries(Object.keys(paths).filter(key=>!['sourceManifest','heldout'].includes(key)).map(key=>[key,parse(bytes[key])]));
 const exposed=Object.values(exposures).flat(),selection=selectFreshEvaluation(source,exposed);
 if(!selection.sufficient)return {prepared:false,reason:'insufficient_unique_authentic_rows',...selection};
 const data=Buffer.from(selection.rows.map(row=>JSON.stringify(row)).join('\n')+'\n');
 const manifest={schemaVersion:1,stage:FRESH_EVALUATION_STAGE,task:'korean_extractive_qa',datasetSha256:sha(data),frozenBeforeContinuationTraining:true,
  sourceRevision:revision,sourceHeldoutSha256:FRESH_EVALUATION_PINS.heldout,sourcePins:FRESH_EVALUATION_PINS,
  sourceInputs:Object.entries(paths).map(([key,path])=>({name:key,path,sha256:sha(bytes[key]),rows:key==='sourceManifest'?null:key==='heldout'?source.length:exposures[key].length})),
  license:upstream.license,licenseUrl:upstream.licenseUrl,attribution:upstream.attribution,humanConstructionEvidence:upstream.humanConstructionEvidence,
  counts:{total:128,answerable:64,impossible:64},exposedInputRows:exposed.length,excluded:selection.excluded,availableCounts:selection.availableCounts,
  previousExposureOverlap:selection.overlap,uniqueSelectedFamilies:selection.uniqueSelectedFamilies,uniqueSelectedContexts:selection.uniqueSelectedContexts,
  selection:{maxContextCodepoints:650,maxQuestionCodepoints:240,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true,
   algorithm:'sha256_42_fresh_evaluation_id_interleaved_labels_unique_family_context',duplicateFamiliesWithinSelection:false},
  originalHumanLabelsPreserved:true,automaticallyGeneratedLabels:false,trainingUsed:false,heldoutUsedForTraining:false,
  localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false,
  limitations:['Original public human annotations; no local human semantic review.','Basic privacy pattern filter is not a comprehensive privacy review.',
   'Rows are isolated from recorded prior training, validation and diagnostic exposure; pretraining corpus overlap is unknown.','Actual tokenizer admission and generation execution remain required.'],
  rowIds:selection.rows.map(row=>row.id)};
 return {prepared:true,...writeFrozenEvaluation(output,selection.rows,manifest),counts:manifest.counts,excluded:selection.excluded,
  availableCounts:selection.availableCounts,previousExposureOverlap:selection.overlap,uniqueSelectedFamilies:selection.uniqueSelectedFamilies,uniqueSelectedContexts:selection.uniqueSelectedContexts};
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){const result=prepareFreshEvaluation();console.log(JSON.stringify(result,null,2));if(!result.prepared)process.exitCode=2;}
