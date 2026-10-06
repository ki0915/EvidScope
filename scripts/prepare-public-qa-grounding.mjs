import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {basicPrivacyMatch,revision} from './prepare-public-qa-run.mjs';

export const GROUNDING_STAGE='public_qa_grounding_v1';
export const GROUNDING_DIRECTORY='.local/public-training/grounding/20261005';
export const GROUNDING_SOURCE_PINS=Object.freeze({sourceManifest:'c412bc1f048a33351be60ce8a4395bcf9d5a160d58047decc380a8c2197db14c',sourceTrain:'e050f9d529ce8932714b5a4fcb7e6e599b76c2ef8ef7c2108a8ba06173b1a855',sourceValidation:'f0ab6e2774ea94926cabe6ef281a353f304717b7ed0845ab3ce5134c823b20ad',oldTraining:'21b4b91ad0f755de666fe2ebe9077f301477da6420ffa0195cb53b5189d2822f',diagnostic:'50561634095f758781c4695fcc30e2d7bd7cf7d9b937d8c10174a3e927c837f9'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const parse=bytes=>bytes.toString('utf8').trim().split(/\r?\n/u).map(JSON.parse);
export function immutableGroundingWrite(path,bytes){if(existsSync(path)){if(!readFileSync(path).equals(Buffer.from(bytes)))throw Error('grounding_output_exists_changed');}else writeFileSync(path,bytes,{flag:'wx'});}
export function selectGroundingRows(sources,excluded,{trainPerLabel=320,validationPerLabel=32}={}){
 const forbidden=Object.fromEntries(['id','familyId','contextSha256'].map(key=>[key,new Set(excluded.map(r=>r[key]))]));
 const selected=[],seen=new Set(),families=new Map(),contexts=new Map(),counts={},exclusions={previousExposure:0,privacyPattern:0,fullContextTooLong:0};
 for(const [split,count]of [['train',trainPerLabel],['validation',validationPerLabel]]){
  const limits=typeof count==='number'?{answerable:count,impossible:count}:count;
  if(!limits||Object.keys(limits).sort().join(',')!=='answerable,impossible'||Object.values(limits).some(value=>!Number.isSafeInteger(value)||value<1))throw Error('grounding_label_limits_invalid');
  const limitFor=label=>limits[label?'impossible':'answerable'];
  const pool=sources[split].slice().sort((a,b)=>a.id.localeCompare(b.id,'en')),labels=new Map([[false,[]],[true,[]]]);
  for(const row of pool){
   if(row.split!==split||row.upstreamSplit!=='train'||row.upstreamRevision!==revision||row.sourceLicense!=='CC-BY-SA-4.0'||row.upstreamAnnotation?.kind!=='human_authored_question_answer_spans')throw Error('grounding_source_identity_invalid');
   if(sha(row.context)!==row.contextSha256||row.question!==row.originalQa?.question||row.isImpossible!==row.originalQa?.is_impossible||JSON.stringify(row.answers)!==JSON.stringify(row.originalQa?.answers)||typeof row.isImpossible!=='boolean')throw Error('grounding_original_changed');
   if(row.isImpossible?row.answers.length:(!row.answers.length||row.answers.some(a=>Array.from(row.context).slice(a.answer_start,a.answer_start+Array.from(a.text).length).join('')!==a.text)))throw Error('grounding_answer_span_invalid');
   if(Object.keys(forbidden).some(key=>forbidden[key].has(row[key]))){exclusions.previousExposure++;continue;}
   if(Array.from(row.context).length>650||Array.from(row.question).length>240||(!row.isImpossible&&Array.from(row.answers[0].text).length>160)){exclusions.fullContextTooLong++;continue;}
   if(basicPrivacyMatch(row.question+'\n'+row.context)){exclusions.privacyPattern++;continue;}
   if(labels.get(row.isImpossible).length<limitFor(row.isImpossible))labels.get(row.isImpossible).push(row);
  }
  if([...labels.entries()].some(([label,rows])=>rows.length!==limitFor(label)))throw Error('grounding_insufficient_'+split);
  // Interleave authentic labels, without synthesizing or modifying questions.
  for(let i=0;i<Math.max(...Object.values(limits));i++)for(const label of [false,true]){
   if(i>=limitFor(label))continue;
   const row=labels.get(label)[i];
   if(seen.has(row.id)||(families.has(row.familyId)&&families.get(row.familyId)!==split)||(contexts.has(row.contextSha256)&&contexts.get(row.contextSha256)!==split))throw Error('grounding_split_leakage');
   seen.add(row.id);families.set(row.familyId,split);contexts.set(row.contextSha256,split);
   selected.push({...row,stage:GROUNDING_STAGE,contextSelection:'full_original_context',localHumanReviewPerformed:false,privacyScreen:{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false}});
  }
  counts[split]=limits.answerable+limits.impossible;
 }
 return {rows:selected,counts,exclusions};
}
export function preparePublicQaGrounding({source=`.local/public-training/klue-mrc/${revision}`,output=GROUNDING_DIRECTORY,oldTraining='.local/public-training/stage1/public-qa-stage1.jsonl',diagnostic='.local/public-training/diagnostic/20260928/data.jsonl'}={}){
 const files={sourceManifest:join(source,'manifest.json'),sourceTrain:join(source,'train.jsonl'),sourceValidation:join(source,'validation.jsonl'),oldTraining,diagnostic};
 const bytes=Object.fromEntries(Object.entries(files).map(([key,path])=>[key,readFileSync(path)]));
 for(const [key,value]of Object.entries(bytes))if(sha(value)!==GROUNDING_SOURCE_PINS[key])throw Error('grounding_source_digest_changed:'+key);
 const upstream=JSON.parse(bytes.sourceManifest);
 if(upstream.revision!==revision||upstream.license!=='CC-BY-SA-4.0')throw Error('grounding_upstream_invalid');
 for(const item of [...upstream.raw,...upstream.outputs]){const path=resolve(source,item.path);if(!path.startsWith(resolve(source)+sep)||sha(readFileSync(path))!==item.sha256)throw Error('grounding_source_artifact_changed');}
 const result=selectGroundingRows({train:parse(bytes.sourceTrain),validation:parse(bytes.sourceValidation)},[...parse(bytes.oldTraining),...parse(bytes.diagnostic)]);
 const data=Buffer.from(result.rows.map(row=>JSON.stringify(row)).join('\n')+'\n');
 const manifest={schemaVersion:1,stage:GROUNDING_STAGE,task:'korean_extractive_qa',datasetSha256:sha(data),upstreamRevision:revision,license:upstream.license,licenseUrl:upstream.licenseUrl,attribution:upstream.attribution,humanConstructionEvidence:upstream.humanConstructionEvidence,counts:result.counts,labelCounts:{train:{answerable:320,impossible:320},validation:{answerable:32,impossible:32}},sourcePins:GROUNDING_SOURCE_PINS,sourceFiles:{sourceManifest:'source-manifest.json',sourceTrain:'source-train.jsonl',sourceValidation:'source-validation.jsonl',oldTraining:'old-training.jsonl',diagnostic:'diagnostic.jsonl'},selection:{maxContextCodepoints:650,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true},exclusions:result.exclusions,previousExposureOverlap:{id:0,family:0,context:0},heldoutUsed:false,localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false,rowIds:result.rows.map(r=>r.id)};
 mkdirSync(output,{recursive:true});
 immutableGroundingWrite(join(output,'data.jsonl'),data);immutableGroundingWrite(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
 for(const [key,name]of Object.entries(manifest.sourceFiles))immutableGroundingWrite(join(output,name),bytes[key]);
 return {directory:output,data:join(output,'data.jsonl'),manifest:join(output,'manifest.json'),datasetSha256:sha(data),manifestSha256:sha(readFileSync(join(output,'manifest.json'))),counts:manifest.counts,labelCounts:manifest.labelCounts,actualTokenizerPreadmissionRequired:true};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)console.log(JSON.stringify(preparePublicQaGrounding(),null,2));
