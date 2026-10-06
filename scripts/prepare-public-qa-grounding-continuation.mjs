import {readFileSync,mkdirSync,lstatSync} from 'node:fs';
import {join,resolve,relative,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {revision} from './prepare-public-qa-run.mjs';
import {GROUNDING_SOURCE_PINS,selectGroundingRows,immutableGroundingWrite} from './prepare-public-qa-grounding.mjs';

export const CONTINUATION_STAGE='public_qa_grounding_continuation_v1';
export const CONTINUATION_DIRECTORY='.local/public-training/grounding-continuation/20261006';
export const SAMPLER=Object.freeze({kind:'stratified_optimizer_groups_v1',groupSize:16,answerablePerGroup:11,impossiblePerGroup:5,seed:42});
export const CONTINUATION_SOURCE_PINS=Object.freeze({...GROUNDING_SOURCE_PINS,previousGrounding:'a080f3ff03ce813d5f4e242512a6442ff148e2341613e227f8c03e2e29a8d4ea'});
export const CONTINUATION_SOURCE_FILES=Object.freeze({sourceManifest:'source-manifest.json',sourceTrain:'source-train.jsonl',sourceValidation:'source-validation.jsonl',oldTraining:'old-training.jsonl',diagnostic:'diagnostic.jsonl',previousGrounding:'previous-grounding.jsonl'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const rows=bytes=>bytes.toString('utf8').trim().split(/\r?\n/).map(JSON.parse);
function verifiedFile(path,digest){if(!lstatSync(path).isFile()||lstatSync(path).isSymbolicLink())throw Error('continuation_source_not_plain_file');const bytes=readFileSync(path);if(sha(bytes)!==digest)throw Error('continuation_source_changed:'+path);return bytes;}

export function selectContinuationRows(sources,excluded){
 // Reuse original human-span and split/exposure checks. Only authentic rows
 // survive this selection; no negative questions or answers are generated.
 const selected=selectGroundingRows(sources,excluded,{trainPerLabel:{answerable:440,impossible:200},validationPerLabel:32});
 const counts={train:{answerable:0,impossible:0},validation:{answerable:0,impossible:0}},limits={train:{answerable:440,impossible:200},validation:{answerable:32,impossible:32}},data=[];
 for(const row of selected.rows){const label=row.isImpossible?'impossible':'answerable';if(counts[row.split][label]>=limits[row.split][label])continue;counts[row.split][label]++;data.push({...row,stage:CONTINUATION_STAGE});}
 if(JSON.stringify(counts)!==JSON.stringify(limits))throw Error('continuation_rows_insufficient');
 return {rows:data,counts:{train:640,validation:64},labelCounts:counts,exclusions:selected.exclusions};
}

export function preparePublicQaGroundingContinuation({source=`.local/public-training/klue-mrc/${revision}`,output=CONTINUATION_DIRECTORY,previousGrounding='.local/public-training/grounding/20261005/public-qa-grounding-20261005-r4/data.jsonl',oldTraining='.local/public-training/stage1/public-qa-stage1.jsonl',diagnostic='.local/public-training/diagnostic/20260928/data.jsonl'}={}){
 const paths={sourceManifest:join(source,'manifest.json'),sourceTrain:join(source,'train.jsonl'),sourceValidation:join(source,'validation.jsonl'),oldTraining,diagnostic,previousGrounding};
 const bytes=Object.fromEntries(Object.entries(paths).map(([key,path])=>[key,verifiedFile(path,CONTINUATION_SOURCE_PINS[key])])),upstream=JSON.parse(bytes.sourceManifest);
 if(upstream.revision!==revision||upstream.license!=='CC-BY-SA-4.0')throw Error('continuation_upstream_identity_invalid');
 for(const item of [...upstream.raw,...upstream.outputs]){const path=resolve(source,item.path),part=relative(resolve(source),path);if(!part||part.startsWith('..')||isAbsolute(part))throw Error('continuation_source_path_escape');verifiedFile(path,item.sha256);}
 const result=selectContinuationRows({train:rows(bytes.sourceTrain),validation:rows(bytes.sourceValidation)},[...rows(bytes.oldTraining),...rows(bytes.diagnostic),...rows(bytes.previousGrounding)]);
 const data=Buffer.from(result.rows.map(row=>JSON.stringify(row)).join('\n')+'\n');
 const manifest={schemaVersion:1,stage:CONTINUATION_STAGE,task:'korean_extractive_qa',datasetSha256:sha(data),upstreamRevision:revision,license:upstream.license,licenseUrl:upstream.licenseUrl,attribution:upstream.attribution,humanConstructionEvidence:upstream.humanConstructionEvidence,counts:result.counts,labelCounts:result.labelCounts,sourcePins:CONTINUATION_SOURCE_PINS,sourceFiles:CONTINUATION_SOURCE_FILES,selection:{maxContextCodepoints:650,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true},sampler:SAMPLER,exclusions:result.exclusions,previousExposureOverlap:{id:0,family:0,context:0},heldoutUsed:false,localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false,rowIds:result.rows.map(row=>row.id),experiment:{hypothesis:'Reduce repeated abstention targets to approximately the original public-source prevalence and measure actual sample exposure.',originalSourceImpossibleRate:3701/12060,priorGroundingImpossibleRate:0.5,plannedOptimizerSteps:20,plannedMicrobatches:320,plannedExposure:{answerable:220,impossible:100},learningRate:0.00003,lengthDistributionExpansion:false,qualityImprovementClaimed:false}};
 mkdirSync(output,{recursive:true});immutableGroundingWrite(join(output,'data.jsonl'),data);immutableGroundingWrite(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
 for(const [key,name]of Object.entries(CONTINUATION_SOURCE_FILES))immutableGroundingWrite(join(output,name),bytes[key]);
 return {directory:output,data:join(output,'data.jsonl'),manifest:join(output,'manifest.json'),datasetSha256:sha(data),manifestSha256:sha(readFileSync(join(output,'manifest.json'))),counts:manifest.counts,labelCounts:manifest.labelCounts};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const output=process.argv[2];console.log(JSON.stringify(preparePublicQaGroundingContinuation(output?{output}:{}),null,2));}
