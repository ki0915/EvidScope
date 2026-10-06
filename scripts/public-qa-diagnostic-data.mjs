import {readFileSync,writeFileSync,mkdirSync,lstatSync} from 'node:fs';
import {resolve,join,relative,isAbsolute,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {basicPrivacyMatch} from './prepare-public-qa-run.mjs';

export const REVISION='3efd98708a40ff49251fddde35453f8fbb11f536';
export const PINS=Object.freeze({sourceManifest:'c412bc1f048a33351be60ce8a4395bcf9d5a160d58047decc380a8c2197db14c',heldout:'681ceb8154dd4131c01679fcf8199e24d27c8d44e2abfe786588b2874bcb16e6',trainingManifest:'9eba08dc67ec2cbb258f199879a2b0610a4c2979e3699a50dafc6bfee52a32ec',trainingData:'21b4b91ad0f755de666fe2ebe9077f301477da6420ffa0195cb53b5189d2822f'});
export const sha=value=>createHash('sha256').update(value).digest('hex');
const lines=bytes=>bytes.toString('utf8').trim().split(/\r?\n/).map(JSON.parse);
const requireTrue=(value,error)=>{if(!value)throw Error(error);};
function file(root,name){const target=resolve(root,name),part=relative(resolve(root),target);requireTrue(part&&!part.startsWith('..')&&!isAbsolute(part),'source_path_escape');requireTrue(lstatSync(target).isFile()&&!lstatSync(target).isSymbolicLink(),'source_file_invalid');return readFileSync(target);}
export function verifySourceArtifacts(source,manifest){for(const item of [...manifest.raw,...manifest.outputs])requireTrue(sha(file(source,item.path))===item.sha256,'source_artifact_changed');}

export function validateDiagnosticRow(row){
 requireTrue(row?.split==='heldout'&&row.upstreamSplit==='dev'&&row.upstreamRevision===REVISION&&row.language==='ko'&&row.sourceLicense==='CC-BY-SA-4.0','heldout_provenance_invalid');
 requireTrue(typeof row.id==='string'&&row.id.length>0&&typeof row.familyId==='string'&&row.familyId.length>0&&typeof row.context==='string'&&row.context.length>0&&typeof row.question==='string'&&row.question.length>0&&sha(row.context)===row.contextSha256,'heldout_content_invalid');
 requireTrue(row.upstreamAnnotation?.kind==='human_authored_question_answer_spans'&&row.upstreamAnnotation.localHumanReviewPerformed===false&&row.localHumanReviewPerformed!==true,'annotation_provenance_invalid');
 requireTrue(typeof row.isImpossible==='boolean'&&Array.isArray(row.answers)&&row.question===row.originalQa?.question&&row.isImpossible===row.originalQa?.is_impossible&&JSON.stringify(row.answers)===JSON.stringify(row.originalQa?.answers),'original_annotation_changed');
 const points=Array.from(row.context);
 requireTrue(row.isImpossible?row.answers.length===0:row.answers.length>0&&row.answers.every(a=>typeof a.text==='string'&&a.text.length>0&&Number.isSafeInteger(a.answer_start)&&a.answer_start>=0&&points.slice(a.answer_start,a.answer_start+Array.from(a.text).length).join('')===a.text),'answer_span_invalid');
 return row;
}

export function selectDiagnosticRows(heldout,training,{perClass=32,maxContextCharacters=1200}={}){
 requireTrue(Number.isSafeInteger(perClass)&&perClass>0&&perClass<=1000&&Number.isSafeInteger(maxContextCharacters)&&maxContextCharacters>0,'diagnostic_selection_invalid');
 const ids=new Set(training.map(r=>r.id)),families=new Set(training.map(r=>r.familyId)),contexts=new Set(training.map(r=>r.contextSha256)),seen=new Set();
 for(const row of heldout){validateDiagnosticRow(row);requireTrue(!seen.has(row.id),'duplicate_heldout_id');seen.add(row.id);requireTrue(!ids.has(row.id)&&!families.has(row.familyId)&&!contexts.has(row.contextSha256),'training_heldout_overlap');}
 const excluded={privacyPattern:0,contextLength:0};
 const eligible=heldout.filter(row=>{if(basicPrivacyMatch(row.question+'\n'+row.context)){excluded.privacyPattern++;return false;}if(Array.from(row.context).length>maxContextCharacters){excluded.contextLength++;return false;}return true;});
 const order=(a,b)=>a.id<b.id?-1:a.id>b.id?1:0;
 const groups=[false,true].map(impossible=>eligible.filter(row=>row.isImpossible===impossible).sort(order).slice(0,perClass));
 requireTrue(groups.every(group=>group.length===perClass),'insufficient_diagnostic_rows');
 const rows=groups.flat().sort(order).map(row=>({...row,diagnosticOnly:true,localHumanReviewPerformed:false,contextSelection:'full_original_context_no_answer_based_crop',privacyScreen:{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false}}));
 return {rows,excluded,selection:{perClass,maxContextCharacters,ordering:'ascending UTF-16 id within answerability class',fullContextPreserved:true,answerBasedCropping:false},overlap:{id:0,family:0,context:0}};
}

export function prepareDiagnostic({source=`.local/public-training/klue-mrc/${REVISION}`,training='.local/public-training/stage1',output='.local/public-training/diagnostic/20260928',perClass=32,maxContextCharacters=1200}={}){
 const sourceBytes=file(source,'manifest.json'),trainingBytes=file(training,'public-qa-stage1.manifest.json');
 requireTrue(sha(sourceBytes)===PINS.sourceManifest&&sha(trainingBytes)===PINS.trainingManifest,'pinned_manifest_mismatch');
 const sourceManifest=JSON.parse(sourceBytes),trainingManifest=JSON.parse(trainingBytes);
 requireTrue(sourceManifest.revision===REVISION&&sourceManifest.license==='CC-BY-SA-4.0','source_identity_mismatch');
 verifySourceArtifacts(source,sourceManifest);
 const heldoutBytes=file(source,'heldout.jsonl'),trainBytes=file(training,'public-qa-stage1.jsonl');
 requireTrue(sha(heldoutBytes)===PINS.heldout&&sha(trainBytes)===PINS.trainingData&&trainingManifest.datasetSha256===PINS.trainingData,'pinned_dataset_mismatch');
 const result=selectDiagnosticRows(lines(heldoutBytes),lines(trainBytes),{perClass,maxContextCharacters}),bytes=Buffer.from(result.rows.map(r=>JSON.stringify(r)).join('\n')+'\n');
 const manifest={schemaVersion:1,mode:'public_qa_diagnostic',diagnosticOnly:true,upstreamRevision:REVISION,sourcePins:PINS,datasetSha256:sha(bytes),counts:{total:result.rows.length,answerable:perClass,unanswerable:perClass},rowIds:result.rows.map(r=>r.id),selection:result.selection,excluded:result.excluded,trainingOverlap:result.overlap,sourceLicense:sourceManifest.license,attribution:sourceManifest.attribution,humanConstructionEvidence:sourceManifest.humanConstructionEvidence,localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false,limitations:['Public Korean extractive QA only; no financial/legal quality claim.','Basic privacy pattern screening is not a comprehensive privacy review.','Full-context character filter is not tokenizer admission; runner must preserve contexts and record token-budget exclusions before inference.','No English regression or human semantic evaluation.']};
 mkdirSync(dirname(resolve(output)),{recursive:true});mkdirSync(output,{recursive:false});writeFileSync(join(output,'data.jsonl'),bytes,{flag:'wx'});writeFileSync(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});return manifest;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const output=process.argv[2];console.log(JSON.stringify(prepareDiagnostic(output?{output}:{}),null,2));}
