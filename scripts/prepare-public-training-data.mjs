import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const REPOSITORY='KLUE-benchmark/KLUE';
const PAPER='https://datasets-benchmarks-proceedings.neurips.cc/paper/2021/file/98dce83da57b0395e163467c9dae521b-Paper-round2.pdf';
const LICENSE='https://creativecommons.org/licenses/by-sa/4.0/';
const FILES=['klue_benchmark/klue-mrc-v1.1/klue-mrc-v1.1_train.json','klue_benchmark/klue-mrc-v1.1/klue-mrc-v1.1_dev.json','License.md','README.md'];
const sha=value=>createHash('sha256').update(value).digest('hex');
const text=value=>typeof value==='string'&&value.trim().length>0;
const normalized=value=>value.normalize('NFKC').replace(/\s+/gu,' ').trim();
const contentKey=row=>sha(JSON.stringify([normalized(row.context),normalized(row.question)]));
const familyKeys=row=>['context:'+sha(normalized(row.context)),...(text(row.title)?['document:'+sha(normalized(row.title))]:[])];

export function normalizeKlue(dataset,{upstreamSplit,revision}){
 if(!['train','dev'].includes(upstreamSplit)||!/^[a-f0-9]{40}$/.test(revision||'')||!dataset||!Array.isArray(dataset.data)||!dataset.data.length)throw Error('klue_dataset_invalid');
 const rows=[],ids=new Set();
 for(const doc of dataset.data){
  if(!doc||typeof doc.title!=='string'||!text(doc.source)||!Array.isArray(doc.paragraphs)||!doc.paragraphs.length)throw Error('klue_document_invalid');
  for(const paragraph of doc.paragraphs){
   if(!text(paragraph?.context)||!Array.isArray(paragraph.qas))throw Error('klue_paragraph_invalid');
   const points=Array.from(paragraph.context);
   for(const qa of paragraph.qas){
    if(!text(qa?.guid)||ids.has(qa.guid)||!text(qa.question)||typeof qa.is_impossible!=='boolean'||!Array.isArray(qa.answers)||![1,2,3].includes(qa.question_type))throw Error('klue_qa_invalid_or_duplicate_id');
    ids.add(qa.guid);
    if(qa.is_impossible?(qa.answers.length!==0||qa.question_type!==3):(qa.answers.length===0||qa.question_type===3))throw Error('klue_unanswerable_marker_invalid');
    if(qa.plausible_answers!==undefined&&!Array.isArray(qa.plausible_answers))throw Error('klue_plausible_answers_invalid');
    for(const answer of [...qa.answers,...(qa.plausible_answers||[])]){
     if(!text(answer?.text)||!Number.isInteger(answer.answer_start)||answer.answer_start<0||points.slice(answer.answer_start,answer.answer_start+Array.from(answer.text).length).join('')!==answer.text)throw Error(`klue_answer_span_invalid:${qa.guid}`);
    }
    rows.push({schemaVersion:1,id:qa.guid,task:'korean_extractive_qa',language:'ko',title:doc.title,source:doc.source,newsCategory:doc.news_category??null,question:qa.question,context:paragraph.context,answers:structuredClone(qa.answers),plausibleAnswers:structuredClone(qa.plausible_answers||[]),isImpossible:qa.is_impossible,questionType:qa.question_type,contextSha256:sha(paragraph.context),upstreamSplit,upstreamRevision:revision,upstreamAnnotation:{kind:'human_authored_question_answer_spans',provider:'KLUE benchmark annotation workers',constructionEvidenceUrl:PAPER,constructionEvidencePage:6,individualReviewerIdentity:'not_provided_upstream',localHumanReviewPerformed:false},sourceLicense:'CC-BY-SA-4.0',licenseUrl:LICENSE,machineValidation:{answerSpanOffsets:'unicode_code_points',answerSpansVerified:true,unanswerableMarkerVerified:true,privacyStatus:'not_reviewed'},originalQa:structuredClone(qa)});
   }
  }
 }
 return rows;
}

export function partitionKlue(train,heldout){
 const all=[...train,...heldout],ids=new Set(),parents=new Map();
 const root=k=>{if(!parents.has(k))parents.set(k,k);if(parents.get(k)!==k)parents.set(k,root(parents.get(k)));return parents.get(k);};
 const union=(a,b)=>{a=root(a);b=root(b);if(a!==b)parents.set(a>b?a:b,a>b?b:a);};
 for(const row of all){if(ids.has(row.id))throw Error('klue_cross_split_duplicate_id');ids.add(row.id);const keys=familyKeys(row);keys.forEach(k=>union(keys[0],k));}
 const family=row=>sha(root(familyKeys(row)[0]));
 const heldoutFamilies=new Set(heldout.map(family)),seen=new Set(),excluded=[],derived={train:[],validation:[],heldout:heldout.map(row=>({...row,familyId:family(row),split:'heldout',splitOrigin:'official_dev_untouched'}))};
 const assignment=new Map();
 const eligibleFamilies=[...new Set(train.map(family).filter(id=>!heldoutFamilies.has(id)))].sort();
 eligibleFamilies.forEach((id,index)=>assignment.set(id,index%10===0?'validation':'train'));
 for(const row of train){
  const id=family(row),key=contentKey(row);
  if(heldoutFamilies.has(id)){excluded.push({id:row.id,reason:'family_overlaps_official_dev'});continue;}
  if(seen.has(key)){excluded.push({id:row.id,reason:'duplicate_context_question'});continue;}
  seen.add(key);const split=assignment.get(id);derived[split].push({...row,familyId:id,split,splitOrigin:'official_train_grouped_by_document_and_context'});
 }
 const cross=new Map();for(const [split,rows] of Object.entries(derived))for(const row of rows){if(cross.has(row.familyId)&&cross.get(row.familyId)!==split)throw Error('klue_family_split_leakage');cross.set(row.familyId,split);}
 return {...derived,excluded};
}

async function download(url,maxBytes){
 const response=await fetch(url,{headers:{'User-Agent':'EvidScope-public-training-acquisition','Accept':'application/vnd.github+json'},signal:AbortSignal.timeout(60000),redirect:'error'});
 if(!response.ok)throw Error(`source_download_failed:${response.status}:${url}`);
 const chunks=[];let size=0;
 for await(const chunk of response.body){size+=chunk.length;if(size>maxBytes)throw Error('source_download_too_large');chunks.push(chunk);}
 return Buffer.concat(chunks);
}
function immutableWrite(path,bytes){if(existsSync(path)){if(sha(readFileSync(path))!==sha(bytes))throw Error('acquisition_existing_file_mismatch:'+path);return;}writeFileSync(path,bytes,{flag:'wx'});}

export async function acquireKlue({directory=resolve('.local/public-training/klue-mrc')}={}){
 const commitUrl=`https://api.github.com/repos/${REPOSITORY}/commits/main`;
 const commitBytes=await download(commitUrl,1024*1024),revision=JSON.parse(commitBytes).sha;
 if(!/^[a-f0-9]{40}$/.test(revision||''))throw Error('upstream_revision_invalid');
 const downloads=await Promise.all(FILES.map(async path=>{const url=`https://raw.githubusercontent.com/${REPOSITORY}/${revision}/${path}`;return {path,url,bytes:await download(url,100*1024*1024)};}));
 const [trainFile,devFile,licenseFile,readmeFile]=downloads;
 if(!licenseFile.bytes.toString('utf8').includes('Attribution-ShareAlike 4.0 International')||!readmeFile.bytes.toString('utf8').includes('creativecommons.org/licenses/by-sa/4.0/'))throw Error('upstream_license_not_verified');
 const destination=join(directory,revision),rawDir=join(destination,'raw');
 mkdirSync(rawDir,{recursive:true});
 for(const file of downloads)immutableWrite(join(rawDir,file.path.split('/').at(-1)),file.bytes);
 const train=normalizeKlue(JSON.parse(trainFile.bytes),{upstreamSplit:'train',revision}),heldout=normalizeKlue(JSON.parse(devFile.bytes),{upstreamSplit:'dev',revision});
 const result=partitionKlue(train,heldout);
 const outputs=[];
 for(const split of ['train','validation','heldout']){const bytes=Buffer.from(result[split].map(row=>JSON.stringify(row)).join('\n')+'\n');const name=`${split}.jsonl`;immutableWrite(join(destination,name),bytes);outputs.push({path:name,records:result[split].length,bytes:bytes.length,sha256:sha(bytes)});}
 const exclusions=Buffer.from(JSON.stringify(result.excluded,null,2)+'\n');immutableWrite(join(destination,'excluded.json'),exclusions);
 const manifest={schemaVersion:1,dataset:'KLUE-MRC v1.1',repository:`https://github.com/${REPOSITORY}`,revision,commitResolutionUrl:commitUrl,acquiredAt:new Date().toISOString(),license:'CC-BY-SA-4.0',licenseUrl:LICENSE,attribution:'KLUE benchmark, Sungjoon Park et al. (2021). See retained upstream README.md and License.md.',changes:'Normalized JSONL without paraphrasing questions, passages or answers; original QA retained. Official train grouped by document title and normalized context into train/validation; any family touching official dev excluded from derived training. Official dev retained in full as heldout.',humanConstructionEvidence:{url:PAPER,page:6,description:'KLUE-MRC annotation workers authored questions and answer spans after guideline training; no local human annotation claimed.'},raw:downloads.map(file=>({path:'raw/'+file.path.split('/').at(-1),url:file.url,sha256:sha(file.bytes),bytes:file.bytes.length})),outputs,counts:{upstreamTrain:train.length,upstreamDev:heldout.length,train:result.train.length,validation:result.validation.length,heldout:result.heldout.length,excluded:result.excluded.length},excludedReasons:Object.fromEntries([...new Set(result.excluded.map(r=>r.reason))].map(reason=>[reason,result.excluded.filter(r=>r.reason===reason).length])),excludedSha256:sha(exclusions),checks:{unicodeCodepointAnswerSpans:true,unanswerableMarkers:true,duplicateIdsRejected:true,trainingDuplicatesRemoved:true,familySplitLeakage:false,officialDevRetained:true},localHumanReviewPerformed:false,privacyReview:'not_performed',trainingAdmission:'not_evaluated_public_QA_is_not_governance_reviewed_dataset',trainingRunAllowed:false,qualityClaimAllowed:false};
 const manifestPath=join(destination,'manifest.json');
 if(existsSync(manifestPath)){const previous=JSON.parse(readFileSync(manifestPath,'utf8'));manifest.acquiredAt=previous.acquiredAt;}
 immutableWrite(manifestPath,Buffer.from(JSON.stringify(manifest,null,2)+'\n'));
 return {directory:destination,manifestPath,...manifest.counts,revision,trainingRunAllowed:false};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{if(process.argv[2]!=='--acquire'||process.argv.length!==3)throw Error('usage: node scripts/prepare-public-training-data.mjs --acquire');console.log(JSON.stringify(await acquireKlue(),null,2));}catch(error){console.error(error.message);process.exitCode=2;}}
