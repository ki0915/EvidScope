import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {resolve, join} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const sha = value => createHash('sha256').update(value).digest('hex');
export const revision = '3efd98708a40ff49251fddde35453f8fbb11f536';
export function basicPrivacyMatch(text) {
  return /[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b01[016789][- .]?\d{3,4}[- .]?\d{4}\b|\b\d{6}[- ]?[1-8]\d{6}\b/iu.test(text);
}
export function preparePublicQaRun(source, output, {trainCount=320, validationCount=64}={}) {
  const manifestBytes=readFileSync(join(source,'manifest.json'));
  const upstream=JSON.parse(manifestBytes);
  if(upstream.revision!==revision || upstream.license!=='CC-BY-SA-4.0') throw Error('upstream_identity_mismatch');
  for(const item of [...upstream.raw,...upstream.outputs]) {
    const file=resolve(source,item.path);
    if(!file.startsWith(resolve(source)+ (process.platform==='win32'?'\\':'/'))) throw Error('source_path_escape');
    if(sha(readFileSync(file))!==item.sha256) throw Error('upstream_digest_mismatch');
  }
  const heldout=readFileSync(join(source,'heldout.jsonl'),'utf8').trim().split(/\r?\n/u).map(JSON.parse);
  const heldoutFamilies=new Set(heldout.map(row=>row.familyId));
  const seen=new Set(), families=new Map(), rows=[], excluded={privacyPattern:0,tooLong:0};
  for(const [split,count] of [['train',trainCount],['validation',validationCount]]) {
    const candidates=readFileSync(join(source,`${split}.jsonl`),'utf8').trim().split(/\r?\n/u).map(JSON.parse).sort((a,b)=>a.id.localeCompare(b.id,'en'));
    let selected=0;
    for(const row of candidates) {
      if(row.split!==split || row.upstreamSplit!=='train' || row.upstreamRevision!==revision || heldoutFamilies.has(row.familyId)) throw Error('split_provenance_invalid');
      if(row.upstreamAnnotation?.kind!=='human_authored_question_answer_spans' || row.sourceLicense!=='CC-BY-SA-4.0' || row.question!==row.originalQa?.question) throw Error('human_annotation_provenance_missing');
      if(sha(row.context)!==row.contextSha256 || JSON.stringify(row.answers)!==JSON.stringify(row.originalQa.answers)) throw Error('original_qa_changed');
      const points=Array.from(row.context);
      if(!row.isImpossible && (!row.answers.length || row.answers.some(a=>points.slice(a.answer_start,a.answer_start+Array.from(a.text).length).join('')!==a.text))) throw Error('answer_span_invalid');
      if(basicPrivacyMatch(`${row.question}\n${row.context}`)) {excluded.privacyPattern++;continue;}
      if(Array.from(row.question).length>240 || (!row.isImpossible && Array.from(row.answers[0].text).length>160)) {excluded.tooLong++;continue;}
      if(seen.has(row.id) || (families.has(row.familyId)&&families.get(row.familyId)!==split)) throw Error('duplicate_or_family_split_leakage');
      seen.add(row.id);families.set(row.familyId,split);
      rows.push({...row,stage:'public_qa_stage1',targetTransformation:'exact_first_upstream_answer_span_to_json_no_generated_reasoning',localHumanReviewPerformed:false,privacyScreen:{kind:'basic_email_mobile_resident_id_regex',passed:true,comprehensivePrivacyReview:false}});
      if(++selected===count) break;
    }
    if(selected!==count) throw Error(`insufficient_${split}_rows`);
  }
  mkdirSync(output,{recursive:true});
  const data=rows.map(row=>JSON.stringify(row)).join('\n')+'\n';
  const datasetPath=join(output,'public-qa-stage1.jsonl');
  writeFileSync(datasetPath,data);
  const receipt={schemaVersion:1,stage:'public_qa_stage1',task:'korean_extractive_qa',datasetSha256:sha(data),sourceManifestSha256:sha(manifestBytes),upstreamRepository:upstream.repository,upstreamRevision:revision,license:upstream.license,attribution:upstream.attribution,licenseUrl:upstream.licenseUrl,humanConstructionEvidence:upstream.humanConstructionEvidence,counts:{train:trainCount,validation:validationCount},excluded,localHumanReviewPerformed:false,heldoutUsed:false,qualityClaimAllowed:false,promotionAllowed:false,changes:'Deterministic subset; basic pattern screen; training encodes an answer-preserving contiguous context window and JSON from the exact first human answer. No generated reasoning or legal labels.',rowIds:rows.map(row=>row.id)};
  writeFileSync(join(output,'public-qa-stage1.manifest.json'),JSON.stringify(receipt,null,2)+'\n');
  return {datasetPath,manifestPath:join(output,'public-qa-stage1.manifest.json'),...receipt};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  const args=process.argv.slice(2), option=(key,fallback)=>{const i=args.indexOf(key);return i<0?fallback:args[i+1];};
  console.log(JSON.stringify(preparePublicQaRun(option('--source',`.local/public-training/klue-mrc/${revision}`),option('--output','.local/public-training/stage1')),null,2));
}
