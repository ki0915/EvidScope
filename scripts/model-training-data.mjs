import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {evaluateLoraAdmission,scoreRoleOutput} from '../src/role-evaluation.mjs';
export const recordHash=record=>createHash('sha256').update(JSON.stringify(record)).digest('hex');
function sorted(value){return Array.isArray(value)?value.map(sorted):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,sorted(value[k])])):value;}
export const reviewedPayloadHash=record=>recordHash(sorted(Object.fromEntries(['id','roleId','split','familyId','sourceId','language','prompt','evidence','truth','approvedOutput'].map(k=>[k,record[k]??null]))));
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const identity=value=>typeof value==='string'&&value.trim().length>0;
function sourceRecords(records){
 if(!Array.isArray(records)||!records.length)throw Error('review_source_records_invalid');
 const byId=new Map();for(const record of records){
  if(!object(record)||!identity(record.id)||byId.has(record.id))throw Error('review_source_identity_invalid');
  if(!Array.isArray(record.evidence)||record.evidence.some(e=>!object(e)||!identity(e.id))||new Set(record.evidence.map(e=>e.id)).size!==record.evidence.length||!object(record.truth)||!Array.isArray(record.truth.labels)||!Array.isArray(record.truth.requiredRefs))throw Error('review_source_record_invalid');
  byId.set(record.id,record);
 }return byId;
}
export function exportHumanReviewPacket(records){
 sourceRecords(records);
 return {schemaVersion:1,notice:'Review locally. expectedOutput in each source record is an unreviewed candidate, never approval. Complete each explicit review field; do not edit the source record. Human-reviewed synthetic scenarios may qualify for training; production quality still needs representative independent evaluation.',records:records.map(record=>({record:structuredClone(record),review:{id:record.id,recordHash:recordHash(record),approved:false,reviewerId:null,reviewedAt:null,sourceConsent:false,piiReviewed:false,approvedOutput:null}}))};
}
function reviewRecords(input,sources){
 if(Array.isArray(input))return input;
 if(!object(input)||input.schemaVersion!==1||!Array.isArray(input.records)||Object.keys(input).some(key=>!['schemaVersion','notice','records'].includes(key))||('notice' in input&&typeof input.notice!=='string'))throw Error('review_packet_invalid');
 return input.records.map(entry=>{
  if(!object(entry)||Object.keys(entry).some(key=>!['record','review'].includes(key))||!object(entry.record)||!object(entry.review)||entry.record.id!==entry.review.id)throw Error('review_packet_record_invalid');
  const source=sources.get(entry.record.id);if(!source)throw Error('review_record_missing');
  if(recordHash(entry.record)!==recordHash(source))throw Error('review_record_hash_mismatch');
  return entry.review;
 });
}
export function importHumanReviews(records,input){
 const sources=sourceRecords(records),reviews=reviewRecords(input,sources);
 const byId=new Map();for(const review of reviews){if(!object(review)||!identity(review.id)||byId.has(review.id))throw Error('review_identity_invalid');if(Object.keys(review).some(key=>!['id','recordHash','approved','reviewerId','reviewedAt','sourceConsent','piiReviewed','approvedOutput'].includes(key)))throw Error('review_schema_invalid');if(!sources.has(review.id))throw Error('review_record_missing');byId.set(review.id,review);}
 const result=records.map(record=>{
  const review=byId.get(record.id);if(!review)return structuredClone(record);
  if(review.recordHash!==recordHash(record))throw Error('review_record_hash_mismatch');
  if(review.approved!==true||review.sourceConsent!==true||review.piiReviewed!==true||typeof review.reviewerId!=='string'||!review.reviewerId.trim()||!Number.isFinite(Date.parse(review.reviewedAt))||Date.parse(review.reviewedAt)>Date.now())throw Error('review_incomplete');
  if(!review.approvedOutput||!scoreRoleOutput(record,review.approvedOutput).passed)throw Error('reviewed_output_invalid');
  const imported={...record,humanReviewed:true,reviewStatus:'HUMAN_REVIEWED',reviewerId:review.reviewerId,reviewedAt:review.reviewedAt,sourceConsent:true,piiReviewed:true,approvedOutput:review.approvedOutput,reviewBinding:review.recordHash};return {...imported,reviewedPayloadHash:reviewedPayloadHash(imported)};
 });return result;
}
export function trainingAdmission(records,{roleId='evidence-organizer'}={}){
 const base=evaluateLoraAdmission(records,{roleId}),scoped=records.filter(v=>v.roleId===roleId),reasons=[...base.reasons],fingerprints=new Map(),ids=new Set();
 for(const r of scoped){
  if(ids.has(r.id))reasons.push('duplicate_record_id');ids.add(r.id);
  if(r.humanReviewed!==true||!r.piiReviewed||!r.reviewBinding||!r.approvedOutput||!r.familyId||!r.sourceId||!r.language||!Number.isFinite(Date.parse(r.reviewedAt)))reasons.push('review_provenance_incomplete');
  if(r.humanReviewed===true&&r.reviewedPayloadHash!==reviewedPayloadHash(r))reasons.push('reviewed_payload_changed');
  const key=recordHash({prompt:typeof r.prompt==='string'?r.prompt.normalize('NFKC').replace(/\s+/g,' ').trim().toLowerCase():r.prompt,evidence:r.evidence});if(fingerprints.has(key)&&fingerprints.get(key)!==r.split)reasons.push('duplicate_content_split_leakage');fingerprints.set(key,r.split);
 }
 const unique=[...new Set(reasons)];return {...base,admitted:!unique.length,trainingRunAllowed:!unique.length,reasons:unique,qualityClaimAllowed:false};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const [command,input,output,reviewFile]=process.argv.slice(2);const records=readFileSync(input,'utf8').trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);
 if(command==='gate'){process.stdout.write(JSON.stringify(trainingAdmission(records),null,2)+'\n');process.exitCode=trainingAdmission(records).admitted?0:2;}
 else if(command==='export-review'){writeFileSync(output,JSON.stringify(exportHumanReviewPacket(records),null,2),{flag:'wx'});}
 else if(command==='import-review'){const reviews=JSON.parse(readFileSync(reviewFile,'utf8'));const imported=importHumanReviews(records,reviews);writeFileSync(output,imported.map(r=>JSON.stringify(r)).join('\n')+'\n',{flag:'wx'});process.stdout.write(JSON.stringify(trainingAdmission(imported),null,2)+'\n');}
 else throw Error('usage: model-training-data.mjs gate input | export-review input output | import-review input output reviews.json');
}
