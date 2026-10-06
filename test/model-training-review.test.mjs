import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync,rmSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {exportHumanReviewPacket,importHumanReviews,recordHash,reviewedPayloadHash,trainingAdmission} from '../scripts/model-training-data.mjs';

const sample=()=>JSON.parse(readFileSync('data/multilingual-evals/evidence-organizer/v1/candidates.jsonl','utf8').split(/\r?\n/)[0]);
// Synthetic test-only approvals exercise the importer; no repository data is reviewed.
const approved=record=>({id:record.id,recordHash:recordHash(record),approved:true,reviewerId:'test-only-reviewer',reviewedAt:'2026-01-01T00:00:00Z',sourceConsent:true,piiReviewed:true,approvedOutput:structuredClone(record.expectedOutput)});

test('export retains candidate output separately and cannot itself approve training data',()=>{
 const record=sample(),before=structuredClone(record),packet=exportHumanReviewPacket([record]);
 assert.deepEqual(packet.records[0].record.expectedOutput,record.expectedOutput);
 assert.equal(packet.records[0].review.approved,false);assert.equal(packet.records[0].review.approvedOutput,null);
 assert.equal(packet.records[0].review.recordHash,recordHash(record));
 assert.throws(()=>importHumanReviews([record],packet),/review_incomplete/);
 assert.deepEqual(record,before);assert.equal(trainingAdmission([record]).trainingRunAllowed,false);
});

test('completed exported packets and deliberate raw review arrays have identical bound imports',()=>{
 const record=sample(),packet=exportHumanReviewPacket([record]);packet.records[0].review=approved(record);
 const imported=importHumanReviews([record],packet);
 assert.deepEqual(imported,importHumanReviews([record],[approved(record)]));
 assert.equal(imported[0].reviewBinding,recordHash(record));assert.equal(imported[0].reviewedPayloadHash,reviewedPayloadHash(imported[0]));
 assert.equal(imported[0].humanReviewed,true);assert.equal(record.humanReviewed,false);
 assert.equal(trainingAdmission(imported).trainingRunAllowed,false);
});

test('source mutations, wrapper mismatch, missing source and duplicate identities fail closed',()=>{
 const record=sample(),packet=exportHumanReviewPacket([record]);packet.records[0].review=approved(record);
 const changed=structuredClone(packet);changed.records[0].record.prompt='Edited after export';
 assert.throws(()=>importHumanReviews([record],changed),/review_record_hash_mismatch/);
 const wrongReview=structuredClone(packet);wrongReview.records[0].review.recordHash='0'.repeat(64);
 assert.throws(()=>importHumanReviews([record],wrongReview),/review_record_hash_mismatch/);
 const mismatch=structuredClone(packet);mismatch.records[0].review.id='other';
 assert.throws(()=>importHumanReviews([record],mismatch),/review_packet_record_invalid/);
 const duplicate=structuredClone(packet);duplicate.records.push(structuredClone(duplicate.records[0]));
 assert.throws(()=>importHumanReviews([record],duplicate),/review_identity_invalid/);
 assert.throws(()=>importHumanReviews([record],[approved(record),approved(record)]),/review_identity_invalid/);
 assert.throws(()=>importHumanReviews([record],[{...approved(record),id:'missing'}]),/review_record_missing/);
 assert.throws(()=>exportHumanReviewPacket([record,record]),/review_source_identity_invalid/);
 assert.throws(()=>importHumanReviews([record,record],[]),/review_source_identity_invalid/);
});

test('malformed packet and review schemas, incomplete or unsafe approvals are rejected',()=>{
 const record=sample();
 for(const input of [null,{},'reviews',{schemaVersion:2,records:[]},{schemaVersion:1,records:{}},{schemaVersion:1,records:[null]},{schemaVersion:1,records:[],approved:true}])assert.throws(()=>importHumanReviews([record],input),/review_packet/);
 assert.throws(()=>importHumanReviews([record],[{...approved(record),autoApprove:true}]),/review_schema_invalid/);
 assert.throws(()=>exportHumanReviewPacket([{...record,evidence:null}]),/review_source_record_invalid/);
 for(const change of [{approved:false},{sourceConsent:false},{piiReviewed:false},{reviewerId:' '},{reviewedAt:'invalid'},{reviewedAt:'2999-01-01T00:00:00Z'}])assert.throws(()=>importHumanReviews([record],[{...approved(record),...change}]),/review_incomplete/);
 const unsafe=approved(record);unsafe.approvedOutput.findings[0].evidenceRefs=['other-tenant-secret'];
 assert.throws(()=>importHumanReviews([record],[unsafe]),/reviewed_output_invalid/);
});

test('CLI exported packet imports after explicit test approval; unapproved packet writes no output',()=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-review-test-'));
 try{
  const record=sample(),source=join(dir,'source.jsonl'),packetFile=join(dir,'review.json'),output=join(dir,'imported.jsonl');
  writeFileSync(source,JSON.stringify(record)+'\n');
  const cli=args=>spawnSync(process.execPath,['scripts/model-training-data.mjs',...args],{encoding:'utf8',timeout:10000,windowsHide:true});
  const exported=cli(['export-review',source,packetFile]);assert.equal(exported.status,0,exported.stderr);
  const blocked=cli(['import-review',source,output,packetFile]);assert.notEqual(blocked.status,0);assert.match(blocked.stderr,/review_incomplete/);assert.equal(existsSync(output),false);
  const packet=JSON.parse(readFileSync(packetFile,'utf8'));packet.records[0].review=approved(record);writeFileSync(packetFile,JSON.stringify(packet));
  const result=cli(['import-review',source,output,packetFile]);assert.equal(result.status,0,result.stderr);
  const imported=JSON.parse(readFileSync(output,'utf8'));assert.equal(imported.reviewBinding,recordHash(record));assert.equal(JSON.parse(result.stdout).trainingRunAllowed,false);
  assert.equal(JSON.parse(readFileSync(source,'utf8')).humanReviewed,false);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
