import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {buildMultilingualCandidates,writeMultilingualCandidates,AUDIT_SCENARIOS} from '../scripts/generate-multilingual-evals.mjs';
import {trainingAdmission} from '../scripts/model-training-data.mjs';
import {scoreRoleOutput} from '../src/role-evaluation.mjs';
import {PRIVACY_CATEGORIES} from '../src/content-screening.mjs';

test('candidate pool has deterministic unique rows and keeps every translation family in one split',()=>{
 const first=buildMultilingualCandidates(),second=buildMultilingualCandidates();assert.deepEqual(first,second);
 assert.equal(first.audit.length,540);assert.equal(first.privacy.length,180);assert.equal(new Set([...first.audit,...first.privacy].map(row=>row.id)).size,720);
 assert.deepEqual(Object.fromEntries(['tune','validation','test'].map(split=>[split,first.audit.filter(row=>row.split===split).length])),{tune:300,validation:60,test:180});
 const families=new Map();for(const row of [...first.audit,...first.privacy]){if(!families.has(row.familyId))families.set(row.familyId,[]);families.get(row.familyId).push(row);}
 assert.equal(families.size,240);for(const rows of families.values()){assert.equal(rows.length,3);assert.equal(new Set(rows.map(row=>row.split)).size,1);assert.equal(new Set(rows.map(row=>row.familyContentHash)).size,1);assert.deepEqual(new Set(rows.map(row=>row.language)),new Set(['en','ko','mixed']));if(rows[0].evidence)for(const row of rows)assert.deepEqual(row.evidence.map(item=>item.id),rows[0].evidence.map(item=>item.id));}
 const contents=new Map();for(const row of first.audit){const content=JSON.stringify({prompt:row.prompt,evidence:row.evidence});assert.ok(!contents.has(content));contents.set(content,row.split);}
});

test('eight audit scenarios have coherent advisory schemas and citations, without claiming candidate correctness',()=>{
 const {audit}=buildMultilingualCandidates();assert.deepEqual(new Set(audit.map(row=>row.scenario)),new Set(AUDIT_SCENARIOS));
 for(const row of audit){
  assert.deepEqual(Object.keys(row.expectedOutput),['summary','findings','uncertainties','limitations','recommendedFollowUps','abstained']);
  assert.equal(scoreRoleOutput(row,row.expectedOutput).passed,true,`template consistency only: ${row.id}`);
  assert.ok(row.expectedOutput.summary.length>0);assert.equal(typeof row.expectedOutput.abstained,'boolean');
  for(const finding of row.expectedOutput.findings){assert.deepEqual(Object.keys(finding),['claim','evidenceRefs','relation','confidence']);assert.ok(['supports','contradicts','context_only'].includes(finding.relation));assert.ok(['low','medium','high'].includes(finding.confidence));for(const ref of finding.evidenceRefs)assert.ok(row.evidence.some(item=>item.id===ref));}
  assert.ok(row.evidence.every(item=>/^[a-z0-9-]+$/.test(item.id)));if(row.language!=='en')assert.match(row.prompt,/\p{Script=Hangul}/u);
 }
 assert.ok(audit.some(row=>row.expectedOutput.abstained));assert.ok(audit.some(row=>!row.expectedOutput.abstained));
});

test('all candidates remain unreviewed, have no approved output, and admission stays blocked',()=>{
 const {audit,privacy,manifest}=buildMultilingualCandidates();
 for(const row of [...audit,...privacy]){assert.equal(row.synthetic,true);assert.equal(row.humanReviewed,false);assert.equal(row.reviewStatus,'UNREVIEWED');assert.equal(row.reviewerId,null);assert.equal(row.reviewedAt,null);assert.equal(row.piiReviewed,false);assert.equal(row.sourceConsent,true);assert.equal(Object.hasOwn(row,'approvedOutput'),false);assert.equal(Object.hasOwn(row,'reviewBinding'),false);}
 const admission=trainingAdmission(audit);assert.equal(admission.admitted,false);assert.equal(admission.trainingRunAllowed,false);assert.deepEqual(admission.counts,{tune:0,validation:0,test:0});assert.ok(admission.reasons.includes('review_provenance_incomplete'));
 assert.equal(manifest.qualityClaimAllowed,false);assert.equal(manifest.trainingRunAllowed,false);assert.match(manifest.limitations.join(' '),/not establish independent/);
});

test('Cipher triads cover twelve categories, false positives, ambiguous instructions and full long tails',()=>{
 const {privacy}=buildMultilingualCandidates();assert.deepEqual(new Set(privacy.filter(row=>row.expectedPrivacy.category).map(row=>row.expectedPrivacy.category)),new Set(PRIVACY_CATEGORIES));
 assert.deepEqual(new Set(privacy.map(row=>row.scenario)),new Set(['sensitive_candidate','keyword_only','masked_value','long_tail','ambiguous_keyword','injected_instruction']));
 for(const row of privacy){assert.equal(Object.hasOwn(row,'truth'),false);assert.equal(row.labelStatus,'CANDIDATE_REQUIRES_POLICY_REVIEW');assert.ok(['safe','unsafe','controversial'].includes(row.expectedPrivacy.safety));assert.equal(row.expectedScreening.mustNotSilentlyTruncate,true);assert.equal(row.expectedScreening.allowUnknownWhenCoverageIncomplete,true);if(row.scenario==='long_tail'){assert.ok(row.text.length>4000);assert.equal(row.expectedPrivacy.safety,'unsafe');}if(row.scenario==='masked_value'){assert.match(row.text,/\[MASKED\]/);assert.equal(row.expectedPrivacy.safety,'safe');}}
});

test('writer produces reproducible artifacts and refuses to overwrite human-reviewed work',()=>{
 mkdirSync('.test-runs',{recursive:true});const root=mkdtempSync(resolve('.test-runs/multilingual-evals-')),report=writeMultilingualCandidates(root);assert.equal(report.auditRows,540);assert.equal(report.cipherRows,180);
 const path=join(root,'evidence-organizer','v1','candidates.jsonl'),before=readFileSync(path,'utf8');assert.deepEqual(writeMultilingualCandidates(root),report);assert.equal(readFileSync(path,'utf8'),before);
 const rows=before.trim().split('\n').map(JSON.parse);rows[0].humanReviewed=true;writeFileSync(path,rows.map(row=>JSON.stringify(row)).join('\n')+'\n');assert.throws(()=>writeMultilingualCandidates(root),/reviewed_candidates_must_not_be_overwritten/);assert.equal(JSON.parse(readFileSync(path,'utf8').split('\n')[0]).humanReviewed,true);
});
