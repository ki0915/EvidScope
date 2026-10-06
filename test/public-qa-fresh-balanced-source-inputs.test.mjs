import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {BALANCED_FRESH_RUN_ID,verifyFrozenFreshEvaluation} from '../scripts/public-qa-fresh-workload.mjs';
import {scoreFreshEvaluation} from '../scripts/score-public-qa-fresh.mjs';

// Actual source experiment proof requires unshipped .local inputs.
// Keep portable guards in public-qa-fresh-balanced.test.mjs.
test('actual frozen r2 blind is independently excluded and scoring cannot import old fresh results',()=>{
 const frozen=verifyFrozenFreshEvaluation({runId:BALANCED_FRESH_RUN_ID}),dataBytes=readFileSync(frozen.data),manifest=JSON.parse(readFileSync(frozen.manifest)),rows=dataBytes.toString().trim().split(/\r?\n/).map(JSON.parse),side=Object.fromEntries(rows.map(row=>[row.id,{content:'{"answer":"","evidenceQuote":"","abstained":true}',seconds:1,outputTokens:12,timedOut:false,tokenLimitReached:false}])),responses={schemaVersion:1,mode:'public_qa_fresh_paired_evaluation',datasetSha256:frozen.datasetSha256,maxOutputTokens:128,requestTimeoutSeconds:120,baseline:side,candidate:side};
 const score=scoreFreshEvaluation({dataBytes,manifest,responses});assert.equal(score.actualModelExecutionVerified,false);assert.equal(score.baseline.count,128);assert.equal(score.candidate.count,128);assert.throws(()=>scoreFreshEvaluation({dataBytes,manifest,responses:{...responses,datasetSha256:'dc8a7bb0c9eb9de9abbc6f3cea39851453db8c60cc91602223f3a9aaeb628142'}}));assert.throws(()=>scoreFreshEvaluation({dataBytes,manifest:{...manifest,plannedTrainingRunId:'public-qa-balanced-20261006-r1'},responses}));
});
