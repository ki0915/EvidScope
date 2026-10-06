import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {scoreFreshEvaluation} from '../scripts/score-public-qa-fresh.mjs';
import {FRESH_EVALUATION_STAGE} from '../scripts/prepare-public-qa-fresh-evaluation.mjs';
import {REVISION} from '../scripts/public-qa-diagnostic-data.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
function fixture(){
 const rows=Array.from({length:128},(_,i)=>{const context=`서울 문서 ${i}`,question='도시는?',isImpossible=i>=64,answers=isImpossible?[]:[{text:'서울',answer_start:0}];return {id:'id-'+i,familyId:'family-'+i,context,question,contextSha256:sha(context),isImpossible,answers,split:'heldout',upstreamSplit:'dev',upstreamRevision:REVISION,language:'ko',sourceLicense:'CC-BY-SA-4.0',upstreamAnnotation:{kind:'human_authored_question_answer_spans',localHumanReviewPerformed:false},originalQa:{question,answers:structuredClone(answers),is_impossible:isImpossible}};});
 const dataBytes=Buffer.from(rows.map(row=>JSON.stringify(row)).join('\n')+'\n'),manifest={schemaVersion:1,stage:FRESH_EVALUATION_STAGE,localHumanReviewPerformed:false,qualityClaimAllowed:false,promotionAllowed:false,datasetSha256:sha(dataBytes),rowIds:rows.map(row=>row.id),counts:{total:128,answerable:64,impossible:64}};
 const outputs=Object.fromEntries(rows.map(row=>[row.id,{content:JSON.stringify({answer:row.isImpossible?'':'서울',evidenceQuote:row.isImpossible?'':row.context,abstained:row.isImpossible}),inputTokens:30,outputTokens:12,seconds:1,timedOut:false,tokenLimitReached:false}]));
 return {dataBytes,manifest,responses:{schemaVersion:1,mode:'public_qa_fresh_paired_evaluation',datasetSha256:manifest.datasetSha256,maxOutputTokens:128,requestTimeoutSeconds:120,baseline:structuredClone(outputs),candidate:structuredClone(outputs)}};
}
test('paired fresh scores retain human spans and class counts without asserting execution or promotion',()=>{
 const value=fixture();value.responses.baseline['id-0'].content='malformed';value.responses.candidate['id-1'].content='malformed';const result=scoreFreshEvaluation(value);
 assert.equal(result.baseline.passed.count,127);assert.equal(result.candidate.passed.count,127);assert.equal(result.byAnswerability.answerable.candidate.count,64);assert.deepEqual(result.gained,['id-0']);assert.deepEqual(result.regressed,['id-1']);assert.equal(result.actualModelExecutionVerified,false);assert.equal(result.qualityClaimAllowed,false);assert.equal(result.promotionAllowed,false);
});
test('missing, foreign and substituted fresh results cannot silently reduce the denominator',()=>{
 for(const mutate of [value=>delete value.responses.candidate['id-0'],value=>value.responses.baseline.foreign=value.responses.baseline['id-0'],value=>value.responses.datasetSha256='0'.repeat(64),value=>value.manifest.rowIds.reverse()]){const value=fixture();mutate(value);assert.throws(()=>scoreFreshEvaluation(value),/fresh_scoring_/);}
});
test('unsupported answers, absent exact quotes, unsafe abstention and resource failures count as failures',()=>{
 const value=fixture();value.responses.candidate['id-0'].content=JSON.stringify({answer:'부산',evidenceQuote:'부산',abstained:false});value.responses.candidate['id-1'].content=JSON.stringify({answer:'서울',evidenceQuote:'',abstained:false});value.responses.candidate['id-64'].content=JSON.stringify({answer:'서울',evidenceQuote:'서울',abstained:false});value.responses.candidate['id-2'].timedOut=true;const result=scoreFreshEvaluation(value);assert.equal(result.candidate.passed.count,124);assert.equal(result.byAnswerability.unanswerable.candidate.passed.count,63);assert.equal(result.rows.candidate[2].failure,'timeout');assert.equal(result.candidate.failures.length,4);assert.match(result.candidate.failures.find(row=>row.id==='id-0').reason,/exact_answer_mismatch.*ungrounded_quote/);assert.equal(result.candidate.failures.find(row=>row.id==='id-1').reason,'ungrounded_quote');assert.match(result.candidate.failures.find(row=>row.id==='id-64').reason,/abstention_mismatch/);
});
