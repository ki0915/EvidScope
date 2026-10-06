import {createHash} from 'node:crypto';
import {scoreResponse} from './score-public-qa-diagnostic.mjs';
import {validateDiagnosticRow} from './public-qa-diagnostic-data.mjs';
import {FRESH_EVALUATION_STAGE} from './prepare-public-qa-fresh-evaluation.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const summary=rows=>({count:rows.length,...Object.fromEntries(['formatValid','exactAnswer','normalizedAnswer','quoteGrounded','abstentionCorrect','passed'].map(key=>[key,{count:rows.filter(row=>row[key]).length,rate:rows.length?rows.filter(row=>row[key]).length/rows.length:null}])),failures:rows.filter(row=>!row.passed).map(row=>({id:row.id,reason:row.failure||[['exactAnswer','exact_answer_mismatch'],['quoteGrounded','ungrounded_quote'],['abstentionCorrect','abstention_mismatch']].filter(([key])=>!row[key]).map(([,reason])=>reason).join('|')}))});

// Supplied outputs can be scored without proving model execution. The separate
// production verifier establishes execution and artifact custody.
export function scoreFreshEvaluation({dataBytes,manifest,responses}){
 if(manifest?.schemaVersion!==1||manifest.stage!==FRESH_EVALUATION_STAGE||manifest.localHumanReviewPerformed!==false||manifest.qualityClaimAllowed!==false||manifest.promotionAllowed!==false||manifest.datasetSha256!==sha(dataBytes))throw Error('fresh_scoring_dataset_invalid');
 const rows=dataBytes.toString('utf8').trim().split(/\r?\n/).map(JSON.parse);rows.forEach(validateDiagnosticRow);
 if(rows.length!==128||new Set(rows.map(row=>row.id)).size!==128||new Set(rows.map(row=>row.familyId)).size!==128||new Set(rows.map(row=>row.contextSha256)).size!==128||rows.filter(row=>row.isImpossible).length!==64||manifest.counts?.total!==128||manifest.counts.answerable!==64||manifest.counts.impossible!==64||JSON.stringify(rows.map(row=>row.id))!==JSON.stringify(manifest.rowIds))throw Error('fresh_scoring_rows_invalid');
 if(responses?.schemaVersion!==1||responses.mode!=='public_qa_fresh_paired_evaluation'||responses.datasetSha256!==manifest.datasetSha256||responses.maxOutputTokens!==128||responses.requestTimeoutSeconds!==120)throw Error('fresh_scoring_measurement_invalid');
 const expected=rows.map(row=>row.id).sort(),scores={};
 for(const side of ['baseline','candidate']){
  const values=responses[side];
  if(!values||Array.isArray(values)||typeof values!=='object'||JSON.stringify(Object.keys(values).sort())!==JSON.stringify(expected))throw Error('fresh_scoring_response_ids_invalid');
  scores[side]=rows.map(row=>({id:row.id,isImpossible:row.isImpossible,...scoreResponse(row,values[row.id],responses)}));
 }
 const gained=[],regressed=[];
 scores.candidate.forEach((row,index)=>{const base=scores.baseline[index];if(row.passed&&!base.passed)gained.push(row.id);if(base.passed&&!row.passed)regressed.push(row.id);});
 return {schemaVersion:1,mode:responses.mode,datasetSha256:manifest.datasetSha256,actualModelExecutionVerified:false,qualityClaimAllowed:false,promotionAllowed:false,localHumanReviewPerformed:false,
  baseline:summary(scores.baseline),candidate:summary(scores.candidate),byAnswerability:Object.fromEntries([false,true].map(impossible=>[impossible?'unanswerable':'answerable',Object.fromEntries(['baseline','candidate'].map(side=>[side,summary(scores[side].filter(row=>row.isImpossible===impossible))]))])),gained,regressed,rows:scores,
  metricsDefinition:{passed:'Exact original human answer and exact context quote containing the answer; impossible requires empty answer/quote and abstained=true. Valid schema, no timeout, output limit or inference error.',normalization:'NFC, trim and Unicode whitespace collapse only.',execution:'Scoring supplied outputs does not establish that a model generated them.',quality:'Public Korean extractive QA is not financial audit or legal sufficiency evaluation.'}};
}
