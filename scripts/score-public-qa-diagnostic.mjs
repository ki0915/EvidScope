import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {sha,validateDiagnosticRow,PINS} from './public-qa-diagnostic-data.mjs';

export const normalizeAnswer=value=>value.normalize('NFC').trim().replace(/\s+/gu,' ');
const fail=reason=>({formatValid:false,exactAnswer:false,normalizedAnswer:false,quoteGrounded:false,abstentionCorrect:false,passed:false,failure:reason});
export function scoreResponse(row,response,{maxOutputTokens,requestTimeoutSeconds}){
 validateDiagnosticRow(row);
 if(!response)return fail('missing_output');
 if(typeof response.content!=='string'||response.content.length>1000000||typeof response.timedOut!=='boolean'||typeof response.tokenLimitReached!=='boolean'||!Number.isFinite(response.seconds)||response.seconds<0||!Number.isSafeInteger(response.inputTokens)||response.inputTokens<1||!Number.isSafeInteger(response.outputTokens)||response.outputTokens<0)return fail('invalid_measurement');
 if(response.error)return fail('inference_error');
 if(response.timedOut||response.seconds>=requestTimeoutSeconds)return fail('timeout');
 if(response.tokenLimitReached||response.outputTokens>=maxOutputTokens)return fail('output_token_limit');
 let body=response.content.trim();const ends=body.split('</think>');if(ends.length===2)body=ends[1].trim();else if(ends.length>2)return fail('malformed_output');
 let value;try{value=JSON.parse(body);}catch{return fail('malformed_output');}
 if(!value||Array.isArray(value)||Object.keys(value).sort().join(',')!=='abstained,answer,evidenceQuote'||typeof value.answer!=='string'||typeof value.evidenceQuote!=='string'||typeof value.abstained!=='boolean')return fail('invalid_output_schema');
 const correct=row.isImpossible?value.answer===''&&value.evidenceQuote===''&&value.abstained:!value.abstained;
 const exact=row.isImpossible?correct:!value.abstained&&row.answers.some(a=>a.text===value.answer);
 const normalized=row.isImpossible?correct:!value.abstained&&normalizeAnswer(value.answer)!==''&&row.answers.some(a=>normalizeAnswer(a.text)===normalizeAnswer(value.answer));
 const quote=row.isImpossible?correct:!value.abstained&&value.answer.length>0&&value.evidenceQuote.length>0&&row.context.includes(value.evidenceQuote)&&value.evidenceQuote.includes(value.answer);
 return {formatValid:true,exactAnswer:exact,normalizedAnswer:normalized,quoteGrounded:quote,abstentionCorrect:correct,passed:exact&&quote&&correct,failure:null};
}

export function scoreDiagnostic({dataBytes,manifest,responses}){
 if(manifest?.schemaVersion!==1||manifest.mode!=='public_qa_diagnostic'||manifest.diagnosticOnly!==true||manifest.localHumanReviewPerformed!==false||manifest.qualityClaimAllowed!==false||manifest.promotionAllowed!==false||manifest.sourcePins?.heldout!==PINS.heldout||manifest.datasetSha256!==sha(dataBytes))throw Error('diagnostic_dataset_binding_invalid');
 const rows=dataBytes.toString('utf8').trim().split(/\r?\n/).map(JSON.parse);rows.forEach(validateDiagnosticRow);
 if(new Set(rows.map(r=>r.id)).size!==rows.length||JSON.stringify(rows.map(r=>r.id))!==JSON.stringify(manifest.rowIds)||rows.length!==manifest.counts.total)throw Error('diagnostic_rows_invalid');
 if(responses?.schemaVersion!==1||responses.mode!=='public_qa_diagnostic'||responses.datasetSha256!==manifest.datasetSha256||!Number.isSafeInteger(responses.maxOutputTokens)||responses.maxOutputTokens<1||!Number.isFinite(responses.requestTimeoutSeconds)||responses.requestTimeoutSeconds<=0)throw Error('diagnostic_measurement_binding_invalid');
 const ids=new Set(rows.map(r=>r.id)),scores={};
 for(const side of ['baseline','candidate']){const outputs=responses[side];if(!outputs||typeof outputs!=='object'||Array.isArray(outputs)||Object.keys(outputs).some(id=>!ids.has(id)))throw Error('unexpected_response_ids');scores[side]=rows.map(row=>({id:row.id,isImpossible:row.isImpossible,...scoreResponse(row,outputs[row.id],responses)}));}
 const summary=values=>({count:values.length,...Object.fromEntries(['formatValid','exactAnswer','normalizedAnswer','quoteGrounded','abstentionCorrect','passed'].map(key=>[key,{count:values.filter(v=>v[key]).length,rate:values.length?values.filter(v=>v[key]).length/values.length:null}])),failures:values.filter(v=>v.failure).map(v=>({id:v.id,reason:v.failure}))});
 return {schemaVersion:1,mode:'public_qa_diagnostic',datasetSha256:manifest.datasetSha256,diagnosticOnly:true,actualModelExecutionVerified:false,controllerExecutionVerified:false,qualityClaimAllowed:false,promotionAllowed:false,localHumanReviewPerformed:false,metricsDefinition:{exactAnswer:'Any original human answer span, exact Unicode string; impossible requires empty answer and quote and abstained=true.',normalizedAnswer:'NFC, trim and collapse Unicode whitespace only; no punctuation deletion or lowercasing.',quoteGrounded:'Exact quote substring of full original context containing the nonempty exact returned answer; impossible requires empty fields.',passed:'Exact answer AND grounded quote AND correct abstention, with valid schema and no timeout/token limit/inference failure.',execution:'This scorer checks supplied outputs and metadata only; it does not prove they came from a model.'},baseline:summary(scores.baseline),candidate:summary(scores.candidate),byAnswerability:Object.fromEntries([false,true].map(impossible=>[impossible?'unanswerable':'answerable',Object.fromEntries(['baseline','candidate'].map(side=>[side,summary(scores[side].filter(v=>v.isImpossible===impossible))]))])),rows:scores};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const [data,manifest,responses,out]=process.argv.slice(2);if(!out)throw Error('usage: score-public-qa-diagnostic DATA MANIFEST RESPONSES OUTPUT');const result=scoreDiagnostic({dataBytes:readFileSync(data),manifest:JSON.parse(readFileSync(manifest)),responses:JSON.parse(readFileSync(responses))});writeFileSync(out,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({count:result.candidate.count,promotionAllowed:false,actualModelExecutionVerified:false}));}
