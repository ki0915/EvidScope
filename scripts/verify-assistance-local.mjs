import {harness} from '../test/harness.mjs';
import {submit} from '../src/client.mjs';
import {loadModelTlsConfig} from '../src/isolated-inference-client.mjs';
import {readIsolatedRuntimeConfig,runIsolatedAssistance} from '../src/isolated-session.mjs';
import {primaryModelPolicy} from '../src/model-policy.mjs';

const args=process.argv.slice(2);
const value=name=>{const index=args.indexOf(name);if(index<0||!args[index+1])throw Error(`Missing ${name}`);return args[index+1];};
if(!args.includes('--execute-isolated-model'))throw Error('Explicit --execute-isolated-model is required before any fixture or model starts');
const tlsConfigPath=value('--tls-config'),runtimeConfigPath=value('--runtime-config');

// Validate every launch gate before starting even the synthetic local API fixture.
readIsolatedRuntimeConfig(runtimeConfigPath,{modelId:'foundation-sec'});
loadModelTlsConfig(tlsConfigPath);

const h=await harness({vaultOnly:true});
try{
 const actionId=`actual-isolated-assistance-${Date.now()}`,common={actionId,traceId:actionId,occurredAt:new Date().toISOString(),actor:'local-verification',tool:'fixed-fixture-reader',action:'read',resource:'synthetic-record'};
 for(const [source,event] of [['agent',{id:`${actionId}-intent`,kind:'intent',status:'started'}],['tool',{id:`${actionId}-result`,kind:'result',status:'success'}]]){const response=await submit(h.vault.url,h.principal(source),{...common,...event});if(response.status!==202)throw Error(`Fixture ingest failed: ${response.status}`);}
 await h.analyze();
 const created=await h.api('/api/cases',{body:{title:'Isolated assistance verification with synthetic metadata',actionId,owner:'local-reviewer'}});if(created.status!==200)throw Error('Case creation failed');
 const context=await h.api(`/api/cases/${created.body.id}/review-context`),ref=`${h.principal('tool').id}/${actionId}-result`;
 const prepared=await h.api('/api/assistance/packages',{body:{caseId:created.body.id,contextHash:context.body.contextHash,profileId:'evidence-organizer',profileVersion:2,selectedEvidenceRefs:[ref]}});
 const dispatched=await h.api(`/api/assistance/packages/${prepared.body.id}/dispatch`,{body:{contextHash:context.body.contextHash}});if(dispatched.status!==200)throw Error('Dispatch failed');
 const receipts=[];await runIsolatedAssistance({credential:dispatched.body.credential,baseUrl:h.vault.url,tlsConfigPath,runtimeConfigPath,onReceipt:r=>receipts.push(r)});
 const detail=await h.api(`/api/assistance/runs/${dispatched.body.run.id}`),finalReceipt=receipts.at(-1);
 if(detail.status!==200||detail.body.state!=='completed'||detail.body.providerReportedModel!==primaryModelPolicy().model||!detail.body.draft?.findings?.length||finalReceipt?.terminationConfirmed!==true)throw Error(`Unexpected isolated run result: ${JSON.stringify({status:detail.status,state:detail.body.state,providerReportedModel:detail.body.providerReportedModel,errorCode:detail.body.errorCode,terminationConfirmed:finalReceipt?.terminationConfirmed===true})}`);
 const reviewed=await h.api(`/api/assistance/runs/${detail.body.id}/review`,{body:{action:'accept',contextHash:context.body.contextHash,reason:'Local verification accepted this output only as an advisory draft.'}}),caseContext=await h.api(`/api/cases/${created.body.id}/review-context`);
 if(reviewed.status!==200||reviewed.body.boundary!=='advisory_review_only_not_case_decision_or_compliance_approval'||caseContext.body.decisions.length!==0)throw Error('Advisory human review boundary verification failed');
 process.stdout.write(JSON.stringify({actualModelRun:true,runId:detail.body.id,state:detail.body.state,configuredModel:detail.body.modelPolicy.model,providerReportedModel:detail.body.providerReportedModel,modelDigest:detail.body.providerReport.modelDigest,quantizationLevel:detail.body.providerReport.quantizationLevel,inputTokens:detail.body.providerReport.inputTokens,outputTokens:detail.body.providerReport.outputTokens,totalDurationNs:detail.body.providerReport.totalDurationNs,responsesUsed:detail.body.responsesUsed,findingCount:detail.body.draft.findings.length,terminationConfirmed:true,advisoryReview:reviewed.body.action,caseDecisionCount:caseContext.body.decisions.length,credentialPrinted:false})+'\n');
}finally{await h.close();}
