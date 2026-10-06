import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync,unlinkSync} from 'node:fs';
import {dirname,join,relative,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonical,digest} from '../src/crypto.mjs';
import {verifyFinanceReport} from '../src/report-verifier.mjs';
import {initialize} from './init.mjs';
import {createLocalRuntime} from './local.mjs';

const repository=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
export const FINANCE_WORKFLOW_FIXTURE=Object.freeze({
 schemaVersion:1,clock:'synthetic_epoch_plus_fixed_offsets',features:{incomeUnits:35,arrears:0},
 cases:[
  {id:'model-version-mismatch',scenario:'model-version-mismatch',modelVersion:'v2'},
  {id:'revoked-before-execution',scenario:'revoked'},
  {id:'block-business-success',scenario:'block-success'},
  {id:'automatic-no-approval',scenario:'automatic'},
  {id:'delayed-earlier-approval',scenario:'delayed-approval'},
  {id:'missing-execution-document',scenario:'missing-evidence'}
 ],
 negatives:[
  {id:'authentication-failure',scenario:'authentication-failure'},
  {id:'wrong-attempt-approval',scenario:'wrong-attempt'},
  {id:'wrong-model-evidence',scenario:'wrong-model'},
  {id:'foreign-tenant-result',scenario:'foreign-tenant'}
 ]
});
const sourceFiles=[
 'scripts/finance-workflow-pilot.mjs','scripts/finance-workflow-producer.mjs','scripts/local.mjs','scripts/init.mjs',
 'src/client.mjs','src/server.mjs','src/finance-evidence.mjs','src/model.mjs','src/worker.mjs','src/store.mjs',
 'src/crypto.mjs','src/report-verifier.mjs','src/service.mjs','src/governance-policy.mjs','data/requirements.json'
];
const exitSeen=child=>child.exitCode!==null||child.signalCode!==null;
async function exitWithin(child,timeoutMs){
 if(exitSeen(child))return true;
 return new Promise(resolve=>{const done=value=>{clearTimeout(timer);child.removeListener('exit',onExit);resolve(value);},onExit=()=>done(true),timer=setTimeout(()=>done(false),timeoutMs);child.once('exit',onExit);});
}
function producer(role,list){
 const child=fork(new URL('./finance-workflow-producer.mjs',import.meta.url),[],{
  cwd:repository,execArgv:[],stdio:['ignore','ignore','pipe','ipc'],
  env:Object.fromEntries(['PATH','Path','SystemRoot','WINDIR','TEMP','TMP'].filter(key=>process.env[key]!==undefined).map(key=>[key,process.env[key]]))
 });
 const entry={child,role,sourceIds:[],stderr:'',pending:new Map(),count:0,terminationConfirmed:false};list.push(entry);
 child.stderr.on('data',chunk=>{entry.stderr=(entry.stderr+chunk.toString()).slice(-8192);});
 const rejectAll=error=>{for(const item of entry.pending.values()){clearTimeout(item.timer);item.reject(error);}entry.pending.clear();};
 child.once('error',error=>rejectAll(Error(`Producer ${role} failed: ${error.code||error.name}`)));
 child.once('exit',(code,signal)=>{entry.exitCode=code;entry.signalCode=signal;entry.terminationConfirmed=true;rejectAll(Error(`Producer ${role} exited: ${signal||code}`));});
 child.on('message',message=>{
  const item=entry.pending.get(message?.rpcId);if(!item)return;entry.pending.delete(message.rpcId);clearTimeout(item.timer);
  if(message.ok)item.resolve(message.result);else item.reject(Error(`Producer ${role}: ${message.error?.message||'operation failed'} (${message.error?.code||message.error?.name||'unknown'})`));
 });
 entry.call=(operation,payload={})=>new Promise((resolve,reject)=>{
  if(exitSeen(child)||!child.connected)return reject(Error(`Producer ${role} unavailable`));
  const rpcId=`${role}-${++entry.count}`,timer=setTimeout(()=>{entry.pending.delete(rpcId);reject(Error(`Producer ${role} ${operation} timed out`));},20000);
  entry.pending.set(rpcId,{resolve,reject,timer});child.send({rpcId,operation,payload},error=>{if(error){const item=entry.pending.get(rpcId);if(item){entry.pending.delete(rpcId);clearTimeout(item.timer);item.reject(Error(`Producer ${role} IPC failed: ${error.code||error.name}`));}}});
 });
 return entry;
}
const principal=(id,tenant,kind)=>({id,tenant,role:'source',kind,token:randomBytes(32).toString('base64url'),hmacSecret:randomBytes(32).toString('base64url')});
function normalizedCase(result,epoch){
 return {
  id:result.id,passed:result.passed,codes:result.codes,issues:result.issues,checks:result.checks,operationalStatus:result.operationalStatus,
  findings:result.findings.map(finding=>({code:finding.code,severity:finding.severity,evidence:[...finding.evidence].sort()})).sort((a,b)=>canonical(a).localeCompare(canonical(b))),
  evidence:result.events.map(event=>({ref:event.ref,tenant:event.tenant,kind:event.kind,status:event.status||null,actionId:event.actionId,requestId:event.requestId,attemptId:event.attemptId,modelId:event.modelId,modelVersion:event.modelVersion,occurredOffsetMs:Date.parse(event.occurredAt)-epoch,late:event.late})).sort((a,b)=>a.ref.localeCompare(b.ref)),
  businessStateSha256:result.businessStateSha256,aiStateSha256:result.aiStateSha256,approvalStateSha256:result.approvalStateSha256,
  submissionStatuses:result.submissions.map(item=>({ref:item.ref,status:item.status,accepted:item.accepted})).sort((a,b)=>a.ref.localeCompare(b.ref)),
  foreignEvents:result.foreignEvents||[]
 };
}

/** Actual loopback HTTP pilot; no models, production config, or sealed files touched. */
export async function runFinanceWorkflowPilot({outputPath=null,expectedFixtureHash,host=process.env.EVIDSCOPE_TEST_HOST||'::1',createRuntime=createLocalRuntime}={}){
 const fixture=structuredClone(FINANCE_WORKFLOW_FIXTURE),fixtureSha256=digest(fixture);
 if(expectedFixtureHash!==undefined)assert.equal(fixtureSha256,expectedFixtureHash,'Pinned fixture hash mismatch');
 assert.ok(['127.0.0.1','::1'].includes(host),'Numeric loopback host required');
 if(outputPath){const target=resolve(outputPath),part=relative(repository,target);assert.ok(part&&!part.startsWith('..')&&!/^[A-Za-z]:/.test(part),'Output must be a new workspace file');outputPath=target;}
 const scratch=join(repository,'.test-runs');mkdirSync(scratch,{recursive:true});const directory=mkdtempSync(join(scratch,'finance-workflow-'));
 const config=initialize(directory),aiPrincipal=principal('workflow-ai','alpha','tool'),businessPrincipal=principal('workflow-business','alpha','tool');
 config.principals.push(aiPrincipal,businessPrincipal);
 // This is a newly initialized fixture configuration, never an existing live file.
 writeFileSync(join(directory,'config.json'),JSON.stringify(config,null,2),{mode:0o600});
 const getPrincipal=(role,tenant='alpha')=>config.principals.find(p=>p.tenant===tenant&&(p.role===role||p.kind===role));
 const trustedPublicKey=readFileSync(join(directory,'trust-anchor.pem'),'utf8'),clockEpochMs=Date.now()-60000;
 const producers=[],runtime=createRuntime({host,portBase:0,directory}),sourceSha256=Object.fromEntries(sourceFiles.map(path=>[path,sha(readFileSync(join(repository,path)))]));
 let ready,failure,cleanupFailure;
 const receipt={schemaVersion:1,createdAt:new Date().toISOString(),passed:false,fixtureSha256,normalizedSha256:null,sourceSha256,fixture,artifactDirectory:directory,transport:'three stateful synthetic child producers directly submit HMAC-authenticated events over HTTP to separate local services',synthetic:true,liveFinancialIntegration:false,modelCalls:0,humanReviewPerformed:false,automaticLegalVerdict:false,competitiveSuperiorityProven:false,clock:{kind:'injected_synthetic_epoch',epoch: new Date(clockEpochMs).toISOString(),approvalDelay:'earlier synthetic occurrence; actual HTTP approval delivery follows AI execution receipt'},cases:[],negatives:[],producers:[],lifecycle:{serverTerminationConfirmed:false},limitations:['결정적인 합성 처리와 프로세스별 상태의 실증이며 실제 금융사·LLM·AGT 운영 연동이 아닙니다.','같은 OS 사용자 계정의 프로세스 분리는 별도 호스트·관리자 간 신뢰 격리를 입증하지 않습니다.','지연 승인의 과거 발생 시각은 합성 clock 주입입니다. 실제 수신 순서와 발생 시각을 구별합니다.','차단 등록은 합성 제어 보고이며 실제 게이트웨이의 강제 차단을 구현하지 않습니다.','서명·수집 인증은 출처 주장의 진실성이나 법률 충분성을 보증하지 않습니다.']};
 try{
  ready=await runtime.start();receipt.endpoints={...ready.endpoints};receipt.lifecycle.serverPids=[...ready.childPids];
  const api=async(path,{body,tenant='alpha',role='reviewer',expectedStatus=200}={})=>{
   if(runtime.failure)throw runtime.failure;
   const response=await fetch(ready.endpoints.audit+path,{method:body===undefined?'GET':'POST',headers:{'content-type':'application/json',authorization:`Bearer ${getPrincipal(role,tenant).token}`},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(15000),redirect:'error'});
   const result=await response.json();assert.equal(response.status,expectedStatus,`${role}/${tenant} ${path}: HTTP ${response.status}`);return {status:response.status,body:result};
  };
  const authority=producer('approval',producers),ai=producer('ai',producers),business=producer('business',producers);
  const credentials={approval:{authority:getPrincipal('authority'),safety:getPrincipal('safety')},ai:{tool:aiPrincipal},business:{tool:businessPrincipal,foreignTool:getPrincipal('tool','beta')}};
  for(const entry of producers){const response=await entry.call('initialize',{role:entry.role,principals:credentials[entry.role],ingress:ready.endpoints.ingress,clockEpochMs});assert.equal(response.pid,entry.child.pid);entry.sourceIds=response.sourceIds;}
  assert.equal(new Set(producers.map(entry=>entry.child.pid)).size,3);assert.notEqual(aiPrincipal.id,businessPrincipal.id);
  for(const spec of [...fixture.cases,...fixture.negatives]){
   const request={caseId:spec.id,scenario:spec.scenario,systemId:`credit-${spec.id}`,actionId:`action-${spec.id}`,traceId:`trace-${spec.id}`,requestId:`request-${spec.id}`,attemptId:'attempt-1',modelId:'synthetic-credit-model',modelVersion:spec.modelVersion||'v1',policyVersion:'synthetic-policy-v1',applicationId:`application-${spec.id}`,features:{...fixture.features}};
   const system={id:request.systemId,name:`합성 독립 업무 ${spec.id}`,owner:'합성 감사팀',purpose:'합성 대출 심사 보조',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',decisionInfluence:'material',supplierId:'synthetic-supplier',modelId:request.modelId,modelVersion:request.modelVersion,suppliedModelVersion:'v1',suppliedPurpose:'합성 대출 심사 보조',substantialModification:false,domesticImpact:true,aiBusinessOperator:true,defenceOrNationalSecurityOnly:false,providedAt:new Date(clockEpochMs-1000000).toISOString(),policyVersion:request.policyVersion};
   await api('/api/governance/systems',{body:system});
   const document=Buffer.from(`합성 ${spec.id} 공급사 시험. 실제 금융 고객 자료가 아닙니다.`),documentHash=sha(document);
   const bundle={id:`bundle-${spec.id}`,systemId:system.id,synthetic:true,supplierId:system.supplierId,modelId:spec.scenario==='wrong-model'?'other-credit-model':system.modelId,modelVersion:'v1',purpose:system.purpose,testScope:'독립 프로세스 합성 금융 대조',measures:['KR-34-RISK'],documents:[{id:'synthetic-risk',name:'synthetic-risk.txt',sha256:documentHash,contentBase64:document.toString('base64')}]};
   await api('/api/governance/bundles',{body:bundle});
   await api('/api/assets',{body:{id:`policy-${spec.id}`,actor:`credit-actor-${spec.id}`,tool:'synthetic-credit-service',owner:'합성 정책팀',policyVersion:request.policyVersion,approvalRequired:spec.scenario!=='automatic',validFrom:new Date(clockEpochMs-900000).toISOString(),destinations:['internal']}});
   const approvalResults=[await authority.call('prepare',{request})];
   if(spec.scenario==='revoked')approvalResults.push(await authority.call('revoke',{request}));
   if(spec.scenario==='block-success')approvalResults.push(await authority.call('block',{request}));
   const aiResult=await ai.call('execute',{request});
   const businessResult=await business.call('apply',{request,decision:spec.scenario==='authentication-failure'?null:aiResult.decision});
   if(spec.scenario==='delayed-approval')approvalResults.push(await authority.call('deliver-approval',{request}));
   if(spec.scenario==='missing-evidence'){
    const documentPath=join(directory,'data','finance-documents',sha(Buffer.from('alpha')),documentHash+'.json');
    assert.ok(!relative(join(directory,'data'),documentPath).startsWith('..'));unlinkSync(documentPath);
   }
   let view;const deadline=Date.now()+20000;
   for(;;){view=(await api(`/api/governance/finance?systemId=${encodeURIComponent(system.id)}`)).body;if(view.operations.every(operation=>!operation.analysisPending&&operation.evaluation))break;if(Date.now()>=deadline)throw Error(`Analysis did not settle for ${spec.id}`);await wait(100);}
   const events=view.operations.flatMap(operation=>operation.events),findings=view.operations.flatMap(operation=>operation.evaluation?.findings||[]),codes=[...new Set(findings.map(item=>item.code))].sort(),issues=[...new Set(view.bundles.flatMap(item=>item.verification.issues))].sort();
   const checks=[],check=(name,value)=>{checks.push({name,passed:value===true});assert.equal(value,true,`${spec.id}: ${name}`);};
   const submissions=[...approvalResults.flatMap(result=>result.receipts),...aiResult.receipts,...businessResult.receipts];
   const received=new Map(events.map(event=>[`${event.source}/${event.id}`,event]));
   check('source_execution_result_separated',aiPrincipal.id!==businessPrincipal.id);
   check('accepted_alpha_source_events_present',submissions.filter(item=>item.accepted&&item.tenant==='alpha').every(item=>received.has(item.ref)));
   check('all_finding_references_resolve',findings.every(finding=>finding.evidence.every(ref=>received.has(ref))));
   if(spec.scenario==='model-version-mismatch')check('v1_supplier_v2_deployment_requires_review',issues.includes('MODEL_VERSION_MISMATCH'));
   if(spec.scenario==='revoked')check('revocation_before_execution_detected',codes.includes('AUTHORITY_MISMATCH'));
   if(spec.scenario==='block-success'){
    check('block_business_success_conflict_detected',codes.includes('BLOCK_SUCCESS_CONFLICT'));
    const conflict=findings.find(finding=>finding.code==='BLOCK_SUCCESS_CONFLICT');check('conflict_has_safety_and_business_refs',conflict.evidence.includes(`alpha-safety/${spec.id}-block`)&&conflict.evidence.includes(`${businessPrincipal.id}/${spec.id}-business-result`));
   }
   if(spec.scenario==='automatic')check('no_unnecessary_human_approval_alert',!codes.some(code=>['HUMAN_APPROVAL_MISSING','APPROVAL_MISMATCH','APPROVAL_REQUIREMENT_UNKNOWN'].includes(code))&&!events.some(event=>event.kind==='human_approval'));
   if(spec.scenario==='delayed-approval'){
    const approved=received.get(`alpha-authority/${spec.id}-approval`),execution=received.get(`${aiPrincipal.id}/${spec.id}-ai-execution`);
    check('earlier_occurrence_later_actual_receipt',Date.parse(approved.occurredAt)<Date.parse(execution.occurredAt)&&approved.seq>execution.seq&&Date.parse(approved.receivedAt)>=Date.parse(execution.receivedAt));
    check('late_approval_not_post_execution_approval',approved.late===true&&codes.includes('LATE_EVIDENCE')&&!codes.includes('APPROVAL_MISMATCH'));
   }
   if(spec.scenario==='missing-evidence')check('missing_execution_and_document_remain_insufficient',view.operationalStatus==='execution_evidence_missing'&&issues.includes('DOCUMENT_EVIDENCE_MISSING'));
   if(spec.scenario==='authentication-failure')check('invalid_hmac_rejected_without_received_event',aiResult.receipts.length===1&&aiResult.receipts[0].status===401&&!received.has(aiResult.receipts[0].ref)&&view.operationalStatus==='execution_evidence_missing');
   if(spec.scenario==='wrong-attempt')check('other_attempt_approval_not_borrowed',codes.includes('APPROVAL_MISMATCH'));
   if(spec.scenario==='wrong-model')check('other_model_approval_and_supplier_evidence_not_borrowed',codes.includes('APPROVAL_MISMATCH')&&issues.includes('MODEL_ID_MISMATCH'));
   let foreignEvents=[];
   if(spec.scenario==='foreign-tenant'){
    const foreign=(await api(`/api/events?traceId=${encodeURIComponent(request.traceId)}`,{tenant:'beta'})).body.items;
    foreignEvents=foreign.map(event=>({ref:`${event.source}/${event.id}`,tenant:event.tenant,actionId:event.actionId,kind:event.kind})).sort((a,b)=>a.ref.localeCompare(b.ref));
    check('same_action_foreign_result_isolated',businessResult.receipts.length===1&&businessResult.receipts[0].status===202&&foreignEvents.some(event=>event.actionId===request.actionId&&event.ref===businessResult.receipts[0].ref)&&!received.has(businessResult.receipts[0].ref)&&events.every(event=>event.tenant==='alpha'));
    await api(`/api/governance/finance?systemId=${encodeURIComponent(system.id)}`,{tenant:'beta',expectedStatus:404});check('foreign_tenant_cannot_read_alpha_finance',true);
   }
   const report=(await api('/api/governance/finance/report',{body:{systemId:system.id}})).body;
   const reportVerification=verifyFinanceReport(report,trustedPublicKey,{expectedReportHash:report.sha256});
   check('report_independently_verified',reportVerification.valid===true&&reportVerification.tenant==='alpha'&&reportVerification.systemId===system.id&&report.snapshot.automaticLegalVerdict===false);
   const signedEvents=report.snapshot.operations.flatMap(operation=>operation.events);check('signed_report_contains_same_source_events',canonical(signedEvents)===canonical(events));
   await api(`/api/governance/finance/reports/${encodeURIComponent(report.id)}`,{tenant:'beta',expectedStatus:404});check('signed_report_tenant_boundary',true);
   writeFileSync(join(directory,`finance-report-${spec.id}.json`),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
   const result={id:spec.id,passed:checks.every(item=>item.passed),codes,issues,checks,findings,evidenceRefs:[...received.keys()].sort(),sourceIds:[...new Set(events.map(event=>event.source))].sort(),reportVerification,reportFile:`finance-report-${spec.id}.json`,reportSha256:report.sha256,operationalStatus:view.operationalStatus,events:events.map(event=>({ref:`${event.source}/${event.id}`,source:event.source,tenant:event.tenant,kind:event.kind,status:event.status,actionId:event.actionId,requestId:event.requestId,attemptId:event.attemptId,modelId:event.modelId,modelVersion:event.modelVersion,occurredAt:event.occurredAt,receivedAt:event.receivedAt,seq:event.seq,late:event.late})),submissions:submissions.map(({role,pid,source,tenant,ref,status,accepted,duplicate})=>({role,pid,source,tenant,ref,status,accepted,duplicate})),businessState:businessResult.state,businessStateSha256:businessResult.stateSha256,aiState:aiResult.state,aiStateSha256:aiResult.stateSha256,approvalState:approvalResults.at(-1).state,approvalStateSha256:approvalResults.at(-1).stateSha256,...(foreignEvents.length?{foreignEvents}:{})};
   (fixture.negatives.some(item=>item.id===spec.id)?receipt.negatives:receipt.cases).push(result);
  }
  for(const entry of producers){const state=await entry.call('state');entry.stateSha256=state.stateSha256;entry.eventCount=state.receipts.length;entry.acceptedEventCount=state.receipts.filter(item=>item.accepted).length;}
  receipt.normalizedSha256=digest({fixtureSha256,cases:receipt.cases.map(result=>normalizedCase(result,clockEpochMs)),negatives:receipt.negatives.map(result=>normalizedCase(result,clockEpochMs))});
 }catch(error){failure=error;receipt.error={name:error.name,message:error.message,code:error.cause?.code||error.code||null};}
 finally{
  // All producers are stopped even after a partial initialization/operation failure.
  for(const entry of producers){
   try{if(!exitSeen(entry.child)&&entry.child.connected)await entry.call('shutdown');}catch(error){cleanupFailure??=error;}
   if(!await exitWithin(entry.child,5000)){entry.child.kill('SIGTERM');if(!await exitWithin(entry.child,3000)){entry.child.kill('SIGKILL');await exitWithin(entry.child,3000);}}
   entry.terminationConfirmed=exitSeen(entry.child);
   receipt.producers.push({pid:entry.child.pid,role:entry.role,sourceIds:entry.sourceIds,exitCode:entry.child.exitCode,signalCode:entry.child.signalCode,terminationConfirmed:entry.terminationConfirmed,stateSha256:entry.stateSha256||null,eventCount:entry.eventCount??null,acceptedEventCount:entry.acceptedEventCount??null});
   if(!entry.terminationConfirmed||entry.child.exitCode!==0)cleanupFailure??=Error(`Producer ${entry.role} normal termination not confirmed`);
  }
  try{const stopped=await runtime.stop();receipt.lifecycle.serverTerminationConfirmed=stopped.terminationConfirmed;receipt.lifecycle.serverPids=stopped.childPids;receipt.lifecycle.serverExitCodes='not_exposed_by_createLocalRuntime';}
  catch(error){cleanupFailure??=error;}
  // An unexpected child exit after the last API read still invalidates this run.
  // Successful teardown proves termination, not a healthy completed workflow.
  if(runtime.failure)cleanupFailure??=runtime.failure;
 }
 if(cleanupFailure)receipt.cleanupError={name:cleanupFailure.name,message:cleanupFailure.message};
 receipt.passed=!failure&&!cleanupFailure&&receipt.cases.length===fixture.cases.length&&receipt.negatives.length===fixture.negatives.length&&receipt.cases.every(result=>result.passed)&&receipt.negatives.every(result=>result.passed)&&receipt.lifecycle.serverTerminationConfirmed&&receipt.producers.length===3&&receipt.producers.every(entry=>entry.terminationConfirmed&&entry.exitCode===0);
 receipt.completedAt=new Date().toISOString();
 const receiptPath=join(directory,'workflow-receipt.json');receipt.receiptPath=receiptPath;
 const serialized=JSON.stringify(receipt,null,2)+'\n';
 for(const entry of config.principals)for(const secret of [entry.token,entry.hmacSecret].filter(Boolean))assert.equal(serialized.includes(secret),false,'Credential must not appear in receipt');
 writeFileSync(receiptPath,serialized,{flag:'wx'});
 if(outputPath){mkdirSync(dirname(outputPath),{recursive:true});writeFileSync(outputPath,serialized,{flag:'wx'});}
 if(failure||cleanupFailure){const error=failure||cleanupFailure;error.message+=`\nWorkflow receipt: ${receiptPath}`;error.workflowReceiptPath=receiptPath;throw error;}
 return receipt;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const args=process.argv.slice(2),value=flag=>args.includes(flag)?args[args.indexOf(flag)+1]:undefined;
 if(args.some((arg,index)=>index%2===0&&!['--output','--expected-fixture-hash','--host'].includes(arg))||args.length%2)throw Error('Usage: node scripts/finance-workflow-pilot.mjs [--output new-receipt.json] [--expected-fixture-hash sha256] [--host ::1]');
 try{
  const result=await runFinanceWorkflowPilot({outputPath:value('--output'),expectedFixtureHash:value('--expected-fixture-hash'),host:value('--host')||process.env.EVIDSCOPE_TEST_HOST||'::1'});
  console.log(JSON.stringify({passed:result.passed,fixtureSha256:result.fixtureSha256,normalizedSha256:result.normalizedSha256,cases:result.cases.map(({id,passed})=>({id,passed})),negatives:result.negatives.map(({id,passed})=>({id,passed})),producers:result.producers,lifecycle:result.lifecycle,receiptPath:result.receiptPath}));
  if(!result.passed)process.exitCode=1;
 }catch(error){console.error(error.message);process.exitCode=1;}
}
