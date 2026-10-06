import {fork} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {performance} from 'node:perf_hooks';
import {initialize} from './init.mjs';
import {createService} from '../src/service.mjs';
import {evaluateJob} from '../src/worker.mjs';

export async function runFinancePilot({output=resolve('reports/finance-pilot-latest.json')}={}){
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs/finance-')),config=initialize(dir),key=readFileSync(join(dir,'signing-private.pem'),'utf8'),requirements=JSON.parse(readFileSync('data/requirements.json','utf8'));
 const service=createService({dataDir:join(dir,'data'),config,key,requirements}),reviewer=config.principals.find(p=>p.tenant==='alpha'&&p.role==='reviewer'),worker=config.principals.find(p=>p.role==='worker');
 const api=(path,body,p=reviewer)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://synthetic.local'),{authorization:'Bearer '+p.token},body===undefined?'':JSON.stringify(body));
 const ids=['normal','automatic','revoked','block-success','late-approval','model-changed','no-execution','document-corrupt'];
 const sourceEvents={agent:[],tool:[],authority:[],safety:[]},at=Date.now()-60000,iso=offset=>new Date(at+offset).toISOString(),bundleInputs=[];
 try{
  for(const id of ids){
   const system={id:'credit-'+id,name:'합성 금융 사례 '+id,owner:'합성 감사팀',purpose:'대출 심사 보조',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',decisionInfluence:'material',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false};
   await api('/api/governance/systems',system);
   const bytes=Buffer.from('합성 문서 '+id+' · 실제 금융 고객 자료 없음'),sha256=createHash('sha256').update(bytes).digest('hex');
   const bundle={id:'evidence-'+id,systemId:system.id,synthetic:true,supplierId:system.supplierId,modelId:system.modelId,modelVersion:'v1',purpose:system.purpose,testScope:'해당 합성 금융 사례의 공급사 위험관리 시험',measures:['KR-34-RISK'],documents:[{id:'risk-test',name:'합성 시험.txt',contentBase64:bytes.toString('base64'),sha256}]};
   bundleInputs.push(bundle);await api('/api/governance/bundles',bundle);
   if(id==='model-changed')await api('/api/governance/systems',{...system,modelVersion:'v2'});
   if(id==='document-corrupt'){const tenant=createHash('sha256').update('alpha').digest('hex');writeFileSync(join(dir,'data','finance-documents',tenant,sha256+'.json'),'synthetic corruption');}
   await api('/api/assets',{id:'policy-'+id,actor:'credit-agent-'+id,tool:'credit-api',owner:'합성 정책팀',policyVersion:'p1',approvalRequired:id!=='automatic',validFrom:iso(-900000),destinations:['internal']});
   if(['no-execution','document-corrupt'].includes(id))continue;
   const common={systemId:system.id,actionId:'action-'+id,traceId:'trace-'+id,requestId:'request-'+id,attemptId:'attempt-1',modelId:'credit-score',modelVersion:id==='model-changed'?'v2':'v1',actor:'credit-agent-'+id,tool:'credit-api',action:'score',resource:'synthetic-application-'+id,destination:'internal',policyVersion:'p1',clockUncertaintyMs:0};
   const scope={actor:common.actor,tool:common.tool,action:common.action,resource:common.resource,destination:common.destination};
   sourceEvents.agent.push({...common,id:'intent-'+id,kind:'intent',occurredAt:iso(-1000)});
   sourceEvents.authority.push({...common,id:'grant-'+id,kind:'grant',scope,occurredAt:iso(-10000),validFrom:iso(-700000),validUntil:iso(600000)});
   if(id!=='automatic')sourceEvents.authority.push({...common,id:'approval-'+id,kind:'human_approval',reviewer:'synthetic-human',scope,occurredAt:iso(id==='late-approval'?-600000:-9000),validFrom:iso(-700000),validUntil:iso(600000)});
   if(id==='revoked')sourceEvents.authority.push({...common,id:'revoke-'+id,kind:'revoke',authorityId:'grant-'+id,occurredAt:iso(-5000)});
   if(id==='block-success')sourceEvents.safety.push({...common,id:'block-'+id,kind:'block_registered',occurredAt:iso(-1000)});
   sourceEvents.tool.push({...common,id:'execution-'+id,kind:'execution',occurredAt:iso(0)},{...common,id:'result-'+id,kind:'result',status:'success',occurredAt:iso(1000)});
  }
  const producers=await Promise.all(Object.entries(sourceEvents).map(([kind,events])=>new Promise((res,rej)=>{
   const child=fork(new URL('./finance-source-fixture.mjs',import.meta.url),[],{stdio:['ignore','ignore','pipe','ipc']}),principal=config.principals.find(p=>p.kind===kind&&p.tenant==='alpha');let response;
   const timeout=setTimeout(()=>{child.kill();rej(Error('Producer timeout'));},15000);
   child.once('error',error=>{clearTimeout(timeout);rej(error);});child.once('message',value=>{response=value;});child.once('exit',code=>{clearTimeout(timeout);code===0&&response?res(response):rej(Error('Producer failed'));});child.send({principal,events});
  })));
  for(const producer of producers)for(const record of producer.records)await service.handle('POST',new URL('/api/ingest','http://synthetic.local'),record.headers,record.body);
  let analyzed=0;for(;;){const claim=await api('/internal/claim',{},worker);if(!claim.jobs.length)break;for(const job of claim.jobs){await api('/internal/complete',{leaseId:job.leaseId,result:evaluateJob(job)},worker);analyzed++;}}
  const cases=[];
  for(const id of ids){const started=performance.now(),view=await api('/api/governance/finance?systemId=credit-'+id),codes=view.operations.flatMap(o=>o.evaluation?.findings.map(f=>f.code)||[]),issues=view.bundles.flatMap(b=>b.verification.issues);let passed;
   if(id==='normal'||id==='automatic')passed=codes.length===0;
   else if(id==='revoked')passed=codes.includes('AUTHORITY_MISMATCH');
   else if(id==='block-success')passed=codes.includes('BLOCK_SUCCESS_CONFLICT');
   else if(id==='late-approval')passed=codes.includes('LATE_EVIDENCE')&&!codes.includes('APPROVAL_MISMATCH');
   else if(id==='model-changed')passed=issues.includes('MODEL_VERSION_MISMATCH');
   else if(id==='no-execution')passed=view.operationalStatus==='execution_evidence_missing';
   else passed=issues.includes('DOCUMENT_EVIDENCE_MISSING');
   const report=await api('/api/governance/finance/report',{systemId:'credit-'+id});cases.push({id,passed,codes:[...new Set(codes)],issues,operationalStatus:view.operationalStatus,reportId:report.id,retrievalMilliseconds:Number((performance.now()-started).toFixed(2)),humanReviewSeconds:null});
  }
  // Convenient reviewable import example, contains synthetic content only.
  mkdirSync(resolve('reports'),{recursive:true});writeFileSync(resolve('reports/finance-supplier-example.json'),JSON.stringify(bundleInputs[0],null,2));
  const report={schemaVersion:1,createdAt:new Date().toISOString(),passed:cases.every(c=>c.passed),cases,analyzedActions:analyzed,producers:producers.map(p=>({pid:p.pid,source:p.source,records:p.records.length})),transport:'independent child producers -> HMAC-authenticated service boundary over IPC; HTTP transport not tested',synthetic:true,liveFinancialIntegration:false,competitiveSuperiorityProven:false,limitations:['독립 프로세스 합성 실증이며 실제 금융사 연동이나 별도 호스트 신뢰 경계 검증이 아닙니다.','retrievalMilliseconds는 프로그램 실행 시간입니다. 감사자 검토 시간은 측정하지 않았습니다.','상용 경쟁 도구와 동일 입력 실행 비교는 수행하지 않았습니다.'],artifactDirectory:dir};
  if(output)writeFileSync(output,JSON.stringify(report,null,2));return report;
 }finally{service.store.db.close();}
}
if(process.argv[1]&&resolve(process.argv[1])===resolve('scripts/finance-pilot.mjs')){const result=await runFinancePilot();console.log(JSON.stringify({passed:result.passed,cases:result.cases.map(({id,passed})=>({id,passed})),report:resolve('reports/finance-pilot-latest.json')}));if(!result.passed)process.exitCode=1;}
