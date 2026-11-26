// Provenance of pack-export-8b3af6c.json, the old-export regression input of test/evidence-pack.test.mjs.
// Run from a checkout of commit 8b3af6c (round 5 closed, before evidence packages): node <this file> OUT.json
// Builds tenant alpha in-process in three phases a few hundred milliseconds apart (so a period can cut between them):
//  1. a production agent in the registry with a signed policy, an approved and a refused approval request, require_approval
//     decisions, executions and results, a signed human approval and a retention policy;
//  2. a KR-34-OVERSIGHT assessment with its independent legal review, a case on one action with a human review decision;
//  3. a whole-agent stop order and the worker's evaluations; then an export and the signed case report.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const pause=ms=>new Promise(done=>setTimeout(done,ms));
export async function buildPackExport(root=process.cwd()){
 const load=path=>import(pathToFileURL(resolve(root,path)).href);
 const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
 const requirements=JSON.parse(readFileSync(resolve(root,'data/requirements.json'),'utf8'));
 const dir=mkdtempSync(join(tmpdir(),'evidscope-pack-export-')),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const token=s=>s.repeat(40).slice(0,40);
 const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('pa'),hmacSecret:token('ph')},
  {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('pt'),hmacSecret:token('pk')},
  {id:'alpha-gateway',tenant:'alpha',role:'source',kind:'enforcement',token:token('pg'),hmacSecret:token('pq')},
  {id:'alpha-authority',tenant:'alpha',role:'source',kind:'authority',token:token('py'),hmacSecret:token('pz')},
  {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('pr')},{id:'alpha-reviewer-2',tenant:'alpha',role:'reviewer',token:token('p2')},
  {id:'alpha-admin',tenant:'alpha',role:'admin',token:token('pm')},{id:'alpha-auditor',tenant:'alpha',role:'auditor',token:token('pu')},
  {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('pw')}];
 const service=createService({dataDir:dir,key:privateKey,config:{principals},requirements}),principal=id=>principals.find(p=>p.id===id);
 try{
  const call=async(path,id,body,extra={})=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
   {authorization:'Bearer '+principal(id).token,...extra},body===undefined?'':typeof body==='string'?body:JSON.stringify(body));
  const signed=async(path,id,body)=>{const text=JSON.stringify(body),stamp=String(Date.now()),nonce=randomUUID(),p=principal(id);
   return call(path,id,text,{'x-evid-timestamp':stamp,'x-evid-nonce':nonce,'x-evid-signature':mac(p.hmacSecret,stamp,nonce,text)});};
  const ingest=async(source,event)=>{const r=await signed('/api/ingest',source,event);if(r.accepted!==true)throw Error('ingest failed');};
  const analyze=()=>{
   const worker=principal('analysis-worker');
   for(let round=0;round<20;round++){const {jobs}=service.analysis.claim(worker);if(!jobs.length)return;
    for(const job of jobs)service.analysis.commit(worker,{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});}
  };
  const now=offset=>new Date(Date.now()+offset).toISOString();
  // Phase 1: registry, approvals, decisions, executions, a human approval and a retention policy.
  await call('/api/registry/policy','alpha-admin',{gates:{low:{},medium:{},high:{}},approvals:{intervalSeconds:1},
   stopPropagation:{windowSeconds:10,enforcementPoints:['alpha-gateway']}});
  await call('/api/assets','alpha-reviewer',{id:'pay-asset',actor:'pay-agent',tool:'payment_transfer',owner:'payments',policyVersion:'p1',approvalRequired:true,
   validFrom:'2026-01-01T00:00:00.000Z'});
  await call('/api/registry','alpha-reviewer',{id:'pay-agent',owner:'payments',purpose:'refunds',sources:['alpha-agent'],actors:['pay-agent'],
   tools:[{name:'payment_transfer',enforcement:'required'}]});
  for(const to of ['testing','approved','production']){
   const r=await call('/api/registry/pay-agent/transitions','alpha-reviewer',{to,reason:to});
   if(r.transition.status==='pending')await call(`/api/registry/transitions/${r.transition.id}/approve`,'alpha-reviewer-2',{reason:'ok'});
  }
  const target=id=>({actor:'pay-agent',tool:'payment_transfer',action:'refund',resource:id});
  const open=async id=>(await signed('/api/approvals/requests','alpha-gateway',{decisionId:id,actionId:id,traceId:'t-'+id,enforcementPointId:'gw-1',
   policyId:'payments.refund',policyVersion:'p1',target:target(id),binding_message:'refund '+id})).auth_req_id;
  const ap1=await open('ap-1'),ap2=await open('ap-2');
  await call(`/api/approvals/${ap1}/approve`,'alpha-reviewer-2',{reason:'checked',version:1});
  await call(`/api/approvals/${ap1}/approve`,'alpha-admin',{reason:'second look',version:2});
  await call(`/api/approvals/${ap2}/refuse`,'alpha-reviewer-2',{reason:'too high',version:1});
  for(const id of ['ap-1','ap-2']){
   await ingest('alpha-gateway',{...target(id),id:'d-'+id,kind:'policy_decision',actionId:id,traceId:'t-'+id,decision:'require_approval',engine:'opa',
    decisionId:id,enforcementPointId:'gw-1',policyVersion:'p1',occurredAt:now(-1000)});
   await ingest('alpha-agent',{...target(id),id:'i-'+id,kind:'intent',actionId:id,traceId:'t-'+id,status:'success',policyVersion:'p1',occurredAt:now(-900)});
   await ingest('alpha-tool',{...target(id),id:'x-'+id,kind:'execution',status:'success',actionId:id,traceId:'t-'+id,policyVersion:'p1',occurredAt:now(0)});
  }
  await ingest('alpha-authority',{...target('ap-1'),id:'h-ap-1',kind:'human_approval',actionId:'ap-1',traceId:'t-ap-1',reviewer:'alpha-reviewer-2',
   status:'success',policyVersion:'p1',scope:target('ap-1'),validFrom:now(-3600000),validUntil:now(3600000),
   occurredAt:now(-800)});
  await call('/api/retention/policy','alpha-reviewer',{retentionSeconds:400*86400,purpose:'audit evidence',reason:'six months and more'});
  analyze();
  await pause(300);
  // Phase 2: a human assessment with an independent legal review, and a case with a human review decision.
  const system={id:'pay-system',name:'Refund assistant',owner:'payments',purpose:'refunds',markets:['EU','KR'],euRoles:['deployer'],krRoles:['deployer'],
   domesticImpact:true,aiBusinessOperator:true,defenceOrNationalSecurityOnly:false,highImpact:'unknown',providedAt:now(-86400000)};
  await call('/api/governance/systems','alpha-reviewer',system);
  const assessment=await call('/api/governance/assessments','alpha-reviewer',{systemId:system.id,requirementId:'KR-34-OVERSIGHT',applicability:'unknown',
   assessment:'insufficient',legalReview:'pending',evidence:[{type:'attestation',ref:'approval queue in production since 2026-01'}],control:'approval queue',
   owner:'payments',reason:'two-person approvals are recorded; oversight plan document not yet attached',nextReviewAt:'2099-01-01T00:00:00.000Z'});
  await call(`/api/governance/assessments/${assessment.id}/legal-review`,'alpha-reviewer-2',{reason:'counsel read the assessment'});
  const kase=await call('/api/cases','alpha-reviewer',{title:'refused refund executed',owner:'audit-team',actionId:'ap-2'});
  const context=await call(`/api/cases/${kase.id}/review-context`,'alpha-auditor');
  await call(`/api/cases/${kase.id}/decisions`,'alpha-auditor',{contextHash:context.contextHash,conclusion:'confirmed_issue',scope:'refund ap-2',
   reason:'the refund ran after the approval was refused',limitations:'payment system state not checked',nextReviewAt:now(86400000),
   evidence:[{ref:'alpha-tool/x-ap-2',supports:'supports',note:'execution after refusal'}]});
  await pause(300);
  // Phase 3: the kill switch and evaluations under the stop.
  await call('/api/registry/pay-agent/stop','alpha-reviewer',{reason:'incident',evidence:[{type:'external',ref:'INC-9'}]});
  analyze();
  const exportBundle=service.store.exportBundle('alpha'),caseReport=await call(`/api/cases/${kase.id}/report`,'alpha-auditor');
  return {exportBundle,caseReports:[caseReport],publicKeyPem:publicKey.export({format:'pem',type:'spki'}),caseId:kase.id};
 }finally{service.store.close();rmSync(dir,{recursive:true,force:true});}
}

if(process.argv[1]&&resolve(process.argv[1])===resolve(new URL(import.meta.url).pathname)){
 const {exportBundle,caseReports,publicKeyPem}=await buildPackExport();
 writeFileSync(process.argv[2],JSON.stringify({format:'evidscope-test-fixture-v1',
  description:'Export and case report written by commit 8b3af6c (round 5 closed, before evidence packages): tenant alpha in three phases with '
   +'registry, approvals, a human approval, a retention policy, a KR assessment with legal review, a reviewed case, a stop order and evaluations.',
  baseCommit:'8b3af6c',publicKeyPem,exportBundle,caseReports},null,1)+'\n');
 const types={};for(const r of exportBundle.records)types[r.type]=(types[r.type]||0)+1;
 console.log(JSON.stringify({ok:true,records:exportBundle.records.length,types}));
}
