// Provenance of approvals-stops-export-503c185.json, and the in-process end-to-end scenario of test/r4-reaudit.test.mjs.
// Run from a checkout of commit 503c185 (round 3 closed: approval queue and kill switch): node <this file> OUT.json
// Builds tenant alpha in-process with approval requests and stop orders at the same time: a production agent, a signed
// registry policy, an approved, a refused and a pending request, require_approval decisions and executions, worker
// evaluations before the stop (engine v3), then a whole-agent stop with its suspension, an OPA status report, an execution
// after the activation and evaluations under engine v4, and an export.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export async function buildApprovalsStopsExport(root=process.cwd()){
 const load=path=>import(pathToFileURL(resolve(root,path)).href);
 const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
 const dir=mkdtempSync(join(tmpdir(),'evidscope-approvals-stops-')),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const token=s=>s.repeat(40).slice(0,40);
 const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('sa'),hmacSecret:token('sh')},
  {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('st'),hmacSecret:token('sk')},
  {id:'alpha-gateway',tenant:'alpha',role:'source',kind:'enforcement',token:token('sg'),hmacSecret:token('sq')},
  {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('sr')},{id:'alpha-reviewer-2',tenant:'alpha',role:'reviewer',token:token('s2')},
  {id:'alpha-admin',tenant:'alpha',role:'admin',token:token('sm')},{id:'alpha-auditor',tenant:'alpha',role:'auditor',token:token('su')},
  {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('sw')}];
 const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
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
  const decide=id=>ingest('alpha-gateway',{...target(id),id:'d-'+id,kind:'policy_decision',actionId:id,traceId:'t-'+id,decision:'require_approval',
   engine:'opa',decisionId:id,enforcementPointId:'gw-1',policyVersion:'p1',occurredAt:now(-1000)});
  const execute=(id,offset=0)=>ingest('alpha-tool',{...target(id),id:'x-'+id,kind:'execution',status:'success',actionId:id,traceId:'t-'+id,
   policyVersion:'p1',occurredAt:now(offset)});
  // ap-1 approved by two people (the registrant is excluded), ap-2 refused, both executed afterwards.
  const ap1=await open('ap-1'),ap2=await open('ap-2');
  await call(`/api/approvals/${ap1}/approve`,'alpha-reviewer-2',{reason:'checked',version:1});
  await call(`/api/approvals/${ap1}/approve`,'alpha-admin',{reason:'second look',version:2});
  await call(`/api/approvals/${ap2}/refuse`,'alpha-reviewer-2',{reason:'too high',version:1});
  for(const id of ['ap-1','ap-2']){await decide(id);await execute(id);}
  analyze();
  // The kill switch on the same agent: stop (with the suspension), activation report, an execution after the activation.
  const stop=await call('/api/registry/pay-agent/stop','alpha-reviewer',{reason:'incident',evidence:[{type:'external',ref:'INC-9'}]});
  const list=await call('/api/enforcement/deny-list','alpha-gateway');
  const revision=JSON.parse(Buffer.from(JSON.parse(Buffer.from(list.body).toString('utf8')).payload,'base64').toString('utf8')).revision;
  const report=await call('/api/enforcement/opa/status','alpha-gateway',{labels:{id:'opa-1',version:'1.4.2'},bundles:{evidscope:{name:'evidscope',
   active_revision:revision,last_successful_activation:now(0)}}});
  if(report.accepted!==1)throw Error('activation not recorded');
  const ap3=await open('st-1');await decide('st-1');await execute('st-1',3000);
  analyze();
  const exportBundle=service.store.exportBundle('alpha');
  return {exportBundle,publicKeyPem:publicKey.export({format:'pem',type:'spki'}),stopOrderId:stop.order.id,requests:{ap1,ap2,ap3}};
 }finally{service.store.close();rmSync(dir,{recursive:true,force:true});}
}

if(process.argv[1]&&resolve(process.argv[1])===resolve(new URL(import.meta.url).pathname)){
 const {exportBundle,publicKeyPem}=await buildApprovalsStopsExport();
 writeFileSync(process.argv[2],JSON.stringify({format:'evidscope-test-fixture-v1',
  description:'Export written by commit 503c185 (round 3: approval queue and kill switch): tenant alpha with approval requests and a stop order '
   +'at the same time, an OPA activation, executions and v3/v4 evaluations.',baseCommit:'503c185',publicKeyPem,exportBundle},null,1)+'\n');
 const evaluations=exportBundle.records.filter(r=>r.type==='evaluation');
 console.log(JSON.stringify({ok:true,records:exportBundle.records.length,evaluations:evaluations.length,
  findings:[...new Set(evaluations.flatMap(r=>r.payload.findings.map(f=>f.code)))].sort(),engines:[...new Set(evaluations.map(r=>r.payload.replay?.engine))]}));
}
