// Provenance of pre-approvals-export-ef18d23.json. Run from a checkout of commit ef18d23 (agent registry, before the approval
// queue): node <this file> OUT.json
// Builds tenant alpha in-process: a registry entry and policy, an asset, require_approval and deny decisions, an external human
// approval, tool executions, worker evaluations (engines v1 and v2) and an export.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const load=path=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
const dir=mkdtempSync(join(tmpdir(),'evidscope-pre-approvals-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('pa'),hmacSecret:token('ph')},
 {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('pt'),hmacSecret:token('pk')},
 {id:'alpha-gateway',tenant:'alpha',role:'source',kind:'enforcement',token:token('pg'),hmacSecret:token('pq')},
 {id:'alpha-authority',tenant:'alpha',role:'source',kind:'authority',token:token('pu'),hmacSecret:token('pv')},
 {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('pr')},{id:'alpha-admin',tenant:'alpha',role:'admin',token:token('pm')},
 {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('pw')}];
const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
const call=async(path,id,body)=>{const r=await service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
 {authorization:'Bearer '+principal(id).token},
 body===undefined?'':JSON.stringify(body));return r;};
const ingest=async(source,event)=>{
 const body=JSON.stringify(event),stamp=String(Date.now()),nonce=randomUUID(),p=principal(source);
 const r=await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+p.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,
  'x-evid-signature':mac(p.hmacSecret,stamp,nonce,body)},body);
 if(r.accepted!==true)throw Error('ingest failed');
};
const analyze=()=>{
 const worker=principal('analysis-worker');
 for(let round=0;round<10;round++){const {jobs}=service.analysis.claim(worker);if(!jobs.length)return;
  for(const job of jobs)service.analysis.commit(worker,{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});}
};
const minute=60000,at=offset=>new Date(Date.now()-10*minute+offset).toISOString();
await call('/api/assets','alpha-reviewer',{id:'pay-asset',actor:'pay-agent',tool:'payment_transfer',owner:'owner',policyVersion:'p1',approvalRequired:true,
 validFrom:'2026-01-01T00:00:00.000Z'});
await call('/api/registry','alpha-reviewer',{id:'pay-agent',owner:'payments',purpose:'refunds',sources:['alpha-agent'],actors:['pay-agent'],
 tools:[{name:'payment_transfer',enforcement:'required'}],dataCategories:['financial']});
const target={actor:'pay-agent',tool:'payment_transfer',action:'refund',resource:'order-7'};
const decision={...target,engine:'opa',enforcementPointId:'gw-1',policyId:'payments.refund',policyVersion:'p1'};
// pay-1: require_approval, then an external authority approval and the execution (no finding from the approval rule).
await ingest('alpha-gateway',{...decision,id:'d-1',kind:'policy_decision',actionId:'pay-1',traceId:'t-1',decision:'require_approval',
 decisionId:'dec-1',occurredAt:at(0)});
await ingest('alpha-authority',{...target,id:'g-1',kind:'grant',actionId:'pay-1',traceId:'t-1',policyVersion:'p1',scope:target,validFrom:at(0),
 validUntil:at(9*minute),occurredAt:at(0)});
await ingest('alpha-authority',{...target,id:'h-1',kind:'human_approval',actionId:'pay-1',traceId:'t-1',policyVersion:'p1',reviewer:'ext-reviewer',scope:target,
 validFrom:at(1000),validUntil:at(9*minute),occurredAt:at(1000)});
await ingest('alpha-tool',{...target,id:'x-1',kind:'execution',actionId:'pay-1',traceId:'t-1',policyVersion:'p1',status:'success',occurredAt:at(2000)});
// pay-2: require_approval and an execution without any approval (REQUIRED_APPROVAL_MISSING).
await ingest('alpha-gateway',{...decision,id:'d-2',kind:'policy_decision',actionId:'pay-2',traceId:'t-2',decision:'require_approval',
 decisionId:'dec-2',occurredAt:at(0)});
await ingest('alpha-tool',{...target,id:'x-2',kind:'execution',actionId:'pay-2',traceId:'t-2',policyVersion:'p1',status:'success',occurredAt:at(3000)});
// pay-3: deny followed by an execution (EXECUTION_AFTER_DENY); other-1: an agent intent without decisions (engine v1).
await ingest('alpha-gateway',{...decision,id:'d-3',kind:'policy_decision',actionId:'pay-3',traceId:'t-3',decision:'deny',decisionId:'dec-3',occurredAt:at(0)});
await ingest('alpha-tool',{...target,id:'x-3',kind:'execution',actionId:'pay-3',traceId:'t-3',policyVersion:'p1',status:'success',occurredAt:at(4000)});
await ingest('alpha-agent',{id:'i-1',kind:'intent',actionId:'other-1',traceId:'t-4',actor:'mail-agent',tool:'mailer',occurredAt:at(0)});
analyze();
await call('/api/registry/policy','alpha-admin',{enforcement:'unregistered_activity'});
analyze();
const exportBundle=service.store.exportBundle('alpha');service.store.close();
writeFileSync(process.argv[2],JSON.stringify({
 format:'evidscope-test-fixture-v1',
 description:'Export written by commit ef18d23 (agent registry, before the approval queue): tenant alpha, registry records, policy decisions, '
  +'an external human approval, executions and v1/v2 evaluations.',
 baseCommit:'ef18d23',publicKeyPem:publicKey.export({format:'pem',type:'spki'}),exportBundle,
},null,1)+'\n');
rmSync(dir,{recursive:true,force:true});
const evaluations=exportBundle.records.filter(r=>r.type==='evaluation');
console.log(JSON.stringify({ok:true,records:exportBundle.records.length,evaluations:evaluations.length,
 findings:[...new Set(evaluations.flatMap(r=>r.payload.findings.map(f=>f.code)))].sort(),engines:[...new Set(evaluations.map(r=>r.payload.replay?.engine))]}));
