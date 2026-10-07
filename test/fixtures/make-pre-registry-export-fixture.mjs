// Provenance of pre-registry-export-9a15b5f.json. Run from a checkout of commit 9a15b5f (before the agent registry and
// policy-decision records): node <this file> OUT.json
// Builds tenant alpha in-process: an asset, an active rule, agent and tool events, worker evaluations (engine v1) and an export.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const load=path=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
const dir=mkdtempSync(join(tmpdir(),'evidscope-pre-registry-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('pa'),hmacSecret:token('ph')},
 {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('pt'),hmacSecret:token('pk')},
 {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('pr')},{id:'alpha-admin',tenant:'alpha',role:'admin',token:token('pm')},
 {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('pw')}];
const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
const call=(path,id,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal(id).token},
 body===undefined?'':JSON.stringify(body));
const ingest=(source,event)=>{
 const body=JSON.stringify(event),stamp=String(Date.now()),nonce=randomUUID(),p=principal(source);
 return service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+p.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,
  'x-evid-signature':mac(p.hmacSecret,stamp,nonce,body)},body);
};
const analyze=()=>{
 const worker=principal('analysis-worker');
 for(let round=0;round<10;round++){const {jobs}=service.analysis.claim(worker);if(!jobs.length)return;
  for(const job of jobs)service.analysis.commit(worker,{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});}
};
const at=new Date(Date.now()-60000).toISOString(),base={traceId:'pre-trace',actor:'pre-agent',tool:'mailer',action:'send',resource:'case-1',policyVersion:'p1',occurredAt:at};
await call('/api/assets','alpha-reviewer',{id:'pre-asset',actor:'pre-agent',tool:'mailer',owner:'owner',policyVersion:'p1',approvalRequired:true,
 validFrom:'2026-01-01T00:00:00.000Z',destinations:['mail.internal']});
for(const [source,event] of [['alpha-agent',{...base,id:'pre-intent',actionId:'pre-action',kind:'intent',destination:'external.example'}],
 ['alpha-tool',{...base,id:'pre-exec',actionId:'pre-action',kind:'execution',status:'success'}],
 ['alpha-agent',{...base,id:'pre-other',actionId:'pre-other-action',kind:'self_report',status:'success',note:'synthetic'}]])
 if((await ingest(source,event)).accepted!==true)throw Error('ingest failed');
analyze();
const rule={id:'external',title:'External destination',field:'destination',op:'eq',value:'external.example',severity:'medium'};
await call('/api/rules','alpha-reviewer',rule);await call('/api/rules/external/test','alpha-reviewer',{version:1});
await call('/api/rules/external/approve','alpha-admin',{version:1});
analyze();
const exportBundle=service.store.exportBundle('alpha');service.store.close();
writeFileSync(process.argv[2],JSON.stringify({
 format:'evidscope-test-fixture-v1',
 description:'Export written by commit 9a15b5f (before the agent registry): tenant alpha, an asset, an active rule, three events and v1 evaluations.',
 baseCommit:'9a15b5f',publicKeyPem:publicKey.export({format:'pem',type:'spki'}),exportBundle,
},null,1)+'\n');
rmSync(dir,{recursive:true,force:true});
console.log(JSON.stringify({ok:true,records:exportBundle.records.length,evaluations:exportBundle.records.filter(r=>r.type==='evaluation').length}));
