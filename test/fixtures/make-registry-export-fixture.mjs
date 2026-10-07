// Provenance of registry-export-ef18d23.json. Run from a checkout of commit ef18d23 (agent registry, before stop orders and
// bundle activations): node <this file> OUT.json
// Builds tenant alpha in-process: a registry entry taken to production with a four-eyes approval, an enforcement decision,
// a suspension, agent/tool/enforcement events, worker evaluations (engines v1 and v2) and an export.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const load=path=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
const dir=mkdtempSync(join(tmpdir(),'evidscope-registry-export-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('pa'),hmacSecret:token('ph')},
 {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('pt'),hmacSecret:token('pk')},
 {id:'alpha-gateway',tenant:'alpha',role:'source',kind:'enforcement',token:token('pg'),hmacSecret:token('pq')},
 {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('pr')},{id:'alpha-reviewer-2',tenant:'alpha',role:'reviewer',token:token('ps')},
 {id:'alpha-admin',tenant:'alpha',role:'admin',token:token('pm')},{id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('pw')}];
const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
const call=async(path,id,body)=>{
 const r=await service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal(id).token},
 body===undefined?'':JSON.stringify(body));return r;};
const ingest=(source,event)=>{
 const body=JSON.stringify(event),stamp=String(Date.now()),nonce=randomUUID(),p=principal(source);
 return service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+p.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,
  'x-evid-signature':mac(p.hmacSecret,stamp,nonce,body)},body);
};
const analyze=()=>{
 const worker=principal('analysis-worker');
 for(let round=0;round<20;round++){const {jobs}=service.analysis.claim(worker);if(!jobs.length)return;
  for(const job of jobs)service.analysis.commit(worker,{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});}
};
const pause=ms=>new Promise(done=>setTimeout(done,ms));
const send=async(source,event)=>{
 if((await ingest(source,{occurredAt:new Date().toISOString(),traceId:'reg-trace',...event})).accepted!==true)throw Error('ingest failed');};
await send('alpha-agent',{id:'reg-pre',actionId:'reg-pre',kind:'intent',actor:'lookup-agent',tool:'lookup'});
analyze();
await call('/api/registry','alpha-reviewer',{id:'lookup-agent',owner:'ops',purpose:'lookups',sources:['alpha-agent'],actors:['lookup-agent'],
 tools:[{name:'lookup',enforcement:'required'}],destinations:['kb.internal']});
await call('/api/registry/lookup-agent/transitions','alpha-reviewer',{to:'testing',reason:'pilot'});
const approved=await call('/api/registry/lookup-agent/transitions','alpha-reviewer',{to:'approved',reason:'pilot passed'});
await call(`/api/registry/transitions/${approved.transition.id}/approve`,'alpha-reviewer-2',{reason:'ok'});
const live=await call('/api/registry/lookup-agent/transitions','alpha-reviewer',{to:'production',reason:'go live'});
const production=await call(`/api/registry/transitions/${live.transition.id}/approve`,'alpha-reviewer-2',{reason:'ok'});
if(production.entry.state!=='production')throw Error('not in production');
const target={actor:'lookup-agent',tool:'lookup',action:'read',resource:'kb-1'};
await send('alpha-gateway',{id:'reg-deny',actionId:'reg-denied',kind:'policy_decision',decision:'deny',decisionId:'d-1',
 enforcementPointId:'gw-1',engine:'opa',...target});
await pause(5);
await send('alpha-tool',{id:'reg-exec',actionId:'reg-denied',kind:'execution',status:'success',...target});
await pause(5);
await call('/api/registry/lookup-agent/transitions','alpha-admin',{to:'suspended',reason:'incident'});
await pause(5);
await send('alpha-tool',{id:'reg-during',actionId:'reg-during',kind:'execution',status:'success',...target});
analyze();
const exportBundle=service.store.exportBundle('alpha');service.store.close();
writeFileSync(process.argv[2],JSON.stringify({
 format:'evidscope-test-fixture-v1',
 description:'Export written by commit ef18d23 (agent registry, before stop orders): tenant alpha, a registry entry in production then suspended, '
  +'a deny decision, tool executions and v1/v2 evaluations.',
 baseCommit:'ef18d23',publicKeyPem:publicKey.export({format:'pem',type:'spki'}),exportBundle,
},null,1)+'\n');
rmSync(dir,{recursive:true,force:true});
console.log(JSON.stringify({ok:true,records:exportBundle.records.length,evaluations:exportBundle.records.filter(r=>r.type==='evaluation').length}));
