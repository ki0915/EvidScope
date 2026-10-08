// Provenance of pre-rotation-export-5cea6b8.json. Run from a checkout of commit 5cea6b8 (round 7 stage 2, before scheduled
// retention rotation): node <this file> OUT.json
// Builds tenant alpha in-process: agent and tool events, an analysis pass, a one-second retention policy, a legal hold on one
// action, a manual two-person disposition (reviewer plans, admin approves and executes) of the expired unheld events, and an export.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const load=path=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
const dir=mkdtempSync(join(tmpdir(),'evidscope-pre-rotation-export-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('ra'),hmacSecret:token('rh')},
 {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('rt'),hmacSecret:token('rk')},
 {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('rr')},{id:'alpha-admin',tenant:'alpha',role:'admin',token:token('rd')},
 {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('rw')}];
const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
const call=(who,path,body)=>service.handle('POST',new URL(path,'http://local'),{authorization:'Bearer '+principal(who).token},JSON.stringify(body));
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
await call('alpha-reviewer','/api/retention/policy',{retentionSeconds:1,purpose:'synthetic fixture',reason:'synthetic only; not a legal period'});
for(let i=0;i<6;i++){
 const source=i%2?'alpha-tool':'alpha-agent',event={id:`rot-${i}`,actionId:`rot-action-${i>>1}`,traceId:'rot-trace',occurredAt:new Date().toISOString(),
  kind:i%2?'result':'intent',actor:'rot-agent',tool:'rot-tool',action:'read',resource:'kb-1',status:'success'};
 if((await ingest(source,event)).accepted!==true)throw Error('ingest failed');
}
analyze();
await call('alpha-reviewer','/api/retention/holds',{scope:'rot-action-2',reason:'synthetic hold'});
await new Promise(resolve=>setTimeout(resolve,1100));
const plan=await call('alpha-reviewer','/api/retention/plans',{reason:'synthetic manual disposition'});
await call('alpha-admin',`/api/retention/plans/${plan.id}/approve`,{reason:'second person'});
const disposition=await call('alpha-admin',`/api/retention/plans/${plan.id}/execute`,{});
analyze();
const exportBundle=service.store.exportBundle('alpha');service.store.close();
writeFileSync(process.argv[2],JSON.stringify({
 format:'evidscope-test-fixture-v1',
 description:'Export written by commit 5cea6b8 (before scheduled retention rotation): tenant alpha, six agent/tool events, v1-v4 '
  +'evaluations, a hold on one action and a manual two-person disposition of the four other expired events.',
 baseCommit:'5cea6b8',publicKeyPem:publicKey.export({format:'pem',type:'spki'}),exportBundle,
},null,1)+'\n');
rmSync(dir,{recursive:true,force:true});
console.log(JSON.stringify({ok:true,records:exportBundle.records.length,erased:disposition.keyIds.length}));
