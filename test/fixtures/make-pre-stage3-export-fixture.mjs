// Provenance of pre-stage3-export-d7413a0.json. Run from a checkout of commit d7413a0 (round 6 closed, before ingest stage 3):
// node <this file> OUT.json
// Builds tenant alpha in-process: agent and tool events submitted together (one group-commit batch), a duplicate retry, an
// analysis pass and an export.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const load=path=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
const dir=mkdtempSync(join(tmpdir(),'evidscope-stage3-export-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('sa'),hmacSecret:token('sh')},
 {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('st'),hmacSecret:token('sk')},
 {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('sw')}];
const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
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
const events=[];
for(let i=0;i<8;i++){
 const source=i%2?'alpha-tool':'alpha-agent',event={id:`s3-${i}`,actionId:`s3-action-${i>>1}`,traceId:'s3-trace',occurredAt:new Date().toISOString(),
  kind:i%2?'result':'intent',actor:'s3-agent',tool:'s3-tool',action:'read',resource:'kb-1',status:'success'};
 events.push([source,event]);
}
if(!(await Promise.all(events.map(args=>ingest(...args)))).every(r=>r.accepted===true&&!r.duplicate))throw Error('ingest failed');
if((await ingest(...events[0])).duplicate!==true)throw Error('retry was not a duplicate');
analyze();
const exportBundle=service.store.exportBundle('alpha');service.store.close();
writeFileSync(process.argv[2],JSON.stringify({
 format:'evidscope-test-fixture-v1',
 description:'Export written by commit d7413a0 (before ingest stage 3): tenant alpha, eight agent/tool events in one group-commit '
  +'batch, one duplicate retry and evaluations.',
 baseCommit:'d7413a0',publicKeyPem:publicKey.export({format:'pem',type:'spki'}),exportBundle,
},null,1)+'\n');
rmSync(dir,{recursive:true,force:true});
console.log(JSON.stringify({ok:true,records:exportBundle.records.length,events:exportBundle.records.filter(r=>r.type==='event').length}));
