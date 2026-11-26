// Ingest throughput stage 3 (round 7, docs/performance.md): the SDK client on a node:http keep-alive pool, the benchmark's
// process measurement, and the vault-side changes that keep every guarantee of stages 1 and 2.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {submit} from '../src/client.mjs';
import {canonical,mac,makeCheckpoint,verifyBundle} from '../src/crypto.mjs';
import {createGroupCommit} from '../src/ingest-batch.mjs';
import {Store} from '../src/store.mjs';
import {main as verifyCli} from '../src/verify-cli.mjs';
import {createService} from '../src/service.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {cpuPerEvent,pinLayout} from '../scripts/benchmark-process.mjs';

async function server(handler){
 const sockets=new Set(),requests=[];
 const s=http.createServer((req,res)=>{
  const chunks=[];req.on('data',c=>chunks.push(c));
  req.on('end',()=>{const body=Buffer.concat(chunks).toString('utf8');requests.push({headers:req.headers,body,path:req.url});handler(req,res,body);});
 });
 s.on('connection',socket=>sockets.add(socket));
 await new Promise(r=>s.listen(0,'127.0.0.1',r));
 return {url:`http://127.0.0.1:${s.address().port}`,requests,sockets,close:()=>new Promise(r=>{s.closeAllConnections();s.close(r);})};
}
const principal={token:'t'.repeat(40),hmacSecret:'h'.repeat(40)};

test('SDK submit over a keep-alive agent: same request as fetch, one connection, redirects refused, deadline enforced', async()=>{
 const srv=await server((req,res,body)=>{
  const {id}=JSON.parse(body);
  if(id==='redirect'){res.writeHead(302,{location:'/elsewhere','content-type':'application/json'});res.end('{}');return;}
  if(id==='slow'){res.writeHead(202,{'content-type':'application/json'});res.write('{"accepted":');setTimeout(()=>res.end('true}'),400);return;}
  res.writeHead(202,{'content-type':'application/json'});res.end(JSON.stringify({accepted:true,id:JSON.parse(body).id}));
 });
 const agent=new http.Agent({keepAlive:true,maxSockets:4});
 try{
  const options={nonce:'n-1',timestamp:'1700000000000'};
  const viaFetch=await submit(srv.url,principal,{id:'e-1'},options),viaAgent=await submit(srv.url,principal,{id:'e-1'},{...options,agent});
  assert.deepEqual(viaAgent,viaFetch);assert.deepEqual(viaAgent,{status:202,body:{accepted:true,id:'e-1'}});
  const [a,b]=srv.requests.slice(-2);
  for(const name of ['authorization','content-type','x-evid-timestamp','x-evid-nonce','x-evid-signature'])assert.equal(b.headers[name],a.headers[name],name);
  assert.equal(b.body,a.body);assert.equal(b.path,'/api/ingest');
  assert.equal(b.headers['x-evid-signature'],mac(principal.hmacSecret,'1700000000000','n-1',JSON.stringify({id:'e-1'})));
  const before=srv.sockets.size;
  for(let i=0;i<10;i++)assert.equal((await submit(srv.url,principal,{id:'k-'+i},{agent})).status,202);
  assert.equal(srv.sockets.size,before,'ten sequential submits reuse the kept-alive connection');
  await assert.rejects(submit(srv.url,principal,{id:'redirect'},{agent}),/redirect refused/);
  await assert.rejects(submit(srv.url,principal,{id:'slow'},{agent,timeoutMs:100}),error=>error.name==='TimeoutError'||error.name==='AbortError');
 }finally{agent.destroy();await srv.close();}
});

test('benchmark process measurement: CPU per event per process and the pinning layout', ()=>{
 const before={vault:{total:100,main:90},ingress:{total:50,main:50},client:{total:null,main:null}};
 const after={vault:{total:300,main:250},ingress:{total:90,main:80},client:{total:10,main:10}};
 assert.deepEqual(cpuPerEvent(before,after,200),{vault:1,vaultMainThread:0.8,ingress:0.2});
 assert.deepEqual(pinLayout('1',4),{vault:'0',ingress:'1',client:'2',other:'3'});
 assert.equal(pinLayout('1',2),null);assert.equal(pinLayout('',4),null);
 assert.deepEqual(pinLayout('vault:0,client:2-3,other:1',4),{vault:'0',client:'2-3',other:'1'});
 assert.throws(()=>pinLayout('vault:0;rm',4),/Invalid BENCHMARK_PIN/);
});

// ---- Vault per-event cost (round 7). Every test below checks a guarantee of stages 1 and 2 under the changed code path.
const token=s=>s.repeat(40).slice(0,40);
function analysisVault(t,options={}){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-s3-')),key=generateKeyPairSync('ed25519').privateKey;
 const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('a1'),hmacSecret:token('h1')},
  {id:'alpha-admin',tenant:'alpha',role:'admin',token:token('m1')},{id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('r1')},
  {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('w1')}];
 const service=createService({dataDir:dir,key,config:{principals},ingestBatch:{maxWaitMs:5,maxEvents:64},...options});
 t.after(()=>{try{service.store.close();}catch{}rmSync(dir,{recursive:true,force:true});});
 const principal=id=>principals.find(p=>p.id===id);
 const send=async(value,{nonce=randomUUID()}={})=>{
  const body=JSON.stringify(value),stamp=String(Date.now()),agent=principal('alpha-agent');
  try{return {status:202,body:await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+agent.token,'x-evid-timestamp':stamp,
   'x-evid-nonce':nonce,'x-evid-signature':mac(agent.hmacSecret,stamp,nonce,body)},body)};}
  catch(error){if(!error.status)throw error;return {status:error.status,body:{error:error.message}};}
 };
 const call=async(path,id,body)=>{
  try{return {status:200,body:await service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal(id).token},
   body===undefined?'':JSON.stringify(body))};}
  catch(error){if(!error.status)throw error;return {status:error.status,body:{error:error.message}};}
 };
 const analyze=()=>{
  const worker=principal('analysis-worker');let committed=0;
  for(let round=0;round<50;round++){const {jobs}=service.analysis.claim(worker);if(!jobs.length)break;
   for(const job of jobs){service.analysis.commit(worker,{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});committed++;}}
  return committed;
 };
 return {dir,service,store:service.store,send,call,analyze};
}
const event=(id,extra={})=>({id,actionId:'act-'+id,traceId:'trace-s3',occurredAt:new Date().toISOString(),kind:'intent',actor:'s3-agent',tool:'s3-tool',
 action:'read',resource:'kb-1',note:'stage three',...extra});
const batch=(send,prefix,n)=>Promise.all(Array.from({length:n},(_,i)=>send(event(`${prefix}-${i}`))));
const rows=(store,sql,...args)=>store.db.prepare(sql).all(...args);

test('checkpoint verification: a text verified or committed once is not verified again; any other text is, and a bad one is refused',async t=>{
 const v=analysisVault(t);
 assert.ok((await batch(v.send,'a',6)).every(r=>r.status===202));v.analyze();
 // Count signature verifications of stored checkpoints: verifyCheckpoint reads store.publicKey for each one.
 const key=v.store.publicKey;let reads=0;Object.defineProperty(v.store,'publicKey',{configurable:true,get(){reads++;return key;}});
 assert.ok((await batch(v.send,'b',6)).every(r=>r.status===202));assert.equal(v.analyze(),6);
 assert.equal(reads,0,'steady-state ingest batches and analysis commits do not verify their own committed checkpoints again');
 const other=new DatabaseSync(join(v.dir,'evidence.db'));t.after(()=>other.close());other.exec('PRAGMA busy_timeout=5000');
 const saved=JSON.parse(other.prepare("SELECT body FROM checkpoints WHERE tenant='alpha'").get().body);
 // The same signed statement as another text (members reordered) is verified in full and accepted.
 const reordered=JSON.stringify(Object.fromEntries(Object.entries(saved).reverse()));
 other.prepare("UPDATE checkpoints SET body=? WHERE tenant='alpha'").run(reordered);
 assert.ok((await batch(v.send,'c',2)).every(r=>r.status===202));assert.ok(reads>0,'a new text is verified');
 // A forged signature over the current head is refused before the next write, as before.
 const head=JSON.parse(other.prepare("SELECT body FROM checkpoints WHERE tenant='alpha'").get().body);
 const forged=makeCheckpoint('alpha',head.count,head.head,generateKeyPairSync('ed25519').privateKey);
 other.prepare("UPDATE checkpoints SET body=? WHERE tenant='alpha'").run(JSON.stringify(forged));
 const before=rows(v.store,"SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'")[0].n,refused=await batch(v.send,'d',2);
 assert.deepEqual(refused.map(r=>r.status),[409,409]);assert.equal(rows(v.store,"SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'")[0].n,before);
 assert.throws(()=>v.store.exportBundle('alpha'),/Checkpoint signature invalid/);
 // An older checkpoint this store once signed and verified (a rollback of the checkpoint row) is still refused.
 other.prepare("UPDATE checkpoints SET body=? WHERE tenant='alpha'").run(JSON.stringify(saved));
 assert.deepEqual((await batch(v.send,'e',2)).map(r=>r.status),[409,409]);
});

test('evaluations delta check: appended rows are read after the last verified id, not with OFFSET, and divergence is still found',async t=>{
 const v=analysisVault(t);
 assert.ok((await batch(v.send,'a',8)).every(r=>r.status===202));assert.equal(v.analyze(),8);
 const prepare=v.store.db.prepare.bind(v.store.db),sql=[];v.store.db.prepare=text=>{sql.push(text);return prepare(text);};
 assert.ok((await batch(v.send,'b',5)).every(r=>r.status===202));assert.equal(v.analyze(),5);
 assert.ok(!sql.some(text=>/OFFSET/.test(text)),'no evaluation delta check scans the earlier rows');
 assert.ok(rows(v.store,"EXPLAIN QUERY PLAN SELECT id,action_id,version,body FROM evaluations WHERE tenant='alpha' AND id>0 ORDER BY id")
  .some(row=>/evaluations_tenant/.test(row.detail)));
 // A projection row written by the vault connection itself inside projectionMutation, beside a real commit, is found by the delta.
 assert.ok((await batch(v.send,'c',1)).every(r=>r.status===202));
 const extra=JSON.parse(rows(v.store,"SELECT body FROM evaluations WHERE tenant='alpha' ORDER BY id DESC LIMIT 1")[0].body);
 v.store.projectionMutation(()=>v.store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)')
  .run('alpha',extra.actionId,extra.version,JSON.stringify(extra)));
 assert.throws(()=>v.analyze(),/행동 상태 조회 사본|Evaluation projection/);
 assert.equal((await v.call('/api/integrity','alpha-admin')).body.valid,false);
});

test('analysis snapshot: one action\'s events come from the per-action index, equal to a scan, and follow retention disposal',async t=>{
 const v=analysisVault(t);
 const shared=['x-1','x-2','x-3'].map(id=>event(id,{actionId:'act-shared'}));
 for(const value of shared)assert.equal((await v.send(value)).status,202);
 assert.ok((await batch(v.send,'a',5)).every(r=>r.status===202));
 const scan=actionId=>[...v.store._verifiedActionState('alpha').eventsBySequence.values()].filter(e=>e.actionId===actionId);
 const indexed=actionId=>v.store._actionEvents(v.store._verifiedActionState('alpha'),actionId);
 for(const actionId of ['act-shared','act-a-0','act-a-4','missing'])assert.deepEqual(indexed(actionId),scan(actionId));
 assert.deepEqual(indexed('act-shared').map(e=>e.id),['x-1','x-2','x-3']);
 const snapshot=v.store.cachedAnalysisSnapshot('alpha','act-shared',{events:1000,assets:5000,rules:100,exceptions:5000,snapshotBytes:10*1024*1024});
 assert.deepEqual(snapshot.events.map(e=>e.id).sort(),['x-1','x-2','x-3']);
 // Erase everything (one-second retention): disposed events leave the index with the sequence map.
 assert.equal((await v.call('/api/retention/policy','alpha-reviewer',{retentionSeconds:1,purpose:'stage 3',reason:'synthetic only'})).status,200);
 assert.equal((await v.send(event('late',{actionId:'act-shared'}))).status,202);
 await new Promise(r=>setTimeout(r,1100));
 const plan=(await v.call('/api/retention/plans','alpha-reviewer',{reason:'expired'})).body;
 assert.equal((await v.call(`/api/retention/plans/${plan.id}/approve`,'alpha-admin',{reason:'second person'})).status,200);
 assert.equal((await v.call(`/api/retention/plans/${plan.id}/execute`,'alpha-admin',{})).status,200);
 assert.deepEqual(plan.items.map(item=>item.eventId),['late']);assert.deepEqual(indexed('act-shared').map(e=>e.id),['x-1','x-2','x-3']);
 for(const actionId of ['act-shared','act-a-0','act-late'])assert.deepEqual(indexed(actionId),scan(actionId));
 const cold=v.store._coldActionState('alpha',v.store.checkpoint('alpha'));
 assert.deepEqual([...cold.eventsByAction].map(([id,s])=>[id,[...s]]),[...v.store._verifiedActionState('alpha').eventsByAction].map(([id,s])=>[id,[...s]]));
});

test('group commit, optimistic isolation: refusals before a write need no savepoint; a refusal after a write reruns the batch isolated',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-s3-')),store=new Store(dir,generateKeyPairSync('ed25519').privateKey);
 t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
 const exec=store.db.exec.bind(store.db);let savepoints=0;store.db.exec=sql=>{if(/^SAVEPOINT/.test(sql))savepoints++;return exec(sql);};
 const group=createGroupCommit({store,maxWaitMs:20,isolation:'optimistic',begin:()=>store.checkActionProjection('alpha')});
 const append=i=>()=>store.append('alpha','note',{i},'unit');
 await group.submit(null,append(0));savepoints=0;
 let settled=await Promise.allSettled([group.submit(null,append(1)),group.submit(null,()=>{throw Object.assign(Error('refused first'),{status:409});}),
  group.submit(null,append(2))]);
 assert.deepEqual(settled.map(r=>r.status),['fulfilled','rejected','fulfilled']);assert.equal(settled[1].reason.status,409);
 assert.equal(savepoints,0);assert.equal(group.stats.isolatedRetries,0);
 settled=await Promise.allSettled([group.submit(null,append(3)),group.submit(null,()=>{append(99)();throw Error('refused after writing');}),
  group.submit(null,append(4))]);
 assert.deepEqual(settled.map(r=>r.status),['fulfilled','rejected','fulfilled']);assert.match(settled[1].reason.message,/after writing/);
 assert.equal(group.stats.isolatedRetries,1);assert.ok(savepoints>=3,'the retry gives every item its own savepoint');
 const notes=rows(store,"SELECT body FROM ledger WHERE tenant='alpha' ORDER BY seq").map(row=>JSON.parse(row.body).payload.i);
 assert.deepEqual(notes,[0,1,2,3,4],'the item refused after writing left nothing, the others are stored once');
 assert.equal(store.checkActionProjection('alpha').valid,true);
 const state=store.actionProjectionCache.get('alpha'),cold=store._coldActionState('alpha',store.checkpoint('alpha'));
 assert.deepEqual([state.count,state.head],[cold.count,cold.head]);verifyBundle(store.exportBundle('alpha'),store.publicKey);
 assert.throws(()=>createGroupCommit({store,isolation:'none'}),/Invalid group commit isolation/);
});

test('ingest batch: no savepoint per event; a refused event leaves no row, its nonce stays unused, as a rolled-back savepoint left it',async t=>{
 const v=analysisVault(t),exec=v.store.db.exec.bind(v.store.db);let savepoints=0;
 v.store.db.exec=sql=>{if(/^SAVEPOINT/.test(sql))savepoints++;return exec(sql);};
 assert.ok((await batch(v.send,'a',6)).every(r=>r.status===202));
 const first=event('dup-1'),nonce=randomUUID(),again=randomUUID();
 const [stored,conflict,replay]=await Promise.all([v.send(first),v.send({...first,note:'changed'},{nonce}),v.send(event('n-1'),{nonce:again})]);
 assert.equal(stored.status,202);assert.equal(conflict.status,409);assert.match(conflict.body.error,/내용 충돌/);assert.equal(replay.status,202);
 assert.equal((await v.send(event('n-2'),{nonce:again})).status,409,'a stored event spends its nonce');
 assert.equal((await v.send(event('n-3'),{nonce})).status,202,'the nonce of the refused conflict was not stored');
 // Backlog refusal (503) after the nonce check: nothing of the event is written.
 process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT='2';t.after(()=>{delete process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT;});
 const full=randomUUID(),before=rows(v.store,"SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'")[0].n;
 const busy=await v.send(event('busy-1'),{nonce:full});assert.equal(busy.status,503);
 assert.equal(rows(v.store,"SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'")[0].n,before);
 assert.equal(rows(v.store,'SELECT COUNT(*) n FROM nonces WHERE nonce=?',full)[0].n,0);
 delete process.env.ANALYSIS_BACKLOG_LIMIT_PER_TENANT;
 assert.equal(savepoints,0,'ingest batches run their events without a savepoint each');
 assert.equal(v.service.ingestBatch.stats.isolatedRetries,0);
 assert.equal((await v.call('/api/integrity','alpha-admin')).body.valid,true);
 const counter=name=>rows(v.store,'SELECT value FROM counters WHERE name=?',name)[0]?.value;
 assert.deepEqual([counter('accepted'),counter('duplicates')??0],[6+1+1+1,0]);
});

test('exports: a d7413a0 export still verifies, and a stage-3 export has the same record shapes and verifies with both verifiers',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-s3-export-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const cli=(file,pem)=>{writeFileSync(join(dir,'b.json'),JSON.stringify(file));writeFileSync(join(dir,'k.pem'),pem);
  return verifyCli(['bundle',join(dir,'b.json'),join(dir,'k.pem')],{stdout:{write(){}},stderr:{write(){}}});};
 const fixture=JSON.parse(readFileSync(new URL('./fixtures/pre-stage3-export-d7413a0.json',import.meta.url),'utf8'));
 assert.equal(fixture.baseCommit,'d7413a0');
 assert.equal(verifyBundle(fixture.exportBundle,fixture.publicKeyPem).valid,true);assert.equal(cli(fixture.exportBundle,fixture.publicKeyPem),0);
 const v=analysisVault(t),first=event('x-0');
 assert.ok((await Promise.all([v.send(first),...Array.from({length:7},(_,i)=>v.send(event('x-'+(i+1))))])).every(r=>r.status===202));
 assert.equal((await v.send(first)).body.duplicate,true);v.analyze();
 const bundle=v.store.exportBundle('alpha'),pem=v.store.publicKey.export({format:'pem',type:'spki'});
 assert.equal(verifyBundle(bundle,pem).valid,true);assert.equal(cli(bundle,pem),0);
 const keys=value=>canonical(Object.keys(value).sort()),shapes=b=>{
  const out={disclosure:keys(b.disclosures[0]),top:keys(b),checkpoint:keys(b.checkpoint)};
  for(const r of b.records)if(['event','event_receipt','evaluation'].includes(r.type))out[r.type]=keys(r)+keys(r.payload);
  return out;
 };
 assert.deepEqual(shapes(bundle),shapes(fixture.exportBundle));
});
