// Source ingest group commit (round 5, docs/performance.md): batching under concurrency, refusals and failures inside a
// batch, a kill during a batch, batched and pre-batching exports under both verifiers, and the latency bound.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {vault} from './event-key-vault.mjs';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {mac,verifyBundle} from '../src/crypto.mjs';
import {main as verifyCli} from '../src/verify-cli.mjs';
import {Store} from '../src/store.mjs';
import {createGroupCommit,ingestBatchOptions,INGEST_BATCH_DEFAULTS} from '../src/ingest-batch.mjs';

const event=(id,extra={})=>({id,actionId:'act-'+id,traceId:'trace-gc',occurredAt:new Date().toISOString(),kind:'intent',actor:'gc-agent',tool:'gc-tool',
 action:'read',resource:'kb-1',...extra});
// In-process ingest with an explicit nonce; answers {status, body} like the HTTP route (202 or the HTTP error).
function sender(v){
 const agent=v.principal('alpha-agent');
 return async(value,{nonce=randomUUID()}={})=>{
  const body=JSON.stringify(value),stamp=String(Date.now());
  try{return {status:202,body:await v.service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+agent.token,'x-evid-timestamp':stamp,
   'x-evid-nonce':nonce,'x-evid-signature':mac(agent.hmacSecret,stamp,nonce,body)},body)};}
  catch(error){return {status:error.status||500,body:{error:error.message}};}
 };
}
const ledgerEvents=store=>{const bundle=store.exportBundle('alpha');return {bundle,events:store.decodeRecords(bundle)};};
const cli=args=>{let out='';const sink={write:text=>{out+=text;}};return {status:verifyCli(args,{stdout:sink,stderr:sink}),out};};
function scratch(t){const dir=mkdtempSync(join(tmpdir(),'evidscope-group-commit-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;}

test('group commit: concurrent events share transactions in submission order; retries stay duplicates and none is lost or doubled',async t=>{
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:20,maxEvents:64}}}),send=sender(v);
 const ids=Array.from({length:150},(_,i)=>`gc-${i}`),originals=ids.map(id=>event(id));
 const answers=await Promise.all([...originals.map(e=>send(e)),...originals.slice(0,10).map(e=>send(e)),send(event('gc-1',{resource:'other'}))]);
 assert.deepEqual(answers.slice(0,150).map(a=>[a.status,a.body.duplicate]),ids.map(()=>[202,false]));
 assert.deepEqual(answers.slice(150,160).map(a=>[a.status,a.body.duplicate]),Array(10).fill([202,true]));
 assert.equal(answers[160].status,409);assert.match(answers[160].body.error,/내용 충돌/);
 const stats=v.service.ingestBatch.stats;
 assert.equal(stats.events,161);assert.ok(stats.batches>=3&&stats.batches<=6,JSON.stringify(stats));assert.equal(stats.largest,64);
 const {bundle,events}=ledgerEvents(v.store);verifyBundle(bundle,v.store.publicKey);
 // One ledger row per accepted event, in submission order, each followed by its own receipt.
 assert.deepEqual(events.map(e=>e.id),ids);
 const receipts=bundle.records.filter(r=>r.type==='event_receipt');
 assert.deepEqual(receipts.map(r=>r.payload.id),ids);
 for(const receipt of receipts){
  const row=bundle.records[receipt.payload.eventSeq-1];assert.equal(row.type,'event');assert.equal(row.hash,receipt.payload.eventHash);
 }
 assert.equal(v.store.db.prepare("SELECT COUNT(*) n FROM events WHERE tenant='alpha'").get().n,150);
 const integrity=await v.call('/api/integrity','alpha-admin');assert.equal(integrity.body.valid,true,JSON.stringify(integrity.body).slice(0,500));
});

test('group commit: a refused event rolls back alone; a batch that cannot commit stores nothing and answers every request',async t=>{
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:20,maxEvents:64}}}),send=sender(v),nonce=randomUUID();
 const [first,replay,other]=await Promise.all([send(event('n-1'),{nonce}),send(event('n-2'),{nonce}),send(event('n-3'))]);
 assert.equal(first.status,202);assert.equal(replay.status,409);assert.match(replay.body.error,/nonce/);assert.equal(other.status,202);
 assert.equal(v.service.ingestBatch.stats.batches,1);
 assert.deepEqual(ledgerEvents(v.store).events.map(e=>e.id),['n-1','n-3']);
 // The checkpoint signature is made at COMMIT: without the signing key every event of the batch fails and none is stored.
 const before=v.store.db.prepare('SELECT COUNT(*) n FROM ledger').get().n,key=v.store.key;v.store.key='not a signing key';
 const failed=await Promise.all(['f-1','f-2','f-3'].map(id=>send(event(id))));
 v.store.key=key;
 assert.deepEqual(failed.map(a=>a.status),[500,500,500]);
 assert.equal(v.store.db.prepare('SELECT COUNT(*) n FROM ledger').get().n,before);
 assert.equal(v.store.db.prepare("SELECT COUNT(*) n FROM events WHERE id LIKE 'f-%'").get().n,0);
 assert.equal(v.store.db.prepare("SELECT COUNT(*) n FROM nonces").get().n,2);
 assert.equal(v.service.ingestBatch.stats.failedBatches,1);
 // The same events are accepted on retry, after the rows of the earlier batch.
 assert.deepEqual((await Promise.all(['f-1','f-2','f-3'].map(id=>send(event(id))))).map(a=>a.status),[202,202,202]);
 const {bundle,events}=ledgerEvents(v.store);verifyBundle(bundle,v.store.publicKey);
 assert.deepEqual(events.map(e=>e.id),['n-1','n-3','f-1','f-2','f-3']);
 assert.equal((await v.call('/api/integrity','alpha-admin')).body.valid,true);
});

// The child acknowledges one batch, then dies by SIGKILL after three events of the next batch were written in its transaction.
const KILL_CHILD=`
import {createService} from ${JSON.stringify(new URL('../src/service.mjs',import.meta.url).href)};
import {mac} from ${JSON.stringify(new URL('../src/crypto.mjs',import.meta.url).href)};
import {writeSync} from 'node:fs';import {randomUUID} from 'node:crypto';
const config=JSON.parse(process.env.GC_CONFIG);
const service=createService({dataDir:process.env.GC_DIR,key:process.env.GC_KEY,config,ingestBatch:{maxWaitMs:20,maxEvents:64}});
const agent=config.principals[0];
const ingest=value=>{const body=JSON.stringify(value),stamp=String(Date.now()),nonce=randomUUID();
 return service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+agent.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,
  'x-evid-signature':mac(agent.hmacSecret,stamp,nonce,body)},body).then(()=>writeSync(1,value.id+'\\n'));};
const event=id=>({id,actionId:'act-'+id,traceId:'t',occurredAt:new Date().toISOString(),kind:'intent',actor:'a',tool:'t',action:'read',resource:'r'});
await Promise.all(['a-1','a-2','a-3','a-4','a-5'].map(id=>ingest(event(id))));
const append=service.store.append.bind(service.store);let appended=0;
service.store.append=(...args)=>{const record=append(...args);if(args[1]==='event'&&++appended===3)process.kill(process.pid,'SIGKILL');return record;};
await Promise.all(Array.from({length:8},(_,i)=>ingest(event('b-'+i))));
writeSync(1,'not killed\\n');
`;

test('group commit: a vault killed inside a batch keeps every acknowledged event and none of the batch it was writing',async t=>{
 const dir=scratch(t),{privateKey}=generateKeyPairSync('ed25519'),pem=privateKey.export({format:'pem',type:'pkcs8'});
 const config={principals:[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:'k'.repeat(40),hmacSecret:'h'.repeat(40)},
  {id:'alpha-admin',tenant:'alpha',role:'admin',token:'m'.repeat(40)}]};
 const child=spawnSync(process.execPath,['--input-type=module','-e',KILL_CHILD],
  {env:{...process.env,GC_DIR:dir,GC_KEY:pem,GC_CONFIG:JSON.stringify(config)},encoding:'utf8',timeout:60000});
 assert.equal(child.signal,'SIGKILL',child.stderr);
 const acknowledged=child.stdout.trim().split('\n');assert.deepEqual(acknowledged.sort(),['a-1','a-2','a-3','a-4','a-5']);
 const store=new Store(dir,pem);t.after(()=>store.close());
 const bundle=store.bundle('alpha');verifyBundle(bundle,store.publicKey);
 assert.deepEqual(store.decodeRecords(bundle).map(e=>e.id),['a-1','a-2','a-3','a-4','a-5']);
 assert.equal(bundle.records.filter(r=>r.type==='event'||r.type==='event_receipt').length,10);
 for(const table of ['events','receipts','event_keys','actions'])
  assert.equal(store.db.prepare(`SELECT COUNT(*) n FROM ${table} WHERE tenant='alpha'`).get().n,5,table);
 assert.equal(store.checkActionProjection('alpha').valid,true);
});

test('group commit: SIGKILL of a loaded vault process loses no 202 and leaves every stored event with its receipt',async t=>{
 const h=await harness({vaultOnly:true});t.after(()=>h.close());
 const acknowledged=new Set(),sent=new Map(),sources=['agent','tool','telemetry'];let next=0,killed=false;
 const kinds={agent:'intent',tool:'result',telemetry:'notice'};
 const sendOne=async i=>{
  const kind=sources[i%3],value={...event(`kill-${i}`),kind:kinds[kind]};sent.set(value.id,[kind,value]);
  try{const r=await submit(h.vault.url,h.principal(kind),value,{timeoutMs:15000});if(r.status===202)acknowledged.add(value.id);}catch{}
 };
 const deadline=Date.now()+60000;
 const restart=(async()=>{while(acknowledged.size<60&&Date.now()<deadline)await new Promise(r=>setTimeout(r,2));killed=true;await h.restart();})();
 await Promise.all(Array.from({length:30},async()=>{while(next<300&&!killed)await sendOne(next++);}));
 await restart;
 assert.ok(acknowledged.size>=60,`only ${acknowledged.size} events acknowledged before the kill`);
 const exported=await h.api('/api/export');assert.equal(exported.status,200);
 const bundle=exported.body;verifyBundle(bundle,h.publicKey);
 const stored=new Set(bundle.disclosures.map(d=>d.event.id));
 for(const id of acknowledged)assert.ok(stored.has(id),`acknowledged ${id} missing after SIGKILL`);
 const receipts=new Set(bundle.records.filter(r=>r.type==='event_receipt').map(r=>r.payload.id));
 assert.deepEqual([...stored].sort(),[...receipts].sort());
 const integrity=await h.api('/api/integrity');assert.equal(integrity.body.valid,true,JSON.stringify(integrity.body).slice(0,500));
 // A retry of each acknowledged event is a duplicate after the restart.
 for(const id of [...acknowledged].slice(0,5)){
  const [kind,value]=sent.get(id),retry=await submit(h.vault.url,h.principal(kind),value);
  assert.equal(retry.status,202);assert.equal(retry.body.duplicate,true);
 }
});

test('group commit: pre-batching and batched exports verify with verifyBundle and evidscope-verify; tampering inside a batch is refused',async t=>{
 const dir=scratch(t),fixture=JSON.parse(readFileSync(new URL('./fixtures/pre-group-commit-export-ee068f7.json',import.meta.url),'utf8'));
 assert.equal(fixture.baseCommit,'ee068f7');
 writeFileSync(join(dir,'old.json'),JSON.stringify(fixture.exportBundle));writeFileSync(join(dir,'old.pem'),fixture.publicKeyPem);
 assert.equal(verifyBundle(fixture.exportBundle,fixture.publicKeyPem).valid,true);
 assert.equal(cli(['bundle',join(dir,'old.json'),join(dir,'old.pem')]).status,0);
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:20,maxEvents:64}}}),send=sender(v);
 assert.deepEqual((await Promise.all(Array.from({length:12},(_,i)=>send(event(`b-${i}`))))).map(a=>a.status),Array(12).fill(202));
 assert.equal(v.service.ingestBatch.stats.batches,1);
 const bundle=v.store.exportBundle('alpha'),pem=v.store.publicKey.export({format:'pem',type:'spki'});
 // The vault's first record is its requirement catalog; then event, event_receipt pairs.
 const rows=bundle.records.map((r,i)=>r.type==='event'?i:-1).filter(i=>i>=0),[e1,e2,e3]=[rows[4],rows[5],rows[6]];
 assert.equal(rows.length,12);assert.equal(bundle.checkpoint.count,bundle.records.length);
 writeFileSync(join(dir,'new.json'),JSON.stringify(bundle));writeFileSync(join(dir,'vault.pem'),pem);
 assert.equal(verifyBundle(bundle,pem).valid,true);
 assert.equal(cli(['bundle',join(dir,'new.json'),join(dir,'vault.pem')]).status,0);
 const refused=(mutate,pattern)=>{
  const copy=structuredClone(bundle);mutate(copy);
  assert.throws(()=>verifyBundle(copy,pem),pattern);
  writeFileSync(join(dir,'bad.json'),JSON.stringify(copy));assert.equal(cli(['bundle',join(dir,'bad.json'),join(dir,'vault.pem')]).status,1);
 };
 // Rows inside the batch, which shares one checkpoint signature: each keeps its own hash and chain position.
 refused(b=>{b.records[e1].payload.ciphertext=b.records[e2].payload.ciphertext;},/Record digest mismatch/);
 refused(b=>{[b.records[e1],b.records[e2]]=[b.records[e2],b.records[e1]];},/Sequence, tenant or previous hash mismatch/);
 refused(b=>{b.records.splice(e2,2);},/Sequence, tenant or previous hash mismatch/);
 refused(b=>{b.records.pop();},/Truncated or inconsistent export/);
 refused(b=>{b.disclosures[5].event.resource='kb-2';},/Missing or altered retained event disclosure/);
 refused(b=>{b.records[e1+1].payload.eventHash=b.records[e3+1].payload.eventHash;},/Record digest mismatch/);
});

test('group commit: the wait for others is bounded by the oldest queued event; a full batch commits at once',async t=>{
 const dir=scratch(t),store=new Store(dir,generateKeyPairSync('ed25519').privateKey);t.after(()=>store.close());
 const work=i=>()=>store.append('alpha','note',{i},'unit');
 const timed=async promise=>{const begin=performance.now();await promise;return performance.now()-begin;};
 // maxWaitMs 0: commits at the end of the event-loop turn.
 const now=createGroupCommit({store,maxWaitMs:0});
 assert.ok(await timed(now.submit(null,work(0)))<1000);
 // A lone event waits for others for at most maxWaitMs.
 const bounded=createGroupCommit({store,maxWaitMs:150,maxEvents:1000});
 const lone=await timed(bounded.submit(null,work(1)));assert.ok(lone>=140&&lone<1500,String(lone));
 // Later arrivals do not extend the wait of the first one: a 1 s trickle does not hold it back.
 const begin=performance.now();let firstDone=0;const trickle=[bounded.submit(null,work(2)).then(()=>{firstDone=performance.now()-begin;})];
 for(let i=0;i<40;i++){await new Promise(r=>setTimeout(r,25));trickle.push(bounded.submit(null,work(3+i)));}
 await Promise.all(trickle);
 assert.ok(firstDone>=140&&firstDone<900,String(firstDone));assert.ok(bounded.stats.maxWaitedMs<1000,JSON.stringify(bounded.stats));
 // maxEvents reached: the batch commits without waiting out maxWaitMs.
 const full=createGroupCommit({store,maxWaitMs:2000,maxEvents:4});
 assert.ok(await timed(Promise.all([0,1,2,3].map(i=>full.submit(null,work(100+i)))))<1000);
 assert.ok(await timed(full.submit(null,work(104)))>=1900);
 assert.equal(full.stats.batches,2);
 verifyBundle(store.bundle('alpha'),store.publicKey);
});

test('group commit options: defaults, bounds and refusal of invalid values',()=>{
 assert.deepEqual(ingestBatchOptions({}),{maxWaitMs:INGEST_BATCH_DEFAULTS.maxWaitMs,maxEvents:INGEST_BATCH_DEFAULTS.maxEvents});
 assert.deepEqual(ingestBatchOptions({INGEST_BATCH_MAX_WAIT_MS:'10',INGEST_BATCH_MAX_EVENTS:'1'}),{maxWaitMs:10,maxEvents:1});
 for(const env of [{INGEST_BATCH_MAX_WAIT_MS:'-1'},{INGEST_BATCH_MAX_WAIT_MS:'1001'},{INGEST_BATCH_MAX_WAIT_MS:'2.5'},{INGEST_BATCH_MAX_EVENTS:'0'},
  {INGEST_BATCH_MAX_EVENTS:'4097'},{INGEST_BATCH_MAX_EVENTS:'many'}])assert.throws(()=>ingestBatchOptions(env),/Invalid INGEST_BATCH_/);
 assert.throws(()=>createGroupCommit({store:{},maxEvents:0}),/Invalid group commit bounds/);
});
