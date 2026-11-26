// Ingest throughput stage 2 (round 6, docs/performance.md): the verified state carried over a write transaction's own rows,
// tampering between transactions still found before the next write, and the gateway's node:http upstream.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import http from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {vault} from './event-key-vault.mjs';
import {canonical,mac,verifyBundle} from '../src/crypto.mjs';
import {Store} from '../src/store.mjs';
import {createGroupCommit} from '../src/ingest-batch.mjs';
import {upstreamRequest} from '../src/upstream-http.mjs';
import {main as verifyCli} from '../src/verify-cli.mjs';

const event=(id,extra={})=>({id,actionId:'act-'+id,traceId:'trace-s2',occurredAt:new Date().toISOString(),kind:'intent',actor:'s2-agent',tool:'s2-tool',
 action:'read',resource:'kb-1',note:'stage two',...extra});
function sender(v){
 const agent=v.principal('alpha-agent');
 return async(value,{nonce=randomUUID()}={})=>{
  const body=JSON.stringify(value),stamp=String(Date.now());
  try{return {status:202,body:await v.service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+agent.token,'x-evid-timestamp':stamp,
   'x-evid-nonce':nonce,'x-evid-signature':mac(agent.hmacSecret,stamp,nonce,body)},body)};}
  catch(error){return {status:error.status||500,body:{error:error.message}};}
 };
}
const batch=(send,prefix,n)=>Promise.all(Array.from({length:n},(_,i)=>send(event(`${prefix}-${i}`))));
// Everything a verified state answers from, in a comparable form.
const summary=state=>canonical({count:state.count,head:state.head,events:[...state.eventsBySequence],actions:state.action.rows(),keys:[...state.keys],
 eventKeys:[...state.eventKeys],receipts:[...state.receiptEntries],covered:[...state.receiptCovered].sort((a,b)=>a-b),evaluations:state.evaluations,
 objects:[...state.objects.keys()],faults:[...state.faults.keys()]});
function coldSummary(store,tenant='alpha'){
 const state=store._coldActionState(tenant,store.checkpoint(tenant));store._verifyActionState(tenant,state);return summary(state);
}
const ledgerCount=store=>store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n;
// Counts work the next transaction would do to re-verify rows: ledger rows read back as a suffix and events decrypted.
function spy(store){
 const counts={opened:0,suffixRows:0,cold:0},open=store._openEvent.bind(store);
 const suffix=store._verifiedActionSuffix.bind(store),cold=store._coldActionState.bind(store);
 store._openEvent=(...args)=>{counts.opened++;return open(...args);};
 store._verifiedActionSuffix=(...args)=>{const rows=suffix(...args);counts.suffixRows+=rows.length;return rows;};
 store._coldActionState=(...args)=>{counts.cold++;return cold(...args);};
 return counts;
}

test('verified state: a write transaction carries it over its own rows, so the next one decrypts and reads back nothing; it equals a cold replay',async t=>{
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:5,maxEvents:64}}}),send=sender(v);
 assert.ok((await batch(send,'warm',5)).every(r=>r.status===202));
 const counts=spy(v.store),retried=event('retried');
 assert.equal((await send(retried)).status,202);
 for(let round=0;round<4;round++)assert.ok((await batch(send,'r'+round,12)).every(r=>r.status===202));
 // A retry is a duplicate and a replayed nonce is refused inside a batch; both leave the carried state exact.
 const nonce=randomUUID(),[dup,first,replay]=await Promise.all([send(retried),send(event('n-1'),{nonce}),send(event('n-2'),{nonce})]);
 assert.equal(dup.body.duplicate,true);assert.equal(first.status,202);assert.equal(replay.status,409);
 assert.deepEqual(counts,{opened:0,suffixRows:0,cold:0},'no event of an earlier batch is decrypted or read back to start the next one');
 const status=v.store.verifiedStateStatus('alpha');assert.equal(status.cached,true);assert.equal(status.count,ledgerCount(v.store));
 assert.equal(summary(v.store.actionProjectionCache.get('alpha')),coldSummary(v.store));
 const counter=name=>v.store.db.prepare('SELECT value FROM counters WHERE name=?').get(name)?.value;
 assert.deepEqual([counter('accepted'),counter('duplicates')],[5+1+48+1,1],'counted once per batch for the events whose savepoints were kept');
 const integrity=await v.call('/api/integrity','alpha-admin');assert.equal(integrity.body.valid,true);
 assert.equal((await v.call('/api/events?limit=100','alpha-admin')).body.items.length,5+1+48+1);
});

test('verified state: rows changed after their transaction by another SQLite connection are found before the next write',async t=>{
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:5,maxEvents:64}}}),send=sender(v);
 await batch(send,'a',6);
 const other=new DatabaseSync(join(v.dir,'evidence.db'));t.after(()=>other.close());other.exec('PRAGMA busy_timeout=5000');
 // 1. The search projection of an event the last batch wrote.
 const row=other.prepare("SELECT body FROM events WHERE tenant='alpha' AND id='a-5'").get();
 other.prepare("UPDATE events SET body=? WHERE tenant='alpha' AND id='a-5'").run(JSON.stringify({...JSON.parse(row.body),note:'forged'}));
 let before=ledgerCount(v.store),refused=await batch(send,'b',3);
 assert.deepEqual(refused.map(r=>r.status),[409,409,409]);assert.match(refused[0].body.error,/이벤트 조회 사본/);assert.equal(ledgerCount(v.store),before);
 other.prepare("UPDATE events SET body=? WHERE tenant='alpha' AND id='a-5'").run(row.body);
 assert.ok((await batch(send,'c',3)).every(r=>r.status===202));
 // 2. The newest ledger row, rewritten with a consistent hash by a writer that removes the append-only trigger.
 const head=other.prepare("SELECT seq,body FROM ledger WHERE tenant='alpha' ORDER BY seq DESC LIMIT 1").get();
 const forged=head.body.replace('"recordedAt":"','"recordedAt":"1');
 other.exec('DROP TRIGGER immutable_update');
 other.prepare("UPDATE ledger SET body=?,hash=? WHERE tenant='alpha' AND seq=?").run(forged,createHash('sha256').update(forged).digest('hex'),head.seq);
 before=ledgerCount(v.store);refused=await batch(send,'d',2);
 assert.deepEqual(refused.map(r=>r.status),[409,409]);assert.equal(ledgerCount(v.store),before);
 assert.equal((await v.call('/api/integrity','alpha-admin')).body.valid,false);
});

test('verified state: a write of the vault connection outside projectionMutation to a just-written row is found before the next write',async t=>{
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:5,maxEvents:64}}}),send=sender(v);
 await batch(send,'a',4);
 const row=v.store.db.prepare("SELECT body FROM events WHERE tenant='alpha' AND id='a-3'").get();
 v.store.db.prepare("UPDATE events SET body=? WHERE tenant='alpha' AND id='a-3'").run(JSON.stringify({...JSON.parse(row.body),note:'forged'}));
 const before=ledgerCount(v.store),refused=await batch(send,'b',2);
 assert.deepEqual(refused.map(r=>r.status),[409,409]);assert.equal(ledgerCount(v.store),before);
});

test('verified state: a batch that fails at COMMIT time leaves no carried state for its rows; later batches carry it again exactly',async t=>{
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:5,maxEvents:64}}}),send=sender(v);
 await batch(send,'a',4);
 // The checkpoint is signed after the state was carried over: without the signing key the whole batch rolls back.
 const key=v.store.key;v.store.key='not a signing key';
 const failed=await batch(send,'f',3);v.store.key=key;
 assert.deepEqual(failed.map(r=>r.status),[500,500,500]);
 const status=v.store.verifiedStateStatus('alpha');assert.ok(!status.cached||status.count===ledgerCount(v.store),'never a state past the committed head');
 assert.ok((await batch(send,'f',3)).every(r=>r.status===202));
 const counts=spy(v.store);
 assert.ok((await batch(send,'g',5)).every(r=>r.status===202));
 assert.deepEqual(counts,{opened:0,suffixRows:0,cold:0});
 assert.equal(summary(v.store.actionProjectionCache.get('alpha')),coldSummary(v.store));
 const exported=v.store.exportBundle('alpha');verifyBundle(exported,v.store.publicKey);
});

test('verified state: an item that fails after appending rolls back alone; the next batch starts warm; the carried state is exact',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-stage2-')),store=new Store(dir,generateKeyPairSync('ed25519').privateKey);
 t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
 const group=createGroupCommit({store,maxWaitMs:20,begin:()=>store.checkActionProjection('alpha')});
 const append=i=>()=>store.append('alpha','note',{i},'unit');
 await group.submit(null,append(0));
 const counts=spy(store);
 const settled=await Promise.allSettled([group.submit(null,append(1)),group.submit(null,()=>{append(2)();throw Error('refused after writing');}),
  group.submit(null,append(3))]);
 assert.deepEqual(settled.map(r=>r.status),['fulfilled','rejected','fulfilled']);
 const state=store.actionProjectionCache.get('alpha');assert.equal(state.count,3);assert.equal(state.head,store.checkpoint('alpha').head);
 assert.deepEqual(counts,{opened:0,suffixRows:0,cold:0},'the undone writes do not read as a write outside projectionMutation');
 assert.equal(summary(state),coldSummary(store));
});

test('exports: an 8b3af6c export still verifies, and a stage-2 export has the same record shapes and verifies with both verifiers',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-stage2-export-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const cli=(file,pem)=>{writeFileSync(join(dir,'b.json'),JSON.stringify(file));writeFileSync(join(dir,'k.pem'),pem);
  return verifyCli(['bundle',join(dir,'b.json'),join(dir,'k.pem')],{stdout:{write(){}},stderr:{write(){}}});};
 const fixture=JSON.parse(readFileSync(new URL('./fixtures/pre-stage2-export-8b3af6c.json',import.meta.url),'utf8'));
 assert.equal(fixture.baseCommit,'8b3af6c');
 assert.equal(verifyBundle(fixture.exportBundle,fixture.publicKeyPem).valid,true);assert.equal(cli(fixture.exportBundle,fixture.publicKeyPem),0);
 const v=vault(t,{options:{ingestBatch:{maxWaitMs:5,maxEvents:64}}}),send=sender(v),first=event('x-0');
 assert.ok((await Promise.all([send(first),...Array.from({length:7},(_,i)=>send(event('x-'+(i+1))))])).every(r=>r.status===202));
 assert.equal((await send(first)).body.duplicate,true);
 const bundle=v.store.exportBundle('alpha'),pem=v.store.publicKey.export({format:'pem',type:'spki'});
 assert.equal(verifyBundle(bundle,pem).valid,true);assert.equal(cli(bundle,pem),0);
 const keys=value=>canonical(Object.keys(value).sort()),shapes=b=>{
  const out={disclosure:keys(b.disclosures[0]),top:keys(b),checkpoint:keys(b.checkpoint)};
  for(const r of b.records)if(['event','event_receipt'].includes(r.type))out[r.type]=keys(r)+keys(r.payload);
  return out;
 };
 assert.deepEqual(shapes(bundle),shapes(fixture.exportBundle));
});

function server(t,handler){
 return new Promise(resolve=>{const s=http.createServer(handler);
  s.listen(0,'127.0.0.1',()=>{t.after(()=>{s.closeAllConnections();s.close();});resolve({s,url:`http://127.0.0.1:${s.address().port}`});});});
}
test('gateway upstream: redirects come back unfollowed, the deadline covers the body, oversized answers and other schemes are refused',async t=>{
 const seen=[];
 const {url}=await server(t,(req,res)=>{
  seen.push({method:req.method,path:req.url,cookie:req.headers.cookie,length:req.headers['content-length'],socket:req.socket.remotePort});
  if(req.url==='/redirect'){res.writeHead(302,{location:'/elsewhere','set-cookie':['a=1','b=2']});res.end('{}');return;}
  if(req.url==='/slow'){res.writeHead(200);res.write('{');return;}
  if(req.url==='/large'){res.end('x'.repeat(5000));return;}
  let body='';req.on('data',c=>body+=c);req.on('end',()=>res.end(JSON.stringify({echo:body})));
 });
 const redirect=await upstreamRequest(new URL('/redirect',url),{method:'GET',headers:{cookie:''},timeoutMs:2000});
 assert.equal(redirect.status,302);assert.equal(redirect.headers.location,'/elsewhere');assert.deepEqual(redirect.headers['set-cookie'],['a=1','b=2']);
 assert.equal(seen.filter(s=>s.path==='/elsewhere').length,0);
 const posted=await upstreamRequest(new URL('/api/ingest',url),{method:'POST',headers:{'content-type':'application/json'},body:'{"é":1}',timeoutMs:2000});
 assert.equal(JSON.parse(posted.body.toString('utf8')).echo,'{"é":1}');assert.equal(seen.at(-1).length,String(Buffer.byteLength('{"é":1}')));
 const started=Date.now();await assert.rejects(upstreamRequest(new URL('/slow',url),{timeoutMs:300}));assert.ok(Date.now()-started<2000);
 await assert.rejects(upstreamRequest(new URL('/large',url),{timeoutMs:2000,maxBytes:1000}),/too large/);
 await assert.rejects(upstreamRequest(new URL('file:///etc/passwd'),{timeoutMs:1000}),/http or https/);
 // Keep-alive: consecutive calls reuse one connection.
 const before=seen.length;for(let i=0;i<5;i++)await upstreamRequest(new URL('/api/ingest',url),{method:'POST',body:'{}',timeoutMs:2000});
 assert.equal(new Set(seen.slice(before).map(s=>s.socket)).size,1);
});
