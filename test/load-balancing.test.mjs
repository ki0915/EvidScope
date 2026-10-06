const fixtureHost=process.env.EVIDSCOPE_TEST_HOST==='::1'?'::1':'127.0.0.1';
const fixtureUrlHost=fixtureHost==='::1'?'[::1]':fixtureHost;
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {harness} from './harness.mjs';

async function probe(url){const response=await fetch(url,{signal:AbortSignal.timeout(4000)});return {status:response.status,instance:response.headers.get('x-evidscope-instance'),body:await response.json()};}
async function eventually(predicate,timeout=4000){const started=Date.now();while(Date.now()-started<timeout){if(await predicate())return;await new Promise(r=>setTimeout(r,75));}assert.fail('Expected probe state was not reached');}
async function mockVault(t,handler){const server=http.createServer(handler);await new Promise(r=>server.listen(0,fixtureHost,r));t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));return `http://${fixtureUrlHost}:${server.address().port}`;}

test('gateway readiness follows vault loss and recovery while local liveness stays available',async t=>{
 const h=await harness();t.after(()=>h.close());
 const gateway=await h.start('audit',{VAULT_URL:h.vault.url,POD_NAME:'audit-replica-1'}),ingress=await h.start('ingress',{VAULT_URL:h.vault.url,POD_NAME:'ingress-replica-2'});
 assert.equal((await probe(h.vault.url+'/readyz')).status,200);
 for(const server of [gateway,ingress])assert.equal((await probe(server.url+'/readyz')).status,200);
 const port=h.vault.port,exited=new Promise(r=>h.vault.child.once('exit',r));h.vault.child.kill('SIGKILL');await exited;
 for(const server of [gateway,ingress]){
  await eventually(async()=>(await probe(server.url+'/readyz')).status===503);
  const alive=await probe(server.url+'/healthz');assert.equal(alive.status,200);assert.ok(alive.instance);
  const notReady=await probe(server.url+'/readyz');assert.deepEqual(notReady.body,{status:'not_ready',component:server===gateway?'audit':'ingress'});
 }
 assert.equal((await h.api('/api/overview',{base:gateway.url})).status,503);
 await h.start('vault',{PORT:String(port)});
 for(const server of [gateway,ingress])await eventually(async()=>(await probe(server.url+'/readyz')).status===200);
 assert.equal((await h.api('/api/overview',{base:gateway.url})).status,200);
});

test('serving gateway identity is bounded and cannot be replaced by request or upstream headers',async t=>{
 const h=await harness();t.after(()=>h.close());let code=200;
 const base=await mockVault(t,(_req,res)=>{res.setHeader('x-evidscope-instance','untrusted-upstream');res.setHeader('content-type','application/json');res.statusCode=code;res.end(JSON.stringify({status:'ready',component:'vault'}));});
 const raw='audit\r\ninjected: bad/'+ 'x'.repeat(200),expected=raw.replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,120),gateway=await h.start('audit',{VAULT_URL:base,POD_NAME:raw});
 for(const status of [200,409,503]){code=status;const response=await fetch(gateway.url+'/api/overview',{headers:{'x-evidscope-instance':'request-forged'}});assert.equal(response.status,status);assert.equal(response.headers.get('x-evidscope-instance'),expected);await response.body.cancel();}
 const denied=await probe(gateway.url+'/api/ingest');assert.equal(denied.status,403);assert.equal(denied.instance,expected);
 const unnamed=await h.start('audit',{VAULT_URL:base,POD_NAME:''});assert.equal((await probe(unnamed.url+'/healthz')).instance,null);
});

test('readiness requests coalesce, cache briefly, validate the upstream result and time out',async t=>{
 const h=await harness();t.after(()=>h.close());let calls=0,status=200,body={status:'ready',component:'vault'},delay=100;
 const base=await mockVault(t,(req,res)=>{assert.equal(req.url,'/healthz');assert.equal(req.headers.authorization,undefined);calls++;setTimeout(()=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(body));},delay);});
 const gateway=await h.start('ingress',{VAULT_URL:base,POD_NAME:'ingress-coalesced'});
 const burst=await Promise.all(Array.from({length:30},()=>probe(gateway.url+'/readyz')));assert.ok(burst.every(r=>r.status===200));assert.equal(calls,1);
 assert.equal((await probe(gateway.url+'/readyz')).status,200);assert.equal(calls,1);
 await new Promise(r=>setTimeout(r,550));body={status:'ready',component:'audit'};
 assert.equal((await probe(gateway.url+'/readyz')).status,503);assert.equal(calls,2);
 await new Promise(r=>setTimeout(r,550));status=503;body={status:'ready',component:'vault'};assert.equal((await probe(gateway.url+'/readyz')).status,503);
 await new Promise(r=>setTimeout(r,550));status=200;delay=2500;const start=Date.now();assert.equal((await probe(gateway.url+'/readyz')).status,503);assert.ok(Date.now()-start<2200,'Readiness dependency timeout must stay within 2 seconds plus test transport overhead');
 assert.equal((await probe(gateway.url+'/healthz')).status,200);
});

test('worker liveness is local but readiness requires a successful analysis tick',async t=>{
 const h=await harness();t.after(()=>h.close());
 const notVault=await mockVault(t,(_req,res)=>{res.writeHead(503,{'content-type':'application/json'});res.end('{"error":"synthetic unavailable"}');});
 const worker=await h.start('worker',{VAULT_URL:notVault,WORKER_TOKEN:h.config.principals.find(p=>p.role==='worker').token,POD_NAME:'worker-unready'});
 assert.equal((await probe(worker.url+'/healthz')).status,200);assert.equal((await probe(worker.url+'/readyz')).status,503);
 const readyWorker=await h.start('worker',{VAULT_URL:h.vault.url,WORKER_TOKEN:h.config.principals.find(p=>p.role==='worker').token,POD_NAME:'worker-ready'});
 await eventually(async()=>(await probe(readyWorker.url+'/readyz')).status===200);
 assert.equal((await probe(readyWorker.url+'/api/overview')).status,403);
});

test('shutdown cannot turn an in-flight dependency probe into a ready response',async t=>{
 const h=await harness();t.after(()=>h.close());let reached;
 const started=new Promise(r=>{reached=r;});
 const base=await mockVault(t,(_req,res)=>{reached();setTimeout(()=>{res.writeHead(200,{'content-type':'application/json'});res.end('{"status":"ready","component":"vault"}');},500);});
 const gateway=await h.start('audit',{VAULT_URL:base,POD_NAME:'audit-stopping'}),request=probe(gateway.url+'/readyz');await started;
 gateway.child.send('shutdown');const response=await request;assert.equal(response.status,503);assert.equal(response.body.status,'not_ready');assert.equal(response.instance,'audit-stopping');
});
