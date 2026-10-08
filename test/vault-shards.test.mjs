// Tenant shards (round 7, src/vault-tenants.mjs, docs/performance.md stage 3): several vaults, each owning disjoint tenants,
// behind gateways that route by credential. A tenant is never written by two vaults.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {mac,verifyBundle} from '../src/crypto.mjs';
import {createService} from '../src/service.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {claimTenants,routeKey,shardConfig,vaultRouter,vaultTenants} from '../src/vault-tenants.mjs';

const token=s=>s.repeat(40).slice(0,40);
const principals=[
 {id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('a1'),hmacSecret:token('h1')},
 {id:'beta-agent',tenant:'beta',role:'source',kind:'agent',token:token('b1'),hmacSecret:token('h2')},
 {id:'alpha-admin',tenant:'alpha',role:'admin',token:token('m1')},{id:'beta-admin',tenant:'beta',role:'admin',token:token('m2')},
 {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha','beta'],token:token('w1')}];
const temp=t=>{const dir=mkdtempSync(join(tmpdir(),'evidscope-shard-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;};
const event=id=>({id,actionId:'act-'+id,traceId:'trace-'+id,occurredAt:new Date().toISOString(),kind:'intent',actor:'a',tool:'t',action:'read',resource:'r'});
async function ingest(service,p,value){
 const body=JSON.stringify(value),stamp=String(Date.now()),nonce=randomUUID();
 try{return {status:202,body:await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+p.token,'x-evid-timestamp':stamp,
  'x-evid-nonce':nonce,'x-evid-signature':mac(p.hmacSecret,stamp,nonce,body)},body)};}
 catch(error){if(!error.status)throw error;return {status:error.status,body:{error:error.message}};}
}

test('shard configuration: tenant list, served credentials, worker scope and routes',()=>{
 assert.equal(vaultTenants(undefined),null);assert.equal(vaultTenants(''),null);
 assert.deepEqual([...vaultTenants('alpha, beta')],['alpha','beta']);
 for(const bad of ['alpha,alpha','alpha,','a b','../x,'])assert.throws(()=>vaultTenants(bad),/Invalid VAULT_TENANTS/);
 const served=shardConfig({principals},new Set(['beta']));
 assert.deepEqual(served.principals.map(p=>p.id),['beta-agent','beta-admin','analysis-worker']);
 assert.deepEqual(served.principals.at(-1).tenants,['beta'],'a worker keeps only the owned part of its tenant list');
 assert.equal(shardConfig({principals},null).principals.length,principals.length);
 assert.throws(()=>shardConfig({principals,oidc:{enabled:true}},new Set(['alpha'])),/OIDC/);
 const dir=mkdtempSync(join(tmpdir(),'evidscope-routes-')),file=join(dir,'routes.json');
 try{
  writeFileSync(file,JSON.stringify({vaults:{alpha:'http://127.0.0.1:1001',beta:'http://127.0.0.1:1002'},credentials:{[routeKey(token('b1'))]:'beta'}}));
  const route=vaultRouter(file,'http://127.0.0.1:1000');
  assert.equal(route('Bearer '+token('b1')),'http://127.0.0.1:1002');assert.equal(route('Bearer '+token('a1')),'http://127.0.0.1:1000');
  assert.equal(route(undefined),'http://127.0.0.1:1000');assert.equal(vaultRouter(undefined,'http://x')('Bearer y'),'http://x');
  writeFileSync(file,JSON.stringify({vaults:{alpha:'http://10.0.0.5:1'}}));
  assert.throws(()=>vaultRouter(file,'http://127.0.0.1:1',{allowed:url=>url.hostname==='127.0.0.1'}),/Invalid VAULT_ROUTES_FILE/);
  writeFileSync(file,JSON.stringify({vaults:{alpha:'http://127.0.0.1:1'},credentials:{[routeKey('x')]:'gamma'}}));
  assert.throws(()=>vaultRouter(file,'http://127.0.0.1:1'),/Invalid VAULT_ROUTES_FILE credential/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});

test('shards in process: each vault serves and writes only its tenants; a tenant claimed by one database is refused to another',async t=>{
 const registry=join(temp(t),'registry'),key=generateKeyPairSync('ed25519').privateKey,a=temp(t),b=temp(t);
 const vaultA=createService({dataDir:a,key,config:{principals},tenants:new Set(['alpha']),tenantRegistryDir:registry});t.after(()=>vaultA.store.close());
 const vaultB=createService({dataDir:b,key,config:{principals},tenants:new Set(['beta']),tenantRegistryDir:registry});
 const [alpha,beta]=principals;
 assert.equal((await ingest(vaultA,alpha,event('a-1'))).status,202);assert.equal((await ingest(vaultB,beta,event('b-1'))).status,202);
 // A credential of another tenant is unknown to a shard; the ledger of another tenant cannot be appended to.
 assert.equal((await ingest(vaultA,beta,event('b-2'))).status,401);assert.equal((await ingest(vaultB,alpha,event('a-2'))).status,401);
 assert.throws(()=>vaultA.store.append('beta','note',{},'test'),error=>error.status===421);
 assert.deepEqual(vaultA.store.db.prepare('SELECT DISTINCT tenant FROM ledger').all().map(r=>r.tenant),['alpha']);
 assert.deepEqual(vaultB.store.db.prepare('SELECT DISTINCT tenant FROM ledger').all().map(r=>r.tenant),['beta']);
 // The shared worker credential analyzes each shard's own tenant there.
 const worker=principals.at(-1);
 for(const service of [vaultA,vaultB]){const {jobs}=service.analysis.claim(worker);assert.equal(jobs.length,1);
  for(const job of jobs)service.analysis.commit(worker,{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});}
 for(const [service,tenant] of [[vaultA,'alpha'],[vaultB,'beta']])verifyBundle(service.store.exportBundle(tenant),service.store.publicKey);
 vaultB.store.close();
 // Another database cannot take a tenant the registry gives to vault A, alone or as part of an unsharded vault.
 assert.throws(()=>createService({dataDir:temp(t),key,config:{principals},tenants:new Set(['alpha']),tenantRegistryDir:registry}),/owned by another vault/);
 assert.throws(()=>createService({dataDir:temp(t),key,config:{principals},tenantRegistryDir:registry}),/owned by another vault/);
 // Vault B's own database takes its tenant back after a restart; it cannot drop a tenant whose history it holds.
 const again=createService({dataDir:b,key,config:{principals},tenants:new Set(['beta']),tenantRegistryDir:registry});again.store.close();
 assert.throws(()=>createService({dataDir:b,key,config:{principals},tenants:new Set(['gamma']),tenantRegistryDir:registry}),/ledger history of tenant beta/);
 assert.throws(()=>createService({dataDir:b,key,config:{principals}}),/belongs to a tenant shard/);
 // claimTenants on its own: an unreadable registry entry is a refusal, not a silent takeover.
 const db=new DatabaseSync(join(temp(t),'x.db'));t.after(()=>db.close());db.exec('CREATE TABLE ledger(tenant TEXT,seq INTEGER)');
 const other=join(temp(t),'registry');claimTenants(db,{owned:new Set(['delta']),registryDir:other});
 const entry=join(other,(await import('node:crypto')).createHash('sha256').update('delta').digest('hex')+'.owner');writeFileSync(entry,'{');
 assert.throws(()=>claimTenants(db,{owned:new Set(['delta']),registryDir:other}),/unreadable/);
});

test('shards behind one ingress: events route to the vault of their tenant; a misrouted credential is refused, never written',async t=>{
 const registry=join(temp(t),'registry'),saved={VAULT_TENANTS:process.env.VAULT_TENANTS,VAULT_TENANT_REGISTRY_DIR:process.env.VAULT_TENANT_REGISTRY_DIR};
 process.env.VAULT_TENANTS='alpha';process.env.VAULT_TENANT_REGISTRY_DIR=registry;
 let h;try{h=await harness({vaultOnly:true});}finally{for(const [k,v] of Object.entries(saved))if(v===undefined)delete process.env[k];else process.env[k]=v;}
 t.after(()=>h.close());
 const vaultB=await h.start('vault',{DATA_DIR:join(h.dir,'data-beta'),VAULT_TENANTS:'beta',VAULT_TENANT_REGISTRY_DIR:registry});
 const credentials=Object.fromEntries(h.config.principals.filter(p=>['alpha','beta'].includes(p.tenant)).map(p=>[routeKey(p.token),p.tenant]));
 const routes=join(h.dir,'routes.json');writeFileSync(routes,JSON.stringify({vaults:{alpha:h.vault.url,beta:vaultB.url},credentials}));
 const ingress=await h.start('ingress',{VAULT_URL:h.vault.url,VAULT_ROUTES_FILE:routes});
 const send=(base,tenant,id)=>submit(base,h.principal('agent',tenant),event(id),{timeoutMs:10000});
 const sent=await Promise.all(['alpha','beta'].flatMap(tenant=>Array.from({length:6},(_,i)=>send(ingress.url,tenant,`${tenant}-${i}`))));
 assert.ok(sent.every(r=>r.status===202),JSON.stringify(sent.map(r=>r.status)));
 const exported=async(base,tenant)=>(await h.api('/api/export',{base,role:'admin',tenant})).body;
 const alpha=await exported(h.vault.url,'alpha'),beta=await exported(vaultB.url,'beta');
 assert.equal(alpha.records.filter(r=>r.type==='event').length,6);assert.equal(beta.records.filter(r=>r.type==='event').length,6);
 verifyBundle(alpha,h.publicKey);verifyBundle(beta,h.publicKey);
 assert.equal((await h.api('/api/export',{base:vaultB.url,role:'admin',tenant:'alpha'})).status,401,'vault B does not serve tenant alpha');
 // A routes file that sends beta's credential to vault A: vault A refuses it and writes nothing for beta.
 const misrouted={...credentials,[routeKey(h.principal('agent','beta').token)]:'alpha'};
 writeFileSync(routes,JSON.stringify({vaults:{alpha:h.vault.url,beta:vaultB.url},credentials:misrouted}));
 const wrong=await h.start('ingress',{VAULT_URL:h.vault.url,VAULT_ROUTES_FILE:routes});
 assert.equal((await send(wrong.url,'beta','beta-x')).status,401);
 assert.equal((await exported(h.vault.url,'alpha')).records.filter(r=>r.tenant==='beta').length,0);
 assert.equal((await exported(vaultB.url,'beta')).records.filter(r=>r.type==='event').length,6);
});
