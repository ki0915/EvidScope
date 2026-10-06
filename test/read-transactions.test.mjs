import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const principals=[{id:'admin',role:'admin',tenant:'alpha',token:'a'.repeat(40)},{id:'reviewer',role:'reviewer',tenant:'alpha',token:'r'.repeat(40)},
 {id:'source',role:'source',kind:'tool',tenant:'alpha',token:'s'.repeat(40),hmacSecret:'h'.repeat(40)}];
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,
 highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'Loan assistance',
 substantialModification:false};

async function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-read-tx-'));
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,who=0)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals[who].token},
  body===undefined?'':JSON.stringify(body));
 const source=principals[2],ingest=async id=>{
  const body=JSON.stringify({id,actionId:'action-one',traceId:'trace',kind:'result',status:'success',occurredAt:new Date().toISOString()});
  const timestamp=String(Date.now()),nonce=randomUUID();
  return service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+source.token,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,
   'x-evid-signature':mac(source.hmacSecret,timestamp,nonce,body)},body);
 };
 await ingest('event-one');
 const created=await call('/api/cases',{title:'Case',actionId:'action-one',owner:'reviewer'});
 await call('/api/rules',{id:'rule-one',title:'Rule',field:'note',op:'eq',value:'x',severity:'low'});
 await call('/api/governance/systems',system);
 const bytes=Buffer.from('control document');
 await call('/api/governance/documents',{id:'control',systemId:'credit',name:'control.txt',mediaType:'text/plain',
  sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')});
 // Records every statement the service runs on the evidence connection and the query_only state at each BEGIN.
 const log=[],exec=store.db.exec.bind(store.db);
 store.db.exec=sql=>{if(/^BEGIN/.test(sql))log.push({sql,queryOnly:store.db.prepare('PRAGMA query_only').get().query_only});return exec(sql);};
 return {dir,service,store,call,ingest,caseId:created.id,log};
}
const ledger=store=>store.db.prepare('SELECT COUNT(*) n FROM ledger').get().n;

test('every GET runs in deferred read snapshots under query_only and appends nothing to the ledger',async t=>{
 const h=await fixture(t);
 await h.call('/api/assistance/profiles');
 const paths=['/api/cases','/api/rules','/api/exceptions','/api/assets','/api/events','/api/overview','/api/alerts','/api/agents','/api/metrics',
  '/api/monitoring','/api/model-runtime','/api/governance','/api/governance/report?systemId=credit','/api/governance/documents/control','/api/retention',
  '/api/investigations','/api/actions/action-one',`/api/cases/${h.caseId}/review-context`,`/api/cases/${h.caseId}/report`,'/api/development-runs',
  '/api/assistance/profiles','/api/assistance/requirements','/api/assistance/packages','/api/assistance/runs','/api/audit/reads'];
 const count=ledger(h.store),checkpoint=h.store.checkpoint('alpha');
 for(const path of paths){
  h.log.length=0;await h.call(path);
  // Assistance GETs first check, in a separate read snapshot, whether a signed upgrade or expiry is due (none is here).
  const expected=path==='/api/assistance/runs'?3:['/api/assistance/profiles','/api/assistance/packages'].includes(path)?2:1;
  assert.deepEqual(h.log,Array(expected).fill({sql:'BEGIN DEFERRED',queryOnly:1}),`${path} is served from one read snapshot under query_only`);
  assert.equal(h.store.db.prepare('PRAGMA query_only').get().query_only,0,`${path} restores write access for the next request`);
 }
 assert.equal(ledger(h.store),count);assert.deepEqual(h.store.checkpoint('alpha'),checkpoint);
 h.log.length=0;await h.call('/api/rules',{id:'rule-two',title:'Rule two',field:'note',op:'eq',value:'y',severity:'low'},1);
 assert.deepEqual(h.log.map(entry=>entry.sql),['BEGIN IMMEDIATE'],'writes stay writer-exclusive');assert.equal(ledger(h.store),count+1);
});

test('a GET handler cannot write, and a failed GET leaves the connection writable',async t=>{
 const h=await fixture(t),count=ledger(h.store),read=h.store.events.bind(h.store);
 h.store.events=(...args)=>{h.store.db.prepare("INSERT INTO counters VALUES('forbidden',1)").run();return read(...args);};
 await assert.rejects(h.call('/api/events'),/readonly database/);
 h.store.events=(...args)=>{h.store.put(principals[0],'rule','sneaky',{id:'sneaky'});return read(...args);};
 await assert.rejects(h.call('/api/events'),/Read-only request cannot append/);
 h.store.events=read;
 assert.equal(h.store.db.prepare("SELECT COUNT(*) n FROM counters WHERE name='forbidden'").get().n,0);assert.equal(ledger(h.store),count);
 assert.equal(h.store.db.isTransaction,false);assert.equal(h.store.readOnlyRequest,false);
 assert.equal((await h.ingest('event-two')).accepted,true,'the next write succeeds');assert.equal(ledger(h.store),count+2);
});

test('due assistance maintenance runs in its own write transaction before the read; when nothing is due no write lock is taken',async t=>{
 const h=await fixture(t),count=ledger(h.store);
 h.log.length=0;const first=await h.call('/api/assistance/profiles');
 assert.ok(first.items.every(profile=>profile.version===2),'the signed model-policy upgrade is visible to the first read');
 assert.deepEqual(h.log.map(entry=>entry.sql),['BEGIN DEFERRED','BEGIN IMMEDIATE','BEGIN DEFERRED']);assert.equal(ledger(h.store),count+first.items.length);
 h.log.length=0;assert.deepEqual(await h.call('/api/assistance/profiles'),first);
 assert.ok(h.log.every(entry=>entry.sql==='BEGIN DEFERRED'),JSON.stringify(h.log));assert.equal(ledger(h.store),count+first.items.length);
});
