import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],
 generative:false,highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',
 suppliedPurpose:'Loan assistance',substantialModification:false};
const rule={id:'rule-one',title:'Original rule',field:'note',op:'eq',value:'original',severity:'high'};

function fixture(t,options={}){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-verified-reads-'));
 const principals=[{id:'reviewer',role:'reviewer',tenant:'alpha',token:'r'.repeat(40)},{id:'admin',role:'admin',tenant:'alpha',token:'a'.repeat(40)},
  {id:'source',role:'source',kind:'tool',tenant:'alpha',token:'s'.repeat(40),hmacSecret:'h'.repeat(40)}];
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements,...options}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,who=0)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
  {authorization:'Bearer '+principals[who].token},body===undefined?'':JSON.stringify(body));
 const status=(path,body,who)=>call(path,body,who).then(()=>200,error=>error.status);
 async function ingest(id,actionId='action-one'){
  const raw={id,actionId,traceId:'trace',kind:'result',status:'success',occurredAt:new Date().toISOString(),note:'original'};
  const body=JSON.stringify(raw),timestamp=String(Date.now()),nonce=randomUUID();
  const headers={authorization:'Bearer '+principals[2].token,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,
   'x-evid-signature':mac(principals[2].hmacSecret,timestamp,nonce,body)};
  return service.handle('POST',new URL('/api/ingest','http://local'),headers,body);
 }
 const ledgerRows=()=>store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n;
 return {dir,service,store,principals,call,status,ingest,ledgerRows};
}
async function populated(t,options){
 const h=fixture(t,options);
 await h.ingest('event-one');await h.call('/api/rules',rule);
 const first=await h.call('/api/cases',{title:'First',actionId:'action-one',owner:'reviewer'});
 const second=await h.call('/api/cases',{title:'Second',actionId:'action-one',owner:'reviewer'});
 await h.call(`/api/cases/${first.id}`,{comment:'later update of the first case'});
 await h.call('/api/governance/systems',system);
 const bytes=Buffer.from('control document');
 await h.call('/api/governance/documents',{id:'control',systemId:'credit',name:'control.txt',mediaType:'text/plain',
  sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')});
 return {...h,first,second};
}
const reads=['/api/cases','/api/rules','/api/exceptions','/api/assets','/api/governance','/api/events','/api/overview','/api/alerts',
 '/api/agents','/api/metrics'];

test('policy reads keep first-signed order with latest values and return copies that cannot alter the verified state',async t=>{
 const h=await populated(t),cases=(await h.call('/api/cases')).items;
 assert.deepEqual(cases.map(c=>c.id),[h.first.id,h.second.id],'an update keeps the first-signed position');
 assert.equal(cases[0].comments.length,1,'latest signed value');
 assert.deepEqual(cases,h.store.ledgerObjects('alpha','case'),'same result as a full signed-ledger scan');
 const copy=h.store.cachedPolicyObjects('alpha','case').values[0].body;copy.title='mutated by a caller';copy.comments.push({text:'injected'});
 const evaluations=h.store.cachedEvaluations('alpha').values;for(const value of evaluations)value.findings?.push({code:'injected'});
 const events=h.store.cachedEvents('alpha');events[0].note='mutated';
 assert.deepEqual((await h.call('/api/cases')).items,cases);
 assert.equal((await h.call('/api/events')).items[0].note,'original');
 assert.ok(!JSON.stringify(await h.call('/api/alerts')).includes('injected'));
 assert.equal((await h.call('/api/integrity')).valid,true);
});

test('warm verified-state reads do not rescan the signed ledger',async t=>{
 const h=await populated(t);for(const path of reads)await h.call(path);
 const original=h.store.verifiedRows.bind(h.store);let scans=0;
 h.store.verifiedRows=function*(...args){scans++;yield* original(...args);};
 for(const path of reads)await h.call(path);
 assert.equal(scans,0,'policy objects, evaluations, events and governance documents come from the incremental verified state');
 await h.ingest('event-two');await h.call('/api/rules',{...rule,title:'Second version'});
 for(const path of reads)await h.call(path);
 assert.equal(scans,0,'new signed rows are verified as a suffix, not by a rescan');
});

test('a projection fault fails only the readers that serve from that projection',async t=>{
 const h=await populated(t);
 const healthy=async(paths,label)=>{for(const path of paths)assert.equal(await h.status(path),200,`${label}: ${path}`);};
 const rejected=async(paths,label)=>{for(const path of paths)assert.equal(await h.status(path),409,`${label}: ${path}`);};
 const eventRow=h.store.db.prepare("SELECT source,id,body FROM events WHERE tenant='alpha'").get();
 const setEvent=body=>h.store.db.prepare('UPDATE events SET body=? WHERE tenant=? AND source=? AND id=?').run(body,'alpha',eventRow.source,eventRow.id);
 setEvent(JSON.stringify({...JSON.parse(eventRow.body),note:'forged'}));
 await rejected(['/api/events','/api/overview','/api/monitoring'],'event projection');
 await healthy(['/api/cases','/api/rules','/api/governance'],'event projection');
 setEvent(eventRow.body);
 await healthy(reads,'restored event projection');

 const caseRow=h.store.db.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='case' AND id=?").get(h.first.id);
 const setCase=body=>h.store.db.prepare("UPDATE objects SET body=? WHERE tenant='alpha' AND type='case' AND id=?").run(body,h.first.id);
 setCase(JSON.stringify({...JSON.parse(caseRow.body),owner:'forged'}));
 await rejected(['/api/cases','/api/overview'],'case projection');
 await healthy(['/api/rules','/api/events','/api/governance'],'case projection');
 setCase(caseRow.body);

 const documentRow=h.store.db.prepare("SELECT body FROM governance_documents WHERE tenant='alpha' AND id='control'").get();
 const setDocument=body=>h.store.db.prepare("UPDATE governance_documents SET body=? WHERE tenant='alpha' AND id='control'").run(body);
 setDocument(JSON.stringify({...JSON.parse(documentRow.body),displayName:'forged.txt'}));
 await rejected(['/api/governance','/api/governance/documents/control'],'governance document projection');
 await healthy(['/api/cases','/api/rules','/api/events','/api/overview'],'governance document projection');
 const before=h.ledgerRows();
 assert.equal((await h.ingest('event-three')).accepted,true,'evidence intake does not depend on the governance document projection');
 assert.equal(h.ledgerRows(),before+2);
 setDocument(documentRow.body);
 await healthy([...reads,'/api/governance/documents/control'],'restored projections');
});

test('the verified state reports when it was verified and is rebuilt cold after its maximum age or for integrity',async t=>{
 const h=await populated(t,{verifiedStateMaxAgeMs:200});
 const metrics=await h.call('/api/metrics');assert.equal(metrics.verifiedState.tenant,'alpha');assert.equal(metrics.verifiedState.maxAgeMs,200);
 assert.ok(Date.parse(metrics.verifiedState.verifiedAt)<=Date.now());assert.deepEqual(metrics.verifiedState.faults,[]);
 // An edit that bypassed every invalidation signal (as a raw file write would) is served from the cached signed state until the
 // maximum age elapses, then found by the forced cold verification.
 const rule=h.store.db.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='rule'").get(),serial=h.store.projectionMutationSerial;
 const unsignalled=sql=>{
  h.store.db.prepare(sql).run(JSON.stringify({...JSON.parse(rule.body),title:'forged'}));
  h.store.projectionMutationSerial=serial;
  h.store.observedProjectionMutationClock=h.store.db.prepare('SELECT serial FROM projection_mutation_clock WHERE id=1').get().serial;
 };
 unsignalled("UPDATE objects SET body=? WHERE tenant='alpha' AND type='rule'");
 assert.equal((await h.call('/api/rules')).items[0].title,'Original rule','served from the signed state, never from the altered row');
 await new Promise(resolve=>setTimeout(resolve,250));
 assert.equal(await h.status('/api/rules'),409);
 h.store.db.prepare("UPDATE objects SET body=? WHERE tenant='alpha' AND type='rule'").run(rule.body);
 assert.equal(await h.status('/api/rules'),200);
 const integrity=await h.call('/api/integrity'),cold=integrity.verifiedState.coldVerifications;
 assert.equal(integrity.valid,true);assert.deepEqual(integrity.verifiedState.faults,[]);
 unsignalled("UPDATE objects SET body=? WHERE tenant='alpha' AND type='rule'");h.store.actionProjectionCache.get('alpha').mutationSerial=serial;
 const detected=await h.call('/api/integrity');
 assert.equal(detected.valid,false,'integrity always re-verifies cold');assert.match(detected.error,/Object projection/);
 h.store.db.prepare("UPDATE objects SET body=? WHERE tenant='alpha' AND type='rule'").run(rule.body);
 const again=await h.call('/api/integrity');assert.equal(again.valid,true);assert.ok(again.verifiedState.coldVerifications>cold);
});

test('development run events are verified incrementally and their projection fault stays scoped',async t=>{
 const h=fixture(t),source=h.principals[2];
 const send=async(eventId,eventName)=>{
  const body=JSON.stringify({eventId,eventName,runId:'run-one',teamId:'team-one',roleId:'role-one',status:eventName==='run.completed'?'completed':'running',
   occurredAt:new Date().toISOString(),toolName:'unknown'}),timestamp=String(Date.now()),nonce=randomUUID();
  const headers={authorization:'Bearer '+source.token,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,
   'x-evid-signature':mac(source.hmacSecret,timestamp,nonce,body)};
  return h.service.handle('POST',new URL('/api/development-runs/events','http://local'),headers,body);
 };
 await send('event-0','run.started');
 const original=h.store.verifiedRows.bind(h.store);let scans=0;
 h.store.verifiedRows=function*(...args){scans++;yield* original(...args);};
 for(let i=1;i<20;i++)await send('event-'+i,i===19?'run.completed':'agent.started');
 assert.equal(scans,0,'each development event verifies only the new suffix');
 assert.equal((await h.call('/api/development-runs')).items[0].eventCount,20);
 h.store.db.prepare("UPDATE development_run_events SET run_id='forged' WHERE tenant='alpha' AND event_id='event-3'").run();
 assert.equal(await h.status('/api/development-runs'),409);
 assert.equal(await h.status('/api/cases'),200);assert.equal(await h.status('/api/overview'),200);
});
