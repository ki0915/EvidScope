import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,mkdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {monitoring} from '../src/monitoring.mjs';
import {mac} from '../src/crypto.mjs';
import {randomUUID} from 'node:crypto';

function fixture(t){mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs/monitor-'));const config=initialize(dir),s=createService({dataDir:join(dir,'data'),config,key:readFileSync(join(dir,'signing-private.pem'),'utf8')});t.after(()=>s.store.close());return {s,config};}
test('monitoring: receipt buckets, tenant/source boundaries, missing statuses and partial bucket',t=>{
 const {s,config}=fixture(t),now=Date.parse('2026-09-08T09:00:05Z'),start=now-3545000;
 const put=(id,received,extra={})=>{const e={tenant:'alpha',source:'alpha-tool',sourceKind:'tool',id,kind:'result',status:'failure',receivedAt:new Date(received).toISOString(),actionId:id,traceId:id,fingerprint:id,...extra};s.store.project(e);};
 put('before',start-1);put('first',start);put('last',now,{status:'success',occurredAt:'2001-01-01T00:00:00Z'});put('future',now+1);
 put('other-tenant',now,{tenant:'beta',source:'beta-tool'});put('claim',now,{source:'alpha-agent',sourceKind:'agent'});put('unknown',now,{status:undefined});put('gap',now,{kind:'gap',source:'alpha-telemetry',sourceKind:'telemetry'});
 const data=monitoring(s.store,config.principals,'alpha',new URLSearchParams(),now);
 assert.equal(data.points.length,60);assert.equal(data.points[0].received,1);assert.equal(data.points.at(-1).received,4);assert.equal(data.points.at(-1).success,1);assert.equal(data.points.at(-1).failure,0);assert.equal(data.points.at(-1).unknown,1);assert.equal(data.points.at(-1).gaps,1);assert.equal(data.points.at(-1).partial,true);
 assert.equal(data.sources.length,5);assert.ok(data.sources.every(s=>s.id.startsWith('alpha-')));
 const filtered=monitoring(s.store,config.principals,'alpha',new URLSearchParams({source:'alpha-tool'}),now);assert.equal(filtered.points.at(-1).received,2);
 for(const [range,length,bucket,refresh] of [['10m',20,30000,30000],['1h',60,60000,60000],['24h',288,300000,300000],['7d',168,3600000,900000]]){const result=monitoring(s.store,config.principals,'alpha',new URLSearchParams({range}),now);assert.equal(result.points.length,length);assert.equal(result.bucketMs,bucket);assert.equal(result.refreshMs,refresh);}
 for(const query of ['range=invalid','range=__proto__','source=beta-tool'])assert.throws(()=>monitoring(s.store,config.principals,'alpha',new URLSearchParams(query),now),e=>e.status===400);
 s.store.db.prepare('DELETE FROM events WHERE tenant=?').run('alpha');assert.ok(monitoring(s.store,config.principals,'alpha',new URLSearchParams(),now).points.every(p=>p.received===0));
});
test('monitoring API: human-only, tenant isolated, signed ingest and dedup reflected without audit-read inflation',async t=>{
 const {s,config}=fixture(t),principal=(role,tenant='alpha')=>config.principals.find(p=>p.tenant===tenant&&(p.role===role||p.kind===role));
 const call=(role,tenant='alpha')=>s.handle('GET',new URL('http://localhost/api/monitoring'),{authorization:'Bearer '+principal(role,tenant)?.token});
 await assert.rejects(call('agent'),e=>e.status===403);await assert.rejects(call('worker'),e=>e.status===401);
 const p=principal('tool'),body=JSON.stringify({id:'monitor-result',actionId:'monitor-action',traceId:'monitor-trace',kind:'result',status:'failure',occurredAt:'2020-01-01T00:00:00Z'});
 async function ingest(){const ts=String(Date.now()),nonce=randomUUID();return s.handle('POST',new URL('http://localhost/api/ingest'),{authorization:'Bearer '+p.token,'x-evid-timestamp':ts,'x-evid-nonce':nonce,'x-evid-signature':mac(p.hmacSecret,ts,nonce,body)},body);}
 assert.equal((await ingest()).duplicate,false);assert.equal((await ingest()).duplicate,true);
 for(let i=0;i<2;i++){const data=await call('auditor');assert.equal(data.points.reduce((n,p)=>n+p.received,0),1);assert.equal(data.points.reduce((n,p)=>n+p.failure,0),1);assert.ok(!JSON.stringify(data).includes('monitor-action'));}
 assert.equal((await call('auditor','beta')).points.reduce((n,p)=>n+p.received,0),0);
 const worker=config.principals.find(p=>p.role==='worker');await assert.rejects(s.handle('GET',new URL('http://localhost/api/monitoring'),{authorization:'Bearer '+worker.token}),e=>e.status===403);
});
