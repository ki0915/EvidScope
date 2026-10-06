import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';
import {canonical} from '../src/crypto.mjs';

const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'credit assistance',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'candidate'};
const requirement={id:'KR-34-RISK',title:'Risk management'};
const assessment={systemId:'credit',requirementId:requirement.id,applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',control:'Synthetic review',owner:'reviewer',reason:'Evidence reviewed',nextReviewAt:'2099-01-01T00:00:00.000Z',evidence:[{type:'document',ref:'external-reference',version:'1'}]};
async function fixture(t){
 const principals=['alpha','beta'].map(tenant=>({id:tenant+'-reviewer',tenant,role:'reviewer',token:tenant.repeat(40)}));
 const service=createService({dataDir:mkdtempSync(join(tmpdir(),'evidscope-assessment-')),key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements:[requirement]});t.after(()=>service.store.close());
 const call=(path,body,tenant='alpha')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant).token},body===undefined?'':JSON.stringify(body));
 const store=service.store;for(const p of principals)await call('/api/governance/systems',system,p.tenant);
 const records=()=>canonical(store.db.prepare('SELECT tenant,seq,body,hash FROM ledger ORDER BY tenant,seq').all());
 return {store,call,records,principals};
}
for(const mutation of ['body','id','missing','injected'])test(`assessment does not seal ${mutation} system projection`,async t=>{
 const h=await fixture(t),db=h.store.db;
 if(mutation==='body')db.prepare("UPDATE objects SET body=json_set(body,'$.purpose','forged purpose') WHERE tenant='alpha' AND type='system'").run();
 if(mutation==='id')db.prepare("UPDATE objects SET id='other' WHERE tenant='alpha' AND type='system'").run();
 if(mutation==='missing')db.prepare("DELETE FROM objects WHERE tenant='alpha' AND type='system'").run();
 if(mutation==='injected')db.prepare("INSERT INTO objects(tenant,type,id,body) VALUES('alpha','system','extra',?)").run(JSON.stringify({...system,id:'extra'}));
 const before=h.records();await assert.rejects(h.call('/api/governance/assessments',assessment),e=>e.status===409);assert.equal(h.records(),before);
 assert.equal((await h.call('/api/governance/assessments',assessment,'beta')).systemId,'credit');
});
test('unsigned event projection cannot become signed assessment evidence',async t=>{
 const h=await fixture(t),event={tenant:'alpha',source:'alpha-agent',id:'forged',actionId:'action',traceId:'trace',kind:'intent',receivedAt:'2026-09-28T00:00:00.000Z',fingerprint:'fake'};
 h.store.project(event);const before=h.records();
 await assert.rejects(h.call('/api/governance/assessments',{...assessment,evidence:[{type:'event',ref:'alpha-agent/forged'}]}),e=>[400,409].includes(e.status));assert.equal(h.records(),before);
});
test('signed event content determines evidence hash; projection changes cannot certify different bytes',async t=>{
 const h=await fixture(t),p=h.principals[0],event={tenant:p.tenant,source:'alpha-agent',id:'real',actionId:'action',traceId:'trace',kind:'intent',receivedAt:'2026-09-28T00:00:00.000Z',fingerprint:'synthetic',note:'signed original'};
 h.store.transaction(()=>{const r=h.store.append(p.tenant,'event',event,p.id);h.store.project({...event,seq:r.seq,hash:r.hash});});
 const input={...assessment,evidence:[{type:'event',ref:'alpha-agent/real',contentHash:'attacker-supplied'}]};
 const saved=await h.call('/api/governance/assessments',input);assert.match(saved.evidence[0].contentHash,/^[a-f0-9]{64}$/);assert.equal(saved.evidence[0].verification,'linked_verified_minimized_record');
 h.store.db.prepare("UPDATE events SET body=json_set(body,'$.note','forged') WHERE tenant='alpha'").run();const before=h.records();
 await assert.rejects(h.call('/api/governance/assessments',input),e=>e.status===409);assert.equal(h.records(),before);
});
for(const type of ['system','assessment','governance_task'])test(`governance report refuses forged ${type} projection`,async t=>{
 const h=await fixture(t);await h.call('/api/governance/assessments',{...assessment,legalReview:'pending'});
 h.store.db.prepare("UPDATE objects SET body=json_set(body,'$.owner','forged') WHERE tenant='alpha' AND type=?").run(type);
 await assert.rejects(h.call('/api/governance/report?systemId=credit'),e=>e.status===409);
 const unaffected=await h.call('/api/governance/report?systemId=credit',undefined,'beta');assert.equal(unaffected.system.id,'credit');
});
