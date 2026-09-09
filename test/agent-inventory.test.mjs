import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {policyState,agentInventory} from '../src/agent-inventory.mjs';
import {digest} from '../src/crypto.mjs';
const version={version:1,analyzed:1},event={sourceKind:'tool',kind:'execution',policyVersion:'p1'};
const evaluation=(findings=[])=>({version:1,status:'evaluated',authority:'matched_at_event_time',findings,coverage:{totalFindings:findings.length,truncated:false}});
test('agent policy: missing/pending/partial/exception cannot become compliant; tool failure is separate',()=>{
 assert.equal(policyState([event],evaluation(),version).state,'compliant');
 assert.equal(policyState([{...event,kind:'result',status:'failure'}],evaluation(),version).state,'compliant');
 assert.equal(policyState([event],evaluation([{code:'DESTINATION_OUTSIDE_POLICY'}]),version).state,'violation');
 for(const code of ['AUTHORITY_MISSING','APPROVAL_MISMATCH','POLICY_CONTEXT_UNVERIFIED','COLLECTION_GAP'])assert.equal(policyState([event],evaluation([{code}]),version).state,'unconfirmed');
 assert.equal(policyState([event],evaluation([{code:'CUSTOM:x:v1',suppressedBy:'exception'}]),version).state,'exception');
 assert.equal(policyState([event],evaluation(),{version:2,analyzed:1}).state,'pending');
 assert.equal(policyState([],evaluation(),version).state,'unconfirmed');assert.equal(policyState([event],evaluation(),version,{ambiguous:true}).state,'unconfirmed');
 assert.equal(policyState([event],{...evaluation(),coverage:{totalFindings:10,truncated:true}},version).state,'unconfirmed');
 assert.equal(policyState([event],evaluation([{code:'FUTURE_POLICY_CODE'}]),version).state,'unconfirmed');
});
test('agent inventory: identities, full denominator, zero-data source, tenant and human access boundaries',async t=>{
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs/agent-')),config=initialize(dir),s=createService({dataDir:join(dir,'data'),config,key:readFileSync(join(dir,'signing-private.pem'),'utf8')});t.after(()=>s.store.close());
 function put(id,findings=[],extra={}){const base={tenant:'alpha',actor:'same-name',actionId:id,traceId:id,receivedAt:new Date().toISOString(),policyVersion:'p1'};s.store.project({...base,id:id+'a',source:'alpha-agent',sourceKind:'agent',kind:'intent',fingerprint:id+'a',...extra});s.store.project({...base,id:id+'t',source:'alpha-tool',sourceKind:'tool',kind:'execution',fingerprint:id+'t'});s.store.db.prepare('INSERT INTO actions VALUES(?,?,?,?)').run('alpha',id,1,1);const e={...evaluation(findings),actionId:id};s.store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run('alpha',id,1,JSON.stringify(e));}
 put('ok');put('bad',[{code:'CUSTOM:policy:v1'}]);put('missing',[{code:'AUTHORITY_MISSING'}]);put('exception',[{code:'CUSTOM:policy:v1',suppressedBy:'x'}]);put('pending');s.store.db.prepare('UPDATE actions SET version=2 WHERE id=?').run('pending');
 let result=agentInventory(s.store,config.principals,'alpha',new URLSearchParams());let agent=result.items[0];assert.equal(result.total,1);assert.equal(agent.actions,5);assert.equal(agent.compliance.percent,50);assert.equal(agent.compliance.denominator,2);assert.equal(agent.compliance.coveragePercent,40);assert.equal(agent.reviews.unreviewed,5);
 put('ambiguous');s.store.project({tenant:'alpha',actor:'same-name',actionId:'ambiguous',traceId:'ambiguous',receivedAt:new Date().toISOString(),id:'second-agent',source:'second-agent',sourceKind:'agent',kind:'intent',fingerprint:'second'});
 result=agentInventory(s.store,config.principals,'alpha',new URLSearchParams());assert.equal(result.total,2);assert.notEqual(result.items[0].id,result.items[1].id);
 const detail=agentInventory(s.store,config.principals,'alpha',new URLSearchParams({id:agent.id}));assert.equal(detail.item.details.find(d=>d.actionId==='ambiguous').state,'unconfirmed');
 const beta=agentInventory(s.store,config.principals,'beta',new URLSearchParams());assert.equal(beta.items[0].actions,0);assert.equal(beta.items[0].compliance.percent,null);
 assert.throws(()=>agentInventory(s.store,config.principals,'beta',new URLSearchParams({id:agent.id})),e=>e.status===404);
 for(const query of ['offset=-1','limit=101','limit=NaN'])assert.throws(()=>agentInventory(s.store,config.principals,'alpha',new URLSearchParams(query)),e=>e.status===400);
 const source=config.principals.find(p=>p.id==='alpha-agent');await assert.rejects(s.handle('GET',new URL('http://localhost/api/agents'),{authorization:'Bearer '+source.token}),e=>e.status===403);
 const auditor=config.principals.find(p=>p.id==='alpha-auditor');assert.equal((await s.handle('GET',new URL('http://localhost/api/agents?q=same-name'),{authorization:'Bearer '+auditor.token})).total,2);
 const contextHash=digest({tenant:'alpha',actionId:'ok',events:s.store.events('alpha','ok'),evaluations:s.store.evaluations('alpha','ok'),analysis:version});
 s.store.db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('alpha','case_decision','decision',JSON.stringify({actionId:'ok',contextHash,conclusion:'no_issue_found',nextReviewAt:new Date(Date.now()+60000).toISOString()}));
 assert.equal(agentInventory(s.store,config.principals,'alpha',new URLSearchParams({id:agent.id})).item.reviews.reviewed,1);
 s.store.db.prepare('UPDATE actions SET version=2 WHERE id=?').run('ok');assert.equal(agentInventory(s.store,config.principals,'alpha',new URLSearchParams({id:agent.id})).item.reviews.stale,1);
});
