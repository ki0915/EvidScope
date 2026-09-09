import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {agentInventory} from '../src/agent-inventory.mjs';

test('agent operations: time boundaries, complete evidence, exact trend totals, focus and pagination',t=>{
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs/agent-ops-')),config=initialize(dir),s=createService({dataDir:join(dir,'data'),config,key:readFileSync(join(dir,'signing-private.pem'),'utf8')});t.after(()=>s.store.close());
 const now=Date.parse('2026-09-08T12:00:00Z'),day=86400000;
 const query=values=>agentInventory(s.store,config.principals,'alpha',new URLSearchParams(values),now);
 function put(id,at,{actor='agent-a',findings=[],toolAt=at,source='alpha-agent'}={}){
  const base={tenant:'alpha',actor,actionId:id,traceId:id,policyVersion:'p1'};
  s.store.project({...base,id:id+'a',source,sourceKind:'agent',kind:'intent',receivedAt:new Date(at).toISOString(),fingerprint:id+'a'});
  s.store.project({...base,id:id+'t',source:'alpha-tool',sourceKind:'tool',kind:'execution',receivedAt:new Date(toolAt).toISOString(),fingerprint:id+'t'});
  s.store.db.prepare('INSERT INTO actions VALUES(?,?,?,?)').run('alpha',id,1,1);
  const e={actionId:id,version:1,status:'evaluated',authority:'matched_at_event_time',findings,coverage:{totalFindings:findings.length,truncated:false}};
  s.store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run('alpha',id,1,JSON.stringify(e));
 }
 put('outside',now-day-1);put('start',now-day,{toolAt:now-2*day});put('end',now);put('future',now+1);
 put('bad',now-1000,{actor:'agent-b',findings:[{code:'CUSTOM:p:v1'}]});put('unknown',now-1000,{actor:'agent-c',findings:[{code:'AUTHORITY_MISSING'}]});
 const list=query({range:'24h'}),a=list.items.find(a=>a.actor==='agent-a');assert.equal(a.actions,2);assert.equal(a.compliance.percent,100);
 const detail=query({range:'24h',id:a.id});assert.equal(detail.trend.length,24);assert.equal(detail.item.details.find(a=>a.actionId==='start').state,'compliant');assert.equal(detail.trend.reduce((n,p)=>n+p.actions,0),2);assert.equal(detail.trend[0].actions,1);assert.equal(detail.trend.at(-1).actions,1);
 for(const p of detail.trend)assert.equal(Object.values(p.counts).reduce((a,b)=>a+b,0),p.actions);
 assert.equal(query({range:'24h',focus:'violation'}).items[0].actor,'agent-b');assert.equal(query({range:'24h',focus:'unconfirmed'}).items[0].actor,'agent-c');assert.equal(query({range:'24h',sort:'attention'}).items[0].actor,'agent-b');assert.equal(query({range:'24h',sort:'coverage'}).items[0].actor,'agent-c');
 assert.equal(query({range:'24h',q:'agent-b',focus:'unconfirmed'}).total,0);assert.equal(query({range:'24h',q:'agent-b',focus:'unconfirmed'}).summary.violation,1);
 const first=query({range:'24h',limit:'1'}),second=query({range:'24h',limit:'1',offset:'1'});assert.notEqual(first.items[0].id,second.items[0].id);assert.equal(first.total,3);
 assert.equal(query({range:'7d',id:a.id}).item.actions,3);assert.equal(query({range:'30d',id:a.id}).trend.length,30);
 put('inactive',now-31*day,{actor:'old-agent'});assert.equal(query({range:'30d',focus:'inactive'}).items[0].actor,'old-agent');
 for(let i=0;i<105;i++)put('many-'+i,now-2000,{actor:'many'});
 const many=query({range:'24h',q:'many'}).items[0];assert.equal(query({range:'24h',id:many.id}).item.details.length,105);
 s.store.project({tenant:'alpha',id:'unattributed',source:'alpha-tool',sourceKind:'tool',kind:'execution',actionId:'unattributed',traceId:'u',receivedAt:new Date(now).toISOString(),fingerprint:'u'});
 assert.equal(query({range:'24h'}).unattributedActions,1);
 const beta=agentInventory(s.store,config.principals,'beta',new URLSearchParams({range:'24h'}),now);assert.equal(beta.items[0].actions,0);assert.equal(beta.items[0].compliance.percent,null);
 const anchored=query({range:'24h',id:a.id,end:new Date(now-1).toISOString()});assert.equal(anchored.item.actions,2);assert.equal(anchored.item.details.some(d=>d.actionId==='end'),false);
 for(const values of [{range:'1s'},{range:'constructor'},{focus:'invalid'},{sort:'invalid'},{end:'invalid'},{end:new Date(now+1).toISOString()}])assert.throws(()=>query(values),e=>e.status===400);
 assert.throws(()=>agentInventory(s.store,config.principals,'beta',new URLSearchParams({id:a.id,range:'24h'}),now),e=>e.status===404);
});
