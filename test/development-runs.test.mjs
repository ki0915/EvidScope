import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {Store} from '../src/store.mjs';
import {mac} from '../src/crypto.mjs';
import {createDevelopmentRuns} from '../src/development-runs.mjs';
import {collectCodexEvent,collectClaudeStreamEvent,collectClaudeStreamEvents} from '../src/development-collectors.mjs';
import {harness} from './harness.mjs';

test('development run HTTP boundary permits signed ingress and human audit reads only',async t=>{
 const h=await harness();t.after(()=>h.close());const tool=h.principal('tool'),auditor=h.principal('auditor'),timestamp=String(Date.now()),nonce='http-boundary-nonce-0001',body=JSON.stringify({eventId:'http-event-1',eventName:'run.started',runId:'http-run-1',teamId:'team-http',roleId:'core',model:'gpt-5.6-sol',modelObserved:true,status:'running',occurredAt:new Date().toISOString(),toolName:'unknown'}),headers={'content-type':'application/json',authorization:`Bearer ${tool.token}`,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':mac(tool.hmacSecret,timestamp,nonce,body)};
 let response=await fetch(`${h.ingress.url}/api/development-runs/events`,{method:'POST',headers,body});assert.equal(response.status,202);assert.equal((await response.json()).accepted,true);
 response=await fetch(`${h.audit.url}/api/development-runs/events`,{method:'POST',headers,body});assert.equal(response.status,403,'audit gateway cannot proxy source writes');
 response=await fetch(`${h.audit.url}/api/development-runs`,{headers:{authorization:`Bearer ${auditor.token}`}});assert.equal(response.status,200);const result=await response.json();assert.equal(result.items.length,1);assert.equal(result.items[0].modelEvidence,'actual_observed');
 response=await fetch(`${h.audit.url}/api/development-runs`,{headers:{authorization:`Bearer ${tool.token}`}});assert.equal(response.status,403,'source cannot read human development view');
 response=await fetch(`${h.ingress.url}/api/development-runs`,{headers:{authorization:`Bearer ${auditor.token}`}});assert.equal(response.status,403,'ingress gateway cannot proxy reads');
});

test('development runs: signed tenant source binding, duplicate/collision, unknowns and minimization',t=>{
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs/dev-runs-')),config=initialize(dir),store=new Store(join(dir,'data'),readFileSync(join(dir,'signing-private.pem'),'utf8')),now=Date.parse('2026-09-09T01:00:00Z'),runs=createDevelopmentRuns(store,{now:()=>now});t.after(()=>store.close());
 const tool=config.principals.find(p=>p.tenant==='alpha'&&p.kind==='tool'),agent=config.principals.find(p=>p.tenant==='alpha'&&p.kind==='agent'),auditor=config.principals.find(p=>p.tenant==='alpha'&&p.role==='auditor'),beta=config.principals.find(p=>p.tenant==='beta'&&p.role==='auditor');let nonce=0;
 const send=(principal,event,overrideBody)=>{const body=overrideBody||JSON.stringify(event),timestamp=String(now),n=`nonce-${String(++nonce).padStart(16,'0')}`;return runs.handle(principal,'POST',new URL('http://local/api/development-runs/events'),{'x-evid-timestamp':timestamp,'x-evid-nonce':n,'x-evid-signature':mac(principal.hmacSecret,timestamp,n,body)},body);};
 const base={eventId:'e1',eventName:'run.started',runId:'run-1',teamId:'team-a',roleId:'core',model:'gpt-5.6-sol',modelObserved:true,status:'running',occurredAt:'2026-09-09T00:59:59Z',toolName:'unknown'};
 assert.deepEqual(send(tool,base),{accepted:true,duplicate:false,late:false});assert.deepEqual(send(tool,base),{accepted:true,duplicate:true,late:false});assert.throws(()=>send(tool,{...base,status:'failed'}),e=>e.status===409);
 send(tool,{...base,eventId:'e2',eventName:'usage.observed',status:'running',streamSequence:2,timeBasis:'replayed_unknown',usage:{inputTokens:10,cacheCreationInputTokens:2,cacheReadInputTokens:3,outputTokens:4},occurredAt:'2026-09-09T00:00:00Z'});
 send(tool,{...base,eventId:'e3',eventName:'run.completed',status:'completed',streamSequence:3,artifacts:[{name:'report',kind:'test-report',path:'reports/dev.json'}]});
 send(agent,{...base,eventId:'a1',modelObserved:true});
 assert.throws(()=>send(tool,{...base,eventId:'e4',teamId:'forged-team'}),e=>e.status===409);assert.throws(()=>send(tool,{...base,eventId:'raw',prompt:'secret'}),e=>e.status===400);assert.throws(()=>send(tool,{...base,eventId:'self-parent',runId:'same',parentRunId:'same'}),e=>e.status===400);
 const result=runs.handle(auditor,'GET',new URL('http://local/api/development-runs'));assert.equal(result.items.length,2);const observed=result.items.find(v=>v.source===tool.id);assert.equal(observed.id,`${tool.id}:run-1`);assert.equal(observed.modelEvidence,'actual_observed');assert.equal(observed.status,'completed');assert.equal(observed.usage.totalTokens,19);assert.equal(observed.lateEventCount,0);assert.equal(result.coverage.actualModelObserved,1);assert.equal(runs.handle(beta,'GET',new URL('http://local/api/development-runs')).items.length,0);assert.throws(()=>runs.handle(tool,'GET',new URL('http://local/api/development-runs')),e=>e.status===403);
});

test('collectors ignore content and preserve external status, order, model and cached usage metadata',()=>{
 const context={runId:'r',teamId:'t',roleId:'ui'};
 assert.equal(collectCodexEvent({type:'item.completed',item:{type:'reasoning',text:'private reasoning'}},{...context,sequence:1}),null);
 const failed=collectCodexEvent({type:'item.completed',item:{id:'item-1',type:'command_execution',command:'secret-command',exit_code:7,status:'failed'}},{...context,sequence:2});assert.equal(failed.eventName,'tool.failed');assert.equal(failed.toolName,'shell');assert.ok(!JSON.stringify(failed).includes('secret-command'));
 const other=collectCodexEvent({type:'item.completed',item:{type:'command_execution',exit_code:0}},{...context,sequence:3});assert.equal(other.eventId,'codex-3');assert.notEqual(other.eventId,failed.eventId);
 const claude=collectClaudeStreamEvent({type:'result',uuid:'result-1',subtype:'success',is_error:true,terminal_reason:'rate_limit',total_cost_usd:99,message:{content:'private'},modelUsage:{'claude-sonnet-5':{}},usage:{input_tokens:5,cache_creation_input_tokens:2,cache_read_input_tokens:7,output_tokens:1}},{...context,sequence:4});assert.equal(claude.eventName,'run.failed');assert.equal(claude.model,'claude-sonnet-5');assert.deepEqual(claude.usage,{inputTokens:5,cacheCreationInputTokens:2,cacheReadInputTokens:7,outputTokens:1});assert.equal(claude.timeBasis,'collector_received');assert.ok(!JSON.stringify(claude).includes('total_cost_usd'));assert.ok(!JSON.stringify(claude).includes('private'));
 const names=new Map(),started=collectClaudeStreamEvents({type:'assistant',uuid:'assistant-1',message:{model:'claude-sonnet-5',content:[{type:'thinking',thinking:'private'},{type:'text',text:'private'},{type:'tool_use',id:'tool-1',name:'Read',input:{file_path:'secret'}}]}},{...context,sequence:5000,toolNames:names});assert.equal(started.length,1);assert.equal(started[0].toolName,'file_read');names.set(started[0].eventId,started[0].toolName);const completed=collectClaudeStreamEvents({type:'user',uuid:'user-1',message:{content:[{type:'tool_result',tool_use_id:'tool-1',content:'private result'}]}},{...context,sequence:6000,toolNames:names});assert.equal(completed[0].toolName,'file_read');assert.ok(!JSON.stringify([...started,...completed]).includes('secret'));assert.ok(!JSON.stringify([...started,...completed]).includes('private'));
});
