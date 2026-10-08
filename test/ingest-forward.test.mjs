// Ingress-to-vault envelopes (round 6, docs/performance.md): every source still gets the answer /api/ingest would give, a 202
// only after the COMMIT that holds its event, and a gateway in front of an older vault falls back to one call per event.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {mac,verifyBundle} from '../src/crypto.mjs';
import {createForwardCoalescer,forwardedIngest,INGEST_FORWARD_FORMAT,INGEST_FORWARD_HEADER,INGEST_FORWARD_MAX_EVENTS} from '../src/ingest-forward.mjs';

const event=(id,extra={})=>({id,actionId:'act-'+id,traceId:'trace-fw',occurredAt:new Date().toISOString(),kind:'intent',actor:'fw-agent',tool:'fw-tool',
 action:'read',resource:'kb-1',...extra});
const envelope=items=>JSON.stringify({format:INGEST_FORWARD_FORMAT,items});
const statusOf=promise=>promise.then(()=>200,error=>error.status);

test('vault envelope: each item runs as its own /api/ingest with the envelope bearer and its own signature headers, in order',async()=>{
 const seen=[],ingest=async(headers,body)=>{seen.push({headers,body});const value=JSON.parse(body);
  if(value.fail)throw Object.assign(Error(value.fail),{status:409});if(value.crash)throw Error('disk');return {accepted:true,id:value.id};};
 const headers={'x-evid-timestamp':'1','x-evid-nonce':'n','x-evid-signature':'s','cookie':'ignored','x-other':'ignored'};
 let admitted=0,logged=0;
 const out=await forwardedIngest(ingest,{authorization:'Bearer t'},envelope([{headers,body:'{"id":"a"}'},{headers,body:'{"id":"b","fail":"conflict"}'},
  {headers,body:'{"id":"c","crash":1}'},{headers:{},body:'x'.repeat(16385)}]),{admit:n=>{admitted=n;},log:()=>logged++});
 assert.equal(admitted,4);assert.equal(logged,1);
 assert.deepEqual(out.items.map(item=>item.status),[202,409,503,413]);
 assert.deepEqual(out.items[0].body,{accepted:true,id:'a'});assert.equal(out.items[1].body.error,'conflict');
 assert.doesNotMatch(out.items[2].body.error,/disk/,'internal errors are not disclosed');
 assert.deepEqual(seen[0].headers,{authorization:'Bearer t','x-evid-timestamp':'1','x-evid-nonce':'n','x-evid-signature':'s'});
 assert.equal(seen.length,3,'an oversized item never reaches the route');
 for(const bad of ['{',envelope([]),JSON.stringify({format:'other',items:[{headers:{},body:'{}'}]}),envelope([{headers:{},body:{}}]),
  envelope([{headers:{'x-evid-nonce':1},body:'{}'}]),envelope(Array.from({length:INGEST_FORWARD_MAX_EVENTS+1},()=>({headers:{},body:'{}'})))])
  assert.equal(await statusOf(forwardedIngest(ingest,{},bad)),400);
 assert.equal(await statusOf(forwardedIngest(ingest,{},envelope([{headers:{},body:'{}'}]),{admit:()=>{throw Object.assign(Error('busy'),{status:503});}})),503);
});

test('gateway coalescer: one envelope per bearer and turn; whole-envelope refusals reach every item; an older vault gets single calls',async()=>{
 const sent=[],singles=[];let reply=null,clock=0;
 const coalescer=createForwardCoalescer({now:()=>clock,retryMs:1000,
  send:async(authorization,text)=>{const value=JSON.parse(text);sent.push({authorization,value});return reply(value);},
  single:async(headers,body)=>{singles.push(body);return {status:202,body:JSON.stringify({single:JSON.parse(body).id})};}});
 const forward=(token,id)=>coalescer.forward({authorization:'Bearer '+token,'x-evid-nonce':'n-'+id,'x-evid-timestamp':'1','x-evid-signature':'s',cookie:'c'},
  JSON.stringify({id}));
 const answer=items=>({status:200,headers:{[INGEST_FORWARD_HEADER]:'1'},body:Buffer.from(JSON.stringify({items}))});
 reply=value=>answer(value.items.map(item=>({status:202,body:{id:JSON.parse(item.body).id}})));
 let answers=await Promise.all([forward('a','1'),forward('b','2'),forward('a','3'),forward('a','4')]);
 assert.deepEqual(answers.map(a=>[a.status,JSON.parse(a.body)]),[[202,{id:'1'}],[202,{single:'2'}],[202,{id:'3'}],[202,{id:'4'}]]);
 assert.equal(sent.length,1);assert.equal(sent[0].authorization,'Bearer a');
 assert.deepEqual(sent[0].value.items[0].headers,{'x-evid-timestamp':'1','x-evid-nonce':'n-1','x-evid-signature':'s'});
 // The vault refused the envelope's bearer (or was busy): each item gets that answer, as it would have alone.
 reply=()=>({status:401,headers:{[INGEST_FORWARD_HEADER]:'1'},body:Buffer.from('{"error":"인증이 필요합니다"}')});
 answers=await Promise.all([forward('x','5'),forward('x','6')]);
 assert.deepEqual(answers.map(a=>a.status),[401,401]);assert.equal(answers[0].body,'{"error":"인증이 필요합니다"}');
 // A vault without the envelope route: each item alone, and no envelope for retryMs.
 reply=()=>({status:403,headers:{},body:Buffer.from('{"error":"인간 감사 계정만 접근할 수 있습니다"}')});
 const before=sent.length;answers=await Promise.all([forward('a','7'),forward('a','8')]);
 assert.deepEqual(answers.map(a=>JSON.parse(a.body)),[{single:'7'},{single:'8'}]);
 await Promise.all([forward('a','9'),forward('a','10')]);assert.equal(sent.length,before+1,'single calls while the vault is known to predate envelopes');
 clock=2000;reply=value=>answer(value.items.map(()=>({status:202,body:{}})));
 await Promise.all([forward('a','11'),forward('a','12')]);assert.equal(sent.length,before+2);
 // A lost connection or a malformed answer fails every item of the envelope (the gateway answers 503, never a guess).
 reply=()=>{throw Error('ECONNRESET');};
 assert.deepEqual((await Promise.allSettled([forward('a','13'),forward('a','14')])).map(r=>r.status),['rejected','rejected']);
 reply=()=>({status:200,headers:{[INGEST_FORWARD_HEADER]:'1'},body:Buffer.from('{"items":[]}')});
 assert.deepEqual((await Promise.allSettled([forward('a','15'),forward('a','16')])).map(r=>r.status),['rejected','rejected']);
 assert.throws(()=>createForwardCoalescer({maxEvents:INGEST_FORWARD_MAX_EVENTS+1}),/Invalid/);
});

// Raw /api/ingest call with explicit headers: {status, body}.
async function post(url,principal,value,{nonce=randomUUID(),stamp=String(Date.now()),signature,token=principal.token}={}){
 const body=JSON.stringify(value);
 const response=await fetch(new URL('/api/ingest',url),{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token,
  'x-evid-timestamp':stamp,'x-evid-nonce':nonce,'x-evid-signature':signature??mac(principal.hmacSecret,stamp,nonce,body)},body});
 return {status:response.status,body:await response.json()};
}
test('gateway envelopes end to end: the same answers as the vault gives directly, for accepted, duplicate and refused events',async t=>{
 const h=await harness();t.after(()=>h.close());
 const agent=h.principal('agent'),tool=h.principal('tool'),reused=randomUUID(),retried=event('fw-retry');
 const cases=[
  ['accepted',p=>post(p,agent,event('fw-1'))],['accepted',p=>post(p,tool,event('fw-2',{kind:'result'}))],
  ['bad signature',p=>post(p,agent,event('fw-3'),{signature:'0'.repeat(64)})],['unknown token',p=>post(p,agent,event('fw-4'),{token:'z'.repeat(40)})],
  ['stale timestamp',p=>post(p,agent,event('fw-5'),{stamp:String(Date.now()-3600000)})],['invalid event',p=>post(p,agent,{id:'fw-6'})],
 ];
 const viaIngress=await Promise.all(cases.map(([,run])=>run(h.ingress.url)));
 // The refused requests again, straight to the vault.
 const direct=await Promise.all(cases.map(([,run],i)=>i<2?viaIngress[i]:run(h.vault.url)));
 assert.deepEqual(viaIngress.slice(0,5).map(r=>r.status),[202,202,401,401,401]);assert.ok(viaIngress[5].status>=400&&viaIngress[5].status<500);
 assert.deepEqual(viaIngress.map(r=>r.status),direct.map(r=>r.status));
 for(let i=2;i<cases.length;i++)assert.deepEqual(viaIngress[i].body,direct[i].body,cases[i][0]);
 assert.equal((await post(h.ingress.url,agent,retried)).status,202);
 const [dup,first,replay]=await Promise.all([post(h.ingress.url,agent,retried),post(h.ingress.url,agent,event('fw-7'),{nonce:reused}),
  post(h.ingress.url,agent,event('fw-8'),{nonce:reused})]);
 assert.equal(dup.body.duplicate,true);assert.equal(first.status,202);assert.equal(replay.status,409);assert.match(replay.body.error,/nonce/);
 // Many sources at once: every 202 is stored once, in a verifying export.
 const sources=['agent','tool','telemetry'],kinds={agent:'intent',tool:'result',telemetry:'notice'};
 const burst=await Promise.all(Array.from({length:90},(_,i)=>
  submit(h.ingress.url,h.principal(sources[i%3]),event('fw-b'+i,{kind:kinds[sources[i%3]]}),{timeoutMs:15000})));
 assert.ok(burst.every(r=>r.status===202&&r.body.duplicate===false));
 const bundle=(await h.api('/api/export')).body;verifyBundle(bundle,h.publicKey);
 const ids=bundle.disclosures.map(d=>d.event.id);assert.equal(new Set(ids).size,ids.length);
 for(let i=0;i<90;i++)assert.ok(ids.includes('fw-b'+i));
 // INGRESS_FORWARD_MAX_EVENTS=1 restores one vault call per event; an invalid value stops the gateway at startup.
 const single=await h.start('ingress',{VAULT_URL:h.vault.url,INGRESS_FORWARD_MAX_EVENTS:'1'});
 assert.ok((await Promise.all([1,2,3].map(i=>post(single.url,agent,event('fw-s'+i))))).every(r=>r.status===202));
 await assert.rejects(h.start('ingress',{VAULT_URL:h.vault.url,INGRESS_FORWARD_MAX_EVENTS:'65'}),/Invalid INGRESS_FORWARD_MAX_EVENTS/);
});

test('gateway envelopes: SIGKILL of the vault under load through the gateway loses no 202',async t=>{
 const h=await harness();t.after(()=>h.close());
 const acknowledged=new Set(),sources=['agent','tool','telemetry'],kinds={agent:'intent',tool:'result',telemetry:'notice'};let next=0,killed=false;
 const sendOne=async i=>{
  const kind=sources[i%3];
  try{const r=await submit(h.ingress.url,h.principal(kind),event(`kill-${i}`,{kind:kinds[kind]}),{timeoutMs:15000});
   if(r.status===202)acknowledged.add(`kill-${i}`);}catch{}
 };
 const deadline=Date.now()+60000;
 const restart=(async()=>{while(acknowledged.size<60&&Date.now()<deadline)await new Promise(r=>setTimeout(r,2));killed=true;await h.restart();})();
 await Promise.all(Array.from({length:30},async()=>{while(next<300&&!killed)await sendOne(next++);}));
 await restart;
 assert.ok(acknowledged.size>=60,`only ${acknowledged.size} events acknowledged before the kill`);
 const exported=await h.api('/api/export');assert.equal(exported.status,200);verifyBundle(exported.body,h.publicKey);
 const stored=new Set(exported.body.disclosures.map(d=>d.event.id));
 for(const id of acknowledged)assert.ok(stored.has(id),`acknowledged ${id} missing after SIGKILL`);
 assert.equal((await h.api('/api/integrity')).body.valid,true);
});
