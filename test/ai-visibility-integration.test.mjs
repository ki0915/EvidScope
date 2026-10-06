import test from 'node:test';
import assert from 'node:assert/strict';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {observationEvent} from '../src/ai-observations.mjs';
import {CIPHER_MODEL,languageSignals} from '../src/content-screening.mjs';

test('signed AI observations drive tenant-scoped visibility without retaining source content',async t=>{
 const h=await harness();t.after(()=>h.close());
 const canary='RAW-PROMPT-CANARY-민감정보',asset={id:'assistant-api',actor:'service',tool:'ai-client',owner:'security',purpose:'승인된 합성 관측 시험',version:'1',policyVersion:'policy-1',destinations:['api.example.test'],validFrom:new Date(Date.now()-1000).toISOString()};
 assert.equal((await h.api('/api/assets',{role:'reviewer',body:asset})).status,200);
 const unsafe={status:'complete',safety:'unsafe',categories:['Credential/Secret'],processedChunks:1,totalChunks:1,model:CIPHER_MODEL,reason:'completed'};
 const content=observationEvent('local',{provider:'openai',model:'gpt-test'},{id:'content-observation',assetRef:asset.id,contentObserved:true,languageSignals:languageSignals({prompt:`한국어 request and English log ${canary}`}),screening:unsafe,now:Date.now()});
 const metadata=observationEvent('http',{url:'https://api.example.test/v1/chat',provider:'openai',model:'gpt-test',prompt:canary},{id:'metadata-observation',assetRef:asset.id,now:Date.now()});
 assert.equal((await submit(h.ingress.url,h.principal('telemetry'),content)).status,202);
 assert.equal((await submit(h.ingress.url,h.principal('telemetry'),metadata)).status,202);

 const visible=await h.api('/api/ai-visibility?range=1h');assert.equal(visible.status,200);
 assert.equal(visible.body.summary.totalObservations,2);assert.equal(visible.body.summary.contentObserved,1);assert.equal(visible.body.summary.bodyNotObserved,1);
 assert.equal(visible.body.screening.unsafe,1);assert.equal(visible.body.languageSignals.mixed,1);
 const row=visible.body.assets.find(v=>v.id===asset.id);assert.equal(row.registered,true);assert.ok(row.attention.some(v=>v.code==='AI_SOURCE_DLP_SENSITIVE_CONTENT'));
 assert.ok(!JSON.stringify(visible.body).includes(canary));
 const stored=await h.api('/api/events?limit=20');assert.ok(!JSON.stringify(stored.body).includes(canary));
 const beta=await h.api('/api/ai-visibility?range=1h',{tenant:'beta'});assert.equal(beta.body.summary.totalObservations,0);

 const rejected=await submit(h.ingress.url,h.principal('telemetry'),{...metadata,id:'raw-rejected',prompt:canary});assert.equal(rejected.status,400);assert.ok(!JSON.stringify(rejected.body).includes(canary));
});
